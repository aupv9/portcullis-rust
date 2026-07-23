//! The provision subsystem's actor: a cloneable [`ProvisionHandle`] (implements
//! [`Provisioner`]) that sends commands over an mpsc to a single owner task
//! ([`run_provision_subsystem`]), mirroring the nft writer-actor shape. The task
//! owns the [`ProvisionMachine`] + the commit-confirm watchdog and emits
//! `WirelessStatus` upward on a bounded channel that `portcullis-control` fans
//! into outbound `EngineFrame`s.
//!
//! ## Isolation (guardrail)
//! This runs as its OWN Tokio task. Every side-effecting step is awaited inside
//! the task and its result is matched — a provision error becomes a status /
//! rollback, never a panic that could unwind into the enforcement tasks. The
//! composition root spawns it separately and aborts it on shutdown like the
//! other subsystems.
//!
//! ## MIPS-safe
//! No `AtomicU64` (the RUTM11 is 32-bit MIPS): the single owner task holds all
//! mutable state directly; the handle carries only an `mpsc::Sender`.

use std::time::Duration;

use async_trait::async_trait;
use portcullis_types::{
    ProvisionError, ProvisionState, Provisioner, SsidResult, WirelessDesiredState, WirelessStatus,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::runner::CommandRunner;
use crate::sm::{self, ProvisionMachine, Snapshot, WirelessMarker};
use crate::uci;

/// Bound on the command channel — provision commands are rare (a handful of CP
/// pushes over a router's lifetime), so a tiny buffer is ample.
const COMMAND_BUFFER: usize = 8;
/// Bound on the upward status channel.
const STATUS_BUFFER: usize = 16;

/// A command sent to the provision actor, carrying its reply channel.
enum Command {
    Set {
        state: Box<WirelessDesiredState>,
        reply: oneshot::Sender<Result<(), ProvisionError>>,
    },
    Confirm {
        config_version: String,
        reply: oneshot::Sender<Result<(), ProvisionError>>,
    },
    Get {
        reply: oneshot::Sender<Result<WirelessDesiredState, ProvisionError>>,
    },
}

/// Cloneable handle to the provision actor. Implements [`Provisioner`].
#[derive(Clone)]
pub struct ProvisionHandle {
    tx: mpsc::Sender<Command>,
}

impl ProvisionHandle {
    async fn call(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<(), ProvisionError>>) -> Command,
    ) -> Result<(), ProvisionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(make(reply_tx))
            .await
            .map_err(|_| ProvisionError::Unavailable("provision actor is gone".into()))?;
        reply_rx
            .await
            .map_err(|_| ProvisionError::Unavailable("provision actor dropped reply".into()))?
    }

    /// The `get_wireless` variant of [`call`](Self::call): its reply carries a
    /// [`WirelessDesiredState`], not `()`.
    async fn call_get_wireless(&self) -> Result<WirelessDesiredState, ProvisionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::Get { reply: reply_tx })
            .await
            .map_err(|_| ProvisionError::Unavailable("provision actor is gone".into()))?;
        reply_rx
            .await
            .map_err(|_| ProvisionError::Unavailable("provision actor dropped reply".into()))?
    }
}

#[async_trait]
impl Provisioner for ProvisionHandle {
    async fn set_wireless(&self, state: WirelessDesiredState) -> Result<(), ProvisionError> {
        self.call(|reply| Command::Set { state: Box::new(state), reply }).await
    }

    async fn confirm_wireless(&self, config_version: &str) -> Result<(), ProvisionError> {
        let v = config_version.to_string();
        self.call(|reply| Command::Confirm { config_version: v, reply }).await
    }

    async fn get_wireless(&self) -> Result<WirelessDesiredState, ProvisionError> {
        self.call_get_wireless().await
    }
}

/// The pending commit-confirm state for a CP-managed wireless push (P-W1):
/// carries the multi-radio reload set, the owned sections present after apply
/// (for the rollback delete), the per-SSID results (echoed in status), and the
/// desired state (cached as last-committed on confirm).
struct WirelessPending {
    config_version: String,
    radios: Vec<String>,
    current_sections: Vec<String>,
    /// Gated-SSID bridge ifaces (enforcement scope) — persisted in the marker so a
    /// confirm after a mid-window restart writes the correct committed-gated set
    /// even though `desired` is not reconstructed (P0 #2).
    gated_ifaces: Vec<String>,
    per_ssid: Vec<SsidResult>,
    deadline: Instant,
    snapshot: Snapshot,
    desired: WirelessDesiredState,
}

/// Spawn the provision subsystem. Returns:
/// - a cloneable [`ProvisionHandle`] to pass into the control channel;
/// - an mpsc [`Receiver`](mpsc::Receiver) of [`WirelessStatus`] (P-W1), fanned by
///   the composition root into outbound `EngineFrame`s (unsolicited on watchdog
///   rollback);
/// - the actor's [`JoinHandle`](tokio::task::JoinHandle) (abort on shutdown).
///
/// `state_dir` is the tmpfs directory ([`sm::DEFAULT_STATE_DIR`] on-device).
/// `responder_port` is the portcullis :8080 redirect responder port
/// ([`portcullis_config::Config::responder_port`]) — opened by the portal
/// firewall rule so pre-auth guests can reach the captive redirect. On startup
/// the actor reconciles any leftover wireless marker before serving commands.
pub fn run_provision_subsystem<R>(
    runner: R,
    state_dir: impl Into<std::path::PathBuf>,
    responder_port: u16,
) -> (ProvisionHandle, mpsc::Receiver<WirelessStatus>, tokio::task::JoinHandle<()>)
where
    R: CommandRunner + 'static,
{
    run_provision_subsystem_with_policy(runner, state_dir, responder_port, Vec::new())
}

/// [`run_provision_subsystem`] plus the engine-local `protected_radios` policy
/// (layer A): radios the CP may not place owned SSIDs on (the admin/management
/// radio). An empty list is exactly [`run_provision_subsystem`]. Wired from
/// [`portcullis_config::Config::wireless_protected_radios`] by the composition
/// root; enforced by [`uci::validate_protected_radios`] before any apply.
pub fn run_provision_subsystem_with_policy<R>(
    runner: R,
    state_dir: impl Into<std::path::PathBuf>,
    responder_port: u16,
    protected_radios: Vec<String>,
) -> (ProvisionHandle, mpsc::Receiver<WirelessStatus>, tokio::task::JoinHandle<()>)
where
    R: CommandRunner + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_BUFFER);
    let (wireless_status_tx, wireless_status_rx) = mpsc::channel(STATUS_BUFFER);
    let machine = ProvisionMachine::new(runner, state_dir, responder_port);
    let actor = ProvisionActor {
        machine,
        cmd_rx,
        wireless_status_tx,
        pending_wireless: None,
        // TODO(reboot-gate): rehydrate last_committed version at boot. Part A
        // self-heals the ENFORCEMENT gate scope from persistent UCI, but
        // GetWirelessConfig still reports an empty config_version after a reboot
        // until the CP re-pushes (last_committed only set on confirm). Rehydrating
        // it would mean persisting config_version in an owned UCI option and
        // reconstructing the desired-state from `uci show` here — invasive (touches
        // the confirm/version-echo path), so deferred to keep the gate self-heal
        // low-risk. The captive gate itself is correct post-reboot regardless.
        last_committed: None,
        protected_radios,
    };
    let join = tokio::spawn(actor.run());
    (ProvisionHandle { tx: cmd_tx }, wireless_status_rx, join)
}

/// The single-owner actor.
struct ProvisionActor<R: CommandRunner> {
    machine: ProvisionMachine<R>,
    cmd_rx: mpsc::Receiver<Command>,
    wireless_status_tx: mpsc::Sender<WirelessStatus>,
    pending_wireless: Option<WirelessPending>,
    /// Last COMMITTED wireless desired-state (served by `get_wireless`).
    last_committed: Option<WirelessDesiredState>,
    /// Layer A: radios owned SSIDs may not target (admin/management radio).
    /// Empty = no restriction. Enforced in [`Self::handle_set_wireless`].
    protected_radios: Vec<String>,
}

impl<R: CommandRunner> ProvisionActor<R> {
    async fn run(mut self) {
        // Crash-recovery reconcile: an unconfirmed wireless push from a previous
        // process incarnation. Past deadline → roll back NOW; still within the
        // window → resume the watchdog for the remainder.
        self.reconcile_wireless_on_start().await;

        loop {
            // Watchdog sleep: armed only while a push is pending confirmation.
            let wl_sleep =
                self.pending_wireless.as_ref().map(|p| tokio::time::sleep_until(p.deadline));

            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(Command::Set { state, reply }) => {
                        let r = self.handle_set_wireless(*state).await;
                        let _ = reply.send(r);
                    }
                    Some(Command::Confirm { config_version, reply }) => {
                        let r = self.handle_confirm_wireless(&config_version).await;
                        let _ = reply.send(r);
                    }
                    Some(Command::Get { reply }) => {
                        let _ = reply.send(Ok(self.last_committed.clone().unwrap_or_default()));
                    }
                    None => break, // all handles dropped -> shut down
                },
                // Only armed when a push is pending confirmation.
                _ = maybe_sleep(wl_sleep) => {
                    self.handle_wireless_watchdog_fire().await;
                }
            }
        }
    }

    // --- CP-managed wireless (P-W1) ---------------------------------------

    /// Per-SSID results (one `ok` row per desired SSID; `iface` = its bridge,
    /// which feeds enforcement scoping when the SSID is gated).
    fn ssid_results(state: &WirelessDesiredState) -> Vec<SsidResult> {
        state
            .ssids
            .iter()
            .map(|s| SsidResult {
                slug: s.slug.clone(),
                ok: true,
                message: String::new(),
                iface: s.bridge_name.clone(),
            })
            .collect()
    }

    /// Validate → snapshot → reconcile (delete pre-existing owned sections, then
    /// set the desired) → apply + multi-radio reload → arm watchdog. Returns once
    /// APPLIED_PENDING (COMMITTED / ROLLED_BACK arrives later as a status).
    async fn handle_set_wireless(
        &mut self,
        state: WirelessDesiredState,
    ) -> Result<(), ProvisionError> {
        // Validate FIRST — a bad desired-state writes nothing (fail-OPEN reject).
        uci::validate_wireless(&state)?;
        // Layer A: never let an owned SSID land on a protected (admin) radio, so a
        // `wifi reload <radio>` can't bounce/dark the admin SSID. No-op when unset.
        uci::validate_protected_radios(&state, &self.protected_radios)?;

        // One pending push at a time — can't honour two watchdogs / rollback
        // safety nets at once.
        if self.pending_wireless.is_some() {
            return Err(ProvisionError::Invalid(
                "a wireless push is already pending confirmation; confirm or await its watchdog first".into(),
            ));
        }

        // Snapshot the CURRENT owned wireless state (pre-apply).
        let snapshot = self.machine.snapshot_wireless().await?;

        // Reload set = desired radios ∪ prior radios (so a removed SSID's radio
        // reloads too). Never empty (fall back to the default radio).
        let mut radios: Vec<String> = Vec::new();
        for ssid in &state.ssids {
            for r in uci::effective_radios(ssid) {
                if !radios.iter().any(|x| x == r) {
                    radios.push(r.to_string());
                }
            }
        }
        for r in sm::snapshot_radios(&snapshot) {
            if !radios.contains(&r) {
                radios.push(r);
            }
        }
        if radios.is_empty() {
            radios.push(uci::DEFAULT_RADIO.to_string());
        }

        // Declarative reconcile: delete EVERY pre-existing owned section, then set
        // the desired ones. Delete-then-set avoids stale options / orphan `ap{i}`
        // sections lingering when an SSID shrinks its radio set or drops an option.
        let sets = uci::render_wireless(&state, self.machine.responder_port());
        let current_sections = uci::section_decls(&sets);
        let mut batch = uci::render_deletes(&snapshot.existing_sections);
        batch.extend(sets);

        // Apply + commit + multi-radio reload. On ANY failure, roll back and
        // report FAILED — never leave a half-applied config on a CGNAT router.
        if let Err(e) = self.machine.apply_wireless(&batch, true, &radios).await {
            tracing::warn!(config_version = %state.config_version, error = %e, "wireless apply failed; rolling back");
            if let Err(re) = self.machine.rollback_to(&snapshot, &current_sections, &radios).await {
                tracing::error!(config_version = %state.config_version, error = %re, "wireless rollback after failed apply ALSO failed");
            }
            let _ = self.machine.clear_wireless_marker().await;
            self.emit_wireless(sm::wireless_status(
                &state.config_version,
                ProvisionState::Failed,
                Self::ssid_results(&state),
                e.to_string(),
            ))
            .await;
            return Err(e);
        }

        // Arm the LOCAL watchdog + persist the marker (tmpfs) so a restart
        // mid-window still honours the confirm/rollback.
        let window = sm::confirm_window_secs(state.confirm_timeout_secs);
        let deadline = Instant::now() + window;
        let deadline_unix = unix_now() + window.as_secs() as i64;
        // Gated-SSID bridge ifaces = the enforcement scope this push commits. Carry
        // it in the marker AND the pending so a restart-then-confirm writes the
        // RIGHT committed-gated set, not an empty one (P0 #2).
        let gated_ifaces: Vec<String> =
            state.ssids.iter().filter(|s| s.gated).map(|s| s.bridge_name.clone()).collect();
        let marker = WirelessMarker {
            config_version: state.config_version.clone(),
            radios: radios.clone(),
            current_sections: current_sections.clone(),
            gated_ifaces: gated_ifaces.clone(),
            deadline_unix,
            snapshot: snapshot.clone(),
        };
        if let Err(e) = self.machine.write_wireless_marker(&marker).await {
            tracing::warn!(config_version = %state.config_version, error = %e, "could not persist wireless marker (crash-recovery only)");
        }

        let per_ssid = Self::ssid_results(&state);
        tracing::info!(
            config_version = %state.config_version,
            window_secs = window.as_secs(),
            ssids = state.ssids.len(),
            "wireless applied; awaiting confirm (commit-confirm armed)"
        );
        self.emit_wireless(sm::wireless_status(
            &state.config_version,
            ProvisionState::AppliedPending,
            per_ssid.clone(),
            "applied; awaiting confirm",
        ))
        .await;
        self.pending_wireless = Some(WirelessPending {
            config_version: state.config_version.clone(),
            radios,
            current_sections,
            gated_ifaces,
            per_ssid,
            deadline,
            snapshot,
            desired: state,
        });
        Ok(())
    }

    /// A confirm before the deadline commits the pending wireless push and caches
    /// it as the last-committed desired-state.
    async fn handle_confirm_wireless(&mut self, config_version: &str) -> Result<(), ProvisionError> {
        match self.pending_wireless.take() {
            Some(p) if p.config_version == config_version => {
                let _ = self.machine.clear_wireless_marker().await;
                // Persist the committed gated-SSID ifaces (F2) so a daemon restart
                // re-scopes enforcement before the CP reconnects. Sourced from the
                // pending's `gated_ifaces` (carried in the marker), NOT re-derived
                // from `desired` — which is empty on a resumed-after-restart push, so
                // deriving would write an empty set and silently un-gate every
                // captive SSID (P0 #2). Best-effort.
                if let Err(e) = self.machine.write_committed_gated(&p.gated_ifaces).await {
                    tracing::warn!(error = %e, "could not persist committed gated ifaces (boot re-scope only)");
                }
                self.last_committed = Some(p.desired);
                tracing::info!(config_version, "wireless push confirmed; committed permanently");
                self.emit_wireless(sm::wireless_status(
                    config_version,
                    ProvisionState::Committed,
                    p.per_ssid,
                    "confirmed",
                ))
                .await;
                Ok(())
            }
            // Not ours: put it back (take() removed it) and report no-pending.
            other => {
                self.pending_wireless = other;
                Err(ProvisionError::NoPending(config_version.to_string()))
            }
        }
    }

    /// Watchdog fired without a confirm → roll back to the snapshot and emit an
    /// UNSOLICITED RolledBack status.
    async fn handle_wireless_watchdog_fire(&mut self) {
        let Some(p) = self.pending_wireless.take() else { return };
        tracing::warn!(
            config_version = %p.config_version,
            "wireless commit-confirm watchdog fired without confirm; rolling back (CGNAT has no inbound rescue)"
        );
        let (state, msg) = match self.machine.rollback_to(&p.snapshot, &p.current_sections, &p.radios).await {
            Ok(()) => (ProvisionState::RolledBack, "watchdog expired; rolled back to snapshot".to_string()),
            Err(e) => {
                tracing::error!(config_version = %p.config_version, error = %e, "wireless watchdog rollback FAILED");
                (ProvisionState::Failed, format!("watchdog rollback failed: {e}"))
            }
        };
        let _ = self.machine.clear_wireless_marker().await;
        self.emit_wireless(sm::wireless_status(&p.config_version, state, p.per_ssid, msg)).await;
    }

    /// Honour a leftover wireless marker at startup: past deadline → roll back
    /// now; still within the window → resume the watchdog for the remainder.
    async fn reconcile_wireless_on_start(&mut self) {
        let marker = match self.machine.read_wireless_marker().await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "could not read wireless marker on start");
                return;
            }
        };
        let now_unix = unix_now();
        if marker.deadline_unix <= now_unix {
            tracing::warn!(
                config_version = %marker.config_version,
                "unconfirmed wireless push past its deadline at startup; rolling back"
            );
            let (state, msg) = match self
                .machine
                .rollback_to(&marker.snapshot, &marker.current_sections, &marker.radios)
                .await
            {
                Ok(()) => (ProvisionState::RolledBack, "rolled back on startup (deadline passed)".to_string()),
                Err(e) => (ProvisionState::Failed, format!("startup rollback failed: {e}")),
            };
            let _ = self.machine.clear_wireless_marker().await;
            self.emit_wireless(sm::wireless_status(&marker.config_version, state, Vec::new(), msg)).await;
        } else {
            let remaining = Duration::from_secs((marker.deadline_unix - now_unix).max(0) as u64);
            tracing::info!(
                config_version = %marker.config_version,
                remaining_secs = remaining.as_secs(),
                "resuming wireless commit-confirm watchdog after restart"
            );
            self.pending_wireless = Some(WirelessPending {
                config_version: marker.config_version,
                radios: marker.radios,
                current_sections: marker.current_sections,
                // Reconstructed from the marker (P0 #2): a confirm after this resume
                // writes the correct committed-gated set, not an empty one.
                gated_ifaces: marker.gated_ifaces,
                per_ssid: Vec::new(),
                deadline: Instant::now() + remaining,
                snapshot: marker.snapshot,
                // The full desired state isn't persisted in the marker; a resumed
                // push that then confirms records an empty last-committed (the CP
                // re-pushes if it needs introspection). The rollback path (the
                // common resume outcome) doesn't need it, and the gated-iface scope
                // — the one thing a confirm MUST get right — is carried above.
                desired: WirelessDesiredState::default(),
            });
        }
    }

    /// Emit a wireless status upward (see [`Self::emit`]).
    async fn emit_wireless(&self, status: WirelessStatus) {
        if self.wireless_status_tx.send(status).await.is_err() {
            tracing::debug!("wireless status channel closed; status dropped");
        }
    }
}

/// Await an optional sleep future: if `None`, never resolves (so the `select!`
/// arm is effectively disarmed when no provision is pending).
async fn maybe_sleep(sleep: Option<tokio::time::Sleep>) {
    match sleep {
        Some(s) => s.await,
        None => std::future::pending::<()>().await,
    }
}

/// Wall-clock UNIX seconds (for the marker deadline, which must survive a
/// process restart — a monotonic `Instant` would not).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;
    // --- CP-managed wireless (P-W1) ----------------------------------------

    fn wssid(slug: &str, gated: bool, subnet3: u8) -> portcullis_types::SsidSpec {
        portcullis_types::SsidSpec {
            slug: slug.into(),
            ssid: format!("WifiHub {slug}"),
            radios: vec!["radio0".into()],
            encryption: if gated { "none".into() } else { "psk2".into() },
            key: if gated { String::new() } else { "supersecret".into() },
            hidden: false,
            isolate: true,
            gated,
            bridge_name: format!("br-{slug}"),
            ipaddr: format!("10.0.{subnet3}.1"),
            netmask: "255.255.255.0".into(),
            dhcp_start: "10".into(),
            dhcp_limit: "200".into(),
            dhcp_leasetime: "2h".into(),
            dhcp_disabled: false,
            egress_zone: String::new(),
            max_clients: 0,
            mac_policy: String::new(),
            mac_list: Vec::new(),
            rate_down_kbps: 0,
            rate_up_kbps: 0,
            mode: String::new(),
            ieee80211r: false,
            ieee80211w: String::new(),
        }
    }

    fn wstate(version: &str, timeout: u32) -> WirelessDesiredState {
        WirelessDesiredState {
            config_version: version.into(),
            confirm_timeout_secs: timeout,
            ssids: vec![wssid("public", true, 0), wssid("home", false, 1)],
            peer_allows: Vec::new(),
        }
    }

    fn wdrain(rx: &mut mpsc::Receiver<WirelessStatus>) -> Vec<WirelessStatus> {
        let mut out = Vec::new();
        while let Ok(s) = rx.try_recv() {
            out.push(s);
        }
        out
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_set_then_confirm_commits() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-1", 90)).await.unwrap();
        let s = wrx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::AppliedPending);
        assert_eq!(s.config_version, "cfg-1");
        // per-SSID ifaces reported (fed to enforcement scoping when gated).
        assert!(s.per_ssid.iter().any(|r| r.slug == "public" && r.iface == "br-public"));

        handle.confirm_wireless("cfg-1").await.unwrap();
        let s = wrx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::Committed);

        // get_wireless now returns the committed desired-state.
        let got = handle.get_wireless().await.unwrap();
        assert_eq!(got.config_version, "cfg-1");
        assert_eq!(got.ssids.len(), 2);

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_set_then_watchdog_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-2", 30)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::AppliedPending);

        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::RolledBack);

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_supersede_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-a", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::AppliedPending);
        // A second push while one is pending is rejected (can't hold two watchdogs).
        let err = handle.set_wireless(wstate("cfg-b", 90)).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_invalid_state_applies_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        let mut bad = wstate("cfg-bad", 90);
        bad.ssids[0].bridge_name = "br-lan".into(); // reserved -> reject
        let err = handle.set_wireless(bad).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));
        // Nothing applied, no status.
        assert!(wdrain(&mut wrx).is_empty());

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_rejects_ssid_on_protected_radio() {
        // Layer A: with radio0 protected (the admin radio), a push whose SSIDs land
        // on radio0 is rejected up front — nothing applied, no reload/bounce.
        let dir = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::new();
        let (handle, mut wrx, join) = run_provision_subsystem_with_policy(
            runner.clone(),
            dir.path().to_path_buf(),
            8080,
            vec!["radio0".to_string()],
        );

        // wstate SSIDs default to radio0 → hits the protected radio → rejected.
        let err = handle.set_wireless(wstate("cfg-prot", 90)).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));
        assert!(wdrain(&mut wrx).is_empty(), "rejected push must apply nothing");
        // Not a single uci/wifi command ran — the guard is pre-apply.
        assert!(runner.flat().is_empty(), "protected-radio reject must touch nothing: {:?}", runner.flat());

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_accepts_ssid_on_unprotected_radio() {
        // Same protection, but the SSIDs sit on radio1 → accepted (applies + arms).
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) = run_provision_subsystem_with_policy(
            RecordingRunner::new(),
            dir.path().to_path_buf(),
            8080,
            vec!["radio0".to_string()],
        );

        let mut st = wstate("cfg-ok", 90);
        for s in &mut st.ssids {
            s.radios = vec!["radio1".into()];
        }
        handle.set_wireless(st).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::AppliedPending);

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_set_applies_expected_uci_batch_and_scoped_reload() {
        // End-to-end (actor + machine + RecordingRunner): a wireless push renders
        // the owned `pc_<slug>_*` sections, commits every owned config, and reloads
        // network → firewall → `wifi <radio>` (scoped) → dnsmasq. No bare `wifi
        // reload`, no `sh`. This is the host-runnable stand-in for the netns test.
        let dir = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::new();
        let (handle, mut wrx, join) =
            run_provision_subsystem(runner.clone(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-e2e", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::AppliedPending);

        let flat = runner.flat();
        let has = |p: &str, a: &str| flat.iter().any(|(pp, aa)| pp == p && aa == a);
        // Owned sections for BOTH ssids are rendered (pc_<slug>_*).
        assert!(has("uci", "set wireless.pc_public_ap0=wifi-iface"), "{flat:?}");
        assert!(has("uci", "set network.pc_home_dev=device"), "{flat:?}");
        assert!(has("uci", "set firewall.pc_public_portal=rule"), "gated SSID gets a portal rule");
        // Per-config commits + ordered reload; wifi scoped to radio0, never bare.
        assert!(has("uci", "commit network"));
        assert!(has("uci", "commit firewall"));
        assert!(has("/etc/init.d/network", "reload"));
        assert!(has("/sbin/wifi", "reload radio0"));
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload"));
        assert!(flat.iter().all(|(p, _)| p != "sh" && p != "/bin/sh"));

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_confirm_unknown_version_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-real", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::AppliedPending);
        // A confirm for a DIFFERENT version does not resolve the pending push.
        let err = handle.confirm_wireless("cfg-wrong").await.unwrap_err();
        assert!(matches!(err, ProvisionError::NoPending(_)));
        // The real one still confirms.
        handle.confirm_wireless("cfg-real").await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn confirm_persists_committed_gated_ifaces_for_boot_rescope() {
        // F2: on COMMIT, the gated-SSID bridge ifaces are persisted to tmpfs so a
        // daemon restart (compose reads `read_committed_gated`) re-scopes
        // enforcement before the CP reconnects.
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-f2", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::AppliedPending);
        handle.confirm_wireless("cfg-f2").await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        // wstate = [public (gated), home (not gated)] → only br-public is gated.
        let gated = crate::sm::read_committed_gated(dir.path()).unwrap();
        assert_eq!(gated, vec!["br-public".to_string()]);

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn resumed_confirm_persists_gated_ifaces_not_empty() {
        // P0 #2: a push confirmed AFTER a mid-window restart must still write the
        // correct committed-gated set (carried in the marker), NOT an empty one —
        // an empty set would silently un-gate every captive SSID (unauth internet).
        let dir = tempfile::tempdir().unwrap();

        // Incarnation A: apply a gated SSID, reach AppliedPending, then "crash"
        // (drop) WITHOUT confirming. The marker (with gated_ifaces) persists.
        {
            let (handle, mut wrx, join) =
                run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);
            handle.set_wireless(wstate("cfg-resume", 600)).await.unwrap();
            assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::AppliedPending);
            drop(handle);
            let _ = join.await;
        }

        // Incarnation B: fresh actor, same tmpfs dir → resumes the pending from the
        // marker. A confirm now must persist the gated ifaces from the marker.
        let (handle, mut wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);
        handle.confirm_wireless("cfg-resume").await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        // The scope survived the restart — NOT wiped to empty.
        let gated = crate::sm::read_committed_gated(dir.path()).unwrap();
        assert_eq!(gated, vec!["br-public".to_string()], "resumed confirm must not wipe the gated scope");

        drop(handle);
        let _ = join.await;
    }
}
