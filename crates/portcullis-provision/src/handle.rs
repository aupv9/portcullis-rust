//! The provision subsystem's actor: a cloneable [`ProvisionHandle`] (implements
//! [`Provisioner`]) that sends commands over an mpsc to a single owner task
//! ([`run_provision_subsystem`]), mirroring the nft writer-actor shape. The task
//! owns the [`ProvisionMachine`] and emits `WirelessStatus` upward on a bounded
//! channel that `portcullis-control` fans into outbound `EngineFrame`s.
//!
//! ## Apply-and-ACK (CP-SOT, P2)
//! Wireless is namespaced to the owned `pc_*` sections — it can NEVER touch the
//! LAN / WAN / dial-out path, so a bad push cannot brick the router's own
//! connectivity the way a raw `network`/`firewall` commit-confirm exists to guard.
//! So the subsystem APPLIES the config and ACKs immediately (emits `Committed`,
//! sets the gate scope from live UCI, returns ok) rather than holding the change
//! under a commit-confirm watchdog + timed rollback. A local apply FAILURE still
//! reverts to the pre-apply snapshot (fail-OPEN). See
//! `docs/design/confirm-on-reconnect.md` for the RISK-op pattern that DOES need
//! commit-confirm (the dial-out-touching ops), which wireless is deliberately not.
//!
//! ## Isolation (guardrail)
//! This runs as its OWN Tokio task. Every side-effecting step is awaited inside
//! the task and its result is matched — a provision error becomes a status /
//! local revert, never a panic that could unwind into the enforcement tasks. The
//! composition root spawns it separately and aborts it on shutdown like the
//! other subsystems.
//!
//! ## MIPS-safe
//! No `AtomicU64` (the RUTM11 is 32-bit MIPS): the single owner task holds all
//! mutable state directly; the handle carries only an `mpsc::Sender`.

use async_trait::async_trait;
use portcullis_types::{
    ProvisionError, ProvisionState, Provisioner, SsidResult, WirelessDesiredState, WirelessStatus,
};
use tokio::sync::{mpsc, oneshot};

use crate::runner::CommandRunner;
use crate::sm::{self, ProvisionMachine};
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

/// Spawn the provision subsystem. Returns:
/// - a cloneable [`ProvisionHandle`] to pass into the control channel;
/// - an mpsc [`Receiver`](mpsc::Receiver) of [`WirelessStatus`] (P-W1), fanned by
///   the composition root into outbound `EngineFrame`s;
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
        // TODO(reboot-gate): rehydrate last_committed version at boot. The boot
        // gate self-heal restores the ENFORCEMENT gate scope from persistent UCI,
        // but GetWirelessConfig still reports an empty config_version after a reboot
        // until the CP re-pushes (last_committed only set on apply). Rehydrating it
        // would mean persisting config_version in an owned UCI option and
        // reconstructing the desired-state from `uci show` here — invasive, so
        // deferred. The captive gate itself is correct post-reboot regardless.
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
    /// Last COMMITTED wireless desired-state (served by `get_wireless`).
    last_committed: Option<WirelessDesiredState>,
    /// Layer A: radios owned SSIDs may not target (admin/management radio).
    /// Empty = no restriction. Enforced in [`Self::handle_set_wireless`].
    protected_radios: Vec<String>,
}

impl<R: CommandRunner> ProvisionActor<R> {
    async fn run(mut self) {
        // Apply-and-ACK (CP-SOT, P2): no commit-confirm watchdog, so nothing to
        // reconcile at start (an interrupted apply is just re-pushed by the CP).
        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                Command::Set { state, reply } => {
                    let r = self.handle_set_wireless(*state).await;
                    let _ = reply.send(r);
                }
                Command::Confirm { config_version, reply } => {
                    let r = self.handle_confirm_wireless(&config_version).await;
                    let _ = reply.send(r);
                }
                Command::Get { reply } => {
                    let _ = reply.send(Ok(self.last_committed.clone().unwrap_or_default()));
                }
            }
        }
        // All handles dropped -> shut down.
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
    /// set the desired) → apply + multi-radio reload → derive+set the gate scope
    /// from live UCI → ACK. Returns once COMMITTED (there is no commit-confirm
    /// watchdog: wireless is namespaced to owned `pc_*` sections and can't brick
    /// dial-out → apply-and-ACK, no timed rollback; see
    /// `docs/design/confirm-on-reconnect.md` for the RISK-op pattern). A local
    /// apply FAILURE still reverts to the pre-apply snapshot (fail-OPEN).
    async fn handle_set_wireless(
        &mut self,
        state: WirelessDesiredState,
    ) -> Result<(), ProvisionError> {
        // Validate FIRST — a bad desired-state writes nothing (fail-OPEN reject).
        uci::validate_wireless(&state)?;
        // Layer A: never let an owned SSID land on a protected (admin) radio, so a
        // `wifi reload <radio>` can't bounce/dark the admin SSID. No-op when unset.
        uci::validate_protected_radios(&state, &self.protected_radios)?;

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
            self.emit_wireless(sm::wireless_status(
                &state.config_version,
                ProvisionState::Failed,
                Self::ssid_results(&state),
                e.to_string(),
            ))
            .await;
            return Err(e);
        }

        // wireless namespaced to owned pc_* (can't brick dial-out) → apply-and-ACK,
        // no commit-confirm; see docs/design/confirm-on-reconnect.md for the RISK-op
        // pattern. The apply above already committed + reloaded the owned sections.

        // Derive the enforcement gate scope from LIVE UCI (the Fix A path) — reads
        // what actually landed, so a section the renderer dropped or the driver
        // rejected is reflected truthfully, and persist it to tmpfs so the boot
        // gate self-heal has it after a daemon restart. Best-effort throughout.
        let gated_ifaces = sm::derive_gated_from_uci(self.machine.runner()).await;
        if let Err(e) = self.machine.write_committed_gated(&gated_ifaces).await {
            tracing::warn!(error = %e, "could not persist committed gated ifaces (boot re-scope only)");
        }

        let per_ssid = Self::ssid_results(&state);
        tracing::info!(
            config_version = %state.config_version,
            ssids = state.ssids.len(),
            gated_ifaces = ?gated_ifaces,
            "wireless applied + committed (apply-and-ACK; no commit-confirm)"
        );
        self.last_committed = Some(state.clone());
        self.emit_wireless(sm::wireless_status(
            &state.config_version,
            ProvisionState::Committed,
            per_ssid,
            "applied + committed",
        ))
        .await;
        Ok(())
    }

    /// `ConfirmWireless` is now an idempotent no-op (apply-and-ACK already
    /// committed on `set`). Kept for backward-compat with a CP that still sends a
    /// confirm after a push — it always succeeds. No pending state, nothing to do.
    async fn handle_confirm_wireless(&self, config_version: &str) -> Result<(), ProvisionError> {
        tracing::debug!(config_version, "confirm_wireless: no-op (apply-and-ACK already committed)");
        Ok(())
    }

    /// Emit a wireless status upward (see [`Self::emit`]).
    async fn emit_wireless(&self, status: WirelessStatus) {
        if self.wireless_status_tx.send(status).await.is_err() {
            tracing::debug!("wireless status channel closed; status dropped");
        }
    }
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
            reservations: Vec::new(),
            egress_zone: String::new(),
            internal_targets: Vec::new(),
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

    /// A runner that applies everything successfully (empty stdout) BUT serves the
    /// gate-derive read (`uci show firewall`/`network`) with the owned gated
    /// `public` SSID's portal rule + bridge — so `derive_gated_from_uci` (run after
    /// a successful apply) resolves `br-public`, mirroring what would actually be on
    /// the box post-apply.
    fn gated_derive_runner() -> RecordingRunner {
        RecordingRunner::with_responder(|prog, args| {
            if prog == "uci" && args.first() == Some(&"show") {
                let body = match args.get(1).copied().unwrap_or("") {
                    "firewall" => "firewall.pc_public_portal=rule\n",
                    "network" => "network.pc_public_dev.name='br-public'\n",
                    _ => "",
                };
                return Ok(body.as_bytes().to_vec());
            }
            Ok(Vec::new())
        })
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_set_applies_and_acks_committed() {
        // Apply-and-ACK: a push applies + commits and returns COMMITTED immediately
        // (no AppliedPending, no watchdog, no separate confirm needed).
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(gated_derive_runner(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-1", 90)).await.unwrap();
        let s = wrx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::Committed);
        assert_eq!(s.config_version, "cfg-1");
        // per-SSID ifaces reported (fed to enforcement scoping when gated).
        assert!(s.per_ssid.iter().any(|r| r.slug == "public" && r.iface == "br-public"));
        // No further status (no watchdog fire).
        assert!(wdrain(&mut wrx).is_empty());

        // get_wireless returns the committed desired-state (set on apply, not confirm).
        let got = handle.get_wireless().await.unwrap();
        assert_eq!(got.config_version, "cfg-1");
        assert_eq!(got.ssids.len(), 2);

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_committed_holds_through_channel_flap() {
        // Simulate a CP/channel flap AFTER a successful apply-and-ACK: with no
        // watchdog, no time-based rollback ever fires, so the config stays COMMITTED
        // and the tmpfs gate scope stays br-public (never wiped to empty).
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(gated_derive_runner(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-flap", 30)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        // Advance well past any old watchdog window — nothing rolls back.
        tokio::time::advance(std::time::Duration::from_secs(600)).await;
        assert!(wdrain(&mut wrx).is_empty(), "no watchdog rollback after a flap");

        // Gate scope held (derived from UCI on apply, persisted to tmpfs).
        let gated = crate::sm::read_committed_gated(dir.path()).unwrap();
        assert_eq!(gated, vec!["br-public".to_string()], "gate scope must hold, never []");
        // Committed view intact.
        assert_eq!(handle.get_wireless().await.unwrap().config_version, "cfg-flap");

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_apply_failure_reverts_and_reports_failed() {
        // A dark-radio / failed reload: the apply errors → local revert to the
        // pre-apply snapshot + a FAILED status (fail-OPEN). No watchdog involved.
        let dir = tempfile::tempdir().unwrap();
        // Dark radio: EVERY `/sbin/wifi` step fails (reload, retry, AND the hard
        // `wifi up` escalation) → the radio can't be brought up → apply_wireless
        // surfaces the error → local revert + FAILED.
        let runner = RecordingRunner::with_responder(|prog, _args| {
            if prog == "/sbin/wifi" {
                return Err(ProvisionError::Apply("radio dark: wifi bring-up failed".into()));
            }
            Ok(Vec::new())
        });
        let (handle, mut wrx, join) =
            run_provision_subsystem(runner, dir.path().to_path_buf(), 8080);

        let err = handle.set_wireless(wstate("cfg-dark", 90)).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
        let s = wrx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::Failed, "apply failure → FAILED (local revert)");
        assert_eq!(s.config_version, "cfg-dark");

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_supersede_is_allowed() {
        // With apply-and-ACK there is no pending state, so a second push simply
        // applies over the first (both COMMITTED) — no "already pending" rejection.
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(gated_derive_runner(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-a", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);
        handle.set_wireless(wstate("cfg-b", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);
        assert_eq!(handle.get_wireless().await.unwrap().config_version, "cfg-b");

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
        // Same protection, but the SSIDs sit on radio1 → accepted (applies + ACKs).
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) = run_provision_subsystem_with_policy(
            gated_derive_runner(),
            dir.path().to_path_buf(),
            8080,
            vec!["radio0".to_string()],
        );

        let mut st = wstate("cfg-ok", 90);
        for s in &mut st.ssids {
            s.radios = vec!["radio1".into()];
        }
        handle.set_wireless(st).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

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
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

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
    async fn wireless_confirm_is_idempotent_noop() {
        // ConfirmWireless is now a backward-compat no-op: it always succeeds and
        // never emits a status (the apply already committed).
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(gated_derive_runner(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-real", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);
        // A confirm for ANY version (even one never pushed) is an ok no-op.
        handle.confirm_wireless("cfg-anything").await.unwrap();
        handle.confirm_wireless("cfg-real").await.unwrap();
        // No extra status frames from the no-op confirms.
        assert!(wdrain(&mut wrx).is_empty());

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn set_persists_committed_gated_ifaces_for_boot_rescope() {
        // On apply-and-ACK the gated-SSID bridge ifaces are DERIVED from live UCI
        // and persisted to tmpfs so a daemon restart (`read_committed_gated`)
        // re-scopes enforcement before the CP reconnects.
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut wrx, join) =
            run_provision_subsystem(gated_derive_runner(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-f2", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        // Derived from live UCI (the gated `public` SSID → br-public).
        let gated = crate::sm::read_committed_gated(dir.path()).unwrap();
        assert_eq!(gated, vec!["br-public".to_string()]);

        drop(handle);
        let _ = join.await;
    }
}
