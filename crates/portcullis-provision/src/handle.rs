//! The provision subsystem's actor: a cloneable [`ProvisionHandle`] (implements
//! [`Provisioner`]) that sends commands over an mpsc to a single owner task
//! ([`run_provision_subsystem`]), mirroring the nft writer-actor shape. The task
//! owns the [`ProvisionMachine`] + the commit-confirm watchdog and emits
//! [`ProvisionStatus`] upward on a bounded channel that `portcullis-control` fans
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
use portcullis_types::{ProvisionError, ProvisionSpec, ProvisionState, ProvisionStatus, Provisioner};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::runner::CommandRunner;
use crate::sm::{self, PendingMarker, ProvisionMachine, Snapshot};
use crate::uci;

/// Bound on the command channel — provision commands are rare (a handful of CP
/// pushes over a router's lifetime), so a tiny buffer is ample.
const COMMAND_BUFFER: usize = 8;
/// Bound on the upward status channel.
const STATUS_BUFFER: usize = 16;

/// A command sent to the provision actor, carrying its reply channel.
enum Command {
    Provision {
        spec: Box<ProvisionSpec>,
        reply: oneshot::Sender<Result<(), ProvisionError>>,
    },
    Confirm {
        provision_id: String,
        reply: oneshot::Sender<Result<(), ProvisionError>>,
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
}

#[async_trait]
impl Provisioner for ProvisionHandle {
    async fn provision(&self, spec: ProvisionSpec) -> Result<(), ProvisionError> {
        self.call(|reply| Command::Provision { spec: Box::new(spec), reply }).await
    }

    async fn confirm(&self, provision_id: &str) -> Result<(), ProvisionError> {
        let id = provision_id.to_string();
        self.call(|reply| Command::Confirm { provision_id: id, reply }).await
    }
}

/// The pending commit-confirm state held by the actor while a provision awaits
/// confirmation.
struct Pending {
    provision_id: String,
    bridge_name: String,
    was_teardown: bool,
    /// The hotspot's wifi-device — the watchdog rollback reloads ONLY this radio,
    /// so the admin/control-plane radio never bounces.
    radio: String,
    /// Watchdog deadline (monotonic).
    deadline: Instant,
    /// The pre-apply snapshot to restore on rollback.
    snapshot: Snapshot,
}

/// Spawn the provision subsystem. Returns:
/// - a cloneable [`ProvisionHandle`] to pass into the control channel;
/// - an mpsc [`Receiver`](mpsc::Receiver) of [`ProvisionStatus`] the composition
///   root fans into outbound `EngineFrame`s (unsolicited on watchdog rollback);
/// - the actor's [`JoinHandle`](tokio::task::JoinHandle) (abort on shutdown).
///
/// `state_dir` is the tmpfs directory ([`sm::DEFAULT_STATE_DIR`] on-device).
/// `responder_port` is the portcullis :8080 redirect responder port
/// ([`portcullis_config::Config::responder_port`]) — opened by the
/// `firewall.hotspot_portal` rule so pre-auth guests can reach the captive
/// redirect. On startup the actor reconciles any leftover pending marker (crash
/// recovery) before serving commands.
pub fn run_provision_subsystem<R>(
    runner: R,
    state_dir: impl Into<std::path::PathBuf>,
    responder_port: u16,
) -> (
    ProvisionHandle,
    mpsc::Receiver<ProvisionStatus>,
    tokio::task::JoinHandle<()>,
)
where
    R: CommandRunner + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_BUFFER);
    let (status_tx, status_rx) = mpsc::channel(STATUS_BUFFER);
    let machine = ProvisionMachine::new(runner, state_dir, responder_port);
    let actor = ProvisionActor { machine, cmd_rx, status_tx, pending: None };
    let join = tokio::spawn(actor.run());
    (ProvisionHandle { tx: cmd_tx }, status_rx, join)
}

/// The single-owner actor.
struct ProvisionActor<R: CommandRunner> {
    machine: ProvisionMachine<R>,
    cmd_rx: mpsc::Receiver<Command>,
    status_tx: mpsc::Sender<ProvisionStatus>,
    pending: Option<Pending>,
}

impl<R: CommandRunner> ProvisionActor<R> {
    async fn run(mut self) {
        // Crash-recovery reconcile: an unconfirmed provision from a previous
        // process incarnation. If its deadline has already passed, roll back
        // NOW; otherwise resume the watchdog for the remaining window.
        self.reconcile_on_start().await;

        loop {
            // Compute the current watchdog sleep (if a provision is pending).
            let sleep = self.pending.as_ref().map(|p| tokio::time::sleep_until(p.deadline));

            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(Command::Provision { spec, reply }) => {
                        let r = self.handle_provision(*spec).await;
                        let _ = reply.send(r);
                    }
                    Some(Command::Confirm { provision_id, reply }) => {
                        let r = self.handle_confirm(&provision_id).await;
                        let _ = reply.send(r);
                    }
                    None => break, // all handles dropped -> shut down
                },
                // Only armed when a provision is pending.
                _ = maybe_sleep(sleep) => {
                    self.handle_watchdog_fire().await;
                }
            }
        }
    }

    /// Validate → snapshot → apply → arm watchdog. Returns once APPLIED_PENDING.
    async fn handle_provision(&mut self, spec: ProvisionSpec) -> Result<(), ProvisionError> {
        // Validate FIRST — nothing is written for a bad spec (fail-OPEN reject).
        uci::validate(&spec)?;

        // If a provision is already pending, treat the new one as superseding:
        // we cannot honour two watchdogs. Reject rather than silently clobber the
        // in-flight rollback safety net.
        if let Some(p) = &self.pending {
            return Err(ProvisionError::Invalid(format!(
                "a provision ({}) is already pending confirmation; confirm or await its watchdog first",
                p.provision_id
            )));
        }

        // The hotspot's radio: the SAME value render_uci uses for the wifi-iface
        // device. Only this radio is reloaded (apply + any rollback), so a
        // dual-band router's admin/control-plane radio never bounces.
        let radio = uci::effective_radio(&spec).to_string();

        // Snapshot the owned sections BEFORE touching anything.
        let snapshot = self.machine.snapshot().await?;

        // Render the batch: enable => set batch (opening the portal firewall rule
        // on the local responder port); teardown => delete batch (deletes tolerate
        // a missing section).
        let (cmds, allow_missing_delete) = if spec.enabled {
            (uci::render_uci(&spec, self.machine.responder_port()), false)
        } else {
            (uci::render_teardown(), true)
        };

        // Apply + commit + reload. On ANY failure, roll back immediately and
        // report FAILED — never leave a half-applied config on a CGNAT router.
        if let Err(e) = self.machine.apply(&cmds, allow_missing_delete, &radio).await {
            tracing::warn!(provision_id = %spec.provision_id, error = %e, "apply failed; rolling back");
            if let Err(re) = self.machine.rollback(&snapshot, &radio).await {
                tracing::error!(provision_id = %spec.provision_id, error = %re, "rollback after failed apply ALSO failed");
            }
            let _ = self.machine.clear_marker().await;
            self.emit(sm::status(&spec.provision_id, ProvisionState::Failed, e.to_string(), &spec.bridge_name)).await;
            return Err(e);
        }

        // Arm the LOCAL watchdog + persist the pending marker (tmpfs) so a restart
        // mid-window still honours the confirm/rollback.
        let window = sm::confirm_window(&spec);
        let deadline = Instant::now() + window;
        let deadline_unix = unix_now() + window.as_secs() as i64;

        let marker = PendingMarker {
            provision_id: spec.provision_id.clone(),
            was_teardown: !spec.enabled,
            bridge_name: spec.bridge_name.clone(),
            radio: radio.clone(),
            deadline_unix,
            snapshot: snapshot.clone(),
        };
        if let Err(e) = self.machine.write_marker(&marker).await {
            // Marker persistence is best-effort for crash recovery only — the
            // in-RAM watchdog still fires. Log and continue (do NOT fail the
            // apply, which already succeeded).
            tracing::warn!(provision_id = %spec.provision_id, error = %e, "could not persist pending marker (crash-recovery only)");
        }

        self.pending = Some(Pending {
            provision_id: spec.provision_id.clone(),
            bridge_name: spec.bridge_name.clone(),
            was_teardown: !spec.enabled,
            radio,
            deadline,
            snapshot,
        });

        tracing::info!(
            provision_id = %spec.provision_id,
            window_secs = window.as_secs(),
            teardown = !spec.enabled,
            "provision applied; awaiting confirm (commit-confirm armed)"
        );
        self.emit(sm::status(
            &spec.provision_id,
            ProvisionState::AppliedPending,
            "applied; awaiting confirm",
            &spec.bridge_name,
        ))
        .await;
        Ok(())
    }

    /// A confirm before the deadline commits the pending provision.
    async fn handle_confirm(&mut self, provision_id: &str) -> Result<(), ProvisionError> {
        match &self.pending {
            Some(p) if p.provision_id == provision_id => {
                let bridge = p.bridge_name.clone();
                self.pending = None; // cancels the watchdog (sleep no longer armed)
                let _ = self.machine.clear_marker().await;
                tracing::info!(provision_id, "provision confirmed; committed permanently");
                self.emit(sm::status(provision_id, ProvisionState::Committed, "confirmed", &bridge)).await;
                Ok(())
            }
            _ => Err(ProvisionError::NoPending(provision_id.to_string())),
        }
    }

    /// The watchdog fired without a confirm → roll back to the snapshot and emit
    /// an UNSOLICITED RolledBack status.
    async fn handle_watchdog_fire(&mut self) {
        let Some(p) = self.pending.take() else { return };
        tracing::warn!(
            provision_id = %p.provision_id,
            "commit-confirm watchdog fired without confirm; rolling back (CGNAT has no inbound rescue)"
        );
        let (state, msg) = match self.machine.rollback(&p.snapshot, &p.radio).await {
            Ok(()) => (ProvisionState::RolledBack, "watchdog expired; rolled back to snapshot".to_string()),
            Err(e) => {
                tracing::error!(provision_id = %p.provision_id, error = %e, "watchdog rollback FAILED");
                (ProvisionState::Failed, format!("watchdog rollback failed: {e}"))
            }
        };
        let _ = self.machine.clear_marker().await;
        // Report against the intent: a teardown that rolled back is back to the
        // prior (enabled) bridge; an enable that rolled back has no bridge.
        let bridge = if p.was_teardown { p.bridge_name.as_str() } else { "" };
        self.emit(sm::status(&p.provision_id, state, msg, bridge)).await;
    }

    /// On startup, honour a leftover pending marker from a crashed/restarted
    /// process: past its deadline → roll back now; still within the window →
    /// resume the watchdog for the remaining time.
    async fn reconcile_on_start(&mut self) {
        let marker = match self.machine.read_marker().await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "could not read pending provision marker on start");
                return;
            }
        };

        let now_unix = unix_now();
        if marker.deadline_unix <= now_unix {
            // Deadline already passed while we were down → roll back on boot.
            tracing::warn!(
                provision_id = %marker.provision_id,
                "unconfirmed provision past its deadline at startup; rolling back"
            );
            let (state, msg) = match self.machine.rollback(&marker.snapshot, &marker.radio).await {
                Ok(()) => (ProvisionState::RolledBack, "rolled back on startup (deadline passed)".to_string()),
                Err(e) => (ProvisionState::Failed, format!("startup rollback failed: {e}")),
            };
            let _ = self.machine.clear_marker().await;
            let bridge = if marker.was_teardown { marker.bridge_name.as_str() } else { "" };
            self.emit(sm::status(&marker.provision_id, state, msg, bridge)).await;
        } else {
            // Still within the window → resume the watchdog for the remainder.
            let remaining = Duration::from_secs((marker.deadline_unix - now_unix).max(0) as u64);
            tracing::info!(
                provision_id = %marker.provision_id,
                remaining_secs = remaining.as_secs(),
                "resuming commit-confirm watchdog for pending provision after restart"
            );
            self.pending = Some(Pending {
                provision_id: marker.provision_id,
                bridge_name: marker.bridge_name,
                was_teardown: marker.was_teardown,
                radio: marker.radio,
                deadline: Instant::now() + remaining,
                snapshot: marker.snapshot,
            });
        }
    }

    /// Emit a status upward. A full/closed channel is not fatal (the CP re-reads
    /// state on reconnect); we drop and warn rather than block the actor.
    async fn emit(&self, status: ProvisionStatus) {
        if self.status_tx.send(status).await.is_err() {
            tracing::debug!("provision status channel closed; status dropped");
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
    use crate::sm::marker_path_for_test;

    fn spec(id: &str, timeout: u32) -> ProvisionSpec {
        ProvisionSpec {
            provision_id: id.into(),
            enabled: true,
            ssid: "Guest".into(),
            radio: "radio0".into(),
            encryption: "none".into(),
            key: String::new(),
            isolate: true,
            bridge_name: "br-hotspot".into(),
            ipaddr: "10.0.0.1".into(),
            netmask: "255.255.255.0".into(),
            dhcp_start: "10".into(),
            dhcp_limit: "200".into(),
            dhcp_leasetime: "2h".into(),
            confirm_timeout_secs: timeout,
        }
    }

    /// Drain any statuses currently queued (non-blocking).
    fn drain(rx: &mut mpsc::Receiver<ProvisionStatus>) -> Vec<ProvisionStatus> {
        let mut out = Vec::new();
        while let Ok(s) = rx.try_recv() {
            out.push(s);
        }
        out
    }

    #[tokio::test(start_paused = true)]
    async fn apply_then_confirm_reaches_committed() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut status_rx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        handle.provision(spec("prov-1", 90)).await.unwrap();
        // AppliedPending emitted, marker persisted.
        let s = status_rx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::AppliedPending);
        assert!(marker_path_for_test(dir.path()).exists());

        handle.confirm("prov-1").await.unwrap();
        let s = status_rx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::Committed);
        assert_eq!(s.bridge_name, "br-hotspot");
        // Marker cleared on commit.
        assert!(!marker_path_for_test(dir.path()).exists());

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn apply_then_timeout_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut status_rx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        handle.provision(spec("prov-2", 30)).await.unwrap();
        let s = status_rx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::AppliedPending);

        // Advance past the 30s window without confirming -> watchdog fires.
        tokio::time::advance(Duration::from_secs(31)).await;
        let s = status_rx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::RolledBack);
        // Marker cleared after rollback.
        assert!(!marker_path_for_test(dir.path()).exists());

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn zero_timeout_uses_default_window() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut status_rx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);
        handle.provision(spec("prov-d", 0)).await.unwrap();
        assert_eq!(status_rx.recv().await.unwrap().state, ProvisionState::AppliedPending);
        // Just before the 90s default: still pending.
        tokio::time::advance(Duration::from_secs(89)).await;
        assert!(drain(&mut status_rx).is_empty());
        // Past it: rolled back.
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(status_rx.recv().await.unwrap().state, ProvisionState::RolledBack);
        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_spec_is_rejected_without_applying() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut status_rx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);
        let mut bad = spec("prov-x", 90);
        bad.bridge_name = "br-lan".into(); // out of allowlist
        let err = handle.provision(bad).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));
        // Nothing applied, no marker, no status.
        assert!(!marker_path_for_test(dir.path()).exists());
        assert!(drain(&mut status_rx).is_empty());
        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn confirm_unknown_id_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, _rx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);
        let err = handle.confirm("nope").await.unwrap_err();
        assert!(matches!(err, ProvisionError::NoPending(_)));
        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn teardown_path_applies_deletes_and_confirms() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, mut status_rx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);
        let mut td = spec("prov-td", 60);
        td.enabled = false;
        handle.provision(td).await.unwrap();
        assert_eq!(status_rx.recv().await.unwrap().state, ProvisionState::AppliedPending);
        handle.confirm("prov-td").await.unwrap();
        assert_eq!(status_rx.recv().await.unwrap().state, ProvisionState::Committed);
        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn crash_recovery_rolls_back_expired_marker_on_start() {
        // Pre-seed a marker whose deadline is already in the past (and whose
        // hotspot was on radio1), then start the subsystem: it must roll back on
        // boot, emit RolledBack, and reload ONLY radio1 (the persisted radio).
        let dir = tempfile::tempdir().unwrap();
        {
            // Write an expired marker via a throwaway machine.
            let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
            let mut snap = Snapshot {
                existing_sections: vec!["network.hotspot".into()],
                ..Default::default()
            };
            snap.prior.insert("network.hotspot.ipaddr".into(), "10.9.9.1".into());
            let marker = PendingMarker {
                provision_id: "old-prov".into(),
                was_teardown: false,
                bridge_name: "br-hotspot".into(),
                radio: "radio1".into(),
                deadline_unix: 1, // long in the past
                snapshot: snap,
            };
            m.write_marker(&marker).await.unwrap();
        }

        // A cloned RecordingRunner shares its call log (Arc), so we can inspect
        // what the subsystem's actor ran after moving one clone into it.
        let runner = RecordingRunner::new();
        let (handle, mut status_rx, join) =
            run_provision_subsystem(runner.clone(), dir.path().to_path_buf(), 8080);
        // Startup reconcile emits a RolledBack for the stale provision.
        let s = status_rx.recv().await.unwrap();
        assert_eq!(s.state, ProvisionState::RolledBack);
        assert_eq!(s.provision_id, "old-prov");
        assert!(!marker_path_for_test(dir.path()).exists());
        // The boot-time rollback reloaded ONLY radio1 (the persisted radio), never
        // the admin radio0 nor bare `wifi reload`.
        let flat = runner.flat();
        assert!(flat.contains(&("/sbin/wifi".to_string(), "reload radio1".to_string())));
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload radio0"));
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload"));
        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_rollback_reloads_only_the_hotspot_radio() {
        // Provision a hotspot on radio1, let the watchdog fire, and confirm the
        // rollback bounced ONLY radio1 (never radio0, the admin/CP radio).
        let dir = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::new();
        let (handle, mut status_rx, join) =
            run_provision_subsystem(runner.clone(), dir.path().to_path_buf(), 8080);
        let mut s = spec("prov-r1", 30);
        s.radio = "radio1".into();
        handle.provision(s).await.unwrap();
        assert_eq!(status_rx.recv().await.unwrap().state, ProvisionState::AppliedPending);
        // Both the apply and the (imminent) rollback must target radio1 only.
        assert!(runner.flat().contains(&("/sbin/wifi".to_string(), "reload radio1".to_string())));

        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(status_rx.recv().await.unwrap().state, ProvisionState::RolledBack);
        let flat = runner.flat();
        // radio0 (admin/CP radio) was never bounced; no bare `wifi reload`.
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload radio0"));
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload"));
        drop(handle);
        let _ = join.await;
    }
}
