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
        self.call(|reply| Command::Set {
            state: Box::new(state),
            reply,
        })
        .await
    }

    async fn confirm_wireless(&self, config_version: &str) -> Result<(), ProvisionError> {
        let v = config_version.to_string();
        self.call(|reply| Command::Confirm {
            config_version: v,
            reply,
        })
        .await
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
) -> (
    ProvisionHandle,
    mpsc::Receiver<WirelessStatus>,
    tokio::task::JoinHandle<()>,
)
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
///
/// Leaves the UNVALIDATED scoped per-BSS reconfigure OFF — exactly today's
/// full-reload behaviour. An operator opts into it via
/// [`run_provision_subsystem_with_scoped`].
pub fn run_provision_subsystem_with_policy<R>(
    runner: R,
    state_dir: impl Into<std::path::PathBuf>,
    responder_port: u16,
    protected_radios: Vec<String>,
) -> (
    ProvisionHandle,
    mpsc::Receiver<WirelessStatus>,
    tokio::task::JoinHandle<()>,
)
where
    R: CommandRunner + 'static,
{
    // scoped_reconfigure = false → the scoped path is NEVER produced (byte-for-byte
    // today's behaviour). See `run_provision_subsystem_with_scoped`.
    run_provision_subsystem_with_scoped(runner, state_dir, responder_port, protected_radios, false)
}

/// [`run_provision_subsystem_with_policy`] plus the `scoped_reconfigure` opt-in
/// (wired from [`portcullis_config::Config::scoped_reconfigure`], default `false`).
///
/// UNVALIDATED — pending P0 on-device mt76/hostapd spike; default-OFF via
/// config.scoped_reconfigure. When `false` (the default and every current caller)
/// the actor always takes [`sm::plan_apply`] → today's full reload, so the
/// observable behaviour is unchanged. When `true` an SSID-only edit may take the
/// scoped per-BSS hostapd path ([`sm::plan_apply_scoped`]); ANY scoped op error
/// falls back to the full apply so the radio is never left dark.
pub fn run_provision_subsystem_with_scoped<R>(
    runner: R,
    state_dir: impl Into<std::path::PathBuf>,
    responder_port: u16,
    protected_radios: Vec<String>,
    scoped_reconfigure: bool,
) -> (
    ProvisionHandle,
    mpsc::Receiver<WirelessStatus>,
    tokio::task::JoinHandle<()>,
)
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
        // Rehydrated from persistent UCI in `run()` BEFORE the first command (the
        // async boot step): the owned `wireless.pc_meta` version stamp survives a
        // reboot, so `GetWirelessConfig` / liveness report the correct
        // config_version without waiting on a CP re-push (P4). A fresh device with
        // no stamp keeps `None` exactly as before. See `ProvisionActor::run`.
        last_committed: None,
        protected_radios,
        scoped_reconfigure,
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
    /// UNVALIDATED — pending P0 on-device mt76/hostapd spike; default-OFF via
    /// config.scoped_reconfigure. Opt-in to the scoped per-BSS reconfigure path in
    /// [`Self::handle_set_wireless`]. `false` (the default) = always [`sm::plan_apply`]
    /// → today's full reload; observable behaviour unchanged.
    scoped_reconfigure: bool,
}

impl<R: CommandRunner> ProvisionActor<R> {
    async fn run(mut self) {
        // Apply-and-ACK (CP-SOT, P2): no commit-confirm watchdog, so nothing to
        // reconcile at start (an interrupted apply is just re-pushed by the CP).
        //
        // Reboot rehydrate (P4): the committed `config_version` is only set on apply
        // and lives in RAM, so a reboot would leave `get_wireless` reporting an empty
        // version until the CP re-pushes — making an in-sync router look drifted. The
        // version is persisted on flash in the owned `wireless.pc_meta` section
        // (written by every commit; reverted with the snapshot on rollback), so read
        // it back here and seed `last_committed` with a version-only desired-state.
        // Fail-soft: a missing stamp (fresh device) or a `uci` error leaves it `None`
        // exactly as before. Only the config_version is reconstructed — the per-SSID
        // config still comes from LIVE UCI (liveness) and the gate scope from the boot
        // self-heal; a version-only committed view carries empty `ssids`, which the CP
        // rescope path deliberately treats as "do not clobber the live gate scope".
        if self.last_committed.is_none() {
            if let Some(config_version) =
                sm::derive_config_version_from_uci(self.machine.runner()).await
            {
                tracing::info!(config_version = %config_version, "rehydrated committed wireless config_version from persistent UCI at boot");
                self.last_committed = Some(WirelessDesiredState {
                    config_version,
                    ..Default::default()
                });
            }
        }
        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                Command::Set { state, reply } => {
                    let r = self.handle_set_wireless(*state).await;
                    let _ = reply.send(r);
                }
                Command::Confirm {
                    config_version,
                    reply,
                } => {
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
        // Equality-gate (the churn brake). Route through the pure apply planner
        // FIRST — before any validate/snapshot/render/apply. An identical CP
        // re-push (same NON-EMPTY config_version as the last commit) has nothing
        // to change: the engine has no reconcile cheaper than a full `wifi reload`,
        // and reloading bounces the WHOLE radio (drops every SSID), so re-applying
        // an unchanged version is a self-inflicted radio flap — the loop that has
        // driven overload reboots on-device. A prior fix (v0.20.2) makes a
        // successful apply fully bind the firewall zones, so a duplicate apply
        // leaves nothing half-done that a re-push would need to heal → skipping is
        // safe. Skip the apply and re-ACK Committed so the CP ledger still
        // converges.
        //
        // Operational caveat: to force a re-render of an already-committed store
        // (e.g. after a render-logic change WITHOUT a config_version bump), an
        // operator clears the persisted stamp (`uci delete wireless.pc_meta`) — the
        // engine then reports an empty version, the gate misses, and the CP
        // re-push applies for real.
        if let sm::ApplyPlan::NoChange = sm::plan_apply(self.last_committed.as_ref(), &state) {
            tracing::info!(
                config_version = %state.config_version,
                "wireless push matches committed config_version; skipping apply (no render/uci/reload) and re-ACKing Committed"
            );
            self.emit_wireless(sm::wireless_status(
                &state.config_version,
                ProvisionState::Committed,
                Self::ssid_results(&state),
                "already committed (identical config_version; apply skipped)",
            ))
            .await;
            return Ok(());
        }

        // Validate FIRST — a bad desired-state writes nothing (fail-OPEN reject).
        uci::validate_wireless(&state)?;
        // Layer A: never let an owned SSID land on a protected (admin) radio, so a
        // `wifi reload <radio>` can't bounce/dark the admin SSID. No-op when unset.
        uci::validate_protected_radios(&state, &self.protected_radios)?;

        // DHCP-only diff-gate (P0). Priority: NoChange (handled above) > DhcpOnly >
        // (scoped, stays off) > FullReload. When the ONLY difference from the last
        // commit is per-SSID static DHCP reservations (MAC→IP), apply just the
        // `dhcp.pc_<slug>_host*` delta + version-stamp bump and reload dnsmasq via
        // SIGHUP — NO `wifi reload`, so no PHY bounce and no SSID drop (the fragile
        // mt76/RUT906 case). On ANY error we fall through to the full apply below
        // (never a half-applied config, never a fail-open gate).
        if let sm::ApplyPlan::DhcpOnly(cmds) =
            sm::plan_apply_dhcp(self.last_committed.as_ref(), &state)
        {
            match self.machine.apply_dhcp_only(&cmds).await {
                Ok(()) => {
                    // Gate scope is unchanged by a reservation edit (no radio/zone
                    // touched), but re-derive+persist from LIVE UCI for parity with
                    // the full path. Best-effort throughout.
                    let gated_ifaces = sm::derive_gated_from_uci(self.machine.runner()).await;
                    if let Err(e) = self.machine.write_committed_gated(&gated_ifaces).await {
                        tracing::warn!(error = %e, "could not persist committed gated ifaces (dhcp-only path)");
                    }
                    tracing::info!(
                        config_version = %state.config_version,
                        cmds = cmds.len(),
                        "wireless applied via DHCP-ONLY diff-gate (dnsmasq reload, no wifi reload)"
                    );
                    self.last_committed = Some(state.clone());
                    self.emit_wireless(sm::wireless_status(
                        &state.config_version,
                        ProvisionState::Committed,
                        Self::ssid_results(&state),
                        "applied + committed (dhcp reservations only; no radio reload)",
                    ))
                    .await;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        config_version = %state.config_version, error = %e,
                        "dhcp-only apply failed; falling back to full apply (never half-applied)"
                    );
                }
            }
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

        // Scoped per-BSS reconfigure (P3, UNVALIDATED — pending P0 on-device mt76/
        // hostapd spike; default-OFF via config.scoped_reconfigure). Only consulted
        // when the operator opted in; `plan_apply_scoped` returns `Scoped` ONLY for a
        // real change with no radio-level change that maps cleanly to BssOps. With
        // the flag OFF we NEVER even compute it — the plan is FullReload, so the code
        // below is byte-for-byte today's path. If a scoped apply is chosen and
        // SUCCEEDS we skip the full reload (no PHY bounce); on ANY error we fall
        // through to the full apply immediately so the radio is never left dark.
        let mut applied_via_scoped = false;
        if self.scoped_reconfigure {
            if let sm::ApplyPlan::Scoped(ops) =
                sm::plan_apply_scoped(true, self.last_committed.as_ref(), &snapshot, &state)
            {
                match self.machine.scoped_apply(&ops, &snapshot, &state).await {
                    Ok(()) => {
                        tracing::info!(
                            config_version = %state.config_version,
                            ops = ops.len(),
                            "wireless applied via SCOPED per-BSS reconfigure (no radio reload)"
                        );
                        applied_via_scoped = true;
                    }
                    Err(e) => {
                        tracing::warn!(
                            config_version = %state.config_version, error = %e,
                            "scoped per-BSS reconfigure failed; falling back to full apply (never dark)"
                        );
                    }
                }
            }
        }

        // Apply + commit + multi-radio reload. On ANY failure, roll back and
        // report FAILED — never leave a half-applied config on a CGNAT router.
        // Skipped only when the scoped path above already applied successfully.
        if !applied_via_scoped {
            if let Err(e) = self.machine.apply_wireless(&batch, true, &radios).await {
                tracing::warn!(config_version = %state.config_version, error = %e, "wireless apply failed; rolling back");
                if let Err(re) = self
                    .machine
                    .rollback_to(&snapshot, &current_sections, &radios)
                    .await
                {
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
        tracing::debug!(
            config_version,
            "confirm_wireless: no-op (apply-and-ACK already committed)"
        );
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
            key: if gated {
                String::new()
            } else {
                "supersecret".into()
            },
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
            static_only: false,
            reservations: Vec::new(),
            bridge_ports: Vec::new(),
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

    /// `wstate` but with `home` carrying the given static DHCP reservations —
    /// identical to `wstate` in every other field, so the ONLY delta between a
    /// `wstate(v)` and a `wstate_resv(v')` push is the reservation list (the
    /// DHCP-only diff-gate's exact special case).
    fn wstate_resv(
        version: &str,
        timeout: u32,
        reservations: Vec<portcullis_types::DhcpReservation>,
    ) -> WirelessDesiredState {
        let mut home = wssid("home", false, 1);
        home.reservations = reservations;
        WirelessDesiredState {
            config_version: version.into(),
            confirm_timeout_secs: timeout,
            ssids: vec![wssid("public", true, 0), home],
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
        assert!(s
            .per_ssid
            .iter()
            .any(|r| r.slug == "public" && r.iface == "br-public"));
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
        assert!(
            wdrain(&mut wrx).is_empty(),
            "no watchdog rollback after a flap"
        );

        // Gate scope held (derived from UCI on apply, persisted to tmpfs).
        let gated = crate::sm::read_committed_gated(dir.path()).unwrap();
        assert_eq!(
            gated,
            vec!["br-public".to_string()],
            "gate scope must hold, never []"
        );
        // Committed view intact.
        assert_eq!(
            handle.get_wireless().await.unwrap().config_version,
            "cfg-flap"
        );

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
                return Err(ProvisionError::Apply(
                    "radio dark: wifi bring-up failed".into(),
                ));
            }
            Ok(Vec::new())
        });
        let (handle, mut wrx, join) =
            run_provision_subsystem(runner, dir.path().to_path_buf(), 8080);

        let err = handle
            .set_wireless(wstate("cfg-dark", 90))
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
        let s = wrx.recv().await.unwrap();
        assert_eq!(
            s.state,
            ProvisionState::Failed,
            "apply failure → FAILED (local revert)"
        );
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
    async fn wireless_identical_repush_is_gated_no_second_reload() {
        // Equality-gate: pushing the SAME config_version twice applies + reloads
        // ONCE. The second (identical) push is short-circuited before any
        // render/uci/reload, but STILL re-ACKs Committed so the CP ledger converges.
        let dir = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::new();
        let (handle, mut wrx, join) =
            run_provision_subsystem(runner.clone(), dir.path().to_path_buf(), 8080);

        handle.set_wireless(wstate("cfg-same", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        // Snapshot the command count after the first (real) apply.
        let after_first = runner.flat();
        let commits_first = after_first
            .iter()
            .filter(|(p, a)| p == "uci" && a.starts_with("commit "))
            .count();
        let wifi_first = after_first.iter().filter(|(p, _)| p == "/sbin/wifi").count();
        assert!(commits_first > 0, "first push must commit: {after_first:?}");
        assert!(wifi_first > 0, "first push must reload wifi: {after_first:?}");

        // Second push: identical config_version → gated.
        handle.set_wireless(wstate("cfg-same", 90)).await.unwrap();
        // It re-ACKs Committed (ledger convergence) even though nothing was applied.
        let s2 = wrx.recv().await.unwrap();
        assert_eq!(s2.state, ProvisionState::Committed);
        assert_eq!(s2.config_version, "cfg-same");
        assert!(wdrain(&mut wrx).is_empty());

        // No NEW commit / wifi burst: the gate ran no render/uci/reload.
        let after_second = runner.flat();
        let commits_second = after_second
            .iter()
            .filter(|(p, a)| p == "uci" && a.starts_with("commit "))
            .count();
        let wifi_second = after_second.iter().filter(|(p, _)| p == "/sbin/wifi").count();
        assert_eq!(
            commits_second, commits_first,
            "identical re-push must not commit again: {after_second:?}"
        );
        assert_eq!(
            wifi_second, wifi_first,
            "identical re-push must not reload wifi again: {after_second:?}"
        );

        // A DIFFERENT version still applies (gate misses) — proves it's not a hard stop.
        handle.set_wireless(wstate("cfg-next", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);
        let wifi_third = runner.flat().iter().filter(|(p, _)| p == "/sbin/wifi").count();
        assert!(
            wifi_third > wifi_second,
            "a changed version must reload again"
        );

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wireless_dhcp_only_change_reloads_dnsmasq_no_wifi_reload() {
        // P0 diff-gate: a push that differs from the last commit ONLY in a static
        // DHCP reservation applies via the dnsmasq-only path — ZERO `wifi reload`
        // and exactly ONE `dnsmasq reload` — instead of bouncing the radio.
        let dir = tempfile::tempdir().unwrap();
        let runner = gated_derive_runner();
        let (handle, mut wrx, join) =
            run_provision_subsystem(runner.clone(), dir.path().to_path_buf(), 8080);

        // First push: full apply (baseline, no reservations).
        handle.set_wireless(wstate("cfg-1", 90)).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);
        let after_first = runner.flat();
        let wifi_first = after_first.iter().filter(|(p, _)| p == "/sbin/wifi").count();
        assert!(wifi_first > 0, "baseline push must reload wifi: {after_first:?}");

        // Second push: SAME config except one added reservation on `home`, new
        // version → DHCP-only diff-gate.
        let resv = portcullis_types::DhcpReservation {
            mac: "aa:bb:cc:dd:ee:01".into(),
            ipaddr: "10.0.1.50".into(),
            hostname: "vend-1".into(),
        };
        handle
            .set_wireless(wstate_resv("cfg-2", 90, vec![resv]))
            .await
            .unwrap();
        let s2 = wrx.recv().await.unwrap();
        assert_eq!(s2.state, ProvisionState::Committed);
        assert_eq!(s2.config_version, "cfg-2");
        assert!(wdrain(&mut wrx).is_empty());

        // Only the DHCP-only path's commands ran between the two pushes.
        let delta: Vec<(String, String)> = runner.flat().into_iter().skip(after_first.len()).collect();
        let wifi_delta = delta.iter().filter(|(p, _)| p == "/sbin/wifi").count();
        assert_eq!(wifi_delta, 0, "dhcp-only push must NOT reload wifi: {delta:?}");
        let dnsmasq_reloads = delta
            .iter()
            .filter(|(p, a)| p == "/etc/init.d/dnsmasq" && a == "reload")
            .count();
        assert_eq!(
            dnsmasq_reloads, 1,
            "dhcp-only push must reload dnsmasq exactly once: {delta:?}"
        );
        // And it committed dhcp (never a `dnsmasq restart`, never a bare `wifi`).
        assert!(
            delta.iter().any(|(p, a)| p == "uci" && a == "commit dhcp"),
            "dhcp-only push must commit dhcp: {delta:?}"
        );
        assert!(
            !delta.iter().any(|(p, a)| p == "/etc/init.d/dnsmasq" && a == "restart"),
            "dhcp-only push must NOT restart dnsmasq: {delta:?}"
        );

        // Committed view reflects the reservation-bearing state.
        let got = handle.get_wireless().await.unwrap();
        assert_eq!(got.config_version, "cfg-2");
        assert!(got.ssids.iter().any(|s| s.slug == "home" && s.reservations.len() == 1));

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
        let err = handle
            .set_wireless(wstate("cfg-prot", 90))
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));
        assert!(
            wdrain(&mut wrx).is_empty(),
            "rejected push must apply nothing"
        );
        // The reject is pre-apply: nothing beyond the one read-only P4 boot rehydrate
        // (`uci show wireless`) runs — no set/commit/reload/wifi at all.
        let touched: Vec<_> = runner
            .flat()
            .into_iter()
            .filter(|(p, a)| !(p == "uci" && a == "show wireless"))
            .collect();
        assert!(
            touched.is_empty(),
            "protected-radio reject must touch nothing: {touched:?}"
        );

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
        assert!(
            has("uci", "set wireless.pc_public_ap0=wifi-iface"),
            "{flat:?}"
        );
        assert!(has("uci", "set network.pc_home_dev=device"), "{flat:?}");
        assert!(
            has("uci", "set firewall.pc_public_portal=rule"),
            "gated SSID gets a portal rule"
        );
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

    /// A runner that both serves the gate-derive read AND round-trips the P4
    /// pc_meta version stamp: `uci show wireless` reports the stamped
    /// `config_version` (as a real device would after a commit), so a freshly
    /// constructed handle rehydrates `last_committed` at boot.
    fn boot_rehydrate_runner(config_version: &'static str) -> RecordingRunner {
        RecordingRunner::with_responder(move |prog, args| {
            if prog == "uci" && args.first() == Some(&"show") {
                let body = match args.get(1).copied().unwrap_or("") {
                    "wireless" => {
                        return Ok(format!(
                            "wireless.pc_meta=pc_meta\nwireless.pc_meta.config_version='{config_version}'\n"
                        )
                        .into_bytes())
                    }
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
    async fn boot_rehydrates_config_version_from_uci_without_repush() {
        // P4: after a reboot the CP has NOT re-pushed, but the owned pc_meta version
        // stamp persists on flash — so get_wireless reports the committed version
        // immediately (what liveness / GetWirelessConfig echo), no re-push needed.
        let dir = tempfile::tempdir().unwrap();
        let (handle, _wrx, join) = run_provision_subsystem(
            boot_rehydrate_runner("cfg-persisted"),
            dir.path().to_path_buf(),
            8080,
        );

        // No set_wireless call in this session — the version comes purely from the
        // boot rehydrate reading persistent UCI.
        let got = handle.get_wireless().await.unwrap();
        assert_eq!(got.config_version, "cfg-persisted");
        // Version-only view: ssids are NOT reconstructed (the CP rescope path treats
        // empty ssids as "keep the live UCI-derived gate scope", never clobber).
        assert!(got.ssids.is_empty());

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn boot_no_stamp_leaves_last_committed_none() {
        // A fresh device (no pc_meta stamp) → get_wireless returns a default
        // (empty version) exactly as before the P4 change.
        let dir = tempfile::tempdir().unwrap();
        let (handle, _wrx, join) =
            run_provision_subsystem(RecordingRunner::new(), dir.path().to_path_buf(), 8080);

        let got = handle.get_wireless().await.unwrap();
        assert_eq!(got.config_version, "");

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn apply_failure_rollback_reverts_config_version_stamp() {
        // The pc_meta version stamp is an OWNED section rendered in the batch, so a
        // failed apply's rollback deletes it (it did not exist pre-apply) — a
        // rolled-back apply must not leave a stale version stamped on flash.
        let dir = tempfile::tempdir().unwrap();
        // Dark radio → apply fails → rollback runs.
        let runner = RecordingRunner::with_responder(|prog, _args| {
            if prog == "/sbin/wifi" {
                return Err(ProvisionError::Apply("radio dark".into()));
            }
            Ok(Vec::new())
        });
        let (handle, mut wrx, join) =
            run_provision_subsystem(runner.clone(), dir.path().to_path_buf(), 8080);

        let _ = handle
            .set_wireless(wstate("cfg-rollback", 90))
            .await
            .unwrap_err();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Failed);

        let flat = runner.flat();
        // The stamp was set in the batch...
        assert!(
            flat.iter().any(|(p, a)| p == "uci" && a == "set wireless.pc_meta.config_version=cfg-rollback"),
            "version stamp must be part of the applied batch: {flat:?}"
        );
        // ...and rollback deleted the added pc_meta section (not present pre-apply).
        assert!(
            flat.iter()
                .any(|(p, a)| p == "uci" && a == "delete wireless.pc_meta"),
            "rollback must delete the added pc_meta stamp: {flat:?}"
        );

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

    // --- Scoped per-BSS reconfigure (P3 dispatch + fallback) ---------------
    // UNVALIDATED — pending P0 on-device mt76/hostapd spike; default-OFF via
    // config.scoped_reconfigure.

    /// A runner that (a) rehydrates `last_committed` = `boot_version` and serves the
    /// pre-apply snapshot of an existing `home` SSID from `uci show wireless`/
    /// `network`, and (b) ERRORS on any `ubus call hostapd*` op (the scoped path) —
    /// so a scoped plan is chosen but its ubus op fails, exercising the fallback.
    fn scoped_ubus_fails_runner(boot_version: &'static str) -> RecordingRunner {
        RecordingRunner::with_responder(move |prog, args| {
            // Fail the per-BSS hostapd reconfigure so the handler must fall back.
            if prog == "ubus" && args.get(1) == Some(&"hostapd")
                || (prog == "ubus"
                    && args.get(1).map(|s| s.starts_with("hostapd.")).unwrap_or(false))
            {
                return Err(ProvisionError::Apply("hostapd ubus not available".into()));
            }
            if prog == "uci" && args.first() == Some(&"show") {
                let body = match args.get(1).copied().unwrap_or("") {
                    "wireless" => format!(
                        "wireless.pc_meta.config_version='{boot_version}'\n\
                         wireless.pc_home_ap0=wifi-iface\n\
                         wireless.pc_home_ap0.ssid='WinX Home'\n\
                         wireless.pc_home_ap0.network='pc_home_if'\n\
                         wireless.pc_home_ap0.device='radio0'\n\
                         wireless.pc_home_ap0.encryption='psk2'\n\
                         wireless.pc_home_ap0.key='secret'\n"
                    ),
                    "network" => "network.pc_home_dev.name='br-home'\n".to_string(),
                    _ => String::new(),
                };
                return Ok(body.into_bytes());
            }
            Ok(Vec::new())
        })
    }

    #[tokio::test(start_paused = true)]
    async fn scoped_apply_failure_falls_back_to_full_reload() {
        // Flag ON: an SSID-only rename (cfg-1 → cfg-2) is scope-able, so the handler
        // tries the per-BSS ubus reconfigure FIRST — but the mock errors on it, so it
        // must fall back to the full apply and issue `/sbin/wifi reload radio0`
        // (never leave the radio dark). Boot rehydrate seeds last_committed=cfg-1.
        let dir = tempfile::tempdir().unwrap();
        let runner = scoped_ubus_fails_runner("cfg-1");
        let (handle, mut wrx, join) = run_provision_subsystem_with_scoped(
            runner.clone(),
            dir.path().to_path_buf(),
            8080,
            Vec::new(),
            true, // opt in to the UNVALIDATED scoped path
        );

        // Rename the `home` SSID at a NEW config_version (a real, scope-able change).
        let st = WirelessDesiredState {
            config_version: "cfg-2".into(),
            ssids: vec![{
                let mut s = wssid("home", false, 1);
                s.ssid = "WinX Home Renamed".into();
                s
            }],
            confirm_timeout_secs: 90,
            peer_allows: Vec::new(),
        };
        handle.set_wireless(st).await.unwrap();
        // Still ACKs Committed — the fallback full apply succeeded.
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        let flat = runner.flat();
        // 1. The scoped path WAS attempted: a `ubus call hostapd*` op was issued...
        assert!(
            flat.iter()
                .any(|(p, a)| p == "ubus" && a.starts_with("call hostapd")),
            "scoped path must attempt a hostapd ubus op: {flat:?}"
        );
        // 2. ...and after it failed, the FULL reload ran: `/sbin/wifi reload radio0`.
        assert!(
            flat.contains(&("/sbin/wifi".to_string(), "reload radio0".to_string())),
            "fallback must run the full reload sequence (never dark): {flat:?}"
        );

        drop(handle);
        let _ = join.await;
    }

    #[tokio::test(start_paused = true)]
    async fn scoped_off_never_issues_hostapd_ubus() {
        // Flag OFF (the default): even a scope-able SSID-only rename takes the full
        // reload — NO `ubus call hostapd*` op is ever issued (behaviour unchanged).
        let dir = tempfile::tempdir().unwrap();
        let runner = scoped_ubus_fails_runner("cfg-1");
        // with_policy → scoped_reconfigure defaults false.
        let (handle, mut wrx, join) = run_provision_subsystem_with_policy(
            runner.clone(),
            dir.path().to_path_buf(),
            8080,
            Vec::new(),
        );

        let st = WirelessDesiredState {
            config_version: "cfg-2".into(),
            ssids: vec![{
                let mut s = wssid("home", false, 1);
                s.ssid = "WinX Home Renamed".into();
                s
            }],
            confirm_timeout_secs: 90,
            peer_allows: Vec::new(),
        };
        handle.set_wireless(st).await.unwrap();
        assert_eq!(wrx.recv().await.unwrap().state, ProvisionState::Committed);

        let flat = runner.flat();
        assert!(
            !flat.iter().any(|(p, a)| p == "ubus" && a.starts_with("call hostapd")),
            "flag-off must never touch hostapd ubus: {flat:?}"
        );
        // The full reload still ran.
        assert!(flat.contains(&("/sbin/wifi".to_string(), "reload radio0".to_string())));

        drop(handle);
        let _ = join.await;
    }
}
