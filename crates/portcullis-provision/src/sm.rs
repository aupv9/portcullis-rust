//! The commit-confirm state machine (the anti-brick core, P0.5).
//!
//! ```text
//! Idle ──provision──▶ Applying ──ok──▶ PendingConfirm{deadline, snapshot}
//!                          └──err──▶ Failed (nothing persisted / reverted)
//! PendingConfirm ──confirm (before deadline)──▶ Committed
//! PendingConfirm ──deadline w/o confirm──▶ (rollback) ──▶ RolledBack
//! ```
//!
//! ## Why fail-OPEN here (and only here)
//! Enforcement is fail-CLOSED. This subsystem is the ONE deliberate exception:
//! it manages the router's *network config*, not enforcement. A bad UCI apply on
//! a CGNAT router (no inbound rescue) could sever the engine's own uplink, so the
//! apply is held under a LOCAL watchdog: the control plane must re-observe the
//! engine and send a confirm within the window, or the engine ROLLS BACK to the
//! pre-apply snapshot on its own. Because of kernel-as-truth, a provision fault
//! (or even a full daemon crash) never drops an authorized client.
//!
//! ## tmpfs only (guardrail)
//! The snapshot + the pending marker live under `/tmp/portcullis/provision/`
//! (tmpfs) — NEVER flash. A power cycle wipes them, which is correct: a fresh
//! boot means `uci`'s own committed state is the truth and there is no pending
//! confirm to honour.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use portcullis_types::{ProvisionError, ProvisionState, SsidResult, WirelessStatus};

use crate::runner::CommandRunner;
use crate::uci::{self, UciCmd, OWNED_CONFIGS};

/// tmpfs directory holding the provision snapshot + pending marker. Never flash.
pub const DEFAULT_STATE_DIR: &str = "/tmp/portcullis/provision";

/// Path of the `uci` binary + the init scripts. Overridable in the runner via
/// argv, but the *program names* are fixed here (explicit, no PATH surprises on
/// the reload path where order matters).
const UCI: &str = "uci";
const WIFI: &str = "/sbin/wifi";
const UBUS: &str = "ubus";
const INIT_NETWORK: &str = "/etc/init.d/network";
const INIT_FIREWALL: &str = "/etc/init.d/firewall";
const INIT_DNSMASQ: &str = "/etc/init.d/dnsmasq";
const INIT_SQM: &str = "/etc/init.d/sqm";

/// A captured snapshot of the owned sections' prior state: the `uci show` option
/// lines that existed BEFORE apply, plus the set of section keys that existed so
/// rollback knows which sections we *added* (delete them) vs *modified* (restore
/// their prior option values).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Prior `key=value` for every owned SCALAR option line present before apply,
    /// e.g. `network.hotspot.ipaddr` -> `10.0.0.1`. Section-decl lines
    /// (`network.hotspot` -> `interface`) are included too so a full re-apply
    /// reproduces them. LIST options are captured in `prior_lists`, not here.
    pub prior: BTreeMap<String, String>,
    /// Prior UCI LIST options (e.g. `wireless.pc_x_ap0.maclist` -> [mac, mac]).
    /// Restored on rollback via `uci delete` + `uci add_list` per element, which a
    /// scalar `uci set` can't round-trip. Serialized as `key+=value` lines.
    pub prior_lists: BTreeMap<String, Vec<String>>,
    /// Owned SECTION keys (of the four in [`OWNED`]) that existed before apply.
    /// Rollback deletes any owned section NOT in this set (we created it), and
    /// restores the option values of sections that ARE in it.
    pub existing_sections: Vec<String>,
}

impl Snapshot {
    /// Serialize to the tmpfs marker text: one `key=value` line per prior entry,
    /// preceded by a `#sections=<comma-list>` header. Deterministic (BTreeMap).
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("#sections=");
        s.push_str(&self.existing_sections.join(","));
        s.push('\n');
        for (k, v) in &self.prior {
            // Values can contain `=`; split on the FIRST `=` when parsing.
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push('\n');
        }
        // List options: one `key+=value` line per element (deterministic order).
        for (k, vals) in &self.prior_lists {
            for v in vals {
                s.push_str(k);
                s.push_str("+=");
                s.push_str(v);
                s.push('\n');
            }
        }
        s
    }

    /// Parse the marker text produced by [`to_text`](Self::to_text).
    pub fn from_text(text: &str) -> Snapshot {
        let mut snap = Snapshot::default();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("#sections=") {
                snap.existing_sections = rest
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                // `key+=value` (trailing `+` on the key) marks a LIST element.
                if let Some(list_key) = k.strip_suffix('+') {
                    snap.prior_lists.entry(list_key.to_string()).or_default().push(v.to_string());
                } else {
                    snap.prior.insert(k.to_string(), v.to_string());
                }
            }
        }
        snap
    }
}

/// The persisted pending marker for a CP-managed wireless push (tmpfs), carrying
/// enough to resume the watchdog / roll back on a restart mid-window: the config
/// version, the radios to reload, the section keys present after apply (so
/// rollback deletes only what we added), the deadline, and the pre-apply snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WirelessMarker {
    pub config_version: String,
    /// Radios reloaded on rollback (union of desired + prior). Never the admin
    /// radio unless an owned SSID sits on it (the CP owns that choice).
    pub radios: Vec<String>,
    /// Owned section keys present after apply (the desired set). Rollback deletes
    /// those NOT in `snapshot.existing_sections` (i.e. the ones this apply added).
    pub current_sections: Vec<String>,
    /// Bridge ifaces of the GATED SSIDs in this push (the enforcement scope to
    /// persist on confirm). Persisted so a daemon restart mid-window can confirm
    /// WITHOUT the desired-state (which the marker does not carry) yet still write
    /// the correct committed-gated set — instead of an empty one that would silently
    /// un-gate every captive SSID (P0 #2). Safe to comma-join: bridge names are
    /// validated `is_uci_ident` (no commas / control chars).
    pub gated_ifaces: Vec<String>,
    pub deadline_unix: i64,
    pub snapshot: Snapshot,
}

impl WirelessMarker {
    fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("config_version={}\n", self.config_version));
        s.push_str(&format!("radios={}\n", self.radios.join(",")));
        s.push_str(&format!("current_sections={}\n", self.current_sections.join(",")));
        s.push_str(&format!("gated_ifaces={}\n", self.gated_ifaces.join(",")));
        s.push_str(&format!("deadline_unix={}\n", self.deadline_unix));
        s.push_str("---\n");
        s.push_str(&self.snapshot.to_text());
        s
    }

    fn from_text(text: &str) -> Option<WirelessMarker> {
        let (head, body) = text.split_once("\n---\n")?;
        let mut config_version = String::new();
        let mut radios = Vec::new();
        let mut current_sections = Vec::new();
        let mut gated_ifaces = Vec::new();
        let mut deadline_unix = None;
        for line in head.lines() {
            let (k, v) = line.split_once('=')?;
            match k {
                "config_version" => config_version = v.to_string(),
                "radios" => {
                    radios = v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()
                }
                "current_sections" => {
                    current_sections =
                        v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()
                }
                "gated_ifaces" => {
                    gated_ifaces =
                        v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()
                }
                "deadline_unix" => deadline_unix = v.parse().ok(),
                _ => {}
            }
        }
        Some(WirelessMarker {
            config_version,
            radios,
            current_sections,
            gated_ifaces,
            deadline_unix: deadline_unix?,
            snapshot: Snapshot::from_text(body),
        })
    }
}

/// The engine of the commit-confirm machine. Stateless between calls except for
/// the tmpfs marker (so it can be reconstructed after a restart). The
/// [`crate::handle`] actor owns one of these and the in-RAM "which id is pending"
/// bookkeeping; this struct provides the side-effecting steps as small,
/// panic-safe, individually-testable async methods.
pub struct ProvisionMachine<R: CommandRunner> {
    runner: R,
    state_dir: PathBuf,
    /// The portcullis :8080 redirect responder port — a LOCAL engine setting
    /// (`Config.responder_port`), injected at construction and used by the actor
    /// when rendering the `firewall.hotspot_portal` rule. Not carried on the wire.
    responder_port: u16,
}

/// The path of the CP-managed wireless pending marker.
fn wireless_marker_path(dir: &Path) -> PathBuf {
    dir.join("wireless.marker")
}

/// The path of the persisted committed gated-SSID iface list (F2): the enforcement
/// scope to restore on a daemon restart before the control plane reconnects.
fn committed_gated_path(dir: &Path) -> PathBuf {
    dir.join("committed.gated")
}

/// Read the committed gated-SSID ifaces persisted by
/// [`ProvisionMachine::write_committed_gated`] (F2). `None` = no committed
/// wireless config on this box (the caller keeps its static seed); `Some(list)` =
/// the committed set (possibly empty, i.e. a committed teardown → no gated ifaces).
/// tmpfs-only, so this survives a daemon restart but not a reboot (correct: after
/// a reboot `uci`'s committed config is the truth and the CP re-syncs).
pub fn read_committed_gated(state_dir: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(committed_gated_path(state_dir)).ok()?;
    Some(text.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect())
}


impl<R: CommandRunner> ProvisionMachine<R> {
    pub fn new(runner: R, state_dir: impl Into<PathBuf>, responder_port: u16) -> Self {
        ProvisionMachine { runner, state_dir: state_dir.into(), responder_port }
    }

    /// Borrow the runner (tests inspect its recorded calls).
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// The redirect-responder port to open in the `hotspot_portal` firewall rule.
    pub fn responder_port(&self) -> u16 {
        self.responder_port
    }

    // --- CP-managed wireless (P-W1) ---------------------------------------

    /// Capture the prior state of ONLY owner-namespaced wireless sections
    /// (`pc_*`, see [`uci::is_owned_wireless_section`]) into a [`Snapshot`]. Same
    /// guardrail as [`Self::snapshot`]: a non-owned section can never enter the
    /// snapshot, so a rollback can never rewrite lan / wan / admin.
    pub async fn snapshot_wireless(&self) -> Result<Snapshot, ProvisionError> {
        let mut snap = Snapshot::default();
        for cfg in OWNED_CONFIGS {
            // `sqm` is optional: a device without sqm-scripts has no /etc/config/sqm,
            // so `uci show sqm` errors — tolerate it (nothing owned to snapshot there).
            let out = match self.runner.run(UCI, &["show", cfg]).await {
                Ok(o) => o,
                Err(_) if cfg == "sqm" => continue,
                Err(e) => return Err(e),
            };
            let text = String::from_utf8_lossy(&out);
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Some((key, raw_val)) = line.split_once('=') else { continue };
                if !uci::is_owned_wireless_section(key) {
                    continue; // guardrail: only owned wireless sections enter
                }
                // A section decl line has exactly one `.` (`config.section`).
                if key.matches('.').count() == 1 && !snap.existing_sections.iter().any(|s| s == key) {
                    snap.existing_sections.push(key.to_string());
                }
                // LIST options (only `maclist` is owned) render as one `uci show`
                // line with space-separated quoted elements: `…maclist='aa' 'bb'`.
                // Capture them list-aware so rollback can replay them via add_list.
                if key.ends_with(".maclist") {
                    snap.prior_lists.insert(key.to_string(), parse_uci_list(raw_val));
                } else {
                    snap.prior.insert(key.to_string(), unquote(raw_val));
                }
            }
        }
        Ok(snap)
    }

    /// Apply a wireless batch, `uci commit`, then reload with a MULTI-radio wifi
    /// step (`wifi reload <r>` for each affected radio — never a bare `wifi
    /// reload`). Same delete-tolerance semantics as [`Self::apply`].
    pub async fn apply_wireless(
        &self,
        cmds: &[UciCmd],
        allow_missing_delete: bool,
        radios: &[String],
    ) -> Result<(), ProvisionError> {
        for cmd in cmds {
            let argv = cmd.argv();
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            match self.runner.run(UCI, &argv_refs).await {
                Ok(_) => {}
                Err(e) => {
                    if allow_missing_delete && matches!(cmd, UciCmd::Delete { .. }) {
                        tracing::debug!(cmd = ?cmd, error = %e, "uci delete of absent section ignored");
                        continue;
                    }
                    // Staged sets so far are uncommitted — drop them so they can't
                    // be flushed later by an external `uci commit` (P0 #3).
                    self.revert_owned().await;
                    return Err(e);
                }
            }
        }
        self.commit_and_reload_multi(radios).await
    }

    /// `uci commit` per owned config then the reload sequence, scoping the wifi
    /// step to EACH radio in `radios` (never bare `wifi reload`). Shared by
    /// [`Self::apply_wireless`] + [`Self::rollback_to`].
    async fn commit_and_reload_multi(&self, radios: &[String]) -> Result<(), ProvisionError> {
        for cfg in OWNED_CONFIGS {
            match self.runner.run(UCI, &["commit", cfg]).await {
                Ok(_) => {}
                Err(_) if cfg == "sqm" => {} // optional (sqm-scripts may be absent)
                Err(e) => {
                    // A commit failed mid-sequence: earlier configs may already be
                    // committed, the rest are still STAGED in /tmp/.uci. Drop the
                    // staged remainder so a LATER external `uci commit` (RUTOS
                    // config-manager, an admin) can't flush them and resurrect a
                    // config we're abandoning (P0 #3). The caller rolls back
                    // whatever DID commit.
                    self.revert_owned().await;
                    return Err(e);
                }
            }
        }
        // Run the WHOLE reload sequence AND the liveness check even if a step
        // fails — the first error is surfaced only at the end (so the caller still
        // rolls back), but every radio is force-up'd and the ubus liveness recovery
        // ALWAYS runs. A bare `?` here (as before) let a non-zero `dnsmasq restart`
        // — which happens on trivial, non-fatal conditions on RutOS — skip the
        // dark-radio recovery entirely AND spuriously roll back a healthy apply
        // (P0 #4).
        let mut first_err: Option<ProvisionError> = None;
        if let Err(e) = self.runner.run(INIT_NETWORK, &["reload"]).await {
            first_err.get_or_insert(e);
        }
        if let Err(e) = self.runner.run(INIT_FIREWALL, &["reload"]).await {
            first_err.get_or_insert(e);
        }
        // Each affected radio with escalating recovery so a radio is NEVER left
        // dark (RC4): `wifi reload <r>` → retry → hard `wifi up <r>`.
        for r in radios {
            if let Err(e) = self.reload_radio_resilient(r).await {
                first_err.get_or_insert(e);
            }
        }
        if let Err(e) = self.runner.run(INIT_DNSMASQ, &["restart"]).await {
            first_err.get_or_insert(e);
        }
        // Reload SQM after the interfaces are up so per-SSID shapers attach to live
        // bridges (F9). Best-effort: a device without sqm-scripts has no init script,
        // and a missing shaper must never fail an otherwise-valid wireless apply.
        let _ = self.runner.run(INIT_SQM, &["reload"]).await;
        // D2 — post-reload liveness. `wifi reload <r>` can exit 0 while hostapd
        // silently failed to bring the radio up (a merged config the structural
        // validation couldn't foresee), leaving it dark despite a clean exit code —
        // the one gap the exit-code recovery above cannot see. Confirm via ubus and
        // hard bring-up anything reported down; a radio STILL down after that
        // surfaces an error so the caller rolls back (removing the bad config
        // recovers the radio). Strictly fail-open (see [`recover_dark_radios`]).
        if let Some(e) = self.recover_dark_radios(radios).await {
            first_err.get_or_insert(e);
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// D2 liveness recovery. Reads `ubus call network.wireless status`; for each of
    /// `radios` explicitly reported down, forces a scoped `wifi up <r>`; then
    /// re-reads and returns an error naming any radio STILL down (so the caller
    /// rolls back). Fail-OPEN at every step — a failed/absent/unparseable ubus call
    /// returns `None` (no radio is ever judged down from noise, so a ubus schema
    /// drift can only make us MISS a dark radio, never falsely roll back a healthy
    /// push). See [`radios_reported_down`].
    async fn recover_dark_radios(&self, radios: &[String]) -> Option<ProvisionError> {
        let status = self.runner.run(UBUS, &["call", "network.wireless", "status"]).await.ok()?;
        let down = radios_reported_down(&String::from_utf8_lossy(&status), radios);
        if down.is_empty() {
            return None;
        }
        for r in &down {
            tracing::warn!(radio = %r, "radio reported down after a clean `wifi reload`; forcing `wifi up`");
            let _ = self.runner.run(WIFI, &["up", r]).await;
        }
        // Re-verify: only a radio STILL down after the forced bring-up is a real
        // fault worth rolling back for (the forced `wifi up` may have fixed it).
        let status2 = self.runner.run(UBUS, &["call", "network.wireless", "status"]).await.ok()?;
        let still_down = radios_reported_down(&String::from_utf8_lossy(&status2), radios);
        if still_down.is_empty() {
            None
        } else {
            tracing::error!(radios = ?still_down, "radios remain down after `wifi up`; will roll back");
            Some(ProvisionError::Apply(format!("radios down after reload: {}", still_down.join(","))))
        }
    }

    /// Drop any STAGED (uncommitted) `uci` deltas on the owned configs
    /// (best-effort). Called on every bail-out BEFORE a successful `uci commit`, so
    /// a failed/partial apply never leaves deltas in `/tmp/.uci` that a LATER
    /// external `uci commit` (RUTOS config-manager, an admin) would silently flush,
    /// resurrecting a config this engine abandoned (P0 #3). `uci revert <cfg>` only
    /// touches STAGED state, never the committed config, so it cannot undo changes
    /// that already committed — those are the caller's rollback's job.
    async fn revert_owned(&self) {
        for cfg in OWNED_CONFIGS {
            let _ = self.runner.run(UCI, &["revert", cfg]).await;
        }
    }

    /// Bring one radio back up, never leaving it dark (RC4). Tries `wifi reload
    /// <r>`; on failure retries once (transient netifd/hostapd bring-up races are
    /// common on a busy router); on a persistent failure escalates to a hard `wifi
    /// up <r>` — SCOPED to the radio, never a bare `wifi` (which would also touch
    /// the control/admin radio). Returns `Err` only when even the hard bring-up
    /// fails (a genuine hardware/driver fault, beyond software recovery).
    async fn reload_radio_resilient(&self, radio: &str) -> Result<(), ProvisionError> {
        match self.runner.run(WIFI, &["reload", radio]).await {
            Ok(_) => return Ok(()),
            Err(e) => tracing::warn!(radio, error = %e, "wifi reload failed; retrying once"),
        }
        match self.runner.run(WIFI, &["reload", radio]).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                tracing::warn!(radio, error = %e, "wifi reload retry failed; escalating to `wifi up` (anti-dark)");
            }
        }
        match self.runner.run(WIFI, &["up", radio]).await {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::error!(radio, error = %e, "radio could not be brought up even with `wifi up`");
                Err(e)
            }
        }
    }

    /// Roll back to `snapshot`: delete the owned sections present now
    /// (`current_sections`) that did NOT exist pre-apply (we added them), restore
    /// the prior option values (re-creates sections this apply deleted, reverts
    /// modified ones), then commit + multi-radio reload. Fail-OPEN's safety net.
    pub async fn rollback_to(
        &self,
        snapshot: &Snapshot,
        current_sections: &[String],
        radios: &[String],
    ) -> Result<(), ProvisionError> {
        for sec in current_sections {
            if !snapshot.existing_sections.iter().any(|s| s == sec) {
                let _ = self.runner.run(UCI, &["delete", sec]).await; // best-effort
            }
        }
        for (key, val) in &snapshot.prior {
            let set = format!("{key}={val}");
            let _ = self.runner.run(UCI, &["set", &set]).await; // best-effort restore
        }
        // Restore LIST options: clear whatever the failed apply left, then re-append
        // each prior element (a scalar `uci set` can't reconstruct a UCI list).
        for (key, vals) in &snapshot.prior_lists {
            let _ = self.runner.run(UCI, &["delete", key]).await; // best-effort clear
            for v in vals {
                let add = format!("{key}={v}");
                let _ = self.runner.run(UCI, &["add_list", &add]).await;
            }
        }
        self.commit_and_reload_multi(radios)
            .await
            .map_err(|e| ProvisionError::Rollback(e.to_string()))
    }

    /// Persist the wireless pending marker to tmpfs.
    pub async fn write_wireless_marker(&self, marker: &WirelessMarker) -> Result<(), ProvisionError> {
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(|e| ProvisionError::Io(format!("create {}: {e}", self.state_dir.display())))?;
        let path = wireless_marker_path(&self.state_dir);
        tokio::fs::write(&path, marker.to_text().as_bytes())
            .await
            .map_err(|e| ProvisionError::Io(format!("write {}: {e}", path.display())))
    }

    /// Remove the wireless pending marker (on commit or after a rollback resolves).
    pub async fn clear_wireless_marker(&self) -> Result<(), ProvisionError> {
        let path = wireless_marker_path(&self.state_dir);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProvisionError::Io(format!("remove {}: {e}", path.display()))),
        }
    }

    /// Read the wireless pending marker if one exists (crash-recovery reconcile).
    pub async fn read_wireless_marker(&self) -> Result<Option<WirelessMarker>, ProvisionError> {
        let path = wireless_marker_path(&self.state_dir);
        match tokio::fs::read_to_string(&path).await {
            Ok(text) => Ok(WirelessMarker::from_text(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ProvisionError::Io(format!("read {}: {e}", path.display()))),
        }
    }

    /// Persist the committed gated-SSID bridge ifaces (comma-joined) to tmpfs (F2)
    /// so a daemon restart can re-scope enforcement before the CP reconnects. An
    /// empty list writes an empty file (a committed teardown → no gated ifaces).
    pub async fn write_committed_gated(&self, ifaces: &[String]) -> Result<(), ProvisionError> {
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(|e| ProvisionError::Io(format!("create {}: {e}", self.state_dir.display())))?;
        let path = committed_gated_path(&self.state_dir);
        tokio::fs::write(&path, ifaces.join(",").as_bytes())
            .await
            .map_err(|e| ProvisionError::Io(format!("write {}: {e}", path.display())))
    }
}

/// Parse a `uci show` LIST value into its elements. `uci show` renders a list as
/// space-separated single-quoted tokens: `'aa:bb:cc:dd:ee:ff' 'ff:ee:dd:cc:bb:aa'`.
/// List elements owned here (MACs) contain no spaces, so whitespace-splitting then
/// unquoting each token is unambiguous.
fn parse_uci_list(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(unquote).filter(|s| !s.is_empty()).collect()
}

/// Strip a single layer of UCI single/double quotes from a `uci show` value.
fn unquote(v: &str) -> String {
    let v = v.trim();
    let bytes = v.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

/// Convert a raw confirm-timeout (seconds, `0` = default) into a `Duration` for
/// the watchdog.
pub fn confirm_window_secs(secs: u32) -> Duration {
    Duration::from_secs(u64::from(uci::effective_confirm_timeout_secs(secs)))
}

/// The reload argv sequence for a MULTI-radio wireless apply (order: network →
/// firewall → `wifi reload <r>` per radio → dnsmasq). Order-assertion tests use
/// this; [`ProvisionMachine::commit_and_reload_multi`] follows the same order.
pub fn reload_sequence_multi(radios: &[String]) -> Vec<(&'static str, Vec<String>)> {
    let mut v = vec![
        (INIT_NETWORK, vec!["reload".to_string()]),
        (INIT_FIREWALL, vec!["reload".to_string()]),
    ];
    for r in radios {
        v.push((WIFI, vec!["reload".to_string(), r.clone()]));
    }
    v.push((INIT_DNSMASQ, vec!["restart".to_string()]));
    v
}

/// Build a [`WirelessStatus`] for a state transition.
pub fn wireless_status(
    config_version: &str,
    state: ProvisionState,
    per_ssid: Vec<SsidResult>,
    message: impl Into<String>,
) -> WirelessStatus {
    WirelessStatus {
        config_version: config_version.to_string(),
        state,
        per_ssid,
        message: message.into(),
    }
}

/// The wifi-device radios referenced by an owned wireless snapshot (the
/// `wireless.pc_*_ap*.device` values) — unioned with the desired radios so a
/// rollback / removal reloads the radio a since-deleted SSID used to sit on.
pub fn snapshot_radios(snapshot: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in &snapshot.prior {
        if k.starts_with("wireless.pc_") && k.ends_with(".device") && !out.contains(v) {
            out.push(v.clone());
        }
    }
    out
}

/// The radios in `radios` that `ubus call network.wireless status` explicitly
/// reports as NOT up (a device object with `"up": false`). Pure + fail-open: an
/// unparseable or unexpectedly-shaped payload yields an EMPTY list — a "down"
/// verdict is only ever produced from an explicit `up == false`, so a ubus schema
/// drift can make the liveness check MISS a dark radio but never manufacture a
/// false one (which would roll back a healthy push). Keyed by wifi-device name
/// (`radio0`/`radio1`…), matching the engine's radio identifiers.
pub fn radios_reported_down(status_json: &str, radios: &[String]) -> Vec<String> {
    let v: serde_json::Value = match serde_json::from_str(status_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    radios
        .iter()
        .filter(|r| {
            v.get(r.as_str()).and_then(|d| d.get("up")).and_then(serde_json::Value::as_bool)
                == Some(false)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn snapshot_text_roundtrip() {
        let mut snap = Snapshot {
            existing_sections: vec!["network.hotspot".into(), "dhcp.hotspot".into()],
            ..Default::default()
        };
        snap.prior.insert("network.hotspot".into(), "interface".into());
        snap.prior.insert("network.hotspot.ipaddr".into(), "10.0.0.1".into());
        // include a LIST option to prove prior_lists round-trips via `key+=value`.
        snap.prior_lists.insert(
            "wireless.pc_home_ap0.maclist".into(),
            vec!["aa:bb:cc:dd:ee:ff".into(), "11:22:33:44:55:66".into()],
        );
        let text = snap.to_text();
        assert_eq!(Snapshot::from_text(&text), snap);
    }

    #[test]
    fn unquote_strips_uci_quotes() {
        assert_eq!(unquote("'10.0.0.1'"), "10.0.0.1");
        assert_eq!(unquote("\"ap\""), "ap");
        assert_eq!(unquote("bare"), "bare");
        assert_eq!(unquote("interface"), "interface");
    }

    // --- CP-managed wireless (P-W1) ----------------------------------------

    #[tokio::test]
    async fn snapshot_wireless_captures_only_pc_sections() {
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "uci" && args.first() == Some(&"show") {
                let cfg = args.get(1).copied().unwrap_or("");
                let body = match cfg {
                    "network" => "network.lan=interface\nnetwork.pc_public_if=interface\nnetwork.pc_public_if.ipaddr='10.0.0.1'\n",
                    "wireless" => "wireless.wifi_admin=wifi-iface\nwireless.pc_public_ap0=wifi-iface\nwireless.pc_public_ap0.device='radio0'\n",
                    _ => "",
                };
                Ok(body.as_bytes().to_vec())
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let snap = m.snapshot_wireless().await.unwrap();
        // pc_* captured; lan / admin NOT.
        assert!(snap.prior.contains_key("network.pc_public_if"));
        assert_eq!(snap.prior.get("network.pc_public_if.ipaddr").map(String::as_str), Some("10.0.0.1"));
        assert!(snap.prior.contains_key("wireless.pc_public_ap0"));
        assert!(!snap.prior.keys().any(|k| k.starts_with("network.lan")));
        assert!(!snap.prior.keys().any(|k| k.starts_with("wireless.wifi_admin")));
        // section decls recorded
        assert!(snap.existing_sections.iter().any(|s| s == "network.pc_public_if"));
        assert!(snap.existing_sections.iter().any(|s| s == "wireless.pc_public_ap0"));
        // radios extracted for the reload set
        assert_eq!(snapshot_radios(&snap), vec!["radio0".to_string()]);
    }

    #[tokio::test]
    async fn apply_wireless_reloads_each_radio_scoped() {
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        m.apply_wireless(&[], false, &["radio0".to_string(), "radio1".to_string()]).await.unwrap();
        let flat = m.runner().flat();
        assert!(flat.contains(&("/sbin/wifi".to_string(), "reload radio0".to_string())));
        assert!(flat.contains(&("/sbin/wifi".to_string(), "reload radio1".to_string())));
        // NEVER a bare `wifi reload` (all radios).
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload"));
        // network reload precedes firewall reload.
        let net = flat.iter().position(|(p, a)| p == "/etc/init.d/network" && a == "reload").unwrap();
        let fw = flat.iter().position(|(p, a)| p == "/etc/init.d/firewall" && a == "reload").unwrap();
        assert!(net < fw);
    }

    #[tokio::test]
    async fn dnsmasq_restart_failure_still_runs_liveness_check() {
        // P0 #4: a non-zero `dnsmasq restart` must NOT short-circuit the sequence
        // before the ubus liveness recovery. The error is surfaced (caller rolls
        // back) but recover_dark_radios still runs.
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "/etc/init.d/dnsmasq" && args == ["restart"] {
                Err(ProvisionError::Apply("dnsmasq exited 1 (non-fatal warning)".into()))
            } else {
                Ok(Vec::new()) // ubus status empty → no radio judged down
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        // dnsmasq failed → error surfaced.
        let err = m.apply_wireless(&[], false, &["radio0".to_string()]).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
        // ...but the ubus liveness check STILL ran (previously the bare `?` returned first).
        let flat = m.runner().flat();
        assert!(
            flat.iter().any(|(p, a)| p == "ubus" && a == "call network.wireless status"),
            "liveness must run even when dnsmasq restart fails: {flat:?}"
        );
    }

    #[tokio::test]
    async fn commit_failure_reverts_staged_deltas() {
        // P0 #3: a failed `uci commit` must `uci revert` the owned configs so no
        // staged delta is left for a later external commit to flush.
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "uci" && args == ["commit", "firewall"] {
                Err(ProvisionError::Apply("commit firewall: flash busy".into()))
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let err = m.apply_wireless(&[], false, &["radio0".to_string()]).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
        let flat = m.runner().flat();
        // revert_owned ran: at least one `uci revert <cfg>` was issued.
        assert!(
            flat.iter().any(|(p, a)| p == "uci" && a.starts_with("revert ")),
            "commit failure must revert staged deltas: {flat:?}"
        );
        // And no reload sequence ran (we bailed at commit).
        assert!(!flat.iter().any(|(p, _)| p == "/sbin/wifi"), "must not reload after commit failure: {flat:?}");
    }

    #[tokio::test]
    async fn apply_set_failure_reverts_staged_deltas() {
        // P0 #3 (apply side): a failing `uci set` mid-batch reverts before returning.
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "uci" && args.first() == Some(&"set") {
                Err(ProvisionError::Apply("uci set rejected".into()))
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let batch =
            vec![UciCmd::Set { key: "wireless.pc_x_ap0".into(), value: "wifi-iface".into() }];
        let err = m.apply_wireless(&batch, false, &["radio0".to_string()]).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
        let flat = m.runner().flat();
        assert!(flat.iter().any(|(p, a)| p == "uci" && a.starts_with("revert ")), "{flat:?}");
    }

    #[tokio::test]
    async fn reload_retries_then_escalates_to_wifi_up_when_reload_fails() {
        // RC4 anti-dark: a failing `wifi reload <r>` must not leave the radio down.
        // It retries once, then hard-brings-up the radio with a SCOPED `wifi up <r>`.
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "/sbin/wifi" && args.first() == Some(&"reload") {
                Err(ProvisionError::Apply("hostapd rejected config".into()))
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        // `wifi up` succeeds → the radio recovers → apply reports success overall.
        m.apply_wireless(&[], false, &["radio0".to_string()]).await.unwrap();
        let flat = m.runner().flat();
        let reloads = flat.iter().filter(|(p, a)| p == "/sbin/wifi" && a == "reload radio0").count();
        assert_eq!(reloads, 2, "reload should be retried exactly once: {flat:?}");
        assert!(
            flat.contains(&("/sbin/wifi".to_string(), "up radio0".to_string())),
            "must escalate to a scoped `wifi up radio0`: {flat:?}"
        );
        // NEVER a bare `wifi reload` / `wifi up` (all radios) — stays scoped.
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && (a == "reload" || a == "up")));
        // dnsmasq is still restarted despite the reload trouble.
        assert!(flat.contains(&("/etc/init.d/dnsmasq".to_string(), "restart".to_string())));
    }

    #[tokio::test]
    async fn reload_surfaces_error_only_when_even_wifi_up_fails() {
        // A genuine hardware/driver fault: reload + retry + `wifi up` all fail. We
        // did everything possible to keep the radio up, so the error is surfaced
        // (the caller then rolls back) — but recovery WAS attempted.
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, _a| {
            if prog == "/sbin/wifi" {
                Err(ProvisionError::Apply("radio hardware fault".into()))
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let err = m.apply_wireless(&[], false, &["radio0".to_string()]).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
        let flat = m.runner().flat();
        // All three recovery rungs were tried before giving up.
        assert_eq!(flat.iter().filter(|(p, a)| p == "/sbin/wifi" && a == "reload radio0").count(), 2);
        assert!(flat.contains(&("/sbin/wifi".to_string(), "up radio0".to_string())));
    }

    #[tokio::test]
    async fn rollback_recovers_radio_when_first_reload_fails() {
        // RC4: even on the rollback path, a flaky first `wifi reload` must escalate
        // so the radio is not abandoned dark. Here reload fails once then succeeds.
        let dir = temp_dir();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a2 = attempts.clone();
        let runner = RecordingRunner::with_responder(move |prog, args| {
            if prog == "/sbin/wifi" && args.first() == Some(&"reload") {
                let n = a2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    return Err(ProvisionError::Apply("transient reload race".into()));
                }
            }
            Ok(Vec::new())
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let snap = Snapshot::default();
        m.rollback_to(&snap, &["network.pc_x_if".to_string()], &["radio0".to_string()])
            .await
            .unwrap();
        let flat = m.runner().flat();
        // Retried the reload (2 attempts); no `wifi up` needed (2nd reload succeeded).
        assert_eq!(flat.iter().filter(|(p, a)| p == "/sbin/wifi" && a == "reload radio0").count(), 2);
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "up radio0"));
    }

    #[test]
    fn radios_reported_down_only_flags_explicit_up_false() {
        let js = r#"{"radio0":{"up":false},"radio1":{"up":true}}"#;
        let radios = vec!["radio0".to_string(), "radio1".to_string()];
        assert_eq!(radios_reported_down(js, &radios), vec!["radio0".to_string()]);
        // Fail-open: unparseable / absent / missing-`up` never yields a "down".
        assert!(radios_reported_down("", &radios).is_empty());
        assert!(radios_reported_down("not json", &radios).is_empty());
        assert!(radios_reported_down(r#"{"radio0":{"up":true}}"#, &radios).is_empty());
        assert!(radios_reported_down(r#"{}"#, &radios).is_empty());
        assert!(radios_reported_down(r#"{"radio0":{}}"#, &radios).is_empty());
    }

    #[tokio::test]
    async fn liveness_rolls_back_when_radio_dark_despite_clean_reload() {
        // RC2/RC4 gap: `wifi reload` exits 0 but hostapd silently failed → the
        // radio is dark. ubus reports it down; a forced `wifi up` doesn't fix it
        // (bad config) → an error is surfaced so the caller rolls back.
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "ubus" && args == ["call", "network.wireless", "status"] {
                Ok(br#"{"radio0":{"up":false}}"#.to_vec()) // persistently down
            } else {
                Ok(Vec::new()) // wifi reload / wifi up / uci / init.d all "succeed"
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let err = m.apply_wireless(&[], false, &["radio0".to_string()]).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)), "want Apply err, got {err:?}");
        let flat = m.runner().flat();
        // The clean reload exited 0, so recovery is driven purely by the liveness
        // check: it forced a `wifi up radio0` and queried ubus twice.
        assert!(flat.contains(&("/sbin/wifi".to_string(), "up radio0".to_string())), "{flat:?}");
        assert_eq!(
            flat.iter().filter(|(p, a)| p == "ubus" && a == "call network.wireless status").count(),
            2,
            "expected a verify-recover-reverify pair: {flat:?}"
        );
    }

    #[tokio::test]
    async fn liveness_recovers_without_rollback_when_wifi_up_fixes_it() {
        // The forced `wifi up` brings the radio back: ubus says down first, up on
        // re-check → no error, the good push stands (no spurious rollback).
        let dir = temp_dir();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = calls.clone();
        let runner = RecordingRunner::with_responder(move |prog, args| {
            if prog == "ubus" && args == ["call", "network.wireless", "status"] {
                let n = c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    return Ok(br#"{"radio0":{"up":false}}"#.to_vec()); // first: dark
                }
                return Ok(br#"{"radio0":{"up":true}}"#.to_vec()); // after wifi up: alive
            }
            Ok(Vec::new())
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        m.apply_wireless(&[], false, &["radio0".to_string()]).await.unwrap();
        let flat = m.runner().flat();
        assert!(flat.contains(&("/sbin/wifi".to_string(), "up radio0".to_string())), "{flat:?}");
    }

    #[tokio::test]
    async fn rollback_to_deletes_added_and_restores_prior() {
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        // Pre-existing: pc_home_if (restore). After apply, current = pc_public_* + pc_home_if.
        let mut snap = Snapshot {
            existing_sections: vec!["network.pc_home_if".to_string()],
            ..Default::default()
        };
        snap.prior.insert("network.pc_home_if".to_string(), "interface".to_string());
        snap.prior.insert("network.pc_home_if.ipaddr".to_string(), "10.1.0.1".to_string());
        let current = vec![
            "network.pc_public_dev".to_string(),
            "network.pc_public_if".to_string(),
            "network.pc_home_if".to_string(),
        ];
        m.rollback_to(&snap, &current, &["radio0".to_string()]).await.unwrap();
        let flat = m.runner().flat();
        // Added sections deleted; the pre-existing one is NOT deleted, its value restored.
        assert!(flat.contains(&("uci".to_string(), "delete network.pc_public_dev".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete network.pc_public_if".to_string())));
        assert!(!flat.contains(&("uci".to_string(), "delete network.pc_home_if".to_string())));
        assert!(flat.contains(&("uci".to_string(), "set network.pc_home_if.ipaddr=10.1.0.1".to_string())));
        assert!(flat.contains(&("/sbin/wifi".to_string(), "reload radio0".to_string())));
    }

    // F7: `uci show` renders a maclist on one line with quoted elements; the
    // snapshot must capture it list-aware (into prior_lists, not prior).
    #[tokio::test]
    async fn snapshot_wireless_captures_maclist_as_list() {
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "uci" && args.first() == Some(&"show") && args.get(1) == Some(&"wireless") {
                Ok(b"wireless.pc_home_ap0=wifi-iface\nwireless.pc_home_ap0.macfilter='deny'\nwireless.pc_home_ap0.maclist='aa:bb:cc:dd:ee:ff' '11:22:33:44:55:66'\n".to_vec())
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let snap = m.snapshot_wireless().await.unwrap();
        assert_eq!(snap.prior.get("wireless.pc_home_ap0.macfilter").map(String::as_str), Some("deny"));
        assert_eq!(
            snap.prior_lists.get("wireless.pc_home_ap0.maclist"),
            Some(&vec!["aa:bb:cc:dd:ee:ff".to_string(), "11:22:33:44:55:66".to_string()]),
        );
        // the list key must NOT leak into the scalar map
        assert!(!snap.prior.contains_key("wireless.pc_home_ap0.maclist"));
    }

    // F9: a device without sqm-scripts has no /etc/config/sqm, so `uci show sqm`
    // errors — the snapshot must tolerate it (not abort the whole apply).
    #[tokio::test]
    async fn snapshot_wireless_tolerates_missing_sqm() {
        let dir = temp_dir();
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "uci" && args.first() == Some(&"show") {
                match args.get(1).copied().unwrap_or("") {
                    "sqm" => Err(ProvisionError::Apply("uci: Entry not found".into())),
                    "wireless" => Ok(b"wireless.pc_home_ap0=wifi-iface\n".to_vec()),
                    _ => Ok(Vec::new()),
                }
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let snap = m.snapshot_wireless().await.expect("missing sqm must not fail snapshot");
        assert!(snap.existing_sections.iter().any(|s| s == "wireless.pc_home_ap0"));
    }

    // F7: rollback restores a prior list via delete + add_list per element (a
    // scalar `uci set` can't reconstruct a UCI list).
    #[tokio::test]
    async fn rollback_restores_prior_list_via_add_list() {
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        let mut snap = Snapshot {
            existing_sections: vec!["wireless.pc_home_ap0".to_string()],
            ..Default::default()
        };
        snap.prior.insert("wireless.pc_home_ap0".to_string(), "wifi-iface".to_string());
        snap.prior_lists.insert(
            "wireless.pc_home_ap0.maclist".to_string(),
            vec!["aa:bb:cc:dd:ee:ff".to_string(), "11:22:33:44:55:66".to_string()],
        );
        m.rollback_to(&snap, &["wireless.pc_home_ap0".to_string()], &["radio0".to_string()])
            .await
            .unwrap();
        let flat = m.runner().flat();
        // clear the list, then append each prior element
        assert!(flat.contains(&("uci".to_string(), "delete wireless.pc_home_ap0.maclist".to_string())));
        assert!(flat.contains(&("uci".to_string(), "add_list wireless.pc_home_ap0.maclist=aa:bb:cc:dd:ee:ff".to_string())));
        assert!(flat.contains(&("uci".to_string(), "add_list wireless.pc_home_ap0.maclist=11:22:33:44:55:66".to_string())));
    }

    #[tokio::test]
    async fn wireless_marker_roundtrips_through_tmpfs() {
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        let mut snap = Snapshot {
            existing_sections: vec!["network.pc_home_if".into()],
            ..Default::default()
        };
        snap.prior.insert("network.pc_home_if.ipaddr".into(), "10.1.0.1".into());
        let marker = WirelessMarker {
            config_version: "cfg-7".into(),
            radios: vec!["radio0".into(), "radio1".into()],
            current_sections: vec!["network.pc_public_if".into(), "network.pc_public_dev".into()],
            gated_ifaces: vec!["br-public".into()],
            deadline_unix: 1_700_000_000,
            snapshot: snap,
        };
        assert!(m.read_wireless_marker().await.unwrap().is_none());
        m.write_wireless_marker(&marker).await.unwrap();
        assert_eq!(m.read_wireless_marker().await.unwrap().unwrap(), marker);
        m.clear_wireless_marker().await.unwrap();
        assert!(m.read_wireless_marker().await.unwrap().is_none());
    }

    #[test]
    fn reload_sequence_multi_scopes_each_radio() {
        let seq = reload_sequence_multi(&["radio0".to_string(), "radio1".to_string()]);
        assert_eq!(seq[0].0, "/etc/init.d/network");
        assert_eq!(seq[1].0, "/etc/init.d/firewall");
        assert_eq!(seq[2], ("/sbin/wifi", vec!["reload".to_string(), "radio0".to_string()]));
        assert_eq!(seq[3], ("/sbin/wifi", vec!["reload".to_string(), "radio1".to_string()]));
        assert_eq!(seq[4].0, "/etc/init.d/dnsmasq");
    }
}
