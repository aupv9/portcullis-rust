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
const INIT_NETWORK: &str = "/etc/init.d/network";
const INIT_FIREWALL: &str = "/etc/init.d/firewall";
const INIT_DNSMASQ: &str = "/etc/init.d/dnsmasq";

/// A captured snapshot of the owned sections' prior state: the `uci show` option
/// lines that existed BEFORE apply, plus the set of section keys that existed so
/// rollback knows which sections we *added* (delete them) vs *modified* (restore
/// their prior option values).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Prior `key=value` for every owned option line present before apply, e.g.
    /// `network.hotspot.ipaddr` -> `10.0.0.1`. Section-decl lines (`network.hotspot`
    /// -> `interface`) are included too so a full re-apply reproduces them.
    pub prior: BTreeMap<String, String>,
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
                snap.prior.insert(k.to_string(), v.to_string());
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
    pub deadline_unix: i64,
    pub snapshot: Snapshot,
}

impl WirelessMarker {
    fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("config_version={}\n", self.config_version));
        s.push_str(&format!("radios={}\n", self.radios.join(",")));
        s.push_str(&format!("current_sections={}\n", self.current_sections.join(",")));
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
                "deadline_unix" => deadline_unix = v.parse().ok(),
                _ => {}
            }
        }
        Some(WirelessMarker {
            config_version,
            radios,
            current_sections,
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
            let out = self.runner.run(UCI, &["show", cfg]).await?;
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
                let val = unquote(raw_val);
                // A section decl line has exactly one `.` (`config.section`).
                if key.matches('.').count() == 1 && !snap.existing_sections.iter().any(|s| s == key) {
                    snap.existing_sections.push(key.to_string());
                }
                snap.prior.insert(key.to_string(), val);
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
            self.runner.run(UCI, &["commit", cfg]).await?;
        }
        self.runner.run(INIT_NETWORK, &["reload"]).await?;
        self.runner.run(INIT_FIREWALL, &["reload"]).await?;
        for r in radios {
            self.runner.run(WIFI, &["reload", r]).await?;
        }
        self.runner.run(INIT_DNSMASQ, &["restart"]).await?;
        Ok(())
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
