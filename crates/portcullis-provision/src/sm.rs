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

use portcullis_types::{ProvisionError, ProvisionSpec, ProvisionState, ProvisionStatus};

use crate::runner::CommandRunner;
use crate::uci::{self, UciCmd, OWNED, OWNED_CONFIGS};

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

/// The persisted pending marker (tmpfs): enough to resume the watchdog / roll
/// back on a daemon restart that lands mid-window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMarker {
    pub provision_id: String,
    /// The spec that was applied (so a boot-time rollback knows whether it was an
    /// enable — restore snapshot — or a teardown — re-apply snapshot).
    pub was_teardown: bool,
    pub bridge_name: String,
    /// The hotspot's wifi-device — persisted so a boot-time rollback reloads only
    /// that radio (never the admin/control-plane radio). See [`crate::uci::effective_radio`].
    pub radio: String,
    /// UNIX-epoch seconds deadline (wall clock — survives a process restart,
    /// unlike a `tokio::time::Instant`).
    pub deadline_unix: i64,
    pub snapshot: Snapshot,
}

impl PendingMarker {
    fn to_text(&self) -> String {
        // A tiny header block followed by the snapshot body.
        let mut s = String::new();
        s.push_str(&format!("provision_id={}\n", self.provision_id));
        s.push_str(&format!("was_teardown={}\n", self.was_teardown));
        s.push_str(&format!("bridge_name={}\n", self.bridge_name));
        s.push_str(&format!("radio={}\n", self.radio));
        s.push_str(&format!("deadline_unix={}\n", self.deadline_unix));
        s.push_str("---\n");
        s.push_str(&self.snapshot.to_text());
        s
    }

    fn from_text(text: &str) -> Option<PendingMarker> {
        let (head, body) = text.split_once("\n---\n")?;
        let mut provision_id = None;
        let mut was_teardown = false;
        let mut bridge_name = String::new();
        // Backward-compatible: a marker written before the radio field existed
        // rolls back on the default radio rather than failing to parse.
        let mut radio = uci::DEFAULT_RADIO.to_string();
        let mut deadline_unix = None;
        for line in head.lines() {
            let (k, v) = line.split_once('=')?;
            match k {
                "provision_id" => provision_id = Some(v.to_string()),
                "was_teardown" => was_teardown = v == "true",
                "bridge_name" => bridge_name = v.to_string(),
                "radio" => radio = v.to_string(),
                "deadline_unix" => deadline_unix = v.parse().ok(),
                _ => {}
            }
        }
        Some(PendingMarker {
            provision_id: provision_id?,
            was_teardown,
            bridge_name,
            radio,
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

/// The path of the pending marker inside the state dir.
fn marker_path(dir: &Path) -> PathBuf {
    dir.join("pending.marker")
}

/// Test-only accessor for the marker path (used by the handle actor tests to
/// assert the marker is created/cleared at the right points).
#[doc(hidden)]
pub fn marker_path_for_test(dir: &Path) -> PathBuf {
    marker_path(dir)
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

    /// Capture the prior state of ONLY the owned sections into a [`Snapshot`].
    ///
    /// Runs `uci show <config>` for each owned config and keeps only the lines
    /// whose section is one of the four owned ones — so a snapshot can never
    /// capture (and thus a rollback can never rewrite) a non-owned section, even
    /// if the filter were fed the whole `uci show`.
    pub async fn snapshot(&self) -> Result<Snapshot, ProvisionError> {
        let mut snap = Snapshot::default();
        for cfg in OWNED_CONFIGS {
            // `uci show network` prints `network.<sec>=<type>` and
            // `network.<sec>.<opt>='<val>'` lines. A show of a config with no
            // matching sections still succeeds (empty output).
            let out = self.runner.run(UCI, &["show", cfg]).await?;
            let text = String::from_utf8_lossy(&out);
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Some((key, raw_val)) = line.split_once('=') else { continue };
                if !is_owned_key(key) {
                    continue; // guardrail: only owned sections enter the snapshot
                }
                let val = unquote(raw_val);
                // A bare section decl line has key == the section key itself.
                if OWNED.contains(&key) && !snap.existing_sections.iter().any(|s| s == key) {
                    snap.existing_sections.push(key.to_string());
                }
                snap.prior.insert(key.to_string(), val);
            }
        }
        Ok(snap)
    }

    /// Apply a batch of [`UciCmd`]s, then `uci commit` the owned configs, then
    /// reload IN ORDER: network → firewall → wifi `<radio>` → dnsmasq.
    /// Panic-guarded by the caller (the actor task) — an error here never takes
    /// down enforcement.
    ///
    /// `radio` is the hotspot's wifi-device (from [`uci::effective_radio`]): only
    /// THAT radio is reloaded, so the admin/control-plane radio on a dual-band
    /// router never bounces (which would sever the engine↔CP link and defeat the
    /// commit-confirm). See [`Self::commit_and_reload`].
    ///
    /// A `delete` on apply is best-effort (a missing section on teardown is not
    /// an error): those are tolerated. A failed `set` / `commit` / reload is a
    /// hard error → the caller rolls back.
    pub async fn apply(
        &self,
        cmds: &[UciCmd],
        allow_missing_delete: bool,
        radio: &str,
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
        self.commit_and_reload(radio).await
    }

    /// `uci commit` per owned config (in order) then the reload sequence. Shared
    /// by apply + rollback so both go through the same ordered path.
    ///
    /// `radio` scopes the wifi reload to the hotspot's device: `wifi reload
    /// <radio>` reloads ONLY that radio. We deliberately do NOT run bare `wifi
    /// reload` (all radios): on a dual-band router the hotspot AP lives on one
    /// radio while the admin + control-plane WiFi lives on the other — bouncing
    /// every radio would drop the engine↔control-plane link, so the CP could
    /// never send the confirm and every provision would roll back.
    async fn commit_and_reload(&self, radio: &str) -> Result<(), ProvisionError> {
        // Commit each owned config SEPARATELY: busybox `uci commit` accepts at
        // most ONE <config> arg — a single `uci commit network wireless dhcp
        // firewall` exits 255 with a usage error on RutOS. Order preserved
        // (firewall last: its zone references the hotspot interface).
        for cfg in OWNED_CONFIGS {
            self.runner.run(UCI, &["commit", cfg]).await?;
        }

        // Reload ORDER matters (design doc): network before firewall (the zone
        // references the just-created interface) before wifi before dnsmasq — or
        // the zone binds a not-yet-up interface / the AP attaches to a not-yet-up
        // bridge / dnsmasq binds a not-yet-configured interface. The wifi step is
        // scoped to `<radio>` (see above).
        self.runner.run(INIT_NETWORK, &["reload"]).await?;
        self.runner.run(INIT_FIREWALL, &["reload"]).await?;
        self.runner.run(WIFI, &["reload", radio]).await?;
        self.runner.run(INIT_DNSMASQ, &["restart"]).await?;
        Ok(())
    }

    /// Roll back to `snapshot`: delete owned sections we ADDED (not in
    /// `existing_sections`), re-create + restore the prior option values of
    /// sections that existed, then commit + reload. Fail-OPEN's safety net.
    ///
    /// `radio` is the hotspot's radio (the one whose vif is being removed); only
    /// it is reloaded, so the admin radio stays untouched during rollback too.
    pub async fn rollback(&self, snapshot: &Snapshot, radio: &str) -> Result<(), ProvisionError> {
        // 1. Delete any owned section that did NOT exist before apply (we made it).
        for sec in OWNED {
            if !snapshot.existing_sections.iter().any(|s| s == sec) {
                let _ = self.runner.run(UCI, &["delete", sec]).await; // best-effort
            }
        }
        // 2. Restore prior sections: re-declare the section (its `key=type` line)
        //    and re-apply every prior option value. Deterministic order (BTreeMap
        //    in the snapshot) keeps section decls before their options because a
        //    bare section key sorts before `key.opt` keys.
        for (key, val) in &snapshot.prior {
            let set = format!("{key}={val}");
            let _ = self.runner.run(UCI, &["set", &set]).await; // best-effort restore
        }
        // 3. Commit + reload so the restored config takes effect.
        self.commit_and_reload(radio)
            .await
            .map_err(|e| ProvisionError::Rollback(e.to_string()))
    }

    // --- tmpfs marker persistence -----------------------------------------

    /// Persist the pending marker to tmpfs.
    pub async fn write_marker(&self, marker: &PendingMarker) -> Result<(), ProvisionError> {
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(|e| ProvisionError::Io(format!("create {}: {e}", self.state_dir.display())))?;
        let path = marker_path(&self.state_dir);
        tokio::fs::write(&path, marker.to_text().as_bytes())
            .await
            .map_err(|e| ProvisionError::Io(format!("write {}: {e}", path.display())))
    }

    /// Remove the pending marker (on commit or after a rollback resolves it).
    pub async fn clear_marker(&self) -> Result<(), ProvisionError> {
        let path = marker_path(&self.state_dir);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProvisionError::Io(format!("remove {}: {e}", path.display()))),
        }
    }

    /// Read the pending marker if one exists (crash-recovery reconcile).
    pub async fn read_marker(&self) -> Result<Option<PendingMarker>, ProvisionError> {
        let path = marker_path(&self.state_dir);
        match tokio::fs::read_to_string(&path).await {
            Ok(text) => Ok(PendingMarker::from_text(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ProvisionError::Io(format!("read {}: {e}", path.display()))),
        }
    }
}

/// The reload argv the design doc mandates, in order, for a hotspot on `radio`.
/// Exposed for order-assertion tests. `(program, args)` in reload order:
/// network reload → firewall reload → **wifi reload `<radio>`** → dnsmasq restart
/// (firewall AFTER network — its zone references the interface; the wifi step is
/// SCOPED to `<radio>` so the admin/control-plane radio never bounces). This is
/// the single source of truth [`ProvisionMachine::commit_and_reload`] follows.
pub fn reload_sequence(radio: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        (INIT_NETWORK, vec!["reload".to_string()]),
        (INIT_FIREWALL, vec!["reload".to_string()]),
        (WIFI, vec!["reload".to_string(), radio.to_string()]),
        (INIT_DNSMASQ, vec!["restart".to_string()]),
    ]
}

/// Build the `ProvisionStatus` for a state transition.
pub fn status(id: &str, state: ProvisionState, message: impl Into<String>, bridge: &str) -> ProvisionStatus {
    ProvisionStatus {
        provision_id: id.to_string(),
        state,
        message: message.into(),
        bridge_name: bridge.to_string(),
    }
}

/// Whether a `uci show` key belongs to one of the four owned sections.
fn is_owned_key(key: &str) -> bool {
    OWNED
        .iter()
        .any(|owned| key == *owned || key.starts_with(&format!("{owned}.")))
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

/// Convert an effective timeout (seconds) into a `Duration` for the watchdog.
pub fn confirm_window(spec: &ProvisionSpec) -> Duration {
    Duration::from_secs(u64::from(uci::effective_confirm_timeout(spec)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    fn spec() -> ProvisionSpec {
        ProvisionSpec {
            provision_id: "prov-1".into(),
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
            confirm_timeout_secs: 90,
        }
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn apply_commits_owned_configs_and_reloads_in_order() {
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        // The default spec's radio is radio0 → the wifi step reloads ONLY radio0.
        m.apply(&uci::render_uci(&spec(), 8080), false, "radio0").await.unwrap();

        let flat = m.runner().flat();
        // The last EIGHT invocations are: four per-config commits (busybox `uci
        // commit` takes one config each), then the four-step reload IN ORDER
        // (network → firewall → wifi <radio> → dnsmasq).
        let tail: Vec<(String, String)> = flat.iter().rev().take(8).rev().cloned().collect();
        assert_eq!(
            tail,
            vec![
                ("uci".to_string(), "commit network".to_string()),
                ("uci".to_string(), "commit wireless".to_string()),
                ("uci".to_string(), "commit dhcp".to_string()),
                ("uci".to_string(), "commit firewall".to_string()),
                ("/etc/init.d/network".to_string(), "reload".to_string()),
                ("/etc/init.d/firewall".to_string(), "reload".to_string()),
                // Scoped to the hotspot radio — NOT bare `wifi reload` (all radios).
                ("/sbin/wifi".to_string(), "reload radio0".to_string()),
                ("/etc/init.d/dnsmasq".to_string(), "restart".to_string()),
            ]
        );
        // firewall reload comes AFTER network reload (zone references the iface).
        let net = flat.iter().position(|(p, a)| p == "/etc/init.d/network" && a == "reload").unwrap();
        let fw = flat.iter().position(|(p, a)| p == "/etc/init.d/firewall" && a == "reload").unwrap();
        assert!(net < fw, "network reload must precede firewall reload");
        // No bare `wifi reload` (all radios) — always scoped to a radio.
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload"));
        // No `sh` ever spawned.
        assert!(flat.iter().all(|(p, _)| p != "sh" && p != "/bin/sh"));
    }

    #[tokio::test]
    async fn wifi_reload_targets_the_hotspot_radio_only() {
        // A hotspot on radio1 (e.g. 5 GHz) must reload ONLY radio1 — the admin/
        // control-plane radio (radio0) must never appear in a wifi reload.
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        m.apply(&[], false, "radio1").await.unwrap();
        let flat = m.runner().flat();
        assert!(flat.contains(&("/sbin/wifi".to_string(), "reload radio1".to_string())));
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload radio0"));
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload"));
    }

    #[test]
    fn reload_sequence_scopes_wifi_to_radio() {
        // radio1 hotspot.
        let seq = reload_sequence("radio1");
        assert_eq!(
            seq,
            vec![
                ("/etc/init.d/network", vec!["reload".to_string()]),
                ("/etc/init.d/firewall", vec!["reload".to_string()]),
                ("/sbin/wifi", vec!["reload".to_string(), "radio1".to_string()]),
                ("/etc/init.d/dnsmasq", vec!["restart".to_string()]),
            ]
        );
        // default radio0.
        let seq0 = reload_sequence("radio0");
        assert_eq!(seq0[2], ("/sbin/wifi", vec!["reload".to_string(), "radio0".to_string()]));
    }

    #[tokio::test]
    async fn snapshot_captures_only_owned_sections() {
        let dir = temp_dir();
        // Fake `uci show <cfg>` returns non-owned sections (br-lan, the wan/lan fw
        // zones) alongside a prior hotspot iface + a prior hotspot fw rule.
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "uci" && args.first() == Some(&"show") {
                let cfg = args.get(1).copied().unwrap_or("");
                let body = match cfg {
                    "network" => "network.lan=interface\nnetwork.lan.proto='static'\nnetwork.hotspot=interface\nnetwork.hotspot.ipaddr='10.9.9.1'\n",
                    "dhcp" => "dhcp.lan=dhcp\n",
                    "firewall" => "firewall.wan=zone\nfirewall.wan.masq='1'\nfirewall.lan=zone\nfirewall.hotspot_dns=rule\nfirewall.hotspot_dns.dest_port='53'\n",
                    _ => "",
                };
                Ok(body.as_bytes().to_vec())
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let snap = m.snapshot().await.unwrap();

        // br-lan / dhcp.lan / firewall.wan / firewall.lan must NOT be captured;
        // the prior hotspot iface + hotspot fw rule MUST.
        assert!(snap.prior.contains_key("network.hotspot"));
        assert_eq!(snap.prior.get("network.hotspot.ipaddr").map(String::as_str), Some("10.9.9.1"));
        assert!(snap.prior.contains_key("firewall.hotspot_dns"));
        assert_eq!(snap.prior.get("firewall.hotspot_dns.dest_port").map(String::as_str), Some("53"));
        assert!(!snap.prior.keys().any(|k| k.starts_with("network.lan")));
        assert!(!snap.prior.keys().any(|k| k.starts_with("dhcp.lan")));
        assert!(!snap.prior.keys().any(|k| k.starts_with("firewall.wan")));
        assert!(!snap.prior.keys().any(|k| k.starts_with("firewall.lan")));
        let mut existing = snap.existing_sections.clone();
        existing.sort();
        assert_eq!(existing, vec!["firewall.hotspot_dns".to_string(), "network.hotspot".to_string()]);
    }

    #[tokio::test]
    async fn rollback_deletes_added_sections_and_restores_prior_then_reloads() {
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        // Snapshot: network.hotspot existed before (restore it); the other eight
        // owned sections did not (they must be deleted on rollback).
        let mut snap = Snapshot {
            existing_sections: vec!["network.hotspot".to_string()],
            ..Default::default()
        };
        snap.prior.insert("network.hotspot".to_string(), "interface".to_string());
        snap.prior.insert("network.hotspot.ipaddr".to_string(), "10.9.9.1".to_string());

        m.rollback(&snap, "radio0").await.unwrap();
        let flat = m.runner().flat();

        // Deletes the sections we added (NOT network.hotspot, which existed) —
        // including the firewall zone/forwarding/rules.
        assert!(flat.contains(&("uci".to_string(), "delete network.br_hotspot".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete wireless.wifi_hotspot".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete dhcp.hotspot".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete firewall.hotspot".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete firewall.hotspot_fwd".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete firewall.hotspot_dhcp".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete firewall.hotspot_dns".to_string())));
        assert!(flat.contains(&("uci".to_string(), "delete firewall.hotspot_portal".to_string())));
        assert!(!flat.contains(&("uci".to_string(), "delete network.hotspot".to_string())));
        // Restores the prior option value.
        assert!(flat.contains(&("uci".to_string(), "set network.hotspot.ipaddr=10.9.9.1".to_string())));
        // And ends with per-config commits (incl. firewall) + reload — wifi step
        // scoped to the hotspot radio only (never bare `wifi reload`).
        assert!(flat.contains(&("uci".to_string(), "commit network".to_string())));
        assert!(flat.contains(&("uci".to_string(), "commit firewall".to_string())));
        assert!(flat.contains(&("/etc/init.d/firewall".to_string(), "reload".to_string())));
        assert!(flat.contains(&("/sbin/wifi".to_string(), "reload radio0".to_string())));
        assert!(!flat.iter().any(|(p, a)| p == "/sbin/wifi" && a == "reload"));
        assert!(flat.contains(&("/etc/init.d/dnsmasq".to_string(), "restart".to_string())));
    }

    #[tokio::test]
    async fn apply_error_propagates_for_rollback() {
        let dir = temp_dir();
        // Make `network reload` fail — the classic "apply severed connectivity"
        // case the watchdog exists for.
        let runner = RecordingRunner::with_responder(|prog, args| {
            if prog == "/etc/init.d/network" && args == ["reload"] {
                Err(ProvisionError::Apply("network reload failed".into()))
            } else {
                Ok(Vec::new())
            }
        });
        let m = ProvisionMachine::new(runner, dir.path(), 8080);
        let err = m.apply(&uci::render_uci(&spec(), 8080), false, "radio0").await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
    }

    #[tokio::test]
    async fn marker_roundtrips_through_tmpfs() {
        let dir = temp_dir();
        let m = ProvisionMachine::new(RecordingRunner::new(), dir.path(), 8080);
        let mut snap = Snapshot {
            existing_sections: vec!["network.hotspot".into()],
            ..Default::default()
        };
        snap.prior.insert("network.hotspot.ipaddr".into(), "10.9.9.1".into());
        let marker = PendingMarker {
            provision_id: "prov-1".into(),
            was_teardown: false,
            bridge_name: "br-hotspot".into(),
            radio: "radio1".into(),
            deadline_unix: 1_700_000_000,
            snapshot: snap,
        };
        assert!(m.read_marker().await.unwrap().is_none());
        m.write_marker(&marker).await.unwrap();
        let read = m.read_marker().await.unwrap().unwrap();
        assert_eq!(read, marker);
        m.clear_marker().await.unwrap();
        assert!(m.read_marker().await.unwrap().is_none());
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

    #[test]
    fn is_owned_key_guards_the_allowlist() {
        assert!(is_owned_key("network.hotspot"));
        assert!(is_owned_key("network.hotspot.ipaddr"));
        assert!(is_owned_key("dhcp.hotspot.start"));
        assert!(!is_owned_key("network.lan"));
        assert!(!is_owned_key("network.lan.proto"));
        assert!(!is_owned_key("firewall.zone"));
    }
}
