//! Per-device telemetry poller (P3 device monitoring).
//!
//! ## What this is
//! The [`run_liveness_poller`](crate::liveness) sibling for **device** SSIDs. The
//! liveness poller only probes *gated* VIFs (captive SSIDs); a **device** SSID —
//! an owned `pc_<slug>` SSID carrying DHCP **reservations** for fixed appliances
//! (vending / smart-POS / camera / NVR) — is typically UNGATED, so liveness never
//! covers it. This poller fills that gap: every tick, for each owned SSID that has
//! reservations, it emits one [`DeviceObservation`] per reservation, combining
//!
//!   - the reservation's static IP + MAC (from the committed desired-state),
//!   - a live association probe (`ubus iwinfo assoclist`): online / signal /
//!     uptime, matched by MAC, and
//!   - per-device-IP **nft named counter** byte totals (upload = `ip saddr`,
//!     download = `ip daddr`), read from `nft -j list counters`.
//!
//! It is purely OBSERVATIONAL — it reads, never writes enforcement, and can never
//! affect a grant. It DOES maintain the metering counters (create/prune) in the
//! engine's own `inet wifihub` table via [`portcullis_nft::device_meter`]; those
//! are pure meters (no verdict) that cannot gate traffic (§7.1).
//!
//! ## Why nft counters keyed on the static IP (not conntrack)
//! `conntrack-tools` is absent on the RUT906 target. The reservation pins each
//! device to a static IP, so two per-IP nft named counters give a cheap
//! cumulative byte total that survives association flaps — see
//! [`portcullis_nft::device_meter`].
//!
//! ## Reconcile, not event-plumb
//! Each tick the poller derives the CURRENT device-IP set from the committed
//! reservations and reconciles the nft counters to it (add missing, prune stale).
//! Counter lifecycle thus tracks reservation lifecycle without threading events
//! through the provision state machine.
//!
//! ## DEVICE-ONLY — parsers unit-tested, shell path on-device
//! `ubus` / `iwinfo` / `nft` exist only on the router. The pure parsers
//! ([`slug_vifs`](crate::liveness::slug_vifs), [`assoc_by_mac`], the counter
//! parsers) are host-unit-tested; [`poll_once`] itself is exercised via the
//! [`CommandRunner`] seam with a mock (see tests), never against real tools here.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use portcullis_types::{DeviceObservation, Provisioner, SsidSpec, WirelessDeviceReport};
use tokio::sync::mpsc;

use crate::liveness::slug_vifs;
use crate::runner::CommandRunner;

const UBUS: &str = "ubus";
const NFT: &str = "nft";

/// Default poll cadence — reuses the liveness cadence (~30 s). Device telemetry
/// is a slow gauge, and the shell-outs are cheap on the MIPS budget.
pub const DEFAULT_DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on the outward device-report mpsc. Tiny: a stale report is worthless, so
/// a full channel drops rather than buffers (`try_send`, never blocks the loop).
pub const DEVICE_REPORT_BUFFER: usize = 4;

/// One associated station as read from `iwinfo assoclist`: signal + uptime.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AssocEntry {
    pub signal_dbm: i32,
    pub uptime_secs: u32,
}

/// Run the device-observation poller until the outward channel closes (engine
/// shutdown) or the task is aborted. Ticks every `interval`, building a
/// [`WirelessDeviceReport`] from the current committed device SSIDs' reservations
/// and pushing it up `tx`.
///
/// Best-effort throughout: a tick that resolves nothing sends an empty report; a
/// send onto a full channel is dropped, not awaited.
pub async fn run_device_obs_poller<R: CommandRunner>(
    runner: Arc<R>,
    provisioner: Arc<dyn Provisioner>,
    tx: mpsc::Sender<WirelessDeviceReport>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Device IPs that have live nft counters, so we can PRUNE those whose
    // reservation disappeared between ticks. Seeded empty (a fresh boot has none).
    let mut known_ips: Vec<String> = Vec::new();
    loop {
        tick.tick().await;
        let (report, current_ips) =
            poll_once(runner.as_ref(), provisioner.as_ref(), &known_ips).await;
        known_ips = current_ips;
        match tx.try_send(report) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!("device-report channel full; dropping report (consumer behind)");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("device-report channel closed; stopping device-obs poller");
                return;
            }
        }
    }
}

/// One device-observation sweep. Reads committed device SSIDs (owned SSIDs that
/// have reservations), reconciles the nft counters to their static IPs (adding
/// new, pruning those in `prev_ips` no longer present), reads the assoclist per
/// VIF + the counter totals, and assembles one [`DeviceObservation`] per
/// reservation. Returns the report plus the CURRENT device-IP set (so the caller
/// can prune next tick). Never fails — an error anywhere yields a thinner report.
///
/// Public for on-device diagnostics + so the poll loop stays trivial.
pub async fn poll_once<R: CommandRunner>(
    runner: &R,
    provisioner: &dyn Provisioner,
    prev_ips: &[String],
) -> (WirelessDeviceReport, Vec<String>) {
    let ts_unix = unix_now();

    let desired = match provisioner.get_wireless().await {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(error = %e, "device-obs: no committed wireless state; empty report");
            return (WirelessDeviceReport { devices: Vec::new(), ts_unix }, Vec::new());
        }
    };

    // Device SSIDs = owned SSIDs that carry at least one reservation.
    let device_ssids: Vec<&SsidSpec> =
        desired.ssids.iter().filter(|s| !s.reservations.is_empty()).collect();

    // The current device-IP set (dedup, non-empty) drives the nft counters.
    let current_ips: Vec<String> = {
        let mut ips: Vec<String> = device_ssids
            .iter()
            .flat_map(|s| s.reservations.iter())
            .map(|r| r.ipaddr.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect();
        ips.sort();
        ips.dedup();
        ips
    };

    // Reconcile the nft metering counters to the current IP set: (re)create the
    // metering chain + per-IP counters (idempotent), then prune counters whose
    // reservation vanished since the previous tick. Best-effort: a failure just
    // means thinner byte totals this tick; NEVER affects enforcement.
    reconcile_counters(runner, prev_ips, &current_ips).await;

    if device_ssids.is_empty() {
        return (WirelessDeviceReport { devices: Vec::new(), ts_unix }, current_ips);
    }

    // Resolve slug -> VIF once (single `ubus call network.wireless status`).
    let status_json = runner
        .run(UBUS, &["call", "network.wireless", "status"])
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let vif_of = slug_vifs(&status_json);

    // Read all owned-table counters once (single `nft -j list counters`).
    let counters = read_counters(runner).await;

    let mut devices = Vec::new();
    for spec in device_ssids {
        // Per-SSID assoclist keyed by MAC (empty if the VIF can't be resolved).
        let assoc = match vif_of.iter().find(|(slug, _)| slug == &spec.slug) {
            Some((_, vif)) => read_assoc(runner, vif).await,
            None => BTreeMap::new(),
        };
        for r in &spec.reservations {
            let mac = r.mac.trim().to_ascii_lowercase();
            let ip = r.ipaddr.trim();
            let entry = assoc.get(&mac);
            let (rx_bytes, tx_bytes) = portcullis_nft::bytes_for_ip(&counters, ip);
            devices.push(DeviceObservation {
                slug: spec.slug.clone(),
                mac,
                ipaddr: ip.to_string(),
                online: entry.is_some(),
                signal_dbm: entry.map(|e| e.signal_dbm).unwrap_or(0),
                rx_bytes,
                tx_bytes,
                uptime_secs: entry.map(|e| e.uptime_secs).unwrap_or(0),
            });
        }
    }

    (WirelessDeviceReport { devices, ts_unix }, current_ips)
}

/// Reconcile the nft metering counters: apply the idempotent reconcile doc for
/// the current IP set, then prune counters for IPs in `prev` no longer in
/// `current`. Best-effort (fail-soft): a missing/failed `nft` just skips.
async fn reconcile_counters<R: CommandRunner>(runner: &R, prev: &[String], current: &[String]) {
    let doc = portcullis_nft::build_reconcile_doc(current);
    apply_nft(runner, &doc).await;

    let stale: Vec<String> = prev.iter().filter(|ip| !current.contains(ip)).cloned().collect();
    if let Some(prune) = portcullis_nft::build_prune_doc(&stale) {
        apply_nft(runner, &prune).await;
    }
}

/// Apply an `nft -j` document via `nft -j -f -` (fed on stdin). Best-effort: a
/// spawn/exec error is logged at debug and swallowed (device-only tool; the
/// observation degrades to zero counters rather than failing the poll).
async fn apply_nft<R: CommandRunner>(runner: &R, doc: &serde_json::Value) {
    let payload = doc.to_string();
    // The CommandRunner seam here shells `nft -j -f -`, feeding the JSON on stdin.
    // The RecordingRunner in tests records the argv without executing anything.
    if let Err(e) = runner.run_stdin(NFT, &["-j", "-f", "-"], payload.as_bytes()).await {
        tracing::debug!(error = %e, "device-obs: nft counter apply failed (device-only); skipping");
    }
}

/// Read + parse the owned table's named counters (`nft -j list counters table
/// inet wifihub`). Fail-soft: an error yields an empty map.
async fn read_counters<R: CommandRunner>(runner: &R) -> BTreeMap<String, u64> {
    let out = runner
        .run(NFT, &["-j", "list", "counters", "table", "inet", "wifihub"])
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    portcullis_nft::parse_counters(&out)
}

/// Read + parse one VIF's assoclist into `mac -> AssocEntry`. Fail-soft.
async fn read_assoc<R: CommandRunner>(runner: &R, vif: &str) -> BTreeMap<String, AssocEntry> {
    let json = runner
        .run(UBUS, &["call", "iwinfo", "assoclist", &format!("{{\"device\":\"{vif}\"}}")])
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    assoc_by_mac(&json)
}

// ---------------------------------------------------------------------------
// Pure parser — fail-soft, unit-tested (runs on any host).
// ---------------------------------------------------------------------------

/// Parse `ubus call iwinfo assoclist {"device":"<vif>"}` into `mac ->
/// AssocEntry`, keyed by the LOWERCASE MAC. Schema:
/// `{ "results": [ { "mac": "AA:BB:..", "signal": -55, "connected_time": 3600,
/// ... }, … ] }`. Fail-soft: unparseable/unexpected ⇒ empty map. `connected_time`
/// (seconds) maps to `uptime_secs`; a missing/negative value reads as `0`.
pub fn assoc_by_mac(assoc_json: &str) -> BTreeMap<String, AssocEntry> {
    let mut out = BTreeMap::new();
    let v: serde_json::Value = match serde_json::from_str(assoc_json) {
        Ok(v) => v,
        Err(_) => return out,
    };
    let Some(results) = v.get("results").and_then(serde_json::Value::as_array) else {
        return out;
    };
    for r in results {
        let Some(mac) = r.get("mac").and_then(serde_json::Value::as_str) else { continue };
        let signal_dbm =
            r.get("signal").and_then(serde_json::Value::as_i64).unwrap_or(0) as i32;
        let uptime_secs = r
            .get("connected_time")
            .and_then(serde_json::Value::as_i64)
            .filter(|&t| t >= 0)
            .map(|t| t.min(u32::MAX as i64) as u32)
            .unwrap_or(0);
        out.insert(mac.to_ascii_lowercase(), AssocEntry { signal_dbm, uptime_secs });
    }
    out
}

/// Engine wall-clock (unix secs). Isolated so tests do not depend on the clock.
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
    use portcullis_types::{
        DhcpReservation, ProvisionError, SsidSpec, WirelessDesiredState,
    };

    // --- pure assoclist parser -------------------------------------------

    #[test]
    fn assoc_by_mac_parses_signal_and_uptime_lowercased() {
        let json = r#"{ "results": [
            { "mac": "AA:BB:CC:DD:EE:01", "signal": -55, "connected_time": 3600 },
            { "mac": "aa:bb:cc:dd:ee:02", "signal": -70 }
        ] }"#;
        let m = assoc_by_mac(json);
        assert_eq!(m.len(), 2);
        let a = m.get("aa:bb:cc:dd:ee:01").unwrap();
        assert_eq!(a.signal_dbm, -55);
        assert_eq!(a.uptime_secs, 3600);
        // Missing connected_time -> 0.
        assert_eq!(m.get("aa:bb:cc:dd:ee:02").unwrap().uptime_secs, 0);
    }

    #[test]
    fn assoc_by_mac_fail_soft() {
        assert!(assoc_by_mac("not json").is_empty());
        assert!(assoc_by_mac("{}").is_empty());
        assert!(assoc_by_mac(r#"{"results":[]}"#).is_empty());
    }

    // --- report assembly via the CommandRunner seam ----------------------

    /// A provisioner double serving a fixed committed desired-state.
    struct FakeProv {
        state: WirelessDesiredState,
    }
    #[async_trait::async_trait]
    impl Provisioner for FakeProv {
        async fn set_wireless(&self, _s: WirelessDesiredState) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn confirm_wireless(&self, _v: &str) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn get_wireless(&self) -> Result<WirelessDesiredState, ProvisionError> {
            Ok(self.state.clone())
        }
    }

    fn device_ssid() -> SsidSpec {
        SsidSpec {
            slug: "devices".into(),
            ssid: "Devices".into(),
            gated: false,
            reservations: vec![
                DhcpReservation {
                    mac: "AA:BB:CC:DD:EE:01".into(), // online (uppercase in spec)
                    ipaddr: "10.40.0.11".into(),
                    hostname: "vending-1".into(),
                },
                DhcpReservation {
                    mac: "aa:bb:cc:dd:ee:02".into(), // offline
                    ipaddr: "10.40.0.12".into(),
                    hostname: "camera-1".into(),
                },
            ],
            ..SsidSpec::default()
        }
    }

    /// Responder simulating a router with ONE of the two devices associated and
    /// nft counters for the online device's IP.
    fn router_responder() -> RecordingRunner {
        RecordingRunner::with_responder(|prog, args| {
            match (prog, args) {
                // slug -> VIF resolution.
                ("ubus", a) if a == ["call", "network.wireless", "status"] => Ok(r#"{
                    "radio0": { "up": true, "interfaces": [
                        { "section": "pc_devices_ap", "ifname": "wlan0" }
                    ] }
                }"#
                .as_bytes()
                .to_vec()),
                // assoclist: only device .01 is associated.
                ("ubus", a) if a.first() == Some(&"call") && a.get(1) == Some(&"iwinfo") => {
                    Ok(r#"{ "results": [
                        { "mac": "AA:BB:CC:DD:EE:01", "signal": -48, "connected_time": 1200 }
                    ] }"#
                    .as_bytes()
                    .to_vec())
                }
                // nft list counters: only .01's IP has traffic.
                ("nft", a) if a.contains(&"list") => Ok(r#"{ "nftables": [
                    { "counter": { "family":"inet","table":"wifihub","name":"pc_dev_ul_10_40_0_11","bytes":1500 } },
                    { "counter": { "family":"inet","table":"wifihub","name":"pc_dev_dl_10_40_0_11","bytes":9000 } }
                ] }"#
                .as_bytes()
                .to_vec()),
                // nft -j -f - (counter apply/prune): succeed silently.
                _ => Ok(Vec::new()),
            }
        })
    }

    #[tokio::test]
    async fn report_assembles_one_row_per_reservation_online_and_offline() {
        let prov = FakeProv {
            state: WirelessDesiredState {
                config_version: "cfg-1".into(),
                ssids: vec![device_ssid()],
                confirm_timeout_secs: 0,
                peer_allows: Vec::new(),
            },
        };
        let runner = router_responder();
        let (report, current_ips) = poll_once(&runner, &prov, &[]).await;

        // 2 reservations -> 2 rows.
        assert_eq!(report.devices.len(), 2);
        let online = report.devices.iter().find(|d| d.mac == "aa:bb:cc:dd:ee:01").unwrap();
        assert!(online.online, "device .01 is associated");
        assert_eq!(online.ipaddr, "10.40.0.11");
        assert_eq!(online.signal_dbm, -48);
        assert_eq!(online.uptime_secs, 1200);
        assert_eq!(online.rx_bytes, 1500, "upload from ip saddr counter");
        assert_eq!(online.tx_bytes, 9000, "download from ip daddr counter");
        assert_eq!(online.slug, "devices");

        let offline = report.devices.iter().find(|d| d.mac == "aa:bb:cc:dd:ee:02").unwrap();
        assert!(!offline.online, "device .02 is NOT associated");
        assert_eq!(offline.signal_dbm, 0, "offline -> unknown signal");
        assert_eq!(offline.uptime_secs, 0);
        assert_eq!(offline.rx_bytes, 0, "offline device has no counter yet");
        assert_eq!(offline.tx_bytes, 0);

        // Current IP set is returned (for next-tick pruning).
        assert_eq!(current_ips, vec!["10.40.0.11".to_string(), "10.40.0.12".to_string()]);

        // The poller reconciled the counters: an `nft -j -f -` apply was issued
        // carrying both device IPs' counter names.
        let flat = runner.flat();
        let applied = flat
            .iter()
            .find(|(p, a)| p == "nft" && a.starts_with("-j -f"))
            .expect("an nft apply was issued");
        // (the JSON payload goes on stdin, not argv, so assert the apply happened;
        // the doc contents are covered by device_meter's own unit tests.)
        let _ = applied;
    }

    #[tokio::test]
    async fn no_reservations_yields_empty_report() {
        // An owned SSID with NO reservations is not a device SSID -> no rows.
        let mut ssid = device_ssid();
        ssid.reservations.clear();
        let prov = FakeProv {
            state: WirelessDesiredState {
                config_version: "cfg-1".into(),
                ssids: vec![ssid],
                confirm_timeout_secs: 0,
                peer_allows: Vec::new(),
            },
        };
        let (report, ips) = poll_once(&RecordingRunner::new(), &prov, &[]).await;
        assert!(report.devices.is_empty());
        assert!(ips.is_empty());
    }

    #[tokio::test]
    async fn reconcile_apply_flushes_chain_and_is_stable_across_repeated_polls() {
        // Idempotency end-to-end: polling the SAME reservation set twice issues the
        // SAME reconcile apply payload each time — the chain-flush in the doc means
        // repeated polls do not accumulate rules (the leak the P3 author flagged).
        let prov = FakeProv {
            state: WirelessDesiredState {
                config_version: "cfg-1".into(),
                ssids: vec![device_ssid()],
                confirm_timeout_secs: 0,
                peer_allows: Vec::new(),
            },
        };

        // Capture the exact `nft -j -f -` stdin payloads across two polls.
        let payloads: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        struct CapturingRunner {
            payloads: Arc<std::sync::Mutex<Vec<String>>>,
        }
        #[async_trait::async_trait]
        impl CommandRunner for CapturingRunner {
            async fn run(&self, prog: &str, args: &[&str]) -> Result<Vec<u8>, ProvisionError> {
                // Reuse the router responder's canned outputs for reads.
                if prog == "nft" && args.contains(&"list") {
                    return Ok(r#"{ "nftables": [
                        { "counter": { "family":"inet","table":"wifihub","name":"pc_dev_ul_10_40_0_11","bytes":1500 } },
                        { "counter": { "family":"inet","table":"wifihub","name":"pc_dev_dl_10_40_0_11","bytes":9000 } }
                    ] }"#
                    .as_bytes()
                    .to_vec());
                }
                Ok(Vec::new())
            }
            async fn run_stdin(
                &self,
                _prog: &str,
                _args: &[&str],
                stdin: &[u8],
            ) -> Result<Vec<u8>, ProvisionError> {
                self.payloads.lock().unwrap().push(String::from_utf8_lossy(stdin).into_owned());
                Ok(Vec::new())
            }
        }
        let runner = CapturingRunner { payloads: payloads.clone() };

        // Two consecutive polls with the SAME current set (prev == current => no
        // prune apply), so each poll issues exactly ONE reconcile apply on stdin.
        let prev = vec!["10.40.0.11".to_string(), "10.40.0.12".to_string()];
        let (_r1, c1) = poll_once(&runner, &prov, &prev).await;
        let (_r2, c2) = poll_once(&runner, &prov, &c1).await;
        assert_eq!(c1, c2, "current IP set is stable across polls");

        let captured = payloads.lock().unwrap().clone();
        assert_eq!(captured.len(), 2, "one reconcile apply per poll, no prune (set unchanged)");
        // Every apply FLUSHES the device_meter chain before re-adding rules.
        for p in &captured {
            assert!(p.contains("\"flush\""), "reconcile apply must flush the chain: {p}");
            assert!(p.contains("device_meter"));
        }
        // Byte-identical payloads across polls ⇒ no rule growth, no accumulation.
        assert_eq!(captured[0], captured[1], "repeated polls emit the SAME reconcile doc");
    }

    #[tokio::test]
    async fn counter_totals_read_by_name_survive_reconcile() {
        // Totals live in named counter OBJECTS, which the chain flush does not
        // touch — so re-applying the reconcile doc (flush + re-add rules) does NOT
        // reset the bytes the poller reads by counter name. Simulated by returning
        // the SAME non-zero counter totals on every poll: they persist tick to tick.
        let prov = FakeProv {
            state: WirelessDesiredState {
                config_version: "cfg-1".into(),
                ssids: vec![device_ssid()],
                confirm_timeout_secs: 0,
                peer_allows: Vec::new(),
            },
        };
        let runner = router_responder();
        let prev = vec!["10.40.0.11".to_string(), "10.40.0.12".to_string()];
        let (r1, c1) = poll_once(&runner, &prov, &prev).await;
        let (r2, _c2) = poll_once(&runner, &prov, &c1).await;

        // Same device, read BY NAME (pc_dev_ul_/pc_dev_dl_10_40_0_11), same totals
        // after a reconcile — the flush did not zero the named counter objects.
        let d1 = r1.devices.iter().find(|d| d.ipaddr == "10.40.0.11").unwrap();
        let d2 = r2.devices.iter().find(|d| d.ipaddr == "10.40.0.11").unwrap();
        assert_eq!((d1.rx_bytes, d1.tx_bytes), (1500, 9000));
        assert_eq!(
            (d2.rx_bytes, d2.tx_bytes),
            (1500, 9000),
            "counter totals survive the reconcile (flush removes rules, not counter objects)"
        );
    }

    #[tokio::test]
    async fn prunes_counters_for_departed_reservation() {
        // Previous tick had .11 and .99; current state only has .11 + .12.
        // The .99 counter must be pruned (a delete-counter nft doc is applied).
        let prov = FakeProv {
            state: WirelessDesiredState {
                config_version: "cfg-1".into(),
                ssids: vec![device_ssid()],
                confirm_timeout_secs: 0,
                peer_allows: Vec::new(),
            },
        };
        // Count how many nft applies (`-j -f -`) happen: reconcile + prune = 2.
        let runner = router_responder();
        let prev = vec!["10.40.0.11".to_string(), "10.40.0.99".to_string()];
        let (_report, current) = poll_once(&runner, &prov, &prev).await;
        assert_eq!(current, vec!["10.40.0.11".to_string(), "10.40.0.12".to_string()]);
        let applies = runner
            .flat()
            .into_iter()
            .filter(|(p, a)| p == "nft" && a.starts_with("-j -f"))
            .count();
        assert_eq!(applies, 2, "one reconcile apply + one prune apply (.99 departed)");
    }
}
