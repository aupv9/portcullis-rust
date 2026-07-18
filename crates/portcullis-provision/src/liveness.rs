//! On-air SSID liveness poller (P5).
//!
//! ## What this is
//! `WirelessStatus` (the rest of this crate) reports the *lifecycle* of a config
//! push — did it apply, commit, or roll back. Liveness reports the *observed
//! radio reality*: for each **gated** SSID the engine owns, is the SSID actually
//! beaconing right now, and how many stations are associated. It is purely
//! OBSERVATIONAL — it reads, never writes, and can NEVER affect enforcement or
//! wireless config. A poll failure just yields a thinner snapshot.
//!
//! ## How
//! A background task ([`run_liveness_poller`]) ticks on a timer (~30 s). Each
//! tick it asks the [`Provisioner`] for the last committed desired-state, keeps
//! only the `gated` SSIDs, resolves each one's on-air VIF, and shells out (via
//! the [`CommandRunner`] seam, explicit argv — never `sh -c`) to three on-device
//! tools:
//!
//!   - `ubus call network.wireless status`      → slug/section → VIF (ifname)
//!   - `ubus call hostapd.<vif> get_status`     → `state == "ENABLED"` ⇒ broadcasting
//!   - `ubus call iwinfo assoclist {"device":"<vif>"}` → station count + signal
//!   - `iwinfo <vif> info`                      → VIF/ESSID fallback + up check
//!
//! The snapshot is sent UP the provided mpsc; the composition root fans it into
//! an unsolicited `EngineFrame::WirelessLiveness`.
//!
//! ## Resilience (best-effort at every step)
//! Every parser is pure + fail-soft: a missing tool, a non-zero exit, or a
//! non-JSON / unexpectedly-shaped payload skips just that VIF (or that field) and
//! NEVER panics. A slug whose VIF cannot be resolved is simply omitted from the
//! snapshot rather than reported as down — the CP treats "absent" as "unknown",
//! not "off the air".
//!
//! ## DEVICE-ONLY — NOT runtime-tested here
//! The shell-outs (`ubus` / `iwinfo` / `hostapd`) exist only on the RUTM11 /
//! OpenWrt device; a dev Mac has none of them. The pure parsers below ARE
//! unit-tested (they run anywhere); the live [`poll_once`] shell path is only
//! exercised on-device. This whole module compiles on the host but its I/O is
//! validated on the router.

use std::sync::Arc;
use std::time::Duration;

use portcullis_types::{Provisioner, SsidLiveness, WirelessLiveness};
use tokio::sync::mpsc;

use crate::runner::CommandRunner;

const UBUS: &str = "ubus";
const IWINFO: &str = "iwinfo";

/// Default poll cadence. Kept coarse (~30 s) so the shell-outs are negligible on
/// the MIPS budget; liveness is a slow-changing gauge, not an event stream.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on the outward liveness mpsc. Tiny: a stale snapshot is worthless, so if
/// the channel task is behind we would rather drop than buffer. The sender uses
/// `try_send` and drops on a full/closed channel (never blocks the poll loop).
pub const LIVENESS_BUFFER: usize = 4;

/// Run the liveness poller until the outward channel closes (engine shutdown) or
/// the task is aborted. Ticks every `interval`, building a [`WirelessLiveness`]
/// from the current committed gated SSIDs and pushing it up `tx`.
///
/// Best-effort throughout: a tick that resolves nothing sends an empty snapshot
/// (which the CP reads as "engine alive, no gated SSID on the air"); a send onto
/// a full channel is dropped, not awaited.
pub async fn run_liveness_poller<R: CommandRunner>(
    runner: Arc<R>,
    provisioner: Arc<dyn Provisioner>,
    tx: mpsc::Sender<WirelessLiveness>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // If a tick is missed (slow shell-out), skip it rather than burst-catch-up.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let snapshot = poll_once(runner.as_ref(), provisioner.as_ref()).await;
        match tx.try_send(snapshot) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!("liveness channel full; dropping snapshot (consumer behind)");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("liveness channel closed; stopping poller");
                return;
            }
        }
    }
}

/// One liveness sweep: read committed gated SSIDs, resolve their VIFs, and probe
/// each. Never fails — an error anywhere yields a thinner (possibly empty)
/// snapshot. Public for on-device diagnostics + so the poll loop stays trivial.
pub async fn poll_once<R: CommandRunner>(runner: &R, provisioner: &dyn Provisioner) -> WirelessLiveness {
    let ts_unix = unix_now();

    // Committed desired-state (introspection). If unavailable, there is nothing
    // to poll — emit an empty snapshot (still a useful "engine is alive" beacon).
    let desired = match provisioner.get_wireless().await {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(error = %e, "liveness: no committed wireless state; empty snapshot");
            return WirelessLiveness { config_version: String::new(), per_ssid: Vec::new(), ts_unix };
        }
    };
    let config_version = desired.config_version.clone();

    // Only GATED SSIDs are captive-relevant; the CP visualises those. (Trusted
    // SSIDs are broadcast plainly and are not the engine's liveness concern.)
    let gated: Vec<&portcullis_types::SsidSpec> = desired.ssids.iter().filter(|s| s.gated).collect();
    if gated.is_empty() {
        return WirelessLiveness { config_version, per_ssid: Vec::new(), ts_unix };
    }

    // Resolve slug -> VIF once (single `ubus call network.wireless status`), then
    // probe each VIF. An unresolvable slug is omitted (unknown, not "down").
    let status_json = runner
        .run(UBUS, &["call", "network.wireless", "status"])
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let vif_of = slug_vifs(&status_json);

    let mut per_ssid = Vec::with_capacity(gated.len());
    for spec in gated {
        let Some(iface) = vif_of
            .iter()
            .find(|(slug, _)| slug == &spec.slug)
            .map(|(_, vif)| vif.clone())
        else {
            // No VIF for this slug in ubus output — skip (unknown state).
            continue;
        };
        per_ssid.push(probe_vif(runner, &spec.slug, &iface).await);
    }

    WirelessLiveness { config_version, per_ssid, ts_unix }
}

/// Probe one resolved VIF: broadcasting (hostapd) + stations/signal (assoclist),
/// with an `iwinfo info` fallback for the up/beacon signal. Always returns a
/// row (the VIF was resolved, so it is worth reporting even if the probes are
/// thin) — missing probes just leave fields at their zero/false default.
async fn probe_vif<R: CommandRunner>(runner: &R, slug: &str, iface: &str) -> SsidLiveness {
    // hostapd get_status: authoritative "is the beacon on the air".
    let hostapd_json = runner
        .run(UBUS, &["call", &format!("hostapd.{iface}"), "get_status"])
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let mut broadcasting = hostapd_enabled(&hostapd_json);

    // Fallback: if hostapd was silent (older schema / no object), treat an
    // `iwinfo <vif> info` that reports an ESSID as "broadcasting" (a VIF that is
    // administratively up and advertising a name).
    if !broadcasting && hostapd_json.is_empty() {
        let info = runner
            .run(IWINFO, &[iface, "info"])
            .await
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        broadcasting = iwinfo_has_essid(&info);
    }

    // assoclist: station count + strongest signal.
    let assoc_json = runner
        .run(UBUS, &["call", "iwinfo", "assoclist", &format!("{{\"device\":\"{iface}\"}}")])
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let (stations, signal_dbm) = assoclist_stats(&assoc_json);

    SsidLiveness { slug: slug.to_string(), iface: iface.to_string(), broadcasting, stations, signal_dbm }
}

// ---------------------------------------------------------------------------
// Pure parsers — fail-soft, unit-tested (these run on any host; the shell path
// above only on-device).
// ---------------------------------------------------------------------------

/// Parse `ubus call network.wireless status` into `(slug, vif)` pairs, extracting
/// the owner slug from the UCI section name (`pc_<slug>_ap` → `<slug>`). The
/// OpenWrt schema is `{ "<radioN>": { "up": bool, "interfaces": [ { "section":
/// "pc_free_ap", "ifname": "wlan0", "config": { "ifname": "wlan0" } } ] } }`.
/// Fail-soft: unparseable/unexpected payloads yield an empty list.
pub fn slug_vifs(status_json: &str) -> Vec<(String, String)> {
    let v: serde_json::Value = match serde_json::from_str(status_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(radios) = v.as_object() else { return Vec::new() };
    let mut out = Vec::new();
    for (_radio, dev) in radios {
        let Some(ifaces) = dev.get("interfaces").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for i in ifaces {
            // The section name carries the owner slug (pc_<slug>_ap).
            let Some(section) = i.get("section").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Some(slug) = slug_from_section(section) else { continue };
            // ifname may be top-level or under `config`; prefer top-level (the
            // netifd-assigned name), fall back to the configured one.
            let ifname = i
                .get("ifname")
                .and_then(serde_json::Value::as_str)
                .or_else(|| i.get("config").and_then(|c| c.get("ifname")).and_then(serde_json::Value::as_str));
            if let Some(ifname) = ifname {
                if !ifname.is_empty() {
                    out.push((slug.to_string(), ifname.to_string()));
                }
            }
        }
    }
    out
}

/// Extract `<slug>` from an owned section name `pc_<slug>_ap`. Returns `None` for
/// any section not matching the engine's ownership namespace (so a foreign VIF is
/// never attributed to a portcullis SSID).
fn slug_from_section(section: &str) -> Option<&str> {
    section.strip_prefix("pc_").and_then(|rest| rest.strip_suffix("_ap"))
}

/// `hostapd.<vif> get_status` → is the beacon on the air. OpenWrt's hostapd ubus
/// object reports `{ "status": "ENABLED", "state": "ENABLED", ... }`. We accept
/// either key being `ENABLED` (case-insensitive). Fail-soft: unparseable ⇒ false.
pub fn hostapd_enabled(status_json: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_str(status_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let is_enabled = |key: &str| {
        v.get(key)
            .and_then(serde_json::Value::as_str)
            .map(|s| s.eq_ignore_ascii_case("ENABLED"))
            .unwrap_or(false)
    };
    is_enabled("state") || is_enabled("status")
}

/// `iwinfo <vif> info` reports a line `ESSID: "..."` when the VIF is advertising.
/// Used only as a fallback beacon check when hostapd is silent. Fail-soft.
pub fn iwinfo_has_essid(info: &str) -> bool {
    info.lines().any(|l| {
        let t = l.trim();
        // `ESSID: "Free WiFi"` (present) vs `ESSID: unknown` / `ESSID: off`.
        t.starts_with("ESSID:") && t.contains('"')
    })
}

/// `ubus call iwinfo assoclist {"device":"<vif>"}` → `(station_count, best_signal_dbm)`.
/// Schema: `{ "results": [ { "mac": "..", "signal": -55, ... }, ... ] }`. The
/// signal reported is the STRONGEST (closest to 0) across stations, or 0 when
/// there are none / it is unparseable. Fail-soft: unparseable ⇒ `(0, 0)`.
pub fn assoclist_stats(assoc_json: &str) -> (u32, i32) {
    let v: serde_json::Value = match serde_json::from_str(assoc_json) {
        Ok(v) => v,
        Err(_) => return (0, 0),
    };
    let Some(results) = v.get("results").and_then(serde_json::Value::as_array) else {
        return (0, 0);
    };
    let stations = results.len() as u32;
    let best = results
        .iter()
        .filter_map(|r| r.get("signal").and_then(serde_json::Value::as_i64))
        .map(|s| s as i32)
        // strongest = max (dBm are negative; -40 is stronger than -80).
        .max()
        .unwrap_or(0);
    (stations, best)
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

    #[test]
    fn slug_from_section_matches_only_owned() {
        assert_eq!(slug_from_section("pc_free_ap"), Some("free"));
        assert_eq!(slug_from_section("pc_guest_wifi_ap"), Some("guest_wifi"));
        assert_eq!(slug_from_section("default_radio0"), None);
        assert_eq!(slug_from_section("pc_free"), None); // no _ap suffix
    }

    #[test]
    fn slug_vifs_extracts_pairs_from_wireless_status() {
        let json = r#"{
            "radio0": {
                "up": true,
                "interfaces": [
                    { "section": "pc_free_ap", "ifname": "wlan0", "config": { "ifname": "wlan0" } },
                    { "section": "default_radio0", "ifname": "wlan0-1" }
                ]
            },
            "radio1": {
                "up": true,
                "interfaces": [
                    { "section": "pc_staff_ap", "config": { "ifname": "wlan1" } }
                ]
            }
        }"#;
        let mut pairs = slug_vifs(json);
        pairs.sort();
        assert_eq!(
            pairs,
            vec![("free".to_string(), "wlan0".to_string()), ("staff".to_string(), "wlan1".to_string())]
        );
    }

    #[test]
    fn slug_vifs_fail_soft_on_garbage() {
        assert!(slug_vifs("not json").is_empty());
        assert!(slug_vifs("{}").is_empty());
        assert!(slug_vifs("[]").is_empty());
    }

    #[test]
    fn hostapd_enabled_reads_state_or_status() {
        assert!(hostapd_enabled(r#"{"state":"ENABLED"}"#));
        assert!(hostapd_enabled(r#"{"status":"enabled"}"#));
        assert!(!hostapd_enabled(r#"{"state":"DISABLED"}"#));
        assert!(!hostapd_enabled(r#"{"state":"COUNTRY_UPDATE"}"#));
        assert!(!hostapd_enabled("garbage"));
        assert!(!hostapd_enabled(""));
    }

    #[test]
    fn iwinfo_has_essid_detects_advertised_name() {
        assert!(iwinfo_has_essid("wlan0\n          ESSID: \"Free WiFi\"\n          Mode: Master"));
        assert!(!iwinfo_has_essid("wlan0\n          ESSID: unknown"));
        assert!(!iwinfo_has_essid(""));
    }

    #[test]
    fn assoclist_stats_counts_and_takes_strongest() {
        let json = r#"{ "results": [
            { "mac": "AA:BB:CC:DD:EE:01", "signal": -72 },
            { "mac": "AA:BB:CC:DD:EE:02", "signal": -45 },
            { "mac": "AA:BB:CC:DD:EE:03", "signal": -88 }
        ] }"#;
        assert_eq!(assoclist_stats(json), (3, -45));
    }

    #[test]
    fn assoclist_stats_empty_and_fail_soft() {
        assert_eq!(assoclist_stats(r#"{"results":[]}"#), (0, 0));
        assert_eq!(assoclist_stats("not json"), (0, 0));
        assert_eq!(assoclist_stats("{}"), (0, 0));
    }
}
