//! On-air SSID liveness poller (P5).
//!
//! ## What this is
//! `WirelessStatus` (the rest of this crate) reports the *lifecycle* of a config
//! push — did it apply, commit, or roll back. Liveness reports the *observed
//! reality* (CP-SOT: the engine is a reporter, the CP is the source of truth).
//! Two observations are merged per owned SSID:
//!
//!   - **observed config** — read from **LIVE UCI** (`uci show`), NOT the
//!     in-memory committed echo, so a reboot / out-of-band `uci` edit / dropped
//!     confirm is reflected truthfully;
//!   - **on-air reality** — is the SSID actually beaconing right now and how many
//!     stations are associated.
//!
//! It is purely OBSERVATIONAL — it reads, never writes, and can NEVER affect
//! enforcement or wireless config. A poll failure just yields a thinner snapshot.
//!
//! ## How
//! A background task ([`run_liveness_poller`]) ticks on a timer (default 5 min,
//! overridable via `PC_LIVENESS_POLL_SECS`). Each poll
//! reads the OBSERVED owned-`pc_*` config from LIVE UCI (via [`observed_ssids_from_uci`]
//! and [`observed_fingerprint`]), then for each observed SSID resolves its on-air VIF
//! and shells out (via the [`CommandRunner`] seam, explicit argv — never `sh -c`)
//! to three on-device tools:
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
//! NEVER panics. A slug whose VIF cannot be resolved is still reported with its
//! observed config (the CP learns the SSID exists + its posture) but with empty
//! on-air fields — "config present, radio not observed", not "off the air".
//!
//! ## DEVICE-ONLY — NOT runtime-tested here
//! The shell-outs (`ubus` / `iwinfo` / `hostapd`) exist only on the RUTM11 /
//! OpenWrt device; a dev Mac has none of them. The pure parsers below ARE
//! unit-tested (they run anywhere); the live [`poll_once`] shell path is only
//! exercised on-device. This whole module compiles on the host but its I/O is
//! validated on the router.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use portcullis_types::{Provisioner, RulesetWriter, SsidLiveness, WirelessLiveness};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::runner::CommandRunner;
use crate::uci::{is_owned_wireless_section, unquote, WIRELESS_SECTION_PREFIX};

const UBUS: &str = "ubus";
const IWINFO: &str = "iwinfo";
const UCI: &str = "uci";

/// Default poll cadence. Coarse on purpose (5 min): wireless config drift is rare
/// (an operator/manual edit), so a slow gauge keeps the shell-outs negligible on the
/// MIPS budget and the control channel quiet. The composition root can override this
/// via the `PC_LIVENESS_POLL_SECS` env var (see `compose.rs`) — a slower period only
/// delays drift detection and the post-apply "committed" re-confirm, never enforcement.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(300);

/// Floor for the env-overridden poll cadence: below this the shell-outs start to
/// matter on the MIPS budget and the value is almost certainly a misconfiguration.
pub const MIN_POLL_INTERVAL_SECS: u64 = 15;

/// Bound on the outward liveness mpsc. Tiny: a stale snapshot is worthless, so if
/// the channel task is behind we would rather drop than buffer. The sender uses
/// `try_send` and drops on a full/closed channel (never blocks the poll loop).
pub const LIVENESS_BUFFER: usize = 4;

/// Run the liveness poller until the outward channel closes (engine shutdown) or
/// the task is aborted. Ticks every `interval`, reads the OBSERVED owned config
/// from LIVE UCI, probes each observed SSID's on-air VIF, and pushes a
/// [`WirelessLiveness`] snapshot (config + on-air + `observed_fingerprint`) up `tx`.
///
/// Best-effort throughout: a poll that resolves nothing sends an empty snapshot
/// (which the CP reads as "engine alive, no owned SSID observed"); a send onto a
/// full channel is dropped, not awaited.
pub async fn run_liveness_poller<R: CommandRunner>(
    runner: Arc<R>,
    provisioner: Arc<dyn Provisioner>,
    writer: Arc<dyn RulesetWriter>,
    tx: mpsc::Sender<WirelessLiveness>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // If a tick is missed (slow shell-out), skip it rather than burst-catch-up.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // TODO(cp-sot): procd reload-trigger on wireless/network/firewall for
        // event-driven emit (follow-on) — an on-device SIGHUP → trigger channel
        // would make an out-of-band `uci` edit surface immediately instead of at
        // the next tick. Shipping PERIODIC-only for now (still catches drift
        // within one interval).
        tick.tick().await;
        let snapshot = poll_once(runner.as_ref(), provisioner.as_ref(), writer.as_ref()).await;
        if emit(&tx, snapshot).is_break() {
            return;
        }
    }
}

/// Send a snapshot up `tx` with the try-send drop-on-full/closed policy. Returns
/// `Break` when the channel is closed (poller should stop).
fn emit(tx: &mpsc::Sender<WirelessLiveness>, snapshot: WirelessLiveness) -> std::ops::ControlFlow<()> {
    match tx.try_send(snapshot) {
        Ok(()) => std::ops::ControlFlow::Continue(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::debug!("liveness channel full; dropping snapshot (consumer behind)");
            std::ops::ControlFlow::Continue(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("liveness channel closed; stopping poller");
            std::ops::ControlFlow::Break(())
        }
    }
}

/// One liveness sweep (CP-SOT): read the OBSERVED owned config from LIVE UCI
/// (`uci show wireless/network/firewall`), compute a stable `observed_fingerprint`,
/// then for each observed SSID resolve its on-air VIF + probe it. Never fails — an
/// error anywhere yields a thinner (possibly empty) snapshot. Public for on-device
/// diagnostics + so the poll loop stays trivial.
///
/// The `provisioner`'s committed `config_version` is still reported (best-effort;
/// it labels which CP push this reflects), but the per-SSID CONFIG comes from live
/// UCI, not the committed echo — so a reboot / out-of-band `uci` edit / dropped
/// confirm is surfaced truthfully rather than parroting stale desired-state.
pub async fn poll_once<R: CommandRunner>(
    runner: &R,
    provisioner: &dyn Provisioner,
    writer: &dyn RulesetWriter,
) -> WirelessLiveness {
    let ts_unix = unix_now();

    // Committed config version (best-effort label only). The per-SSID config is
    // read from LIVE UCI below, so a failure here just leaves the label empty.
    let config_version = provisioner
        .get_wireless()
        .await
        .map(|d| d.config_version)
        .unwrap_or_default();

    // OBSERVED owned config from LIVE UCI (the CP-SOT read). Fail-soft: a `uci`
    // error yields empty strings → no observed SSID → empty snapshot (still a
    // useful "engine alive" beacon). `observed_fingerprint` moves iff the owned
    // `pc_*` config actually changed on the device.
    let (wireless_show, network_show, firewall_show) = uci_show_owned(runner).await;
    let observed = observed_ssids_from_uci(&wireless_show, &network_show, &firewall_show);
    let observed_fingerprint = observed_fingerprint(&wireless_show, &network_show, &firewall_show);
    if observed.is_empty() {
        return WirelessLiveness { config_version, per_ssid: Vec::new(), ts_unix, observed_fingerprint };
    }

    // P2: the enforcement writer's CURRENT gated-iface scope (bridge names). Read
    // once per tick, fail-soft — an error yields an empty scope so gate_enforced
    // reports `false` (conservative: "not known to be gated"), never a panic or a
    // false "gated". This is the signal that surfaces the reboot fail-OPEN: an SSID
    // that is broadcasting but whose bridge is NOT in this scope is un-gated.
    let gated_scope = writer.gated_ifaces().await.unwrap_or_else(|e| {
        tracing::debug!(error = %e, "liveness: could not read gated-iface scope; gate_enforced=false");
        Vec::new()
    });

    // Resolve slug -> VIF once (single `ubus call network.wireless status`), then
    // probe each observed SSID's VIF. A slug with no VIF is still reported (config
    // present, on-air fields left at their zero/false default = "not observed").
    let status_json = runner
        .run(UBUS, &["call", "network.wireless", "status"])
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let vif_of = slug_vifs(&status_json);

    let mut per_ssid = Vec::with_capacity(observed.len());
    for obs in observed {
        let iface = vif_of
            .iter()
            .find(|(slug, _)| slug == &obs.slug)
            .map(|(_, vif)| vif.clone())
            .unwrap_or_default();
        // On-air probe (only meaningful with a resolved VIF; empty iface → thin row).
        let mut row = if iface.is_empty() {
            SsidLiveness::default()
        } else {
            probe_vif(runner, &iface).await
        };
        // Observed CONFIG from LIVE UCI (CP-SOT).
        row.slug = obs.slug.clone();
        row.ssid = obs.ssid;
        row.bridge = obs.bridge.clone();
        row.gated = obs.gated;
        row.encryption = obs.encryption;
        row.enabled = obs.enabled;
        // gate_enforced = the enforcement scope actually covers THIS SSID's bridge
        // (the gate is keyed on the bridge iface, e.g. `br-public`, not the VIF).
        row.gate_enforced = !obs.bridge.is_empty() && gated_scope.iter().any(|b| b == &obs.bridge);
        per_ssid.push(row);
    }

    WirelessLiveness { config_version, per_ssid, ts_unix, observed_fingerprint }
}

/// Probe one resolved VIF: broadcasting (hostapd) + stations/signal (assoclist),
/// with an `iwinfo info` fallback for the up/beacon signal. Sets only the on-air
/// fields (`iface`/`broadcasting`/`stations`/`signal_dbm`); the caller
/// ([`poll_once`]) overlays the observed-config fields + `gate_enforced`. Missing
/// probes just leave fields at their zero/false default.
async fn probe_vif<R: CommandRunner>(runner: &R, iface: &str) -> SsidLiveness {
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

    SsidLiveness {
        iface: iface.to_string(),
        broadcasting,
        stations,
        signal_dbm,
        ..SsidLiveness::default()
    }
}

// ---------------------------------------------------------------------------
// Observed config from LIVE UCI (CP-SOT). These read what the DEVICE actually has
// (`uci show`), not the in-memory committed echo — the whole point of P1.
// ---------------------------------------------------------------------------

/// One owned SSID's OBSERVED config, parsed from LIVE `uci show` output (NOT the
/// committed desired-state). Config-only — the on-air fields are added by probing.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ObservedSsid {
    /// Owner-namespace slug (`pc_<slug>_*`).
    pub slug: String,
    /// Advertised SSID name (`wireless.pc_<slug>_ap*.ssid`).
    pub ssid: String,
    /// Bridge iface (`network.pc_<slug>_dev.name`).
    pub bridge: String,
    /// Captive-gated: an owned `firewall.pc_<slug>_portal=rule` exists.
    pub gated: bool,
    /// Encryption (`wireless.pc_<slug>_ap*.encryption`); empty ⇒ render default `none`.
    pub encryption: String,
    /// Administratively enabled: the wifi-iface is NOT `disabled '1'`.
    pub enabled: bool,
}

/// Shell out to `uci show wireless/network/firewall` (mirrors `derive_gated_from_uci`
/// in [`crate::sm`]). Fail-soft: a `uci` error for a config yields an empty string
/// for it. Returns `(wireless_show, network_show, firewall_show)`.
async fn uci_show_owned<R: CommandRunner>(runner: &R) -> (String, String, String) {
    let show = |cfg: &'static str| async move {
        match runner.run(UCI, &["show", cfg]).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                tracing::debug!(config = cfg, error = %e, "liveness: `uci show` failed; treating as empty");
                String::new()
            }
        }
    };
    let wireless = show("wireless").await;
    let network = show("network").await;
    let firewall = show("firewall").await;
    (wireless, network, firewall)
}

/// Parse the OBSERVED owned SSIDs from LIVE `uci show` output. PURE + fail-soft.
///
/// For each owned (`is_owned_wireless_section`) wifi-iface section `pc_<slug>_ap*`:
///
///   - `.ssid`       → [`ObservedSsid::ssid`]
///   - `.encryption` → [`ObservedSsid::encryption`]
///   - `.disabled`   → [`ObservedSsid::enabled`] = `!(disabled == "1")`
///
/// then overlaid from the other configs by slug:
///
///   - `network.pc_<slug>_dev.name`     → [`ObservedSsid::bridge`]
///   - `firewall.pc_<slug>_portal=rule` present → [`ObservedSsid::gated`] = true
///
/// Deduped by slug (a multi-radio SSID has `pc_<slug>_ap0`, `_ap1`, … — first
/// wins for the scalar fields), returned in deterministic (sorted-by-slug) order.
/// Only `pc_`-namespaced sections are ever read, so `br-lan` / admin / a foreign
/// AP can never be attributed to a portcullis SSID.
pub fn observed_ssids_from_uci(
    wireless_show: &str,
    network_show: &str,
    firewall_show: &str,
) -> Vec<ObservedSsid> {
    // 1. wifi-iface scalars, keyed by slug (BTreeMap = deterministic order; first
    //    ap-section per slug wins for the scalar fields).
    let mut by_slug: BTreeMap<String, ObservedSsid> = BTreeMap::new();
    for (key, val) in uci_lines(wireless_show) {
        // Owned wireless option line: `wireless.pc_<slug>_ap<n>.<opt>=<val>`.
        if !is_owned_wireless_section(key) {
            continue;
        }
        let Some((_, rest)) = key.split_once('.') else { continue };
        // `pc_<slug>_ap<n>.<opt>` — the section is everything before the last `.`.
        let Some((section, opt)) = rest.split_once('.') else { continue };
        let Some(slug) = slug_from_ap_section(section) else { continue };
        let entry = by_slug.entry(slug.to_string()).or_insert_with(|| ObservedSsid {
            slug: slug.to_string(),
            // A wifi-iface exists → enabled unless a `disabled '1'` says otherwise.
            enabled: true,
            ..ObservedSsid::default()
        });
        match opt {
            "ssid" if entry.ssid.is_empty() => entry.ssid = unquote(val),
            "encryption" if entry.encryption.is_empty() => entry.encryption = unquote(val),
            "disabled" => entry.enabled = unquote(val) != "1",
            _ => {}
        }
    }

    // 2. Bridge per slug: `network.pc_<slug>_dev.name='br-…'`.
    for (key, val) in uci_lines(network_show) {
        if !is_owned_wireless_section(key) {
            continue;
        }
        let Some((_, rest)) = key.split_once('.') else { continue };
        let Some((section, opt)) = rest.split_once('.') else { continue };
        if opt != "name" {
            continue;
        }
        let Some(slug) = section
            .strip_prefix(WIRELESS_SECTION_PREFIX)
            .and_then(|s| s.strip_suffix("_dev"))
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        if let Some(entry) = by_slug.get_mut(slug) {
            entry.bridge = unquote(val);
        }
    }

    // 3. Gated per slug: an owned `firewall.pc_<slug>_portal=rule` section-decl.
    for (key, val) in uci_lines(firewall_show) {
        // Section-decl line only (`config.section=rule`, exactly one `.`), owned.
        if key.matches('.').count() != 1 || !is_owned_wireless_section(key) {
            continue;
        }
        if unquote(val) != "rule" {
            continue;
        }
        let Some((_, section)) = key.split_once('.') else { continue };
        let Some(slug) = section
            .strip_prefix(WIRELESS_SECTION_PREFIX)
            .and_then(|s| s.strip_suffix("_portal"))
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        if let Some(entry) = by_slug.get_mut(slug) {
            entry.gated = true;
        }
    }

    by_slug.into_values().collect()
}

/// Extract `<slug>` from an owned wifi-iface section `pc_<slug>_ap<n>` (the `<n>`
/// suffix, e.g. `_ap`, `_ap0`, `_ap1`, is one section per radio). Returns `None`
/// for any section not matching. The slug itself may contain `_`, so we match on
/// the `_ap` marker: split off the `pc_` prefix, then find `_ap` followed by only
/// digits (or nothing).
fn slug_from_ap_section(section: &str) -> Option<&str> {
    let rest = section.strip_prefix(WIRELESS_SECTION_PREFIX)?;
    // Find the LAST `_ap` occurrence whose tail is empty or all-digits.
    for (idx, _) in rest.rmatch_indices("_ap") {
        let tail = &rest[idx + "_ap".len()..];
        if tail.is_empty() || tail.bytes().all(|b| b.is_ascii_digit()) {
            let slug = &rest[..idx];
            if !slug.is_empty() {
                return Some(slug);
            }
        }
    }
    None
}

/// A stable hash over the canonicalized OBSERVED owned-`pc_*` config across the
/// three `uci show` outputs. PURE + deterministic: collect every owned line from
/// all three configs, sort them (order-independent), join, sha256, take the first
/// 16 hex chars. Moves iff the device's owned config actually changed — the CP
/// uses it to detect drift cheaply. Non-owned lines never enter, so an unrelated
/// `uci` change (a foreign section) does not move the fingerprint.
pub fn observed_fingerprint(wireless_show: &str, network_show: &str, firewall_show: &str) -> String {
    let mut owned: Vec<String> = Vec::new();
    for show in [wireless_show, network_show, firewall_show] {
        for (key, val) in uci_lines(show) {
            if is_owned_wireless_section(key) {
                owned.push(format!("{key}={val}"));
            }
        }
    }
    owned.sort();
    owned.dedup();
    let mut hasher = Sha256::new();
    hasher.update(owned.join("\n").as_bytes());
    let digest = hasher.finalize();
    // 16 hex chars (8 bytes) — ample to detect drift without a fat wire field.
    let mut hex = String::with_capacity(16);
    for b in digest.iter().take(8) {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Iterate `uci show` output as `(key, raw_value)` pairs, one per non-empty line.
/// `key` is the `config.section[.option]` left of the first `=`; `raw_value` is
/// the (still-quoted) right side. Lines without an `=` (section headers already
/// carry `=rule`/`=device`) are skipped.
fn uci_lines(show: &str) -> impl Iterator<Item = (&str, &str)> {
    show.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        line.split_once('=')
    })
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

    // --- gate_enforced (P2) --------------------------------------------------

    use async_trait::async_trait;
    use portcullis_types::{ProvisionError, Result, SsidSpec, WirelessDesiredState};

    use crate::runner::RecordingRunner;

    /// A `Provisioner` that returns a fixed committed desired-state.
    struct FixedProvisioner(WirelessDesiredState);
    #[async_trait]
    impl Provisioner for FixedProvisioner {
        async fn set_wireless(&self, _s: WirelessDesiredState) -> std::result::Result<(), ProvisionError> {
            Ok(())
        }
        async fn confirm_wireless(&self, _v: &str) -> std::result::Result<(), ProvisionError> {
            Ok(())
        }
        async fn get_wireless(&self) -> std::result::Result<WirelessDesiredState, ProvisionError> {
            Ok(self.0.clone())
        }
    }

    /// A `RulesetWriter` test double that reports a fixed gated-iface scope (and
    /// only implements the reader; every mutation uses the trait default no-op).
    struct FixedScopeWriter(Vec<String>);
    #[async_trait]
    impl RulesetWriter for FixedScopeWriter {
        async fn ensure_base(&self) -> Result<()> {
            Ok(())
        }
        async fn add_auth(&self, _mac: portcullis_types::MacAddr, _ttl: Duration) -> Result<()> {
            Ok(())
        }
        async fn del_auth(&self, _mac: portcullis_types::MacAddr) -> Result<()> {
            Ok(())
        }
        async fn list_auth(&self) -> Result<Vec<portcullis_types::AuthElement>> {
            Ok(Vec::new())
        }
        async fn gated_ifaces(&self) -> Result<Vec<String>> {
            Ok(self.0.clone())
        }
    }

    fn gated_spec(slug: &str, bridge: &str) -> SsidSpec {
        SsidSpec {
            slug: slug.into(),
            ssid: format!("Wifi {slug}"),
            radios: vec!["radio0".into()],
            encryption: "none".into(),
            key: String::new(),
            hidden: false,
            isolate: true,
            gated: true,
            bridge_name: bridge.into(),
            ipaddr: "10.0.0.1".into(),
            netmask: "255.255.255.0".into(),
            dhcp_start: "10".into(),
            dhcp_limit: "200".into(),
            dhcp_leasetime: "2h".into(),
            dhcp_disabled: false,
            egress_zone: String::new(),
            ..SsidSpec::default()
        }
    }

    /// A runner that serves both the OBSERVED-config reads (`uci show
    /// wireless/network/firewall` for two owned gated SSIDs `public`+`guest`) and
    /// the `ubus network.wireless status` VIF map; every other command
    /// (hostapd/iwinfo/assoclist) returns empty (best-effort thin probe).
    fn wireless_status_runner() -> RecordingRunner {
        RecordingRunner::with_responder(|prog, args| {
            if prog == UBUS && args == ["call", "network.wireless", "status"] {
                let json = r#"{
                    "radio0": { "interfaces": [
                        { "section": "pc_public_ap", "ifname": "wlan0" },
                        { "section": "pc_guest_ap",  "ifname": "wlan1" }
                    ] }
                }"#;
                return Ok(json.as_bytes().to_vec());
            }
            if prog == UCI && args == ["show", "wireless"] {
                return Ok(b"wireless.pc_public_ap=wifi-iface\nwireless.pc_public_ap.ssid='Public WiFi'\nwireless.pc_public_ap.encryption='none'\nwireless.pc_guest_ap=wifi-iface\nwireless.pc_guest_ap.ssid='Guest WiFi'\nwireless.pc_guest_ap.encryption='none'\n".to_vec());
            }
            if prog == UCI && args == ["show", "network"] {
                return Ok(b"network.pc_public_dev=device\nnetwork.pc_public_dev.name='br-public'\nnetwork.pc_guest_dev=device\nnetwork.pc_guest_dev.name='br-guest'\n".to_vec());
            }
            if prog == UCI && args == ["show", "firewall"] {
                return Ok(b"firewall.pc_public_portal=rule\nfirewall.pc_guest_portal=rule\n".to_vec());
            }
            Ok(Vec::new())
        })
    }

    #[tokio::test]
    async fn poll_once_sets_gate_enforced_from_writer_scope() {
        // Two gated SSIDs (read from LIVE UCI); only `br-public` is in the
        // enforcement scope → `public` reports gate_enforced=true, `guest`
        // (observed gated but bridge out of scope — the reboot fail-OPEN) → false.
        let desired = WirelessDesiredState {
            config_version: "cfg-1".into(),
            ssids: vec![gated_spec("public", "br-public"), gated_spec("guest", "br-guest")],
            confirm_timeout_secs: 0,
            peer_allows: Vec::new(),
        };
        let prov = FixedProvisioner(desired);
        let writer = FixedScopeWriter(vec!["br-public".to_string()]);
        let runner = wireless_status_runner();

        let snap = poll_once(&runner, &prov, &writer).await;
        assert_eq!(snap.config_version, "cfg-1", "committed version labels the snapshot");
        assert!(!snap.observed_fingerprint.is_empty(), "fingerprint computed over observed config");
        assert_eq!(snap.per_ssid.len(), 2);
        let public = snap.per_ssid.iter().find(|s| s.slug == "public").unwrap();
        let guest = snap.per_ssid.iter().find(|s| s.slug == "guest").unwrap();
        // Observed CONFIG fields come from LIVE UCI, not the committed echo.
        assert_eq!(public.ssid, "Public WiFi");
        assert_eq!(public.bridge, "br-public");
        assert!(public.gated && public.enabled);
        assert!(public.gate_enforced, "public's bridge is in scope → gated");
        assert!(!guest.gate_enforced, "guest observed-gated but bridge NOT in scope → fail-OPEN");
    }

    #[tokio::test]
    async fn poll_once_gate_enforced_false_when_scope_read_fails() {
        // A writer whose scope read errors → gate_enforced=false (conservative),
        // never a panic (fail-soft).
        struct FailingWriter;
        #[async_trait]
        impl RulesetWriter for FailingWriter {
            async fn ensure_base(&self) -> Result<()> {
                Ok(())
            }
            async fn add_auth(&self, _m: portcullis_types::MacAddr, _t: Duration) -> Result<()> {
                Ok(())
            }
            async fn del_auth(&self, _m: portcullis_types::MacAddr) -> Result<()> {
                Ok(())
            }
            async fn list_auth(&self) -> Result<Vec<portcullis_types::AuthElement>> {
                Ok(Vec::new())
            }
            async fn gated_ifaces(&self) -> Result<Vec<String>> {
                Err(portcullis_types::Error::NftTransaction("boom".into()))
            }
        }
        let desired = WirelessDesiredState {
            config_version: "cfg-1".into(),
            ssids: vec![gated_spec("public", "br-public")],
            confirm_timeout_secs: 0,
            peer_allows: Vec::new(),
        };
        // Observed config comes from LIVE UCI (both public+guest), independent of
        // the committed desired-state; a failed scope read forces gate_enforced=false.
        let snap = poll_once(&wireless_status_runner(), &FixedProvisioner(desired), &FailingWriter).await;
        assert_eq!(snap.per_ssid.len(), 2);
        assert!(snap.per_ssid.iter().all(|s| !s.gate_enforced));
    }

    #[tokio::test]
    async fn poll_once_empty_when_uci_reports_no_owned_ssid() {
        // No owned `pc_*` config on the device → empty per-SSID snapshot, but still
        // a live beacon (config_version labelled, fingerprint over the empty set).
        let runner = RecordingRunner::with_responder(|_prog, _args| Ok(Vec::new()));
        let desired = WirelessDesiredState { config_version: "cfg-9".into(), ..Default::default() };
        let snap = poll_once(&runner, &FixedProvisioner(desired), &FixedScopeWriter(Vec::new())).await;
        assert!(snap.per_ssid.is_empty());
        assert_eq!(snap.config_version, "cfg-9");
    }

    // --- observed_ssids_from_uci / observed_fingerprint (P1 CP-SOT) ----------

    const WIRELESS_SHOW: &str = "\
wireless.pc_free_ap=wifi-iface
wireless.pc_free_ap.device='radio0'
wireless.pc_free_ap.ssid='Free WiFi'
wireless.pc_free_ap.encryption='none'
wireless.pc_staff_ap=wifi-iface
wireless.pc_staff_ap.ssid='Staff'
wireless.pc_staff_ap.encryption='psk2'
wireless.pc_staff_ap.disabled='1'
wireless.default_radio0=wifi-iface
wireless.default_radio0.ssid='RUT-Admin'
";
    const NETWORK_SHOW: &str = "\
network.pc_free_dev=device
network.pc_free_dev.name='br-free'
network.pc_staff_dev=device
network.pc_staff_dev.name='br-staff'
network.lan=interface
network.lan.device='br-lan'
";
    const FIREWALL_SHOW: &str = "\
firewall.pc_free_portal=rule
firewall.pc_free_portal.target='ACCEPT'
firewall.wan=zone
";

    #[test]
    fn observed_ssids_from_uci_parses_owned_and_excludes_others() {
        let obs = observed_ssids_from_uci(WIRELESS_SHOW, NETWORK_SHOW, FIREWALL_SHOW);
        // Deterministic (sorted-by-slug) order: free, staff. `default_radio0` and
        // `network.lan` (non-owned) are excluded.
        assert_eq!(obs.len(), 2);

        let free = &obs[0];
        assert_eq!(free.slug, "free");
        assert_eq!(free.ssid, "Free WiFi");
        assert_eq!(free.bridge, "br-free");
        assert_eq!(free.encryption, "none");
        assert!(free.enabled, "no disabled option → enabled");
        assert!(free.gated, "owned portal rule present → gated");

        let staff = &obs[1];
        assert_eq!(staff.slug, "staff");
        assert_eq!(staff.ssid, "Staff");
        assert_eq!(staff.bridge, "br-staff");
        assert_eq!(staff.encryption, "psk2");
        assert!(!staff.enabled, "disabled '1' → not enabled");
        assert!(!staff.gated, "no portal rule → un-gated (trusted)");
    }

    #[test]
    fn observed_ssids_from_uci_fail_soft_on_empty() {
        assert!(observed_ssids_from_uci("", "", "").is_empty());
        assert!(observed_ssids_from_uci("garbage no equals", "x", "y").is_empty());
    }

    #[test]
    fn observed_ssids_from_uci_multi_radio_dedups_by_slug() {
        // A two-radio SSID renders `pc_free_ap0` + `pc_free_ap1` — one row, first wins.
        let wireless = "\
wireless.pc_free_ap0=wifi-iface
wireless.pc_free_ap0.ssid='Free'
wireless.pc_free_ap1=wifi-iface
wireless.pc_free_ap1.ssid='Free'
";
        let obs = observed_ssids_from_uci(wireless, "", "");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].slug, "free");
        assert_eq!(obs[0].ssid, "Free");
    }

    #[test]
    fn slug_from_ap_section_handles_underscore_slugs_and_radio_index() {
        assert_eq!(slug_from_ap_section("pc_free_ap"), Some("free"));
        assert_eq!(slug_from_ap_section("pc_free_ap0"), Some("free"));
        assert_eq!(slug_from_ap_section("pc_guest_wifi_ap1"), Some("guest_wifi"));
        assert_eq!(slug_from_ap_section("pc_free_dev"), None);
        assert_eq!(slug_from_ap_section("default_radio0"), None);
        assert_eq!(slug_from_ap_section("pc__ap"), None); // empty slug
    }

    #[test]
    fn observed_fingerprint_stable_then_moves() {
        let a = observed_fingerprint(WIRELESS_SHOW, NETWORK_SHOW, FIREWALL_SHOW);
        // Deterministic: same input → same hash, 16 hex chars.
        assert_eq!(a, observed_fingerprint(WIRELESS_SHOW, NETWORK_SHOW, FIREWALL_SHOW));
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));

        // Line ORDER within a config must not change the fingerprint (canonicalized).
        let reordered = "\
wireless.pc_staff_ap=wifi-iface
wireless.pc_staff_ap.ssid='Staff'
wireless.pc_staff_ap.encryption='psk2'
wireless.pc_staff_ap.disabled='1'
wireless.pc_free_ap=wifi-iface
wireless.pc_free_ap.device='radio0'
wireless.pc_free_ap.ssid='Free WiFi'
wireless.pc_free_ap.encryption='none'
wireless.default_radio0=wifi-iface
wireless.default_radio0.ssid='RUT-Admin'
";
        assert_eq!(a, observed_fingerprint(reordered, NETWORK_SHOW, FIREWALL_SHOW));

        // A change to an OWNED line moves the fingerprint.
        let changed = WIRELESS_SHOW.replace("Free WiFi", "Free WiFi 2");
        assert_ne!(a, observed_fingerprint(&changed, NETWORK_SHOW, FIREWALL_SHOW));
    }

    #[test]
    fn observed_fingerprint_ignores_non_owned_changes() {
        let a = observed_fingerprint(WIRELESS_SHOW, NETWORK_SHOW, FIREWALL_SHOW);
        // Change a NON-owned line (the admin SSID / lan iface) → fingerprint unchanged.
        let changed_wireless = WIRELESS_SHOW.replace("RUT-Admin", "RUT-Admin-New");
        let changed_network = NETWORK_SHOW.replace("br-lan", "br-lan0");
        assert_eq!(a, observed_fingerprint(&changed_wireless, &changed_network, FIREWALL_SHOW));
    }
}
