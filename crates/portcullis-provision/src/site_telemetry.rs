//! Whole-site telemetry poller (Transport A — engine-native "Giám sát trực tiếp").
//!
//! The sibling of [`device_obs`](crate::device_obs) and [`liveness`](crate::liveness),
//! but SITE-wide: every tick it builds ONE [`SiteTelemetryReport`] covering
//!
//!   - **per SSID** (enumerated from the committed desired-state, keyed by the
//!     owned bridge): on-air, gated/gate-enforced, client count, channel, and
//!     cumulative FORWARD egress counters,
//!   - **per client** across every owned VIF (`iw … station dump`): signal, PHY
//!     rates, byte counters, association age, DHCP-leased IP (or none), and
//!   - **uplink** (mwan3 / default route / ping / gsm): active WAN vs SIM, Internet
//!     reachability + latency/loss, public IP, backup-SIM signal.
//!
//! Purely OBSERVATIONAL — it only reads (via the [`CommandRunner`] seam) and never
//! writes enforcement or config. Every shell-out is fail-soft: a missing tool or an
//! unparseable reply degrades that one field, never the whole report. The pure
//! parsers below are host-unit-tested; [`poll_once`] runs against the real tools
//! only on-device (exercised in tests through a [`RecordingRunner`] mock).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use portcullis_types::{
    ControlChannelHealth, SiteClient, SiteSsid, SiteTelemetryReport, SiteUplink, SiteUplinkSim,
};
use tokio::sync::mpsc;

use crate::runner::CommandRunner;

/// Default site-telemetry cadence (~60 s). A slow site gauge; the shell-outs are
/// cheap on the MIPS budget and a stale snapshot is worthless, so we do not go faster.
pub const DEFAULT_SITE_TELEMETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Bound on the outward mpsc. Tiny: a full channel drops (a stale snapshot is
/// worthless), never blocks the poll loop.
pub const SITE_TELEMETRY_BUFFER: usize = 2;

/// Ping target for the Internet-reachability probe (public resolver; ICMP only).
const PING_TARGET: &str = "8.8.8.8";

/// Run the site-telemetry poller until the outward channel closes (engine
/// shutdown) or the task is aborted. Ticks every `interval`, building one
/// [`SiteTelemetryReport`] and pushing it up `tx` (dropped if the consumer is behind).
pub async fn run_site_telemetry_poller<R: CommandRunner>(
    runner: Arc<R>,
    health: Arc<ControlChannelHealth>,
    tx: mpsc::Sender<SiteTelemetryReport>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let mut report = poll_once(runner.as_ref()).await;
        report.control = health.snapshot();
        match tx.try_send(report) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!("site-telemetry channel full; dropping snapshot (consumer behind)");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("site-telemetry channel closed; stopping poller");
                return;
            }
        }
    }
}

/// One site-telemetry sweep. Enumerates SSIDs from LIVE UCI (every wifi-iface
/// bound to a `br-ss*` bridge), probes each (on-air / clients / egress / gate),
/// and gathers uplink state. Never fails — an error anywhere yields a thinner
/// snapshot.
///
/// Enumeration is LIVE (not the engine's committed desired-state): after a
/// restart the committed state is rehydrated version-only with EMPTY ssids
/// (`handle.rs`) until the CP re-pushes, so `get_wireless()` would report 0 SSIDs
/// even while they are broadcasting. Reading live UCI mirrors `net-report.sh` and
/// reflects what is actually on-air.
pub async fn poll_once<R: CommandRunner>(runner: &R) -> SiteTelemetryReport {
    let ts_unix = unix_now();
    let router_uptime_secs = parse_uptime(&run_text(runner, "cat", &["/proc/uptime"]).await);

    // LIVE SSID set: wifi-iface sections whose network binds to a br-ss* bridge.
    let wireless = run_text(runner, "uci", &["-q", "show", "wireless"]).await;
    let network = run_text(runner, "uci", &["-q", "show", "network"]).await;
    let bridges = parse_wireless_bridges(&wireless, &network);

    // FORWARD counters + gated set (one `iptables -nvxL FORWARD`), DHCP leases, gate.
    let (fwd, gated_ifaces) =
        parse_forward_counters(&run_text(runner, "iptables", &["-nvxL", "FORWARD"]).await);
    let auth_present = runner.run("ipset", &["list", "wifihub_auth"]).await.is_ok();
    let leases = parse_leases(&run_text(runner, "cat", &["/tmp/dhcp.leases"]).await);

    let mut ssids: Vec<SiteSsid> = Vec::new();
    let mut clients: Vec<SiteClient> = Vec::new();

    for (ifname, name) in bridges {
        let vifs = list_bridge_vifs(runner, &ifname).await;

        // on_air = at least one VIF operationally up. channel from the first VIF.
        let mut on_air = false;
        let mut channel = 0u32;
        for (i, vif) in vifs.iter().enumerate() {
            let path = format!("/sys/class/net/{vif}/operstate");
            if run_text(runner, "cat", &[&path]).await.trim() == "up" {
                on_air = true;
            }
            if i == 0 {
                channel = parse_channel(&run_text(runner, "iw", &["dev", vif, "info"]).await);
            }
        }

        // Clients across the bridge's VIFs (iw station dump).
        let mut client_count = 0u32;
        for vif in &vifs {
            for st in parse_station_dump(&run_text(runner, "iw", &["dev", vif, "station", "dump"]).await) {
                client_count += 1;
                let (ip, hostname) = leases.get(&st.mac).cloned().unwrap_or_default();
                clients.push(SiteClient {
                    mac: st.mac,
                    ssid_ifname: ifname.clone(),
                    ip,
                    signal_dbm: st.signal_dbm,
                    tx_rate_mbps: st.tx_rate_mbps,
                    rx_rate_mbps: st.rx_rate_mbps,
                    rx_bytes: st.rx_bytes,
                    tx_bytes: st.tx_bytes,
                    connected_secs: st.connected_secs,
                    hostname,
                });
            }
        }

        let (fwd_pkts, fwd_bytes) = fwd.get(&ifname).copied().unwrap_or((0, 0));
        // Per-SSID directional bytes from the bridge's own counters (like net-report):
        // rx = client->internet (upload), tx = internet->client (download).
        let ul_bytes = read_u64(runner, &format!("/sys/class/net/{ifname}/statistics/rx_bytes")).await;
        let dl_bytes = read_u64(runner, &format!("/sys/class/net/{ifname}/statistics/tx_bytes")).await;
        let gated = gated_ifaces.contains(&ifname); // has a FORWARD -> wifihub_fwd jump
        ssids.push(SiteSsid {
            ifname,
            name,
            on_air,
            gated,
            gate_enforced: gated && auth_present,
            client_count,
            channel,
            fwd_pkts,
            fwd_bytes,
            ul_bytes,
            dl_bytes,
        });
    }

    let uplink = gather_uplink(runner).await;

    // control is filled by the poller from the shared ControlChannelHealth.
    SiteTelemetryReport { ts_unix, router_uptime_secs, ssids, clients, uplink, control: Default::default() }
}

/// List a bridge's wireless VIF members from `/sys/class/net/<bridge>/brif`.
async fn list_bridge_vifs<R: CommandRunner>(runner: &R, bridge: &str) -> Vec<String> {
    let path = format!("/sys/class/net/{bridge}/brif");
    run_text(runner, "ls", &["-1", &path])
        .await
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.starts_with("wlan"))
        .collect()
}

/// Gather site uplink state: active WAN vs SIM, Internet reachability (+latency/
/// loss), public IP, and backup-SIM signal. Fail-soft per field.
async fn gather_uplink<R: CommandRunner>(runner: &R) -> SiteUplink {
    let (wan_up, sim_up) = parse_mwan3(&run_text(runner, "mwan3", &["status"]).await);
    let dev = parse_default_dev(&run_text(runner, "ip", &["route", "show", "default"]).await);
    let active_wan = match dev.as_str() {
        "wan" => "wan".to_string(),
        d if d.starts_with("mob") || d.starts_with("wwan") || d.starts_with("qmimux") || d.starts_with("rmnet") => "sim".to_string(),
        "" => "unknown".to_string(),
        other => other.to_string(),
    };
    let (loss_pct, latency_ms) =
        parse_ping(&run_text(runner, "ping", &["-c", "3", "-W", "3", PING_TARGET]).await);
    let public_ip =
        run_text(runner, "curl", &["-s", "--max-time", "5", "https://api.ipify.org"]).await
            .trim()
            .to_string();
    let sim = parse_gsm(&run_text(runner, "ubus", &["call", "gsm.modem0", "info"]).await);
    SiteUplink {
        active_wan,
        wan_up,
        sim_up,
        internet_reachable: loss_pct < 100.0,
        latency_ms,
        loss_pct,
        public_ip,
        sim,
    }
}

async fn run_text<R: CommandRunner>(runner: &R, prog: &str, args: &[&str]) -> String {
    runner
        .run(prog, args)
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Pure parsers — fail-soft, host-unit-tested.
// ---------------------------------------------------------------------------

/// One parsed `iw … station dump` station.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct StationRow {
    pub mac: String,
    pub signal_dbm: i32,
    pub tx_rate_mbps: f64,
    pub rx_rate_mbps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub connected_secs: u32,
}

/// Parse `iw dev <vif> station dump` into per-station rows (lowercased MAC).
/// Fail-soft: unparseable lines are skipped.
pub fn parse_station_dump(text: &str) -> Vec<StationRow> {
    let mut out = Vec::new();
    let mut cur: Option<StationRow> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Station ") {
            if let Some(row) = cur.take() {
                out.push(row);
            }
            let mac = rest.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            cur = Some(StationRow { mac, ..StationRow::default() });
            continue;
        }
        let Some(row) = cur.as_mut() else { continue };
        let toks: Vec<&str> = t.split_whitespace().collect();
        if t.starts_with("signal:") {
            // "signal:  -52 [-55,-60] dBm" -> tokens[1] = -52
            row.signal_dbm = toks.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if t.starts_with("tx bitrate:") {
            row.tx_rate_mbps = toks.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        } else if t.starts_with("rx bitrate:") {
            row.rx_rate_mbps = toks.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        } else if t.starts_with("rx bytes:") {
            row.rx_bytes = toks.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if t.starts_with("tx bytes:") {
            row.tx_bytes = toks.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if t.starts_with("connected time:") {
            row.connected_secs = toks.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    if let Some(row) = cur.take() {
        out.push(row);
    }
    out
}

/// Parse `iptables -nvxL FORWARD` into (ifname -> (pkts, bytes)) accumulated per
/// in-interface starting `br-`, plus the set of bridges with a `wifihub_fwd` jump
/// (⇒ portcullis-gated). Columns: pkts bytes target prot opt in out src dst.
pub fn parse_forward_counters(text: &str) -> (BTreeMap<String, (u64, u64)>, BTreeSet<String>) {
    let mut fwd: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut gated: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 7 {
            continue;
        }
        let (Ok(pkts), Ok(bytes)) = (f[0].parse::<u64>(), f[1].parse::<u64>()) else {
            continue; // header / non-data line
        };
        let target = f[2];
        let inif = f[5];
        if !inif.starts_with("br-") {
            continue;
        }
        let e = fwd.entry(inif.to_string()).or_insert((0, 0));
        e.0 += pkts;
        e.1 += bytes;
        if target == "wifihub_fwd" {
            gated.insert(inif.to_string());
        }
    }
    (fwd, gated)
}

/// Parse `/tmp/dhcp.leases` (`<expiry> <mac> <ip> <name> <id>`) into
/// mac -> (ip, hostname). A `*`/absent name maps to "".
pub fn parse_leases(text: &str) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 {
            let host = f.get(3).copied().filter(|s| *s != "*").unwrap_or("").to_string();
            out.insert(f[1].to_ascii_lowercase(), (f[2].to_string(), host));
        }
    }
    out
}

/// Read a single u64 from a `/sys` file (e.g. bridge byte counter). 0 on any error.
async fn read_u64<R: CommandRunner>(runner: &R, path: &str) -> u64 {
    run_text(runner, "cat", &[path]).await.trim().parse().unwrap_or(0)
}

/// Parse `mwan3 status` -> (wan_up, sim_up). Lines: "interface <name> is <state>".
pub fn parse_mwan3(text: &str) -> (bool, bool) {
    let (mut wan_up, mut sim_up) = (false, false);
    for line in text.lines() {
        let t = line.trim();
        let f: Vec<&str> = t.split_whitespace().collect();
        // interface <name> is <state>
        if f.len() >= 4 && f[0] == "interface" && f[2] == "is" {
            let online = f[3] == "online";
            match f[1] {
                "wan" => wan_up |= online,
                n if n.starts_with("mob") || n.starts_with("wwan") => sim_up |= online,
                _ => {}
            }
        }
    }
    (wan_up, sim_up)
}

/// Parse `ping -c N` output -> (loss_pct, avg_ms). Loss defaults to 100 (no reply).
pub fn parse_ping(text: &str) -> (f64, f64) {
    let mut loss = 100.0;
    let mut avg = 0.0;
    for line in text.lines() {
        if let Some(i) = line.find("% packet loss") {
            // "... , X% packet loss" -> the number right before '%'
            let pre = &line[..i];
            if let Some(tok) = pre.split_whitespace().last() {
                if let Ok(v) = tok.parse::<f64>() {
                    loss = v;
                }
            }
        }
        // "round-trip min/avg/max = 12.0/14.3/20.1 ms"  (avg = 2nd field)
        if let Some(eq) = line.find('=') {
            if line.contains("min/avg/max") || line.contains("/avg/") || line.contains("rtt") {
                let stats = line[eq + 1..].trim();
                let nums = stats.split('/').collect::<Vec<_>>();
                if nums.len() >= 2 {
                    if let Ok(v) = nums[1].trim().split_whitespace().next().unwrap_or("").parse::<f64>() {
                        avg = v;
                    }
                }
            }
        }
    }
    (loss, avg)
}

/// Parse `ip route show default` -> the default egress netdev (`dev <x>`).
pub fn parse_default_dev(text: &str) -> String {
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = toks.iter().position(|&t| t == "dev") {
            if let Some(dev) = toks.get(i + 1) {
                return dev.to_string();
            }
        }
    }
    String::new()
}

/// Parse `iw dev <vif> info` -> primary channel (0 if absent).
pub fn parse_channel(text: &str) -> u32 {
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("channel ") {
            return rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    0
}

/// Parse `/proc/uptime` -> integer seconds.
pub fn parse_uptime(text: &str) -> u32 {
    text.split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as u32)
        .unwrap_or(0)
}

/// Parse `uci show wireless` + `uci show network` into (bridge, ssid) for every
/// wifi-iface bound to a `br-ss*` bridge, deduped by bridge (first ssid wins),
/// sorted by bridge. LIVE enumeration — mirrors net-report.sh; independent of the
/// engine's committed desired-state (empty after a restart).
pub fn parse_wireless_bridges(wireless: &str, network: &str) -> Vec<(String, String)> {
    // network.<net>.device='br-ssX'
    let mut dev_of: BTreeMap<String, String> = BTreeMap::new();
    for line in network.lines() {
        if let Some(rest) = line.strip_prefix("network.") {
            if let Some((sect, val)) = rest.split_once(".device=") {
                dev_of.insert(sect.to_string(), unquote(val));
            }
        }
    }
    // wifi-iface: ssid + network per section.
    let mut ssid_of: BTreeMap<String, String> = BTreeMap::new();
    let mut net_of: BTreeMap<String, String> = BTreeMap::new();
    for line in wireless.lines() {
        let Some(rest) = line.strip_prefix("wireless.") else { continue };
        if let Some((sect, val)) = rest.split_once(".ssid=") {
            ssid_of.insert(sect.to_string(), unquote(val));
        } else if let Some((sect, val)) = rest.split_once(".network=") {
            net_of.insert(sect.to_string(), unquote(val));
        }
    }
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (sect, ssid) in &ssid_of {
        let Some(net) = net_of.get(sect) else { continue };
        let Some(dev) = dev_of.get(net) else { continue };
        if dev.starts_with("br-ss") && seen.insert(dev.clone()) {
            out.push((dev.clone(), ssid.clone()));
        }
    }
    out.sort();
    out
}

/// Strip surrounding single/double quotes from a `uci show` value.
fn unquote(s: &str) -> String {
    s.trim().trim_matches('\'').trim_matches('"').to_string()
}

/// Parse `ubus call gsm.modem0 info` JSON -> SIM signal, or None (no modem / empty).
pub fn parse_gsm(json: &str) -> Option<SiteUplinkSim> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let operator = v.get("operator").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let rsrp = v.get("rsrp_value").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let sinr = v.get("sinr_value").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    if operator.is_empty() && rsrp == 0 && sinr == 0 {
        return None;
    }
    Some(SiteUplinkSim { operator, rsrp, sinr })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn station_dump_parses_all_fields_lowercased() {
        let text = "\
Station A4:83:E7:1C:22:9F (on wlan1-D-1)
\tsignal:  \t-52 [-55, -60] dBm
\ttx bitrate:\t866.7 MBit/s VHT-MCS 9
\trx bitrate:\t780.0 MBit/s
\trx bytes:\t5242880
\ttx bytes:\t1048576
\tconnected time:\t1440 seconds
Station dc:0b:34:77:1e:02 (on wlan1-D-1)
\tsignal:\t-61 [-64] dBm
\ttx bitrate:\t433.3 MBit/s
\trx bytes:\t880000
\ttx bytes:\t96000
\tconnected time:\t4320 seconds";
        let rows = parse_station_dump(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].mac, "a4:83:e7:1c:22:9f");
        assert_eq!(rows[0].signal_dbm, -52);
        assert_eq!(rows[0].tx_rate_mbps, 866.7);
        assert_eq!(rows[0].rx_rate_mbps, 780.0);
        assert_eq!(rows[0].rx_bytes, 5242880);
        assert_eq!(rows[0].tx_bytes, 1048576);
        assert_eq!(rows[0].connected_secs, 1440);
        assert_eq!(rows[1].mac, "dc:0b:34:77:1e:02");
        assert_eq!(rows[1].signal_dbm, -61);
    }

    #[test]
    fn station_dump_fail_soft() {
        assert!(parse_station_dump("").is_empty());
        assert!(parse_station_dump("garbage\nlines").is_empty());
    }

    #[test]
    fn forward_counters_accumulate_and_flag_gated() {
        let text = "\
Chain FORWARD (policy DROP 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination
    2544   477831 wifihub_fwd  all  --  br-ss1 *       0.0.0.0/0            0.0.0.0/0
     425   241270 zone_free_fwd  all  --  br-ss1 *     0.0.0.0/0            0.0.0.0/0
       0        0 zone_win_fwd   all  --  br-ss2 *     0.0.0.0/0            0.0.0.0/0
      10      600 ACCEPT         all  --  eth0   *     0.0.0.0/0            0.0.0.0/0";
        let (fwd, gated) = parse_forward_counters(text);
        // br-ss1 accumulates both its rules; br-ss2 present; eth0 excluded.
        assert_eq!(fwd.get("br-ss1"), Some(&(2969, 719101)));
        assert_eq!(fwd.get("br-ss2"), Some(&(0, 0)));
        assert!(fwd.get("eth0").is_none());
        // only br-ss1 has a wifihub_fwd jump -> gated.
        assert!(gated.contains("br-ss1"));
        assert!(!gated.contains("br-ss2"));
    }

    #[test]
    fn mwan3_and_ping_and_dev_parse() {
        let mw = "Interface status:\n interface wan is online 10h, uptime 10h\n interface mob1s1a1 is offline";
        assert_eq!(parse_mwan3(mw), (true, false));
        let ping = "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\nround-trip min/avg/max = 12.0/14.3/20.1 ms";
        let (loss, avg) = parse_ping(ping);
        assert_eq!(loss, 0.0);
        assert_eq!(avg, 14.3);
        let lost = "3 packets transmitted, 0 received, 100% packet loss";
        assert_eq!(parse_ping(lost).0, 100.0);
        assert_eq!(parse_default_dev("default via 10.0.0.1 dev wan proto static"), "wan");
    }

    #[test]
    fn gsm_none_when_empty() {
        assert!(parse_gsm("{}").is_none());
        assert!(parse_gsm("not json").is_none());
        let s = parse_gsm(r#"{"operator":"Viettel","rsrp_value":-71,"sinr_value":12}"#).unwrap();
        assert_eq!(s.operator, "Viettel");
        assert_eq!(s.rsrp, -71);
    }

    #[test]
    fn leases_and_uptime_and_channel() {
        let l = parse_leases("1786000000 A4:83:E7:1C:22:9F 10.20.0.34 iPhone *\nbad\n1786 dc:0b:34:77:1e:02 10.20.0.51 * *");
        assert_eq!(l.get("a4:83:e7:1c:22:9f"), Some(&("10.20.0.34".to_string(), "iPhone".to_string())));
        assert_eq!(l.get("dc:0b:34:77:1e:02"), Some(&("10.20.0.51".to_string(), String::new())));
        assert_eq!(l.len(), 2);
        assert_eq!(parse_uptime("42938.37 166407.14"), 42938);
        assert_eq!(parse_channel("\tssid Foo\n\tchannel 36 (5180 MHz)"), 36);
    }

    #[test]
    fn wireless_bridges_enumerates_br_ss_deduped_sorted() {
        let wireless = "\
wireless.default_radio0=wifi-iface
wireless.default_radio0.ssid='RUT_325A_2G'
wireless.default_radio0.network='lan'
wireless.pc_win_free_ap0=wifi-iface
wireless.pc_win_free_ap0.ssid='pilot-devWIN+FREE'
wireless.pc_win_free_ap0.network='pc_win_free_if'
wireless.pc_win_ap0=wifi-iface
wireless.pc_win_ap0.ssid='pilot-dev Thiet Bi'
wireless.pc_win_ap0.network='pc_win_if'
wireless.pc_win_ap1=wifi-iface
wireless.pc_win_ap1.ssid='pilot-dev Thiet Bi'
wireless.pc_win_ap1.network='pc_win_if'";
        let network = "\
network.lan=interface
network.lan.device='br-lan'
network.pc_win_free_if=interface
network.pc_win_free_if.device='br-ss1'
network.pc_win_if=interface
network.pc_win_if.device='br-ss2'";
        let b = parse_wireless_bridges(wireless, network);
        // br-lan excluded; br-ss2 deduped (dual-band ap0/ap1); sorted by bridge.
        assert_eq!(
            b,
            vec![
                ("br-ss1".to_string(), "pilot-devWIN+FREE".to_string()),
                ("br-ss2".to_string(), "pilot-dev Thiet Bi".to_string()),
            ]
        );
    }
}
