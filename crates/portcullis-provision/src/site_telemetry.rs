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
    ControlChannelHealth, SiteClient, SiteHealth, SiteSsid, SiteTelemetryReport, SiteUplink,
    SiteUplinkSim,
};
use tokio::sync::mpsc;

use crate::runner::CommandRunner;

/// Default LIGHT site-telemetry cadence (~20 s) — SSID/clients/bytes/airtime/health,
/// all cheap reads. The expensive uplink probe (ping + curl) runs only every
/// [`UPLINK_REFRESH_EVERY`] ticks (~60 s) and is cached in between, so the dashboard
/// feels live without paying ping/curl every tick.
pub const DEFAULT_SITE_TELEMETRY_INTERVAL: Duration = Duration::from_secs(20);

/// Refresh the uplink probe (ping/curl/gsm) every Nth light tick (~60 s at 20 s).
pub const UPLINK_REFRESH_EVERY: u32 = 3;

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
    // Byte accounting + airtime% are cumulative across ticks (conntrack is per-live-
    // flow; survey times are since-boot), so their state lives with the poller.
    let mut acc = FlowByteAccumulator::new();
    let mut survey = SurveyState::default();
    // Cached uplink refreshed every UPLINK_REFRESH_EVERY ticks (ping/curl are slow).
    let mut uplink = gather_uplink(runner.as_ref()).await;
    let mut tick_n: u32 = 0;
    loop {
        tick.tick().await;
        if tick_n != 0 && tick_n.is_multiple_of(UPLINK_REFRESH_EVERY) {
            uplink = gather_uplink(runner.as_ref()).await;
        }
        tick_n = tick_n.wrapping_add(1);
        let mut report = poll_once(runner.as_ref(), &mut acc, &mut survey, &uplink).await;
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
pub async fn poll_once<R: CommandRunner>(
    runner: &R,
    acc: &mut FlowByteAccumulator,
    survey: &mut SurveyState,
    uplink: &SiteUplink,
) -> SiteTelemetryReport {
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
    // ARP/neighbour table — resolves the IP of clients with a STATIC IP (no DHCP
    // lease), e.g. IoT devices. Without this they falsely show "no IP" on the tab.
    let neigh = parse_neigh(&run_text(runner, "ip", &["neigh"]).await);

    // Byte accounting from conntrack. The bridge `/sys` and `iw station dump` byte
    // counters MISS hardware-offloaded traffic on MT7621 (flow_offloading_hw) — the
    // offloaded bulk (mostly download) is switched in the PPE and never touches those
    // netdev/xtables counters, so they read backwards (upload > download). conntrack
    // reflects offloaded bytes; `acc` folds each flow's increment into a monotonic
    // per-client-IP cumulative, and `subnets` attributes IPs to their SSID bridge.
    acc.ingest(&parse_conntrack(&run_text(runner, "cat", &["/proc/net/nf_conntrack"]).await));
    let subnets = parse_bridge_subnets(&network);
    // DHCP pool size per bridge (uci dhcp .limit) + lease counts per subnet.
    let dhcp = run_text(runner, "uci", &["-q", "show", "dhcp"]).await;
    let dhcp_pools = parse_dhcp_pools(&dhcp, &network);
    let leased_by_prefix = count_leases_by_prefix(&leases);

    let health = gather_health(runner).await;

    let mut ssids: Vec<SiteSsid> = Vec::new();
    let mut clients: Vec<SiteClient> = Vec::new();

    for (ifname, name) in bridges {
        let vifs = list_bridge_vifs(runner, &ifname).await;
        let first_vif = vifs.first().cloned();

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
                let (mut ip, hostname) = leases.get(&st.mac).cloned().unwrap_or_default();
                // No DHCP lease? Fall back to the ARP table (static-IP devices have a
                // neighbour entry but no lease) so they aren't flagged "chưa có IP".
                if ip.is_empty() {
                    if let Some(nip) = neigh.get(&st.mac) {
                        ip = nip.clone();
                    }
                }
                // Bytes from conntrack (offload-aware), keyed by the leased IP —
                // station-dump byte counters miss HW-offloaded traffic. Preserve the
                // field meaning: rx_bytes = upload (client→net), tx_bytes = download.
                let (upload, download) = acc.client(&ip);
                clients.push(SiteClient {
                    mac: st.mac,
                    ssid_ifname: ifname.clone(),
                    ip,
                    signal_dbm: st.signal_dbm,
                    tx_rate_mbps: st.tx_rate_mbps,
                    rx_rate_mbps: st.rx_rate_mbps,
                    rx_bytes: upload,
                    tx_bytes: download,
                    connected_secs: st.connected_secs,
                    hostname,
                    tx_retries: st.tx_retries,
                    tx_failed: st.tx_failed,
                });
            }
        }

        let (fwd_pkts, fwd_bytes) = fwd.get(&ifname).copied().unwrap_or((0, 0));
        // Per-SSID directional bytes = conntrack cumulative summed over this bridge's
        // /24 (offload-aware). ul = client→internet (upload), dl = internet→client.
        let (ul_bytes, dl_bytes) = match subnets.get(&ifname) {
            Some(prefix) => acc.subnet_bytes(prefix),
            None => (0, 0),
        };
        // Bridge reliability counters (netdev /sys) — router-side drop evidence.
        let stat = |c: &str| format!("/sys/class/net/{ifname}/statistics/{c}");
        let rx_errors = read_sys_u64(runner, &stat("rx_errors")).await;
        let rx_dropped = read_sys_u64(runner, &stat("rx_dropped")).await;
        let tx_errors = read_sys_u64(runner, &stat("tx_errors")).await;
        let tx_dropped = read_sys_u64(runner, &stat("tx_dropped")).await;
        let gated = gated_ifaces.contains(&ifname); // has a FORWARD -> wifihub_fwd jump

        // Radio airtime busy% (delta since last poll) + noise, from the first VIF's
        // survey; explains high client retries (congestion vs. router fault).
        let (mut airtime_busy_pct, mut noise_dbm) = (0u32, 0i32);
        if let Some(vif) = &first_vif {
            let (active, busy, noise) =
                parse_survey(&run_text(runner, "iw", &["dev", vif, "survey", "dump"]).await);
            airtime_busy_pct = survey.delta_busy_pct(vif, active, busy);
            noise_dbm = noise;
        }
        // DHCP pool fill for this SSID's subnet.
        let dhcp_capacity = dhcp_pools.get(&ifname).copied().unwrap_or(0);
        let dhcp_leased = subnets
            .get(&ifname)
            .and_then(|p| leased_by_prefix.get(p))
            .copied()
            .unwrap_or(0);

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
            rx_errors,
            rx_dropped,
            tx_errors,
            tx_dropped,
            airtime_busy_pct,
            noise_dbm,
            dhcp_leased,
            dhcp_capacity,
        });
    }

    // control is filled by the poller from the shared ControlChannelHealth; uplink is
    // the poller's cached probe (refreshed on a slower cadence).
    SiteTelemetryReport {
        ts_unix,
        router_uptime_secs,
        ssids,
        clients,
        uplink: uplink.clone(),
        control: Default::default(),
        health,
    }
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

/// Router system health via local sources (SNMP-equivalent, no snmpd): ubus for
/// load+memory, df for persistent flash (/overlay), gsmctl for modem temp. Fail-soft.
/// MT7621 exposes no CPU/board thermal sensor, so only the modem temp is available.
async fn gather_health<R: CommandRunner>(runner: &R) -> SiteHealth {
    let (cpu_load1, cpu_load5, cpu_load15, mem_total, mem_available) =
        parse_system_info(&run_text(runner, "ubus", &["call", "system", "info"]).await);
    let (flash_total, flash_free) = parse_df_overlay(&run_text(runner, "df", &["-k"]).await);
    let modem_temp_dc = run_text(runner, "gsmctl", &["-c"]).await.trim().parse().unwrap_or(0);
    SiteHealth {
        cpu_load1,
        cpu_load5,
        cpu_load15,
        mem_total,
        mem_available,
        flash_total,
        flash_free,
        modem_temp_dc,
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

/// Read a single u64 from a `/sys` counter file. 0 on any error (fail-soft).
async fn read_sys_u64<R: CommandRunner>(runner: &R, path: &str) -> u64 {
    run_text(runner, "cat", &[path]).await.trim().parse().unwrap_or(0)
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
    pub tx_retries: u64,
    pub tx_failed: u64,
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
        } else if t.starts_with("tx retries:") {
            row.tx_retries = toks.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if t.starts_with("tx failed:") {
            row.tx_failed = toks.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
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

/// Parse `ip neigh` into mac -> IPv4, for clients that have an IP but no DHCP lease
/// (static-IP devices). Line: `<ip> dev <if> lladdr <mac> <STATE>`. Only IPv4 entries
/// in a usable state (REACHABLE/STALE/DELAY/PROBE/PERMANENT) with an lladdr; REACHABLE
/// wins over a staler duplicate. Skips FAILED/INCOMPLETE/NOARP (no valid binding).
pub fn parse_neigh(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let ip = f[0];
        if !ip.contains('.') || ip.contains(':') {
            continue; // IPv4 only
        }
        let Some(li) = f.iter().position(|&t| t == "lladdr") else { continue };
        let Some(mac) = f.get(li + 1).map(|m| m.to_ascii_lowercase()) else { continue };
        let state = f.last().copied().unwrap_or("");
        if !matches!(state, "REACHABLE" | "STALE" | "DELAY" | "PROBE" | "PERMANENT") {
            continue;
        }
        if state == "REACHABLE" {
            out.insert(mac, ip.to_string()); // freshest binding wins
        } else {
            out.entry(mac).or_insert_with(|| ip.to_string());
        }
    }
    out
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

/// Parse `uci show network` -> (br-ss* device -> its /24 prefix, e.g. "10.21.0"),
/// from each interface section's `device` + `ipaddr`. Used to attribute a conntrack
/// client IP to the SSID bridge that owns its subnet.
pub fn parse_bridge_subnets(network: &str) -> BTreeMap<String, String> {
    let mut dev_of: BTreeMap<String, String> = BTreeMap::new();
    let mut ip_of: BTreeMap<String, String> = BTreeMap::new();
    for line in network.lines() {
        let Some(rest) = line.strip_prefix("network.") else { continue };
        if let Some((sect, val)) = rest.split_once(".device=") {
            dev_of.insert(sect.to_string(), unquote(val));
        } else if let Some((sect, val)) = rest.split_once(".ipaddr=") {
            ip_of.insert(sect.to_string(), unquote(val));
        }
    }
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (sect, dev) in &dev_of {
        if !dev.starts_with("br-ss") {
            continue;
        }
        if let Some(prefix) = ip_of.get(sect).and_then(|ip| ipv4_24_prefix(ip)) {
            out.insert(dev.clone(), prefix);
        }
    }
    out
}

/// "10.21.0.1" -> Some("10.21.0"); None if not a dotted IPv4 quad.
fn ipv4_24_prefix(ip: &str) -> Option<String> {
    let o: Vec<&str> = ip.split('.').collect();
    if o.len() == 4 && o.iter().all(|p| p.parse::<u8>().is_ok()) {
        Some(format!("{}.{}.{}", o[0], o[1], o[2]))
    } else {
        None
    }
}

/// True if `ip` is inside the /24 `prefix` ("10.21.0" matches "10.21.0.\d+"),
/// boundary-safe (won't match "10.21.05.x").
fn ip_in_prefix(ip: &str, prefix: &str) -> bool {
    ip.strip_prefix(prefix).map(|r| r.starts_with('.')).unwrap_or(false)
}

/// Parse `ubus call system info` -> (load1, load5, load15, mem_total, mem_available).
/// ubus load values are fixed-point ×65536 (12608 => 0.19). Bytes for memory.
pub fn parse_system_info(json: &str) -> (f64, f64, f64, u64, u64) {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return (0.0, 0.0, 0.0, 0, 0),
    };
    let ld = |i| v.get("load").and_then(|l| l.get(i)).and_then(|x| x.as_f64()).map(|f| f / 65536.0).unwrap_or(0.0);
    let mem = |k| v.get("memory").and_then(|m| m.get(k)).and_then(|x| x.as_u64()).unwrap_or(0);
    (ld(0), ld(1), ld(2), mem("total"), mem("available"))
}

/// Parse `df -k` -> (total_bytes, free_bytes) for the persistent `/overlay` mount.
/// Columns: Filesystem 1K-blocks Used Available Use% Mounted (read from the end).
pub fn parse_df_overlay(text: &str) -> (u64, u64) {
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.last() == Some(&"/overlay") && f.len() >= 6 {
            let total = f[f.len() - 5].parse::<u64>().unwrap_or(0);
            let avail = f[f.len() - 3].parse::<u64>().unwrap_or(0);
            return (total * 1024, avail * 1024);
        }
    }
    (0, 0)
}

/// Parse `iw dev <vif> survey dump` -> (active_ms, busy_ms, noise_dbm) for the
/// in-use channel (cumulative times since boot; caller deltas them).
pub fn parse_survey(text: &str) -> (u64, u64, i32) {
    let (mut active, mut busy, mut noise) = (0u64, 0u64, 0i32);
    let mut in_use = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("frequency:") {
            in_use = t.contains("[in use]");
            continue;
        }
        if !in_use {
            continue;
        }
        if let Some(r) = t.strip_prefix("noise:") {
            noise = r.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(r) = t.strip_prefix("channel active time:") {
            active = r.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(r) = t.strip_prefix("channel busy time:") {
            busy = r.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    (active, busy, noise)
}

/// Per-VIF last survey sample, so the poller can report the busy% over the interval
/// (the raw times are cumulative since boot).
#[derive(Default)]
pub struct SurveyState {
    last: BTreeMap<String, (u64, u64)>, // vif -> (active_ms, busy_ms)
}

impl SurveyState {
    /// busy% (0..100) over the interval since the last sample of this VIF. Returns 0
    /// on the first sample (baseline) or if the counters did not advance / reset.
    pub fn delta_busy_pct(&mut self, vif: &str, active: u64, busy: u64) -> u32 {
        let prev = self.last.insert(vif.to_string(), (active, busy));
        let (la, lb) = match prev {
            Some(p) => p,
            None => return 0, // first sample = baseline, no spike
        };
        if active <= la || busy < lb {
            return 0; // no advance / counter reset
        }
        let da = active - la;
        let db = busy - lb;
        if da == 0 {
            return 0;
        }
        ((db.saturating_mul(100)) / da).min(100) as u32
    }
}

/// Parse `uci show dhcp` + `uci show network` -> (br-ss* bridge -> DHCP pool size),
/// via dhcp `.interface`(network name) + `.limit`, joined to network `.device`.
pub fn parse_dhcp_pools(dhcp: &str, network: &str) -> BTreeMap<String, u32> {
    let mut iface_of: BTreeMap<String, String> = BTreeMap::new(); // dhcp section -> netname
    let mut limit_of: BTreeMap<String, u32> = BTreeMap::new(); // dhcp section -> limit
    for line in dhcp.lines() {
        let Some(rest) = line.strip_prefix("dhcp.") else { continue };
        if let Some((s, v)) = rest.split_once(".interface=") {
            iface_of.insert(s.to_string(), unquote(v));
        } else if let Some((s, v)) = rest.split_once(".limit=") {
            if let Ok(n) = unquote(v).parse() {
                limit_of.insert(s.to_string(), n);
            }
        }
    }
    let mut dev_of: BTreeMap<String, String> = BTreeMap::new(); // netname -> device
    for line in network.lines() {
        if let Some(rest) = line.strip_prefix("network.") {
            if let Some((s, v)) = rest.split_once(".device=") {
                dev_of.insert(s.to_string(), unquote(v));
            }
        }
    }
    let mut out = BTreeMap::new();
    for (sect, netname) in &iface_of {
        if let (Some(limit), Some(dev)) = (limit_of.get(sect), dev_of.get(netname)) {
            if dev.starts_with("br-ss") {
                out.insert(dev.clone(), *limit);
            }
        }
    }
    out
}

/// Count active DHCP leases per /24 prefix (from parsed leases).
fn count_leases_by_prefix(leases: &BTreeMap<String, (String, String)>) -> BTreeMap<String, u32> {
    let mut out: BTreeMap<String, u32> = BTreeMap::new();
    for (ip, _host) in leases.values() {
        if let Some(pre) = ipv4_24_prefix(ip) {
            *out.entry(pre).or_insert(0) += 1;
        }
    }
    out
}

/// One parsed `/proc/net/nf_conntrack` IPv4 tcp/udp flow. Each line carries two
/// `src=/dst=/sport=/dport=/bytes=` groups: original direction then reply. For a
/// client-initiated flow the original src is the client's LAN IP, so orig_bytes =
/// upload (client→net) and reply_bytes = download (net→client).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ConntrackFlow {
    pub proto: String,
    pub src_ip: String,
    pub src_port: u32,
    pub dst_ip: String,
    pub dst_port: u32,
    pub orig_bytes: u64,
    pub reply_bytes: u64,
}

impl ConntrackFlow {
    /// Stable per-flow identity (proto + original 5-tuple) for delta accounting.
    fn key(&self) -> String {
        format!("{}|{}:{}|{}:{}", self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
}

/// Parse `/proc/net/nf_conntrack` into IPv4 tcp/udp flows with per-direction byte
/// counters. Fail-soft: ipv6 / non-tcp-udp / unparseable lines are skipped. Crucially
/// this source DOES count `[HW_OFFLOAD]` flows, unlike the bridge/iptables/station
/// counters. Field layout: `ipv4 2 <proto> <num> ... src= dst= sport= dport= ...
/// packets= bytes= [reply:] src= dst= sport= dport= packets= bytes= ...`.
pub fn parse_conntrack(text: &str) -> Vec<ConntrackFlow> {
    let mut out = Vec::new();
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.first() != Some(&"ipv4") {
            continue; // skip ipv6 / unknown l3
        }
        let proto = match toks.get(2) {
            Some(&"tcp") => "tcp",
            Some(&"udp") => "udp",
            _ => continue, // icmp/other: no client byte interest
        };
        let mut f = ConntrackFlow { proto: proto.to_string(), ..Default::default() };
        let (mut got_src, mut got_dst, mut got_sport, mut got_dport) = (false, false, false, false);
        let mut bytes_seen = 0u8;
        for t in &toks {
            if let Some(v) = t.strip_prefix("src=") {
                if !got_src {
                    f.src_ip = v.to_string();
                    got_src = true;
                }
            } else if let Some(v) = t.strip_prefix("dst=") {
                if !got_dst {
                    f.dst_ip = v.to_string();
                    got_dst = true;
                }
            } else if let Some(v) = t.strip_prefix("sport=") {
                if !got_sport {
                    f.src_port = v.parse().unwrap_or(0);
                    got_sport = true;
                }
            } else if let Some(v) = t.strip_prefix("dport=") {
                if !got_dport {
                    f.dst_port = v.parse().unwrap_or(0);
                    got_dport = true;
                }
            } else if let Some(v) = t.strip_prefix("bytes=") {
                let b = v.parse().unwrap_or(0);
                match bytes_seen {
                    0 => f.orig_bytes = b,
                    1 => f.reply_bytes = b,
                    _ => {}
                }
                bytes_seen = bytes_seen.saturating_add(1);
            }
        }
        if f.src_ip.is_empty() {
            continue;
        }
        out.push(f);
    }
    out
}

/// Monotonic per-client-IP byte accounting fed from successive conntrack snapshots.
///
/// conntrack counters are per-LIVE-flow: a flow that times out drops out of the table,
/// so a plain sum falls over time — which the control plane's cumulative-delta rate
/// math would misread as a counter reset. Instead we remember each flow's last-seen
/// (orig, reply) bytes and fold only the INCREMENT into a per-client-IP running total
/// that only grows. The first snapshot just establishes the baseline (pre-existing
/// flows' historical bytes are not counted as a startup spike). Resets to zero on
/// engine restart (in-RAM) — the CP clamps that like any counter reset.
#[derive(Default)]
pub struct FlowByteAccumulator {
    primed: bool,
    seen: BTreeMap<String, (u64, u64)>, // flow key -> last (orig_bytes, reply_bytes)
    cum: BTreeMap<String, (u64, u64)>,  // client IP -> (upload, download) cumulative
}

impl FlowByteAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one conntrack snapshot into the cumulative totals.
    pub fn ingest(&mut self, flows: &[ConntrackFlow]) {
        let mut present: BTreeSet<String> = BTreeSet::new();
        for fl in flows {
            let key = fl.key();
            let (last_o, last_r) = self.seen.get(&key).copied().unwrap_or((0, 0));
            if self.primed {
                let d_o = fl.orig_bytes.saturating_sub(last_o);
                let d_r = fl.reply_bytes.saturating_sub(last_r);
                if d_o != 0 || d_r != 0 {
                    let e = self.cum.entry(fl.src_ip.clone()).or_insert((0, 0));
                    e.0 = e.0.saturating_add(d_o);
                    e.1 = e.1.saturating_add(d_r);
                }
            }
            self.seen.insert(key.clone(), (fl.orig_bytes, fl.reply_bytes));
            present.insert(key);
        }
        // Drop flows gone this tick — their final bytes are already folded in.
        self.seen.retain(|k, _| present.contains(k));
        self.primed = true;
    }

    /// (upload, download) cumulative for one client IP.
    pub fn client(&self, ip: &str) -> (u64, u64) {
        self.cum.get(ip).copied().unwrap_or((0, 0))
    }

    /// (upload, download) summed over every client IP inside a /24 `prefix`.
    pub fn subnet_bytes(&self, prefix: &str) -> (u64, u64) {
        if prefix.is_empty() {
            return (0, 0);
        }
        let (mut up, mut down) = (0u64, 0u64);
        for (ip, (u, d)) in &self.cum {
            if ip_in_prefix(ip, prefix) {
                up = up.saturating_add(*u);
                down = down.saturating_add(*d);
            }
        }
        (up, down)
    }
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
\ttx retries:\t398270
\ttx failed:\t7550
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
        assert_eq!(rows[0].tx_retries, 398270);
        assert_eq!(rows[0].tx_failed, 7550);
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

    #[test]
    fn conntrack_parses_directional_bytes() {
        // Real .25 line: YouTube QUIC flow, orig=upload, reply=download, offloaded.
        let line = "ipv4     2 udp      17 30 src=10.21.0.41 dst=113.171.68.17 sport=50346 dport=443 packets=269 bytes=61884 src=113.171.68.17 dst=192.168.1.236 sport=443 dport=50346 packets=2572 bytes=3164892 [HW_OFFLOAD] mark=256 zone=0 use=3";
        let f = parse_conntrack(line);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].proto, "udp");
        assert_eq!(f[0].src_ip, "10.21.0.41");
        assert_eq!(f[0].src_port, 50346);
        assert_eq!(f[0].dst_port, 443);
        assert_eq!(f[0].orig_bytes, 61884); // upload (client -> net)
        assert_eq!(f[0].reply_bytes, 3164892); // download (net -> client)
    }

    #[test]
    fn conntrack_skips_ipv6_and_non_tcp_udp() {
        let text = "\
ipv6     10 tcp      6 src=fe80::1 dst=fe80::2 sport=1 dport=2 bytes=5 src=a dst=b bytes=6
ipv4     2 icmp     1 30 src=10.21.0.5 dst=8.8.8.8 type=8 code=0 id=1 packets=1 bytes=84";
        assert!(parse_conntrack(text).is_empty());
    }

    #[test]
    fn accumulator_baselines_then_folds_increments_across_expiry() {
        let mut acc = FlowByteAccumulator::new();
        let flow = |o, r| ConntrackFlow {
            proto: "tcp".into(), src_ip: "10.21.0.41".into(), src_port: 1,
            dst_ip: "1.1.1.1".into(), dst_port: 443, orig_bytes: o, reply_bytes: r,
        };
        // First snapshot = baseline only (no startup spike from pre-existing bytes).
        acc.ingest(&[flow(100, 1000)]);
        assert_eq!(acc.client("10.21.0.41"), (0, 0));
        // Same flow grows -> fold only the increment.
        acc.ingest(&[flow(150, 1500)]);
        assert_eq!(acc.client("10.21.0.41"), (50, 500));
        // Flow expires, a NEW flow (same client) appears: prior total retained, the
        // new flow counted from zero -> monotonic across expiry.
        acc.ingest(&[ConntrackFlow {
            proto: "tcp".into(), src_ip: "10.21.0.41".into(), src_port: 2,
            dst_ip: "2.2.2.2".into(), dst_port: 443, orig_bytes: 10, reply_bytes: 20,
        }]);
        assert_eq!(acc.client("10.21.0.41"), (60, 520));
    }

    #[test]
    fn bridge_subnets_and_subnet_bytes() {
        let network = "\
network.lan=interface
network.lan.device='br-lan'
network.lan.ipaddr='192.168.9.1'
network.pc_win_if=interface
network.pc_win_if.device='br-ss2'
network.pc_win_if.ipaddr='10.21.0.1'";
        let subs = parse_bridge_subnets(network);
        assert_eq!(subs.get("br-ss2"), Some(&"10.21.0".to_string()));
        assert!(!subs.contains_key("br-lan")); // only br-ss* bridges

        let mut acc = FlowByteAccumulator::new();
        let mk = |ip: &str, o, r| ConntrackFlow {
            proto: "tcp".into(), src_ip: ip.into(), src_port: 1,
            dst_ip: "1.1.1.1".into(), dst_port: 443, orig_bytes: o, reply_bytes: r,
        };
        acc.ingest(&[mk("10.21.0.41", 0, 0), mk("10.21.0.42", 0, 0), mk("10.99.0.1", 0, 0)]);
        acc.ingest(&[mk("10.21.0.41", 100, 900), mk("10.21.0.42", 50, 400), mk("10.99.0.1", 999, 999)]);
        // Subnet sum includes only 10.21.0.x (upload 150, download 1300); 10.99.* excluded.
        assert_eq!(acc.subnet_bytes("10.21.0"), (150, 1300));
        assert_eq!(acc.client("10.21.0.41"), (100, 900));
    }

    #[test]
    fn system_info_parses_load_and_memory() {
        let j = r#"{"uptime":74522,"load":[12608,13440,11840],"memory":{"total":253820928,"free":119619584,"available":127864832}}"#;
        let (l1, l5, l15, total, avail) = parse_system_info(j);
        assert!((l1 - 0.1924).abs() < 0.001); // 12608/65536
        assert!((l5 - 0.2051).abs() < 0.001);
        assert!((l15 - 0.1807).abs() < 0.001);
        assert_eq!(total, 253820928);
        assert_eq!(avail, 127864832);
        assert_eq!(parse_system_info("not json"), (0.0, 0.0, 0.0, 0, 0));
    }

    #[test]
    fn df_overlay_parses_persistent_mount_only() {
        let text = "\
Filesystem           1K-blocks      Used Available Use% Mounted on
/dev/root                22016     22016         0 100% /
tmpfs                   123936      3792    120144   3% /tmp
/dev/ubi0_2              85096     14172     66540  18% /overlay
overlay                  85096     14172     66540  18% /etc";
        assert_eq!(parse_df_overlay(text), (85096 * 1024, 66540 * 1024));
    }

    #[test]
    fn survey_parses_in_use_channel_only() {
        let text = "\
Survey data from wlan0-D-3
\tfrequency:\t\t\t2412 MHz
\tnoise:\t\t\t\t-100 dBm
\tchannel active time:\t\t999 ms
Survey data from wlan0-D-3
\tfrequency:\t\t\t2462 MHz [in use]
\tnoise:\t\t\t\t-90 dBm
\tchannel active time:\t\t76172369 ms
\tchannel busy time:\t\t13149124 ms";
        assert_eq!(parse_survey(text), (76172369, 13149124, -90));
    }

    #[test]
    fn survey_state_deltas_busy_pct() {
        let mut s = SurveyState::default();
        assert_eq!(s.delta_busy_pct("w0", 1000, 100), 0); // first = baseline
        assert_eq!(s.delta_busy_pct("w0", 2000, 600), 50); // +500 busy / +1000 active
        assert_eq!(s.delta_busy_pct("w0", 1500, 300), 0); // counter reset -> 0
    }

    #[test]
    fn dhcp_pools_map_bridge_to_limit() {
        let dhcp = "\
dhcp.pc_win=dhcp
dhcp.pc_win.interface='pc_win_if'
dhcp.pc_win.start='10'
dhcp.pc_win.limit='200'";
        let network = "\
network.pc_win_if=interface
network.pc_win_if.device='br-ss2'";
        let pools = parse_dhcp_pools(dhcp, network);
        assert_eq!(pools.get("br-ss2"), Some(&200u32));
    }

    #[test]
    fn neigh_resolves_static_ip_lowercased_skips_ipv6_and_no_lladdr() {
        let text = "\
10.21.0.171 dev br-ss2 lladdr 96:22:95:06:f8:d7 STALE
10.22.0.87 dev br-ss3 lladdr F6:83:90:06:19:CB REACHABLE
fe80::1 dev br-ss2 lladdr aa:bb:cc:dd:ee:ff STALE
10.21.0.9 dev br-ss2  FAILED";
        let n = parse_neigh(text);
        assert_eq!(n.get("96:22:95:06:f8:d7"), Some(&"10.21.0.171".to_string()));
        assert_eq!(n.get("f6:83:90:06:19:cb"), Some(&"10.22.0.87".to_string())); // MAC lowercased
        assert_eq!(n.len(), 2); // ipv6 + no-lladdr(FAILED) skipped
    }
}
