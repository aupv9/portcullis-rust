# Changelog

All notable changes to the `portcullis` engine are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/); the engine
follows semver at the workspace level (`[workspace.package] version`).

## [0.41.0] — 2026-08-13

### Fixed
- **Uplink false alarm on USB-modem routers (e.g. RUT906 usb0 cellular).** These run the
  cellular data path on `usb0`, which mwan3 doesn't track (`wan offline`, `mob disabled`).
  The 0.36.0 near-realtime change derived `internet_reachable` purely from mwan3
  (`wan_up || sim_up`), so a box happily online via `usb0` reported `internet_reachable=
  false`, `active_wan="usb0"` (unclassified) and `sim_up=false` → the dashboard falsely
  showed "Internet mất" and "WAN down". Now: `usb*` classifies as a cellular uplink
  (`active_wan="sim"`); `internet_reachable = wan_up || sim_up || has-default-route`
  (a route via any recognised uplink means online — local + near-realtime, covers modem
  stacks mwan3 misses); and `sim_up` is derived true when the active path is cellular.
  Removed the now-redundant mwan3-seen/ping fallback. Tests updated.

## [0.40.0] — 2026-08-12

### Fixed / Added
- **Full backup-SIM info (fixes the always-empty SIM signal).** The engine was querying
  `ubus gsm.modem0 info`, which returns modem *hardware* info (no operator/signal), so the
  SIM always read empty. `gather_sim` now reads the correct sources: `read_signal_db`
  (RSSI/RSRP/RSRQ/SINR + band from the newest sample), `get_network_info` (net_mode →
  net_type + connected), `gsmctl -o` (operator name), and `gsmctl -A "AT+CNUM"` (SIM own
  number/MSISDN — SIM-reported, often unprovisioned). `SiteUplinkSim` gains
  `rsrq/rssi/net_type/band/connected/msisdn` (additive proto fields). New parser unit tests
  against real RUT906 output.

## [0.39.0] — 2026-08-12

### Fixed
- **swconfig LAN ports: enumerate real (wired) ports, not every chip port.** rt305x
  switches (RUT200/RUT906) expose 6 switch ports but a board wires only some to jacks
  (RUT200 = 1 LAN). The previous `get lan`==1 probe surfaced the unwired chip ports as
  phantom LAN ports. Now derive the physical LAN ports from the switch-VLAN membership
  in `uci show network` (untagged member ports of the switch_vlan the LAN bridge sits on;
  the tagged CPU port is excluded), falling back to the port probe only if the layout
  can't be resolved. New unit test against the real RUT200 UCI layout.

## [0.38.0] — 2026-08-12

### Added
- **LAN port telemetry on swconfig switches** (RUT200 / RUT906 — rt305x/mt7530, which have
  no DSA `lanN` netdevs). `gather_lan_ports` now falls back to `swconfig` when no DSA
  slaves exist: per LAN port (`port N get lan == 1`) it reports link/speed/duplex parsed
  from `swconfig … port N get link`, and the downstream device(s) from the switch ARL table
  (`get dump_arl`, PORTMAP hex bitmask → port) matched to DHCP leases. rt305x exposes no
  per-port **byte** counters, so `rx_bytes`/`tx_bytes` stay 0 (throughput unknown) — the
  dashboard shows link + device but "—" for throughput on these switches; DSA boxes
  (RUTM11) keep full per-port throughput. New unit tests cover the link / `list` / ARL
  parsers against real RUT200 output. No proto change.

## [0.37.0] — 2026-08-12

### Added
- **Wired LAN port telemetry.** New `SiteLanPort` (+ `SiteLanDevice`) in the site-telemetry
  report (`SiteTelemetryReport.lan_ports`, field 10 — additive, wire-compatible). Per
  physical DSA LAN port (`lan1/lan2/…`) the engine reports, every tick (~20s, local reads):
  - link up/down, negotiated speed (10/100/1000) and duplex — from
    `/sys/class/net/<port>/{carrier,speed,duplex}`;
  - cumulative rx/tx bytes — from `/sys/class/net/<port>/statistics/*` (the CP derives
    per-port throughput, same Δbytes/Δt as clients/uplink);
  - the downstream device(s) learned on the port — from `bridge fdb show` (dynamic entries
    only, router-own/multicast filtered) matched to DHCP leases → mac/ip/hostname. >1 MAC on
    a port surfaces as a downstream switch.
  Enumeration is DSA-only (netdevs named `lanN`); non-DSA boxes (swconfig, e.g. RUT906)
  report no ports and the dashboard panel hides itself. WAN stays under `SiteUplink`. New
  unit tests cover the `ls`/netdev filter and the bridge-FDB parser.

## [0.36.0] — 2026-08-11

### Changed
- **Near-realtime uplink telemetry (P1).** Split `gather_uplink` by cost so the fast
  LOCAL reads (mwan3 status, default route, `/proc/net/dev` per-uplink bytes,
  `/sys/.../carrier_changes`) run EVERY site-telemetry tick (~20s), while only the slow
  network probes (ping / curl / ubus gsm) stay cached and refresh every
  `UPLINK_REFRESH_EVERY` ticks (~60s). Result: **WAN up/down, failover, link-flap and
  per-uplink throughput now surface at ~20s instead of ~60s** — no cadence change, no
  extra probe cost (local reads are sub-ms).
- **`internet_reachable` now follows mwan3's own tracking** (`wan_up || sim_up`) when
  mwan3 reports interfaces, so "có Internet" flips at the tick cadence (~20s) instead of
  the 60s ping cache. Falls back to the ping result when mwan3 is unavailable/empty so a
  missing tool never reads a false "down". Ping still supplies the latency/loss numbers
  (cached ~60s). New unit tests cover both the mwan3 and ping-fallback paths.

## [0.35.0] — 2026-08-10

### Added
- **Net-monitor coverage in site telemetry** (all observational, fail-soft, cumulative
  so the CP derives rates):
  - `SiteUplink` += `wan_carrier_changes` (`/sys/class/net/<wan>/carrier_changes` —
    catches brief physical WAN flaps mwan3 rides through), `wan_uptime_secs` (mwan3
    online age), `wan_rx/tx_bytes` + `sim_rx/tx_bytes` (`/proc/net/dev` per-uplink
    throughput). Fixes the "flapping WAN reads solid green" blind spot.
  - `SiteHealth` += `cpu_pct` (`/proc/stat` delta), `conntrack_count`/`conntrack_max`
    (`/proc/sys/net/netfilter` — table-exhaustion signal).
  - `SiteFlow` (new) — top-N client→internet conversations from `nf_conntrack`
    (RMON-Matrix / mini-NetFlow), L3/L4 metadata only, restricted to resolved client
    IPs. Adds who-talks-to-whom / by-port that SNMP/RMON can't do on OpenWrt.
  - `SiteEvent` (new) — trap-style edge/threshold events (`wan_down`/`wan_up`/
    `wan_flap`/`conntrack_high`/`cpu_high`/`cp_reconnect`) detected in the poller
    (hysteresis on thresholds) and carried on the push (≤ tick latency). CP flattens
    into an event log.
  - proto tags all additive (proto3 forward-compat: old CP ignores them). Engine-only.

## [0.34.1] — 2026-08-09

### Changed
- **Inbound-idle watchdog now defaults ON (`control_inbound_idle_secs` 0 → 90).**
  The keep-alive-timeout + inbound-idle watchdog that kills zombie half-open control
  streams already shipped in the codebase, but the inbound-idle half defaulted OFF
  (safe only once the CP sent periodic Attach pings). The edge now sends a
  `ControlFrame_Ping` every 30 s (`domain/edge .../attach/handler.go` `pingInterval`),
  so 90 s (= 3× the ping) is safe and on by default: when the CP drops/stops feeding
  the Attach stream while h2 still looks alive (site-.22: WAN/NAT flap → edge detaches,
  engine holds a zombie), the engine now self-heals in ≤90 s instead of hanging until a
  manual restart. Set `control_inbound_idle_secs = 0` in UCI only for a CP that does not
  ping (e.g. the on-net dev server). Engine-only; contract unchanged.

## [0.34.0] — 2026-08-09

### Changed
- **SSID `on_air` now uses netifd's authoritative wireless state, not just netdev
  operstate.** A VIF counts as on-air only when its `operstate == up` AND netifd's
  `network.wireless status` reports its radio `up && !disabled && !retry_setup_failed`
  (`parse_wireless_status`) — i.e. hostapd actually launched the BSS. A bare
  `operstate=up` can lie when hostapd setup failed; this catches that and makes the
  24h liveness heatmap more truthful. Fail-soft: if netifd status is unavailable for
  a VIF, falls back to operstate only (no regression). Engine-only; contract
  unchanged. (Tier 2 of the wireless-accuracy work; the CP-side "chập chờn"/deg
  per-bucket state is Tier 1.)

## [0.33.0] — 2026-08-09

### Fixed
- **Static-IP clients no longer show "no IP".** A client's IP was resolved only from
  `/tmp/dhcp.leases`, so a device with a STATIC IP (no lease — common for IoT, e.g. a
  fleet-wide device at 10.21.0.171 on the "iot" SSID) was reported with `ip=""` and
  flagged "chưa có IP" on the dashboard, even though it had a working IP (visible in
  the ARP table). `poll_once` now falls back to `ip neigh` (`parse_neigh`) when there
  is no lease: a MAC with a usable neighbour entry (REACHABLE/STALE/DELAY/PROBE/
  PERMANENT) takes that IP. Engine-only; the wire contract (`SiteClient.ip`) is
  unchanged, so the "chưa có IP" count now reflects only genuinely IP-less devices
  (real DHCP failure / mid-handshake). Bonus: their conntrack per-client bytes now
  resolve too.

## [0.32.0] — 2026-08-09

### Added
- **Router health, radio airtime, and DHCP pool in site telemetry** (SNMP-equivalent
  metrics, read locally — no snmpd, offload-independent gauges):
  - `SiteHealth` block: CPU load (1/5/15), RAM total/available, persistent flash
    (`/overlay`) total/free, modem temperature — from `ubus system info`, `df`,
    `gsmctl -c`. (MT7621 has no CPU/board thermal sensor, so only modem temp.)
  - `SiteSsid` += `airtime_busy_pct` (radio busy %, delta-based — explains why client
    retries are high: congestion vs. router fault) + `noise_dbm`, from
    `iw dev <vif> survey dump`; plus `dhcp_leased` / `dhcp_capacity` (pool fill).

### Changed
- **Split poll cadence for a livelier dashboard.** The light snapshot (SSID / clients
  / bytes / airtime / health) now emits every ~20 s (`DEFAULT_SITE_TELEMETRY_INTERVAL`
  60 s → 20 s); the expensive uplink probe (ping + curl) runs only every
  `UPLINK_REFRESH_EVERY` (3) ticks (~60 s) and is cached in between — so throughput/
  clients feel live without paying ping/curl each tick.

## [0.31.0] — 2026-08-09

### Added
- **Per-SSID / per-client reliability evidence in site telemetry.** For proving,
  during a third-party SSID integration, whether the router itself is dropping
  traffic (it usually is not) vs. the client's own RF/coverage problem:
  - `SiteSsid` gains bridge netdev counters `rx_errors`, `rx_dropped`,
    `tx_errors`, `tx_dropped` (from `/sys/class/net/<bridge>/statistics/*`).
    ~0 on a healthy router.
  - `SiteClient` gains `tx_retries` and `tx_failed` from `iw … station dump`
    (802.11 retransmit attempts and frames given up after retries) — the actual
    WiFi-quality signal. Offload-independent (PHY/L2 counters, not byte counters),
    so unlike the byte counters these were always accurate; they were just not
    collected. The dashboard shows "Router: không rớt/lỗi gói" per SSID plus a
    per-client "Chất lượng liên kết" column (✗failed · ↻retries).

## [0.30.0] — 2026-08-09

### Fixed
- **Site-telemetry byte counters were wrong under hardware flow offload.** On the
  MT7621 (`flow_offloading_hw=1`) the bulk of forwarded traffic — mostly download —
  is switched in the PPE and never touches the Linux bridge `/sys` counters,
  `iptables` FORWARD counters, or `iw station dump` byte counters. The old
  per-SSID `ul/dl_bytes` (bridge `rx/tx`) and per-client `rx/tx_bytes` (station
  dump) therefore undercounted download and read backwards (upload > download) —
  e.g. a client that pulled 4.1 MB of video showed 0.48 MB "download" / 1.30 MB
  "upload". Byte accounting now comes from `/proc/net/nf_conntrack`, which DOES
  reflect offloaded flows. A new `FlowByteAccumulator` folds each flow's byte
  increment into a monotonic per-client-IP cumulative (conntrack is per-live-flow,
  not a cumulative counter, so a plain sum falls when flows expire); per-SSID
  totals sum the cumulative over the bridge's `/24`. The wire contract is
  unchanged (`ul/dl_bytes`, client `rx/tx_bytes`) — only the source — so the CP
  egress/today derivations and the FE become correct with no downstream change.
  Note: the cumulative is in-RAM, so an engine restart resets it (the CP clamps
  that like any counter reset). `fwd_bytes/fwd_pkts` remain but are unreliable
  under offload and unused by the dashboard.

## [0.29.0] — 2026-08-09

### Added
- **Engine↔CP control-channel health in site telemetry.** `SiteTelemetryReport`
  gains a `control` block — `cp_connected`, `reconnects_since_boot`,
  `connected_secs` (uptime of the current dial) — sourced from a shared
  `ControlChannelHealth` the control task updates from its `cp_state` callback and
  the poller reads. Surfaces the `.22` zombie signals (is the engine dialed in, is
  the channel flapping, how long has it held) directly in the dashboard.

## [0.28.0] — 2026-08-09

### Added
- **Per-SSID directional byte counters + client DHCP hostname** (site-telemetry
  mockup parity). `SiteSsid` gains `ul_bytes`/`dl_bytes` (client→internet /
  internet→client, read from the bridge's own `rx_bytes`/`tx_bytes` counters like
  `net-report.sh`) so the dashboard can show ↓/↑ throughput per SSID and a
  down/up chart toggle. `SiteClient` gains `hostname` (from the DHCP lease name)
  so the clients table can show a device name, not just a MAC.

## [0.27.0] — 2026-08-09

### Fixed
- **Site-telemetry poller enumerates LIVE SSIDs, not committed desired-state.**
  v0.26.0 enumerated SSIDs from `provisioner.get_wireless()`, but after any engine
  restart the committed wireless state is rehydrated version-only with EMPTY `ssids`
  (until the CP re-pushes) — so the poller reported 0 SSIDs even while they were
  broadcasting ("SSID phát nhưng dashboard = 0"). The poller now reads live UCI
  (`uci show wireless`/`network` → every wifi-iface bound to a `br-ss*` bridge,
  VIFs from `/sys/class/net/<bridge>/brif`), mirroring `net-report.sh` — it reflects
  what is actually on-air. Drops the provisioner dependency; adds the
  `parse_wireless_bridges` pure parser (host-tested). `gated` now derives from the
  live FORWARD → `wifihub_fwd` jump rather than the committed spec.

## [0.26.0] — 2026-08-09

### Added
- **Whole-site telemetry poller (Transport A — engine-native "Giám sát trực tiếp").**
  A new isolated, read-only task (`portcullis-provision::site_telemetry`) polls the
  site every ~60 s and pushes ONE `SiteTelemetryReport` up the control channel
  (unsolicited `EngineFrame.site_telemetry`): per-SSID on-air / gated / gate-enforced
  / client-count / channel / cumulative FORWARD egress counters, one row per
  associated client (signal / PHY rates / byte counters / association age / DHCP IP),
  and site uplink (active WAN vs SIM, Internet reachability + latency/loss, public IP,
  backup-SIM signal). SSIDs are enumerated from the committed desired-state; all
  collection goes through the `CommandRunner` seam (`iw` / `iptables` / `ubus` /
  `mwan3` / `ping`) with host-unit-tested pure parsers. Purely observational — it
  reads only and never writes wireless config or touches enforcement. The control
  plane stores the latest snapshot + a 24 h history and derives per-SSID uptime% /
  liveness for the admin monitoring tab. Cut from 0.24.4 (carries the tier-2
  control-channel keepalive/watchdog fix).

## [0.24.2] — 2026-07-29

### Changed
- **Temporarily disable wired LAN-port-joins-SSID (`bridge_ports`) behind a flag.**
  The feature that bridges a physical LAN port onto an SSID's bridge assumes a DSA
  switch (netdevs `lan1..lanN`); on a swconfig board like the RUT906 those netdevs
  don't exist (LAN ports are switch ports on `eth0.1`), so a `bridge_ports` entry is
  meaningless and can break the bridge. A new const `WIRED_BRIDGE_PORTS_ENABLED =
  false` gates both the render (no `network.pc_<slug>_dev.ports` is emitted) and the
  validation (a spec carrying `bridge_ports` is accepted-but-ignored, never an
  error). Reversible: flip the const to `true` to restore. The proto field and all
  code are retained. The control plane also stops sending `bridge_ports`
  (defence-in-depth); this is the engine-side guard.

## [0.24.1] — 2026-07-29

### Fixed
- **Sanitize DHCP reservation names — a device named with a space no longer kills
  DHCP for the whole router.** A device static-IP reservation whose name held an
  illegal hostname character (a SPACE, e.g. "Pos device", or a non-ASCII diacritic,
  e.g. "Máy in") was rendered VERBATIM as the dnsmasq `dhcp-host` name. dnsmasq
  refuses to start on a bad host name ("bad DHCP host name") and crash-loops — taking
  DHCP down for EVERY SSID on the router, including the stock LAN, so clients
  associate but never get an IP and drop after ~18s. Observed live on a RUT906.
  `render_reservation_host` (the single source of truth for both the full apply path
  and the DHCP-only diff-gate) now runs the name through `sanitize_dhcp_hostname`:
  keep `[A-Za-z0-9_]` (underscores are accepted, so "camera_2" is unchanged), map
  every other rune to '-', collapse runs, trim, cap to a 63-char DNS label; if
  nothing legal survives, omit `.name` entirely (a nameless `dhcp-host=<mac>,<ip>`
  is valid). Idempotent on already-legal names so the diff-gate render stays stable.

## [0.24.0] — 2026-07-29

### Fixed
- **DHCP-only apply path — a device reservation edit no longer bounces the radio.**
  Any wireless change (including adding/editing a device static-IP reservation)
  previously bumped the config_version and took the full re-render + `wifi reload
  <radio>` path, dropping every SSID on that radio (fragile on mt76/RUT906; rapid
  edits could collide mid-reload and wedge the radio). A new `ApplyPlan::DhcpOnly`
  planner (`plan_apply_dhcp`) detects when the ONLY delta between the committed and
  desired wireless spec is DHCP reservations — every SSID/radio/encryption/bridge/
  subnet/pool field identical — and applies just the `dhcp.pc_<slug>_host*` sections
  followed by `dnsmasq reload` (SIGHUP): no `wifi reload`, no PHY bounce, no SSID
  drop. Any non-DHCP-only diff (subnet/pool/SSID change, dhcp-disabled SSID, no
  prior commit) falls back to the full reload path (fail-safe). Priority:
  NoChange > DhcpOnly > scoped(off) > FullReload; a DhcpOnly apply error falls
  through to the full path (never half-applied).

## [0.23.0] — 2026-07-28

### Fixed
- **Wire `scoped_reconfigure` from config into the running engine.** The
  `option scoped_reconfigure` UCI flag parsed into `Config.scoped_reconfigure` but
  never reached the provision actor: `compose` called
  `run_provision_subsystem_with_policy`, which hardcodes `scoped_reconfigure = false`,
  so the actor always took the full-reload path and setting the flag on-device was a
  no-op. `compose` now calls `run_provision_subsystem_with_scoped(..., cfg.scoped_reconfigure)`
  and the crate re-exports that entry point. With this, `option scoped_reconfigure '1'`
  actually enables the per-BSS hostapd reconfigure path from 0.22.0.
  **Still DEFAULT-OFF and UNVALIDATED** on mt76/RutOS hardware — any scoped-op error
  still falls back to a full `wifi reload` (never leaves a radio dark). Run
  `deploy/hostapd-scope-spike.sh` and get a GO before enabling.

## [0.22.0] — 2026-07-28

### Added
- **Scoped hostapd reconfigure — scaffolding, DEFAULT-OFF and UNVALIDATED.** New
  `scoped_reconfigure` config option (default `false`). When enabled, an SSID edit
  reconfigures only the changed BSS via hostapd ubus (`config_add` /
  `config_remove` / `<vif> reload`) instead of a radio-wide `wifi reload`, so the
  other SSIDs' clients are not dropped. With the flag OFF (the default) the apply
  path is byte-for-byte unchanged — always a full reload — and any scoped-op error
  falls back to the full reload, so the radio is never left dark.
  **⚠ Do NOT enable in production yet.** The mt76/RutOS hostapd behaviour is
  unconfirmed: run the P0 feasibility harness `deploy/hostapd-scope-spike.sh` on
  the target and get a GO before flipping the flag. Radio-level changes
  (channel / HT mode / country) always take the full reload regardless of the flag.
- `deploy/hostapd-scope-spike.sh` — on-device P0 feasibility harness. Probes
  `wifi reconf`, hostapd `config_add`/`config_remove`/`<vif> reload`, and
  `iw interface add`; snapshots + trap-restores wireless/network/firewall and
  `wifi reload`s on exit; emits a GO/NO-GO matrix (whether one BSS can be
  reconfigured without dropping the others).

## [0.21.0] — 2026-07-28

### Added
- **Equality-gate on wireless apply — identical control-plane re-pushes no longer
  bounce the radio.** The apply path now routes through `plan_apply()`: when the
  control plane re-pushes a wireless config whose `config_version` equals the last
  committed one (churn / detect-only reconcile), the engine SKIPS the whole apply —
  no re-render, no `uci` write, no `wifi reload` — and just re-ACKs `Committed` so
  the CP ledger still converges. Previously every re-push, even an identical one,
  ran a full `wifi reload <radio>` that bounced every SSID on the (single) radio;
  a churning store could flap the radio continuously and overload-reboot the
  router. A genuine config change still takes the full reload unchanged. Safe with
  the 0.20.2 firewall-zone fix (a successful apply now fully binds, so a skipped
  duplicate leaves nothing half-applied). Operational note: to force a re-render of
  an already-committed store on an unchanged `config_version` (e.g. after an engine
  render-logic change), clear the persisted version — `uci delete wireless.pc_meta`
  — so the engine reports an empty version and the CP re-pushes.
- **`ApplyPlan` foundation** (`NoChange` / `FullReload`) for the apply path. A
  `Scoped(..)` per-BSS hostapd variant — reconfigure one SSID without bouncing the
  whole radio — is scaffolded as a `TODO` gated on an on-device mt76/hostapd
  feasibility spike; no scoped/ubus code ships here (it manipulates the sole radio
  and cannot be unit-tested).

## [0.20.2] — 2026-07-28

### Fixed
- **The REAL cause of "a device/family SSID can't get an IP": a long slug's
  firewall zone silently vanished.** An SSID's fw3 zone was named after its slug,
  and fw3 derives iptables chain names as `zone_<slug>_postrouting` (slug + 17
  chars). iptables SILENTLY rejects a chain name over 28 chars, so a slug of
  12–16 chars (slugs are validated `[a-z0-9_]{1,16}`) — e.g. `win_gia_dinh`
  → `zone_win_gia_dinh_postrouting` (29) — made fw3 drop the ENTIRE zone: no DHCP
  allow, no forward-to-WAN. A client joined the SSID (WPA2 OK) but got no lease
  and no internet. `fw3 print` generated **zero** rules for that bridge while a
  short-slug neighbour got 20. The zone name now goes through `fw_zone_name()`:
  slugs ≤ 11 chars stay verbatim (readable, backward-compatible); longer ones
  collapse to a short stable hash (`z<8 hex>`) that always fits. Every reference —
  the zone, its forwarding, its DHCP/DNS/portal/internal rules, and inter-SSID
  peer allows — resolves through it, so they stay consistent. (0.20.0/0.20.1 fixed
  a real-but-separate firewall-reload TIMING race; this is the actual root cause.)

## [0.20.1] — 2026-07-28

### Fixed
- **Follow-up to 0.20.0: the final firewall reload must WAIT for the owned bridges
  to gain carrier.** 0.20.0 moved the firewall reload to the end of the apply
  sequence, but a wifi-only bridge attaches its VIF member ASYNChronously —
  the bridge link (`br-ss<n>`) comes up a few seconds AFTER `wifi reload` returns,
  so the reload still ran before the last bridge existed and its zone (e.g.
  `br-ss3`'s) never bound. The engine now polls each owned (`pc_*`) interface's
  bridge `carrier` via `ubus call network.device status` (bounded ~15 s,
  fail-open) BEFORE the final `/etc/init.d/firewall reload`, so fw3 binds every
  owned zone's `-i br-ss<n>` DHCP/forward rules deterministically. Confirmed
  on-device: the bridge link came up ~3 s after the apply completed, so 0.20.0's
  reload landed too early.

## [0.20.0] — 2026-07-28

### Fixed
- **A wifi-only SSID bridge could get its firewall zone in UCI but not in the
  running iptables ruleset — so clients associated but never got an IP or
  internet.** The wireless apply reload sequence
  (`commit_and_reload_multi`) reloaded the firewall BEFORE `wifi reload`, i.e.
  before the owned wifi-only bridges (`br-ss<n>`) exist. fw3 cannot bind a zone's
  `-i br-ss<n>` DHCP/forward rules to a device that isn't there yet, and netifd's
  per-`ifup` firewall reload is edge-triggered + coalesced, so it races the async
  bridge bring-up: the LAST bridge to appear (e.g. `br-ss3` for a 3rd SSID) could
  end up with its zone committed to UCI but with NO rules attached to it — no
  DHCP allow, no forward-to-WAN — so a phone joined the SSID (WPA2 handshake OK)
  but got no lease and dropped after ~18 s. The engine now runs a FINAL,
  level-triggered `/etc/init.d/firewall reload` AFTER the wifi step (once every
  owned bridge exists), so fw3 binds every owned zone's rules deterministically,
  independent of netifd's racy per-`ifup` reloads.

## [0.16.0] — 2026-07-23

### Fixed
- **Reboot gate-loss (silent fail-open) — self-heal from UCI at boot.** After a
  reboot the engine's tmpfs runtime state (`/tmp/portcullis/committed.gated`) is
  wiped, so a previously-gated SSID came back on-air with NO captive gate (the
  `wifihub_pre`/`wifihub_fwd` chains are created but never jumped from
  PREROUTING/FORWARD) while the control-plane manual-apply reconcile stayed silent
  — a silent fail-open (violates invariant #5). The engine now re-derives the
  gated bridges from durable UCI at boot (presence of the `pc_<slug>_portal`
  section ⟺ gated) and re-scopes enforcement BEFORE dialing the control plane,
  closing the window without depending on a CP re-push. Fail-closed, independent
  of the CP. Confirmed on-device: RUT906 reboot with v0.15.0 reproduced the
  fail-open; this fix restores the gate at boot.

### Added
- **Per-SSID `gate_enforced` liveness signal** — the liveness poller reports
  whether the enforcement gate is actually scoped to each SSID's bridge, so the CP
  can raise an "SSID up but UNGATED" alert. Deploy this engine BEFORE the CP alert
  (proto3 absent == false) to avoid a false-alarm storm.

## [0.15.0] — 2026-07-23

### Added
- **Device-SSID engine** — DHCP reservations, internal-target firewalling, and
  per-device telemetry (P3) for store-device SSIDs (vending / smartPOS / camera /
  NVR): the engine honours reserved MAC→IP leases, renders internal-target allow
  rules, meters per-device IP counters, and fans an observational
  `WirelessDeviceReport` up-frame to the control plane. Purely diagnostic — the
  telemetry path never touches the enforcement gate.
- **Engine trace-context propagation (tracing P0)** — `ControlFrame` and
  `EngineFrame` now carry a `trace_ctx` (W3C `traceparent`). The engine parses it
  (hand-rolled, **no OpenTelemetry dependency** — MIPS binary-size budget), labels
  the command-dispatch span and its logs with the originating `trace_id` for
  trace→logs correlation, and echoes the context back so the control plane can
  confirm continuity. A malformed value is treated as absent (fail-closed, never
  aborts a command). See `docs/design/engine-tracing.md`.

### Notes
- Both are wire-compatible additions (a new scalar `trace_ctx` + proto fields an
  old peer ignores). No new runtime dependency; the release binary stays within
  the MIPS size budget.

## [0.14.0] — 2026-07-18

### Added
- **On-air SSID liveness (P5)** — a periodic poller reads `ubus` hostapd
  `get_status` + `iwinfo` (assoclist / info) and fans an observational
  `WirelessLiveness` up-frame to the control plane. Purely diagnostic; never
  touches the enforcement gate. Device-validation of the poll path pending.
- **Inter-SSID peer isolation (P2)** — CP-managed wireless now renders explicit
  `pc_peer_*` forwarding sections from `WirelessDesiredState.peer_allows`.
  Inter-SSID traffic was already default-deny; this makes it explicit with
  allow-pairs, with validation (reject unknown slug, self-pair, duplicate, bad
  slug).
- **ZTP golden-image tooling** — `deploy/build-golden-image.sh` bakes a
  first-boot auto-claim `.bin`; `deploy/ZTP-DEPLOYMENT-PLAN.md` documents the
  flow. Packaging (`Makefile`, `ci/pack-ipk.sh`) updated to match.
- Design note `docs/design/confirm-on-reconnect.md` (proposed): re-confirm
  committed wireless config after a control-channel reconnect. Not yet built.

## [0.13.0] — SSID mode / 802.11r / 802.11w (Phase 3)

### Added
- CP-managed wireless SSID fields: encryption mode, 802.11r (fast transition),
  802.11w (management-frame protection).

## [0.12.2]

### Added
- Optional 802.11 deauth on revoke — an L2 companion to the L3 gate: when the
  control plane sets `deauth` on a revoke, the engine also asks hostapd (over
  `ubus`) to deauthenticate the client so it re-onboards into the portal
  cleanly. Best-effort; never affects the L3 gate.

## [0.12.1]

### Fixed
- Strip trailing whitespace from the HMAC key file. Enroll/file writers append a
  newline, but the control plane keys the redirect-signature HMAC on the bare
  64-hex string — signing over the extra `\n` made every engine signature
  mismatch, yielding a 401 "bad signature" and no captive grant.

## [0.12.0]

### Changed
- Align the captive redirect to the FE/CP contract: redirect to `/portal` with
  `mac`, `nas_id`, `ts`, `sig` (was `/splash?store` → 404).
