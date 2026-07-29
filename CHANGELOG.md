# Changelog

All notable changes to the `portcullis` engine are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/); the engine
follows semver at the workspace level (`[workspace.package] version`).

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
