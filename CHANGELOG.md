# Changelog

All notable changes to the `portcullis` engine are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/); the engine
follows semver at the workspace level (`[workspace.package] version`).

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
