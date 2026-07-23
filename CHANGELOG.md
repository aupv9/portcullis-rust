# Changelog

All notable changes to the `portcullis` engine are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/); the engine
follows semver at the workspace level (`[workspace.package] version`).

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
