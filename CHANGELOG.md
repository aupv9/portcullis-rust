# Changelog

All notable changes to the `portcullis` engine are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/); the engine
follows semver at the workspace level (`[workspace.package] version`).

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
