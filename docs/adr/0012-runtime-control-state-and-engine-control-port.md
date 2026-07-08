# ADR-0012: Runtime control-state store + `EngineControl` port

- Status: Accepted
- Recorded: 2026-07-08

## Context

The control plane needs to manage a running engine — push per-tier grant policies
(user-groups), the walled-garden list, the global enforcement toggle, and tunable
timers/caps — and read back engine info + metrics for fleet drift detection. That
config is distinct from the startup `Config` (foundational bindings, restart-only)
and must survive a daemon restart without touching flash.

## Decision

One `EngineControl` port (`portcullis-types`) with `set_enforcement` / `set_garden`
/ `set_tier_policies` / `set_engine_parameters` / `engine_info` / `metrics_snapshot`
/ `tier_policy`. The composition root's `RuntimeController` implements it: holds the
CP-pushed state, persists it to tmpfs (`runtime.json`,
[0006](0006-no-flash-writes-ram-tmpfs-only.md)), adopts it at startup, and publishes
changes on `watch` channels that the effect loops react to (garden re-render,
enforcement scope, metering cadence). Both the mTLS `Attach` dispatcher and the
unary gRPC server route the `Set*`/`Get*` frames into it — one code path for both.

## Consequences

- CP can drive tiers/garden/enforcement/params live; drift is detectable via
  config hashes in `GetEngineInfo`.
- A rejected config is answered `ok:false`, never silently applied
  ([0007](0007-fail-closed-everywhere.md)).
- Effects are decoupled from dispatch via `watch` channels — a push writes state;
  the relevant loop applies it.

## Where it lives

`EngineControl` + `RuntimeConfig`/`TierPolicy`/`EngineParameters` in
`portcullis-types`; `engined/src/runtime.rs`; dispatch in
`portcullis-control/src/{channel.rs,service.rs}`.
