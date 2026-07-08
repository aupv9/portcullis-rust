# ADR-0006: No runtime state on flash — RAM / tmpfs only

- Status: Accepted (CLAUDE.md invariant #1)
- Recorded: 2026-07-08

## Context

The target routers have NAND/SPI flash with limited write endurance. Writing
session/runtime state to flash on every grant/meter tick wears it out and bricks
routers (the openNDS-on-flash precedent, §5.4).

## Decision

No runtime state touches flash. Session state lives in RAM; anything that must
survive a daemon restart goes to **tmpfs** (`/tmp/portcullis/`) — the committed
wireless scope, the runtime control config ([0012](0012-runtime-control-state-and-engine-control-port.md)),
the provision watchdog marker. No sqlite/redb-on-flash. Durability comes from the
kernel holding the ruleset ([0004](0004-kernel-as-truth-adopt-never-flush.md)) and
the control plane as the record of truth ([0002](0002-no-radius-cp-is-nas-of-record.md)).

## Consequences

- Flash lifetime is protected; a `PACKAGING.md` flash-write audit guards it.
- tmpfs state is best-effort — a lost tmpfs file falls back to defaults / kernel
  adoption, never a crash.
- Persistence writes are pretty-printed JSON, small and infrequent.

## Where it lives

`engined/src/runtime.rs` (`/tmp/portcullis/runtime.json`), `portcullis-provision`
(tmpfs marker), `compose.rs` (committed-gated restore).
