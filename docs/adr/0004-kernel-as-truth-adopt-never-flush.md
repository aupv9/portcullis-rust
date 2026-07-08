# ADR-0004: Kernel-as-truth — the nftables `auth` set is authoritative

- Status: Accepted (CLAUDE.md invariant #2)
- Recorded: 2026-07-08

## Context

The daemon can crash, be upgraded, or be `kill -9`'d mid-session. If the source of
truth were process memory, a restart would drop every authorized client (the
openNDS precedent, §5.4). Clients would be re-gated through the ad flow on every
daemon blip — unacceptable.

## Decision

The kernel `auth` set (per-element `timeout`) is the authoritative session state.
On startup the engine **adopts** existing kernel state: list `@auth`, rebuild the
in-RAM view, re-baseline accounting from current conntrack counters — it **never
flushes**. `ensure_base` is create-if-missing / adopt-if-present.

## Consequences

- No authorized client is dropped across a restart or upgrade.
- The kernel set-element timeout is a standalone backstop (see
  [0010](0010-dual-path-expiry.md)) — sessions expire even if the daemon is dead.
- Durability needs no flash (see [0006](0006-no-flash-writes-ram-tmpfs-only.md)):
  the kernel holds the ruleset, the CP is the durable record.
- Restart adoption is a first-class tested path, not an afterthought.

## Where it lives

`crates/portcullis-session/src/lib.rs` (`adopt`, `reconcile_at`); nft backends'
`ensure_base`/`list_auth`; `engined/compose.rs` (steps 1–2).
