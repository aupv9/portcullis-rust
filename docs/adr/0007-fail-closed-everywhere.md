# ADR-0007: Fail closed on every error path

- Status: Accepted (CLAUDE.md invariant #5)
- Recorded: 2026-07-08

## Context

This is a security gate. The dangerous failure mode is *fail-open* — an error that
accidentally lets unauthenticated traffic through, or lets a bad config be believed
applied when it isn't.

## Decision

Every error branch keeps prior state or blocks new access; no branch ever fails
open. Concretely:

- Grant does `add_auth` (kernel) **before** recording the session — a writer error
  means no session and no internet.
- nft transaction error → retry once → mark degraded; **never flush**
  ([0005](0005-single-nft-writer-actor.md)).
- Control-plane unreachable → keep enforcing existing sessions, block *new* grants,
  queue events in bounded RAM ([0003](0003-cgnat-engine-dials-the-control-plane.md)).
- A `Set*` config-push that fails validation is answered `ok:false` — never a silent
  accept ([0012](0012-runtime-control-state-and-engine-control-port.md)).
- Best-effort degradations (reap, shaper) log + meter but never abort the gate.
- The one deliberate exception: `portcullis-provision` is **fail-open with rollback**
  (commit-confirm watchdog) — it manages router config, not enforcement, and a
  CGNAT router has no inbound rescue, so a bad wireless push must self-revert.

## Consequences

- The gate errs toward blocked, never open.
- Degraded modes are explicit + observable (metrics), not silent.

## Where it lives

Across all crates; the `Error` enum has no "success-on-error" variant.
