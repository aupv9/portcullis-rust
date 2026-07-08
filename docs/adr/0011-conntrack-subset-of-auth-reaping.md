# ADR-0011: `conntrack ⊆ auth` — reap established flows on de-auth

- Status: Accepted (CLAUDE.md invariant #9) — design: [`../design/conntrack-reaping-on-deauth.md`](../design/conntrack-reaping-on-deauth.md)
- Recorded: 2026-07-08

## Context

Removing a MAC from `@auth` only gates *new* connections. An already-established
flow sails through the `ct established,related accept` fast path indefinitely — so
a revoked / expired / quota-capped / idle client whose browser or VPN holds a
long-lived socket **stays online**. Observed live on a RUT200.

## Decision

Invariant: a conntrack flow may exist only while its source MAC is in `@auth`.
Every de-auth reaps the client's established flows (`FlowReaper`, `conntrack -D -s
<ip>`) right after `del_auth`. A periodic reconcile sweep backstops it: reap any
neighbour IP whose MAC ∉ `@auth`; the first tick at boot severs flows left over
from before adoption.

## Consequences

- De-auth actually stops the client, not just its new connections.
- Fail-closed degradation: a reap error is logged + metered, never aborts the
  revoke or unblocks the gate ([0007](0007-fail-closed-everywhere.md)).
- Only LAN neighbours are candidates, so the router's own IPs and the outbound
  control-plane flow are structurally never reaped.
- The `established,related accept` fast path is kept safe **only** by this invariant.

## Where it lives

`FlowReaper` in `portcullis-types`; `ConntrackReaper` + `reap_orphan_flows` in
`portcullis-accounting/src/reaper.rs`; wired in `session` (`revoke_internal`,
`tick_expiry`) + `compose.rs` (sweep). Config: `reap_conntrack` (default on).
