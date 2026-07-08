# ADR-0010: Dual-path expiry — kernel timeout + daemon sweep

- Status: Accepted (CLAUDE.md invariant #6)
- Recorded: 2026-07-08

## Context

A session must end when its TTL elapses — even if the daemon is dead. But the
control plane also needs an accounting-stop event with final bytes, which only the
daemon can emit.

## Decision

Two independent paths, neither of which alone can leave a permanent session:

1. **Kernel path (authoritative backstop):** the `auth` set element carries a
   per-element `timeout`; the kernel removes it when it elapses — works with the
   daemon dead. The client's next `:80` re-gates.
2. **Daemon path:** an expiry-tick sweep removes sessions past `expires_at`,
   idempotently calls `del_auth` (belt-and-suspenders), reaps flows
   ([0011](0011-conntrack-subset-of-auth-reaping.md)), and emits EXPIRED with bytes.

## Consequences

- A crashed daemon still expires sessions (kernel path).
- A live daemon still produces accounting-stop (daemon path).
- The same tick also runs the idle sweep ([0013](0013-bandwidth-shaping-tc-htb.md)
  neighbour, G6).

## Where it lives

`crates/portcullis-session/src/lib.rs` (`tick_expiry`, `sweep_idle`); nft backends
(set-element `timeout`); `engined/compose.rs` (expiry loop).
