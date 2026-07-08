# ADR-0003: CGNAT — the engine dials the control plane (outbound mTLS bidi stream)

- Status: Accepted (supersedes the WireGuard overlay + "CP dials the router" model)
- Recorded: 2026-07-08 — full write-up: [`../design/cgnat-bidi-control-channel.md`](../design/cgnat-bidi-control-channel.md)

## Context

Sites sit behind **carrier-grade NAT**: the router has no stable inbound address,
so the control plane cannot dial *into* it. The earlier model gave the CP inbound
reachability via a WireGuard overlay (persistent keepalive) — an extra tunnel,
key management, and attack surface per site.

## Decision

Invert the direction. The engine is the gRPC **client**: it dials the CP and holds
a long-lived `Attach` **bidirectional** stream over **mTLS** (client cert = per-store
identity, pinned CP server CA). Control commands arrive on the stream; events +
acks flow back. No inbound port, no WireGuard. Only control + accounting cross the
link — never client data (that breaks out locally at the store WAN).

## Consequences

- CGNAT-safe with zero inbound surface; identity is bound to the client cert.
- A dropped CP link **cannot** grant new access (no code path accepts a grant while
  detached) — reinforces [0007](0007-fail-closed-everywhere.md); existing sessions
  keep being enforced by [0004](0004-kernel-as-truth-adopt-never-flush.md).
- Reconnect uses capped backoff + per-store jitter and re-sends a `Hello` snapshot.
- The Go CP must be re-coded as the `Attach` *server*.

## Where it lives

`crates/portcullis-control/src/{transport.rs,channel.rs}`; `engined/compose.rs`
(step 5); `proto/enforcement.proto` (`Attach`, `ControlFrame`/`EngineFrame`).
