# ADR-0001: Hexagonal core — depend only on `portcullis-types`

- Status: Accepted
- Recorded: 2026-07-08 (from the implemented workspace)

## Context

The engine touches the kernel (nftables/ipset), sockets (gRPC, HTTP), and shells
out (`ip`, `conntrack`, `tc`, `uci`). Mixing that I/O with the session/expiry/quota
logic would make the domain untestable without a live router and couple every
change to netfilter.

## Decision

A hexagonal (ports-and-adapters) layout. `portcullis-types` is the contract hub:
data types + object-safe **port traits** (`RulesetWriter`, `EventSink`,
`NeighResolver`, `CounterSource`, `Enforcer`, `MeteringSink`, `FlowReaper`,
`Shaper`, `EngineControl`, `MetricsSink`). Every other crate depends *only* on
`portcullis-types`. Concrete adapters (nft backends, conntrack, redirect, control
channel) implement the ports; the composition root `portcullis-engined` wires the
real adapters and is the only crate that knows about all of them.

## Consequences

- The domain (`portcullis-session`, parsers) is pure and unit-tested without a
  kernel; adapters are swapped for mocks (`MockBackend`, `MockNeighResolver`,
  `NoopReaper`, …).
- New capabilities add a port to `types` + an adapter, without touching siblings.
- Cost: a little indirection and some `Arc<dyn Trait>` in the composition root.

## Where it lives

`crates/portcullis-types/src/lib.rs` (ports); `crates/portcullis-engined/src/main.rs`
(`wire`) + `compose.rs` (adapter wiring).
