# ADR-0013: Bandwidth shaping via `tc`/HTB, capability-gated `rate_bps`

- Status: Accepted (wiring shipped; tc execution device-validation pending)
- Recorded: 2026-07-08

## Context

Per-session bandwidth caps (`rate_bps`) are a hotspot-parity feature. nftables
`limit rate` caps *packets/sec*, not *bytes/sec* — the wrong tool. The CP must also
never believe a cap is in effect when it isn't.

## Decision

Shape with `tc`/HTB: a per-MAC HTB class (stable classid from the MAC) + filter on
the LAN egress, attached on grant and torn down on de-auth, behind a `Shaper` port
(`portcullis-types`) — `TcShaper` (real) / `NoopShaper` (default). Shaping is
**off by default** (`shape_bandwidth`), and the engine advertises the `shaper`
capability via `GetEngineInfo` **only when enabled**, so the CP only sends caps the
engine will honor. Applying/clearing is best-effort: a `tc` error degrades
bandwidth control but never fails the grant/gate ([0007](0007-fail-closed-everywhere.md)).

## Consequences

- Correct byte-rate caps; `rate_bps` (previously hard-rejected) now flows through
  and resolves from tier policy ([0012](0012-runtime-control-state-and-engine-control-port.md)).
- The `tc` invocation is device-specific — validated on the MIPS target, like the
  nft/ipset backends; host tests cover classid + argument construction + the
  session apply/clear wiring against a mock.

## Where it lives

`Shaper`/`NoopShaper` in `portcullis-types`; `TcShaper` in
`portcullis-accounting/src/shaper.rs`; injected into `SessionManager`; capability
gated in `engined/compose.rs` + `runtime.rs`.
