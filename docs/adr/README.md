# Architecture Decision Records

The **in-repo source of truth** for *why* portcullis is built the way it is. Each
ADR captures one load-bearing decision reconstructed from the implemented engine —
so the rationale lives beside the code, not only in inline comments or the
local-only design doc (the `TDD §x` references scattered through the source).

These are descriptive (recorded from what shipped), not speculative. Where a
decision has a fuller write-up, the ADR links to [`../design/`](../design). The
load-bearing safety rules are also summarized as numbered invariants in
[`../../CLAUDE.md`](../../CLAUDE.md); the ADRs explain the decisions behind them.

## Index

| # | Decision | Touches |
|---|---|---|
| [0001](0001-hexagonal-ports-and-adapters.md) | Hexagonal core — crates depend only on `portcullis-types` (ports) | all crates |
| [0002](0002-no-radius-cp-is-nas-of-record.md) | No RADIUS — engine emits `SessionEvent`s; the Go CP is NAS-of-record | control, session |
| [0003](0003-cgnat-engine-dials-the-control-plane.md) | CGNAT — the engine dials the CP over an outbound mTLS bidi stream | control, engined |
| [0004](0004-kernel-as-truth-adopt-never-flush.md) | Kernel-as-truth — the nftables `auth` set is authoritative; adopt on restart | nft, session, engined |
| [0005](0005-single-nft-writer-actor.md) | A single writer actor owns every netfilter mutation | nft, session |
| [0006](0006-no-flash-writes-ram-tmpfs-only.md) | No runtime state on flash — RAM / tmpfs only | all |
| [0007](0007-fail-closed-everywhere.md) | Fail closed on every error path | all |
| [0008](0008-firewallbackend-trait-nft-and-ipset.md) | `FirewallBackend` trait + two backends (nft-json, ipset/iptables), auto-probe | nft, engined |
| [0009](0009-mac-session-key-hmac-signed-redirect.md) | MAC is the session key, signed by the redirect responder | redirect, session |
| [0010](0010-dual-path-expiry.md) | Dual-path expiry — kernel timeout + daemon sweep | session, nft |
| [0011](0011-conntrack-subset-of-auth-reaping.md) | `conntrack ⊆ auth` — reap established flows on de-auth | session, accounting |
| [0012](0012-runtime-control-state-and-engine-control-port.md) | Runtime control-state store + `EngineControl` port (CP config-push) | types, engined, control |
| [0013](0013-bandwidth-shaping-tc-htb.md) | Bandwidth shaping via `tc`/HTB, capability-gated `rate_bps` | accounting, session |
| [0014](0014-backend-aware-walled-garden.md) | Backend-aware walled garden (`nftset=` vs `ipset=`) | garden, engined |
| [0015](0015-single-threaded-tokio-runtime.md) | Single-threaded Tokio runtime for the embedded target | engined |
| [0016](0016-proto-contract-buf-committed-bindings.md) | gRPC contract via Buf; committed bindings; superset/reserved-tag discipline | proto, control |
| [0017](0017-upx-packing-flash-budget.md) | UPX-pack the binary for the flash budget (trades RAM) | deploy |

## Format

Short [MADR](https://adr.github.io/madr/)-style: **Status · Context · Decision ·
Consequences · Where it lives**. Status is `Accepted` unless noted. A superseded
decision keeps its file and links forward (e.g. WireGuard → [0003](0003-cgnat-engine-dials-the-control-plane.md)).
