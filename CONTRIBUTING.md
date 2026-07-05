# 🤝 Contributing to portcullis

Thanks for working on the enforcement engine. This is safety-critical, embedded networking code running on ~10,000 routers — correctness and footprint matter more than cleverness. Please read this before opening a change.

## 🧭 Before you start

- Read the [README](./README.md) (architecture & flows) and [`CLAUDE.md`](./CLAUDE.md) (the load-bearing invariants).
- Skim the per-area engineering notes in [`.claude/skills/`](./.claude/skills/) for the crate you're touching:
  `nft-ruleset` · `openwrt-build` · `netns-harness` · `accounting-metering` · `embedded-perf`.

## 🏗️ Architecture rules (non-negotiable)

1. **Depend only on `portcullis-types`.** Worker crates must not depend on each other; shared types and the port traits (`RulesetWriter`, `EventSink`, `NeighResolver`, `CounterSource`, `Enforcer`, `MeteringSink`) live in `portcullis-types`. The composition root `portcullis-engined` wires concrete adapters. This is what keeps crates independently testable.
2. **`portcullis-nft` is the only crate that touches netfilter.** Everything else goes through the `RulesetWriter` port.
3. **`portcullis-session` does no I/O.** Pure domain logic, fully unit-testable with mock ports and an injected `now: Instant`.
4. **Abstract Linux-only I/O behind a port trait** (subprocess via `tokio::process`), with an in-memory mock for tests. The workspace must build on the host (macOS/Linux), which is the CI-equivalent. Never add a dependency that only builds on Linux.

## 🛡️ The invariants (a change that breaks one will be rejected)

- **No fail-open** — every error path keeps prior state or fails closed.
- **No flash writes** — runtime state stays in RAM/tmpfs.
- **Single nft writer actor** — all mutations funnel through it.
- **`accept` is not terminal in nftables** — the `forward` chain drops unauth non-garden, lets the rest fall through to fw3; no postrouting/masquerade; touch only `inet wifihub`.
- **Kernel-as-truth** — adopt on restart, never flush.
- **Dual-path expiry** — grants always carry a set-element `timeout`.

When in doubt, the reviewer agents encode the full checklists:
[`.claude/agents/portcullis-reviewer.md`](./.claude/agents/portcullis-reviewer.md),
[`.claude/agents/security-auditor.md`](./.claude/agents/security-auditor.md),
[`.claude/agents/proto-contract-guard.md`](./.claude/agents/proto-contract-guard.md).

## ✅ Definition of done

Every PR must keep all of these green:

```bash
cargo build --workspace
cargo test  --workspace                          # currently 165 tests
cargo clippy --workspace --all-targets -- -D warnings
```

- Add unit tests for new logic; pure code should be fully covered.
- New behavior reachable from a client request must include a "no panic on adversarial input" test (the `:8080` responder is the primary attack surface).
- Keep `#![forbid(unsafe_code)]` — no `unsafe`.
- Mind the footprint: prefer `Box<str>`/compact types, bounded channels, and capacity hints on hot/periodic paths (see `embedded-perf`). If you add a dependency, justify its binary-size cost.

## 🔌 Changing the gRPC contract

`proto/enforcement.proto` is **shared with the Go control plane**. proto3 wire rules: never renumber/retype/reuse a field tag; only add new tags; reserve removed ones. A proto change usually needs a matching change on the Go side — call it out in the PR.

## 🧪 Testing layers

- **Unit / mock-backend:** always run in plain `cargo test`.
- **Linux netns integration & fault injection:** gate behind a `requires-root` runner (see `netns-harness`); don't make them part of the default `cargo test`.
- **On-device:** RUTM11 acceptance items (nft-vs-fw3 priorities, conntrack-under-NAT, flash-write audit) are validated in the lab, not in CI.

## 🌱 Commit / PR style

- Small, focused commits; reference the TDD section (e.g. `§7.4`) when relevant.
- Describe *why*, and which invariant(s) the change touches.
- If a change is a deliberate trade-off (e.g. degrade-and-log), say so and add a metric/log so it's observable.
