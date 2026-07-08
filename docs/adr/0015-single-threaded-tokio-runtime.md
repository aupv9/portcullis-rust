# ADR-0015: Single-threaded Tokio runtime for the embedded target

- Status: Accepted
- Recorded: 2026-07-08

## Context

The device is a 2-core ~880 MHz MIPS box with 256 MB RAM and a <30 MB RSS budget.
The data plane lives in the kernel (nftables); the daemon itself is purely
control/metering — a handful of long-lived, I/O-bound tasks (gRPC, redirect,
accounting, garden, expiry) with tiny per-store churn.

## Decision

Run a `current_thread` Tokio runtime (`#[tokio::main(flavor = "current_thread")]`),
not `rt-multi-thread`. This lets the workspace drop the `rt-multi-thread` feature
entirely.

## Consequences

- Saves worker-thread stacks (RSS) and the multi-thread scheduler code (binary
  size) — a multi-thread runtime would buy nothing for this I/O-bound workload.
- Tasks must not block the executor; blocking file I/O uses `tokio::fs` (offloaded)
  and counters use `Mutex<u64>` not `AtomicU64` (32-bit MIPS has no 64-bit atomics).
- Same embedded-perf discipline drives other choices: no `EnvFilter` (drops the
  regex engine), size-first release profile (`opt-level=z`, LTO, `panic=abort`).

## Where it lives

`crates/portcullis-engined/src/main.rs`; workspace `tokio` features in `Cargo.toml`;
`portcullis-types::Counter`.
