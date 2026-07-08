# ADR-0005: A single writer actor owns every netfilter mutation

- Status: Accepted (CLAUDE.md invariant #3)
- Recorded: 2026-07-08

## Context

Grants, revokes, expiry sweeps, reconcile repairs, and enforcement re-scoping can
all fire concurrently. Concurrent `nft` transactions against the same table race
and corrupt the ruleset.

## Decision

All netfilter mutations funnel through **one** `portcullis-nft::writer` actor over
an mpsc channel. Only the `SessionManager` issues commands to it. The actor
executes transactions serially and applies a **retry-once-then-degrade** policy
(never flush, never fail open on a transaction error).

## Consequences

- nft/ipset transactions never race — ordering is total.
- A clean seam for the retry/degrade logic and for injecting `MockBackend` in tests.
- The writer is a `Clone` handle (`RulesetWriter` port); many producers, one owner.

## Where it lives

`crates/portcullis-nft/src/writer.rs` (`WriterActor`, `WriterHandle`, `retry_once`);
consumers hold `Arc<dyn RulesetWriter>`.
