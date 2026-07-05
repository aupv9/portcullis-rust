---
name: netns-harness
description: Build and run portcullis integration tests using Linux network namespaces (veth pairs, fake clients) plus the fault-injection suite. Use when writing or debugging integration tests that assert ruleset verdicts, restart adoption, control-plane-loss behaviour, or no-fail-open.
---

# Network-namespace integration & fault-injection harness

The ruleset logic is **arch-independent**, so integration tests run on **x86 in CI** (TDD §15). Real RUTM11 hardware is reserved for platform-specific acceptance (module availability, fw3 priority ordering, conntrack-under-masquerade, flash audit, procd respawn). Requires root / `CAP_NET_ADMIN` and a kernel with `nf_tables` + `nft` userspace.

## Topology

Build a namespace per fake client and a "router" namespace that runs the real `inet wifihub` ruleset:

```
[client ns] --veth--> [router ns: nft ruleset + redirect responder + (mock) garden] --veth--> [upstream ns]
```

- Assign each client veth a MAC + IP; the router ns sees the MAC at L2 (matches the real local-breakout model).
- Populate `garden4/garden6` directly (skip dnsmasq) for determinism; or run dnsmasq-full in the router ns if testing garden reconciliation.
- The upstream ns stands in for "the internet" (an echo/HTTP server) so "forwarded" is observable.

## Verdict matrix to assert (the core of §15)

| Scenario | Setup | Expected |
|---|---|---|
| unauth HTTP `:80` | no `auth` element | redirected to `:8080` responder, gets 302 with valid HMAC sig |
| garden destination | dst in `garden4` | allowed pre-auth |
| authed client | MAC in `auth` | forwarded to upstream |
| expired | grant with short `timeout`, wait | element gone, next `:80` re-redirects |
| revoked | delete `auth` element | dropped immediately, `REVOKED` emitted with final bytes |
| unauth `:443` non-garden | no element | hits `forward` drop (no interception) |

Assert the **HMAC** on the 302 (`HMAC-SHA256(key, "<mac>|<store_id>|<ts>")`) and that the responder rejects/parses malformed requests safely.

## Fault injection (§15) — the no-fail-open guarantees

- **`kill -9` the daemon mid-session** → restart → assert it *adopts* kernel `@auth` (no client dropped), rebuilds in-RAM sessions, and **re-baselines accounting from current conntrack counters** (totals not corrupted, not reset to zero).
- **Sever the control-plane link** (kill the mock CP server the engine dials) → assert existing sessions keep being enforced, `SessionEvent`s queue in bounded RAM, new grants are blocked (fail-closed for *new* access), engine reconnects with backoff and re-sends its `Hello` snapshot.
- **Corrupt an nft transaction** → assert retry-once then degraded-mode; assert the ruleset is **not** flushed and nothing fails open.
- **Router-reboot analogue** (flush the ns ruleset + conntrack) → all sessions end, clients re-auth — acceptable, no persistence expected.

## Layers below integration

- **Unit:** `portcullis-session` (lifecycle/expiry/quota math) and `portcullis-redirect` (parsing, HMAC) are I/O-free — pure unit tests, run with `cargo test -p portcullis-session`.
- **nft layer:** test against `MockBackend` (the `FirewallBackend` trait), asserting the exact transaction batches produced for grant/revoke/adopt — no kernel needed.
- **Fuzz** the redirect parser (cf. CVE-2023-38314): malformed/missing query params must never panic or deref null.

Gate netns tests behind a feature/`#[ignore]` or a `requires-root` runner so the I/O-free unit + MockBackend tests always run in plain `cargo test`.
