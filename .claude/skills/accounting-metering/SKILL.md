---
name: accounting-metering
description: Implement portcullis per-session byte accounting (conntrack/CTNETLINK under fw3 masquerade), quota enforcement, and rate limiting (tc/HTB). Use when working on portcullis-accounting, the metering loop, quota revocation, interim events, or bandwidth shaping.
---

# Accounting, quota & rate limiting

Covers `portcullis-accounting` and the shaping module (TDD §7.6, §7.7). The engine meters per-session bytes, emits accounting events to the control plane, and enforces quota/rate locally. The control plane turns events into RADIUS Accounting and ships to ClickHouse — **the engine never speaks RADIUS**.

## Byte metering via conntrack (§7.6)

- Enable kernel acct: `net.netfilter.nf_conntrack_acct=1`. Read counters via **CTNETLINK** (not by shelling out per poll if avoidable).
- **The router runs fw3 masquerade on the WAN.** Conntrack entries carry original/reply tuples; aggregate per client on the **original source** tuple — this yields correct per-client totals *despite* NAT. Do NOT aggregate on the reply/post-NAT side.
- Map the original source IP back to **MAC** via the kernel neighbour table (the session key is MAC, not IP).
- **Periodic loop, default 15 s** (matches openNDS's proven cadence; configurable `accounting_interval`). Each tick computes deltas and emits `INTERIM` `SessionEvent`s.
- **Re-baseline on restart, never assume zero.** On daemon start, read current conntrack counters as the baseline so an engine restart doesn't corrupt totals. A *router* reboot flushes conntrack → sessions naturally end (acceptable).
- Final accounting (`bytes_in`/`bytes_out`) is emitted on `EXPIRED` / `REVOKED` / `QUOTA_EXCEEDED`.

## Quota enforcement (§7.7)

- Condition: `bytes_in + bytes_out > quota_bytes` (where `quota_bytes == 0` means **unlimited** — skip the check).
- On breach: instruct the **SessionManager** to revoke (which deletes the `auth` element via the single nft writer actor) and emit `QUOTA_EXCEEDED`. The accounting loop does not mutate the ruleset directly.
- **TTL is the backstop:** even if the quota counter is unavailable, the kernel set-element `timeout` still expires the session — degrade quota gracefully and log, never fail open.

## Rate limiting / bandwidth shaping (§7.7)

- Use **`tc` (HTB)** on OpenWrt, **not** nftables `limit` — `limit` rate-limits *packets*, not bandwidth. This is a common mistake; don't reach for `nft ... limit rate` for `rate_bps`.
- Apply a per-tier or per-session HTB class when a session is granted; tear it down on expiry/revoke.
- This is an **optional Phase-2 module**. Phase 1 may ship without shaping if the uplink is otherwise capped (`rate_bps == 0` = unlimited).

## Failure behaviour (§11)

- Quota counter unavailable → sessions still expire on TTL; log and continue (graceful degrade).
- Bounded RAM only: the in-RAM event queue and per-session counters must be capped (10k-fleet budget: <30 MB RSS). Never grow unbounded while the control plane is unreachable — queue with a bound and drop/coalesce oldest interims if needed, but never the final stop event.
- All counters live in RAM/tmpfs — never persist to flash.
