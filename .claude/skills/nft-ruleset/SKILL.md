---
name: nft-ruleset
description: Reason about and modify the portcullis nftables ruleset (table inet wifihub) on RutOS/OpenWrt 21.02 where fw3/iptables is the native firewall. Use when working on portcullis-nft, the redirect/forward/garden chains, set-element grant/revoke, hook priorities vs fw3, or netns verdict tests.
---

# nftables ruleset work for portcullis

The engine owns **exactly one table, `inet wifihub`**, running *alongside* the platform's native **fw3 (iptables/xtables)** — RutOS 7.x is OpenWrt 21.02, kernel 5.4.147, so there is no fw4. Netfilter multiplexes both backends at the hooks, ordered by priority. Read TDD §5.2, §7.1, §7.8 before changing rules.

## Non-negotiable semantics (these cause silent fail-open if wrong)

- **`accept` in a base chain is NOT globally terminal — only `drop` is.** A packet that `accept`s in our chain still traverses other base chains at the same hook (including fw3's). So our `forward` chain is a *pre-filter*: it `drop`s unauthenticated non-garden traffic (terminal) and lets everything else fall through to fw3, which already permits LAN→WAN. Never try to "force accept".
- **We never duplicate NAT.** fw3 already masquerades the WAN. No `postrouting`/masquerade in `inet wifihub`.
- **We never touch any other table** and never flush. fw3 manages xtables; we manage one nf_tables table. Bootstrap is idempotent: create-if-missing, adopt-if-present.
- **Hook priority offsets (`dstnat - 50`, `filter - 50`) put us *before* fw3** so our redirect/drop decisions run first. These offsets are a starting point and **must be verified on-device** (TDD §18 item 2) — fw3's actual hook priorities on RutOS decide the real numbers.

## Base ruleset (TDD §7.1)

```nft
table inet wifihub {
    set garden4 { type ipv4_addr; flags interval; }   # populated by dnsmasq nftset
    set garden6 { type ipv6_addr; flags interval; }
    set auth    { type ether_addr; flags timeout; }    # authorized MACs, kernel-expired

    chain prerouting {
        type nat hook prerouting priority dstnat - 50; policy accept;
        ether saddr @auth accept
        ip   daddr @garden4 accept
        ip6  daddr @garden6 accept
        tcp dport 80 redirect to :8080                 # unauth HTTP -> local 302 responder
    }
    chain forward {
        type filter hook forward priority filter - 50; policy accept;
        ct state established,related accept
        ether saddr @auth accept
        ip   daddr @garden4 accept
        ip6  daddr @garden6 accept
        drop                                           # terminal: unauth + non-garden
    }
}
```

`:443` is deliberately NOT intercepted — capturing it breaks TLS and is unnecessary (OS captive-portal detection probes a `:80` URL, which the redirect catches). Pre-auth `:443` to non-garden just hits the `forward` drop.

## Per-session hot path (single element op)

- **Grant:** `add element inet wifihub auth { aa:bb:cc:dd:ee:ff timeout 1800s }` — the `timeout` IS the session length.
- **Revoke:** `delete element inet wifihub auth { aa:bb:cc:dd:ee:ff }`
- **Expiry is the kernel's job:** when the timeout elapses the kernel removes the element automatically; the client's next `:80` falls back to redirect (re-gates ads). Always set a `timeout` on grant — never add a permanent element.

## Backend & implementation rules

- Backend is **`nftables-rs` driving `nft -j` (JSON)** — pure Rust, easiest MIPS cross-compile; fork/exec per batch is fine (per-store churn is tiny). It requires the `nft` binary at runtime. Abstracted behind the `FirewallBackend` trait so `MockBackend` is used in unit tests.
- **All mutations go through the single `portcullis-nft::writer` actor.** Build transactions as atomic batches; log the JSON at DEBUG for debuggability. On txn error: retry once, then mark degraded — never flush, never fail open.
- Garden sets are populated by **dnsmasq** via `nftset=/.../4#inet#wifihub#garden4` (needs `dnsmasq-full`). `portcullis-garden` owns only the FQDN list and reconciles dnsmasq config — it writes no DNS logic.

## Testing verdicts (TDD §15)

Integration tests run on x86 in CI (ruleset logic is arch-independent) using **Linux network namespaces**: build veth pairs + fake clients, apply the real ruleset, and assert: unauth → redirect; garden → allowed; authed → forwarded; expired → re-gated; revoked → dropped. Unit-test the nft layer against `MockBackend`. Reserve real RUTM11 hardware for the platform-specific checks (module availability, priority ordering vs fw3, conntrack-under-masquerade).
