# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state: implemented

The full Cargo workspace is implemented and tested (9 crates; host build/tests + clippy green). The architecture below is real, not aspirational. Section references like `(§7.4)` point at the internal design doc, which is kept **out of this repo** (local-only); the README plus these notes are the public source of truth. (The "planned commands" / "workspace does not exist yet" phrasing further down predates the implementation — treat the workspace as present.)

## What `portcullis` is

The **data-plane enforcement arm** of an ad-gated public-WiFi captive portal — a single Tokio daemon running on each site's **OpenWrt** router (one router per site, scaling to thousands of sites). Its one job: **no client reaches the internet until the central control plane explicitly grants a session**, then enforce/meter/expire that grant.

**Not vendor-locked.** The only hard platform requirement is OpenWrt (vanilla OpenWrt, Teltonika RutOS, GL.iNet, or any OpenWrt-derived firmware). The firewall layer is behind the `FirewallBackend` seam (nftables `nft -j` *or* ipset+iptables/ip6tables, auto-selected at boot to match the kernel), so no single vendor's firmware is assumed. The **Teltonika RUTM11 / RutOS** is the **reference/primary validation device** — a deliberately constrained MIPS target chosen so that meeting its budget guarantees headroom elsewhere — not a supported-hardware whitelist.

It is **not** a NAS, not an ad renderer, not a business-logic owner. Hard boundaries (do not blur these):
- **RADIUS** is spoken only by the Go control plane. `portcullis` never speaks RADIUS — it emits `SessionEvent`s; the control plane translates them to RADIUS Accounting.
- **Ad decisioning / OTP / rendering** live in the Next.js portal + Rust/Axum ad engine.
- `portcullis` owns exactly **one nftables table** (`inet wifihub`) and never touches any other table or fw3's rules.

Client data traffic breaks out **locally** at the store's WAN. The WireGuard overlay carries **control + accounting only**, never client data. Identity is the client **MAC** (visible at L2 locally), not IP.

## Target architecture (Cargo workspace, TDD §6)

```
crates/
  portcullis-engined/    binary: runtime, signals, composition root, restart adoption
  portcullis-nft/        ONLY crate touching netfilter; FirewallBackend trait + nft -j impl + single-owner writer actor
  portcullis-session/    pure domain (Session lifecycle, expiry, quota math) — NO I/O, fully unit-testable
  portcullis-redirect/   :8080 HTTP 302 responder + MAC lookup via neigh table + HMAC signing
  portcullis-garden/     manages dnsmasq nftset entries (owns domain list only, no DNS logic)
  portcullis-accounting/ conntrack metering + quota watcher + event export
  portcullis-control/    tonic gRPC server, mTLS over WireGuard
  portcullis-config/     UCI/TOML config types, load, hot-reload
proto/enforcement.proto  contract shared with the Go control plane (package wifihub.enforcement.v1)
deploy/                  procd init script, OpenWrt SDK Makefile, uci-defaults first-boot bootstrap
```

## Invariants that are easy to break (read before touching enforcement code)

These come from §5/§7 and are load-bearing — violating them causes flash failure, fail-open, or races:

1. **No runtime state on flash.** All session/runtime state lives in RAM/tmpfs (`/tmp/portcullis/`). Writing session state to NAND wears it out and bricks routers (openNDS precedent, §5.4). No sqlite/redb-on-flash. Durability comes from the kernel holding the ruleset + the control plane as source of truth.
2. **Kernel-as-truth, not process memory (§7.8).** The nftables `auth` set with per-element `timeout` is authoritative. On daemon restart, *adopt* existing kernel state (list `@auth`, rebuild in-RAM view, re-baseline accounting) — never drop authorized clients, never flush.
3. **All nftables mutations go through the single `portcullis-nft::writer` actor (§7.9)** via an mpsc channel. Only the SessionManager issues commands to it. nft transactions must not race.
4. **In nftables, `accept` in a base chain is NOT globally terminal — only `drop` is (§7.1).** The `forward` chain is a pre-filter that *drops* unauth non-garden traffic and lets everything else fall through to fw3. Never try to "force accept".
5. **Never fail open (G2).** Every error branch keeps prior state or fails closed. Control-plane unreachable → keep enforcing existing sessions, block *new* grants, queue events in RAM. nft txn error → retry once, then mark degraded; never flush.
6. **Dual-path expiry:** the kernel set-element `timeout` is the backstop (removes the element even if the daemon is dead); the daemon also tracks `expires_at` to emit accounting-stop. Neither path alone can leave a permanent session.
7. **MAC is the session key, signed by the router.** The redirect responder computes `sig = HMAC-SHA256(key, "<mac>|<store_id>|<ts>")`; the portal/control plane trust `mac`/`store` only because the signature validates. A client cannot forge another's MAC into a grant.
8. **The redirect responder (:8080) is the primary inbound attack surface.** It's reachable by any unauthenticated client. Strict/bounded request parsing, no client-controlled data in privileged paths, fuzz the parser (cf. CVE-2023-38314, an openNDS NULL-deref DoS via a missing query param).

## Platform constraints (OpenWrt; validated on the RUTM11 reference — §5)

These are **OpenWrt-class realities**, not one vendor's quirks — RutOS is just where they were first hit. Portability across OpenWrt firmwares is a first-class goal.

- **Targets: any OpenWrt CPU family** — CI cross-builds static-musl `.ipk`s for `mipsel-unknown-linux-musl` (MT7621, RUTM11-class), `mips-unknown-linux-musl` (RUT9xx), and `armv7-unknown-linux-musleabihf` (RUTX and many OpenWrt APs). MIPS is the hardest (`build-std` friction, no 64-bit atomics); if it builds there it builds on the ARM path.
- **Native firewall varies by firmware.** OpenWrt 21.02 / RutOS 7.x use **fw3 (iptables/xtables)**; OpenWrt 22.03+ uses **fw4 (nftables)**. `portcullis` runs its **own** table/sets *alongside* the native firewall (non-invasive coexistence, ordered by hook priority `dstnat -50` / `filter -50`) — never editing the vendor's rules. This coexistence is the single biggest design risk (§18) and must be validated per firmware.
- **Backend auto-detect handles the variance.** At boot the engine probes for nftables-NAT support: present → `NftJsonBackend` (`nft -j`); absent (e.g. stock RutOS lacks `CONFIG_NFT_NAT`) → `IpsetIptablesBackend` (ipset + iptables/ip6tables, runs on stock firmware). Both sit behind the `FirewallBackend` trait; the choice is config-overridable (`firewall_backend = auto|ipset|nft`) and advertised as a capability. `dnsmasq-full` (not slim dnsmasq) is required for the `ipset=`/`nftset=` walled garden.
- Resource budget: < 30 MB RSS steady-state, binary < 15 MB — sized for the 256 MB RUTM11 low end, so roomier OpenWrt hardware has headroom.

## Commands (planned — workspace does not exist yet)

Once the Cargo workspace is scaffolded, the intended commands are:

```bash
# Host build / test (ruleset logic is arch-independent; CI runs on x86)
cargo build --workspace
cargo test  --workspace
cargo test -p portcullis-session                 # single crate
cargo test -p portcullis-session expiry          # single test by name filter

# nft layer is tested against a MockBackend; integration tests use Linux netns
# (veth pairs + fake clients), asserting: unauth->redirect, garden->allow,
# authed->forward, expired->re-gate, revoked->drop.

# Cross-compile for an OpenWrt target (pick the arch for your device)
cargo build --release --target mipsel-unknown-linux-musl        # or mips- / armv7-...

# CI cross-builds .ipk for all three arches (zig, no vendor SDK); or via an SDK:
./scripts/dockerbuild make pm                    # produces bin/packages/<arch>/*.ipk
```

When adding the proto, regenerate the tonic bindings from `proto/enforcement.proto` (the Go control plane shares this contract — keep `package wifihub.enforcement.v1` and the message fields in sync).

## When choosing an implementation approach

The TDD (§17) explicitly flags that **adopting/forking openNDS (option C)** may be higher-leverage than a from-scratch nftables engine (option A), and that the **iptables/ipset path (option B)** avoids the nft-module risk. The from-scratch nftables build is the documented plan but the POC (§16 step 1) is a **go/no-go gate**. Don't treat option A as settled — surface the alternative if the platform risks in §18 bite.
