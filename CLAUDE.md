# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state: implemented

The full Cargo workspace is implemented and tested (9 crates; host build/tests + clippy green). The architecture below is real, not aspirational. Section references like `(§7.4)` point at the internal design doc, which is kept **out of this repo** (local-only); the README plus these notes are the public source of truth. (The "planned commands" / "workspace does not exist yet" phrasing further down predates the implementation — treat the workspace as present.)

## What `portcullis` is

The **data-plane enforcement arm** of an ad-gated public-WiFi captive portal — a single Tokio daemon running on each site's OpenWrt router (built for the Teltonika RUTM11; one router per site, scaling to thousands of sites). Its one job: **no client reaches the internet until the central control plane explicitly grants a session**, then enforce/meter/expire that grant.

It is **not** a NAS, not an ad renderer, not a business-logic owner. Hard boundaries (do not blur these):
- **RADIUS** is spoken only by the Go control plane. `portcullis` never speaks RADIUS — it emits `SessionEvent`s; the control plane translates them to RADIUS Accounting.
- **Ad decisioning / OTP / rendering** live in the Next.js portal + Rust/Axum ad engine.
- `portcullis` owns exactly **one nftables table** (`inet wifihub`) and never touches any other table or fw3's rules.

Client data traffic breaks out **locally** at the store's WAN. The router sits behind **CGNAT**, so the engine **dials the control plane outbound** over an mTLS gRPC bidirectional stream (no WireGuard, no inbound port) carrying **control + accounting only**, never client data. See `docs/design/cgnat-bidi-control-channel.md`. Identity is the client **MAC** (visible at L2 locally), not IP.

## Target architecture (Cargo workspace, TDD §6)

```
crates/
  portcullis-engined/    binary: runtime, signals, composition root, restart adoption
  portcullis-nft/        ONLY crate touching netfilter; FirewallBackend trait + nft -j impl + single-owner writer actor
  portcullis-session/    pure domain (Session lifecycle, expiry, quota math) — NO I/O, fully unit-testable
  portcullis-redirect/   :8080 HTTP 302 responder + MAC lookup via neigh table + HMAC signing
  portcullis-garden/     manages dnsmasq nftset entries (owns domain list only, no DNS logic)
  portcullis-accounting/ conntrack metering + quota watcher + event export
  portcullis-control/    tonic gRPC client: dials CP over mTLS bidi stream (CGNAT-safe) + on-net/dev server
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

## Platform constraints (RUTM11 / RutOS — §5)

- **Target triple: `mipsel-unknown-linux-musl`** (MediaTek MT7621, MIPS 1004Kc, little-endian). Statically linked against musl. Expect `build-std` friction; this is harder than the ARM/RUTX path.
- RutOS 7.x = **OpenWrt 21.02, kernel 5.4.147**. The native firewall is **fw3 (iptables/xtables), not fw4/nftables**. `portcullis` runs its own `nf_tables` table *alongside* fw3 — non-standard coexistence, ordered by hook priority (`dstnat - 50`, `filter - 50`). This is the single biggest design risk (§18) and must be validated on-device.
- `kmod-nft-*` + `nftables` userspace may not ship in stock RutOS — may need SDK-building. `dnsmasq-full` (not stock slim dnsmasq) is required for `nftset=`.
- Firewall backend: **`nftables-rs` (drives `nft -j` JSON)** is chosen — pure-Rust, easiest MIPS cross-compile; fork/exec per batch is fine because per-store churn is tiny. Abstracted behind the `FirewallBackend` trait so it can be revisited (fallback: `rustables` netlink, or iptables/ipset).
- Resource budget: < 30 MB RSS steady-state, binary < 15 MB, on 256 MB RAM.
- **Secondary target — RUT200 (MT7628, `ramips/mt76x8`):** same `mipsel-unknown-linux-musl` triple / `mipsel_24kc` arch, but only **128 MB RAM and 16 MB SPI NOR flash**. Flash is the binding constraint: the package builds with the `release-min` profile (`panic="abort"` + `-Z build-std-features=panic_immediate_abort`) and is UPX-packed by default (`PORTCULLIS_UPX=1`) so the on-flash binary lands ~1 MB. See `deploy/PACKAGING.md §5.1`.

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

# Cross-compile for the router
cargo build --release --target mipsel-unknown-linux-musl

# Package as .ipk via the RutOS / OpenWrt SDK (ramips/mt7621 target)
./scripts/dockerbuild make pm                    # produces bin/packages/<arch>/*.ipk
```

When adding the proto, regenerate the tonic bindings from `proto/enforcement.proto` (the Go control plane shares this contract — keep `package wifihub.enforcement.v1` and the message fields in sync).

## When choosing an implementation approach

The TDD (§17) explicitly flags that **adopting/forking openNDS (option C)** may be higher-leverage than a from-scratch nftables engine (option A), and that the **iptables/ipset path (option B)** avoids the nft-module risk. The from-scratch nftables build is the documented plan but the POC (§16 step 1) is a **go/no-go gate**. Don't treat option A as settled — surface the alternative if the platform risks in §18 bite.
