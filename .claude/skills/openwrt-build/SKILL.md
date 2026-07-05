---
name: openwrt-build
description: Cross-compile portcullis for the RUTM11 (mipsel-unknown-linux-musl) and package it as an OpenWrt .ipk via the RutOS SDK, including procd init, capabilities, and dependency declaration. Use when working on the deploy/ directory, the package Makefile, cross-compilation toolchain, or first-boot bootstrap.
---

# Building & packaging portcullis for RutOS / RUTM11

Target hardware: Teltonika RUTM11 — MediaTek MT7621 (MIPS 1004Kc, little-endian), 256 MB RAM, 16 MB NOR + 256 MB NAND. Firmware: RutOS 7.x = OpenWrt 21.02, kernel 5.4.147. See TDD §5, §10.

## Toolchain reality (budget time for this — TDD §18 item 3)

- **Rust target: `mipsel-unknown-linux-musl`**, statically linked against musl. This is a less-travelled target than ARM — confirm std/tier availability; you may need `-Z build-std` and to link against the **SDK's musl toolchain**. This is meaningfully harder than the RUTX/ARM (ipq40xx) path.
- Keep the binary lean: target **< 15 MB binary, < 30 MB RSS**. Prefer `nftables-rs` (pure Rust, no C link) over netlink-C-lib backends specifically because it cross-compiles cleanly on MIPS.

```bash
# Cross-compile
cargo build --release --target mipsel-unknown-linux-musl
# (configure linker + sysroot in .cargo/config.toml to point at the SDK musl toolchain)
```

## OpenWrt SDK / .ipk packaging

The **RutOS SDK is a standard OpenWrt buildroot** for the `ramips/mt7621` target. Packages build under `bin/packages/<arch>/`.

```bash
./scripts/dockerbuild make pm        # build packages -> bin/packages/<arch>/*.ipk
```

Two things may need to be SDK-built (don't assume they're in the stock feed — TDD §18 item 1):
- `kmod-nft-*` + `nftables` userspace (the `nft` binary the engine execs).
- `dnsmasq-full` (stock slim dnsmasq lacks `nftset=`).

Declare these as package dependencies in the Makefile so they're pulled or co-built.

## Runtime packaging rules (deploy/)

- **procd init script** with respawn (threshold/timeout/retry), started early at boot.
- **Least privilege:** dedicated non-root user with **`CAP_NET_ADMIN` only** (via procd capabilities). No root.
- **State dir is tmpfs** (`/tmp/portcullis/`) — NEVER write runtime state to NAND (flash wear bricks routers; TDD §5.4). Audit for zero NAND writes under sustained load (§18 item 4).
- **Config via UCI** (`/etc/config/portcullis`), bootstrapped by `uci-defaults/` at first boot (store_id, outbound control endpoint, mTLS client cert/key + pinned CP server CA, HMAC key, dnsmasq-full garden config). No WireGuard — the engine dials the control plane outbound (CGNAT). Hot-reloadable: garden FQDN list, tier defaults, accounting interval. Restart-required: control endpoint, CP server CA/name, HMAC key, responder port.

## Fleet context

`portcullis` is one artifact among the store's provisioned config across ~10,000 routers. The **control plane** owns version pinning and rollout (desired state in Git/Postgres vs device state via the RutOS API); the engine is a *target*, not the orchestrator. Rollout is canary → pilot (5–20 stores) → ring (1% → 10% → 50% → 100%) gated on health metrics (TDD §16). The POC on real RUTM11 hardware is the **go/no-go gate** for the whole nftables-on-fw3 approach.
