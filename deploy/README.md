# 📦 deploy/ — OpenWrt packaging for portcullis

Artifacts that turn the Rust workspace into an installable RutOS/OpenWrt package
for the Teltonika **RUTM11** (`ramips/mt7621`) and **RUT200** (`ramips/mt76x8`) —
same `mipsel-unknown-linux-musl` triple and `mipsel_24kc` arch, different SDK
subtarget. See the [`openwrt-build`](../.claude/skills/openwrt-build) skill.

> 🪶 **Flash budget.** The RUT200 has only **16 MB SPI NOR flash** (vs the RUTM11's
> roomy NAND). The package is built with the size-first `release-min` cargo profile
> (`panic=abort` + `-Z build-std-features=panic_immediate_abort`) and, by default,
> UPX-packed so the on-flash binary lands ~1 MB. Pass `PORTCULLIS_UPX=0` to skip
> packing. Install `upx` (or `upx-ucl`) on the build host, or you'll get a warning
> and an uncompressed binary.

> 📘 **Full step-by-step build + install + provision + verify guide:
> [`PACKAGING.md`](./PACKAGING.md).** Or run [`build-ipk.sh`](./build-ipk.sh)
> against an extracted SDK: `SDK_DIR=/path/to/sdk ./deploy/build-ipk.sh`.

| File | Installs to | Purpose |
|---|---|---|
| `Makefile` | — | OpenWrt SDK package recipe (cross-compile + package the `.ipk`) |
| `portcullis.init` | `/etc/init.d/portcullis` | procd init: supervise as non-root + `CAP_NET_ADMIN`, respawn, hot-reload |
| `config/portcullis` | `/etc/config/portcullis` | default UCI config (§9); per-store values filled by the fleet pipeline |
| `capabilities/portcullis.json` | `/etc/capabilities/portcullis.json` | procd capability set — `CAP_NET_ADMIN` only |
| `uci-defaults/99-portcullis` | `/etc/uci-defaults/99-portcullis` | first-boot: user, tmpfs state dir, secrets dir, dnsmasq garden seed, enable service |

## Build

```sh
# Inside a RutOS / OpenWrt SDK checkout (ramips/mt7621 target):
cp -r <this-repo> package/portcullis     # the recipe expects deploy/.. = workspace root
./scripts/feeds update -a && ./scripts/feeds install -a
make package/portcullis/compile V=s
# -> bin/packages/<arch>/.../portcullis_0.1.0-1_*.ipk
```

## ⚠️ Known open item — MIPS toolchain

`mipsel-unknown-linux-musl` is a Rust **tier-3** target (no prebuilt `std`), so the
Makefile builds `std` from source with `-Z build-std` on nightly, linked against
the SDK's musl toolchain (TDD §5.3, §18 item 3). This is the single biggest build
risk; if the `rust` OpenWrt feed is available, prefer its `rust-package.mk`. The
host CI build (stable) is the correctness gate; this packaging path is validated
on real RUTM11 hardware (TDD §16 POC), not in generic CI.

## Provisioning boundary

Per-store identity is **not** baked into the package (TDD §13): `store_id`,
`control_endpoint`, the per-store HMAC key, and the mTLS material (client
cert/key + pinned control-plane server CA) are injected by the fleet
provisioning pipeline into `/etc/config/portcullis` and
`/etc/portcullis/{hmac.key,tls/}` (`0600`, owned by the `portcullis` user). The
first-boot script only prepares directories and the dnsmasq garden wiring.
