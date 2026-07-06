# 📦 Building & installing the portcullis `.ipk` on RutOS

End-to-end guide to turn this Rust workspace into an OpenWrt package and install
it on a **Teltonika RUTM11** (RutOS 7.x = OpenWrt 21.02, `ramips/mt7621`,
`mipsel-unknown-linux-musl`) or a **Teltonika RUT200** (MT7628, `ramips/mt76x8`,
same triple / `mipsel_24kc` arch). The only differences are the SDK subtarget you
unpack and — because the RUT200 has just **16 MB SPI NOR flash** — that the binary
is UPX-packed by default (see [§5.1](#51-size--the-rut200-16-mb-flash-budget)).

> TL;DR
> ```sh
> # on a Linux build host, inside an extracted RutOS/OpenWrt SDK:
> ln -s /path/to/portcullis-rust/deploy package/portcullis
> ./scripts/feeds update -a && ./scripts/feeds install -a
> make defconfig
> make package/portcullis/compile V=s
> # → bin/packages/mipsel_24kc/base/portcullis_0.1.0-1_mipsel_24kc.ipk
> scp bin/packages/*/base/portcullis_*.ipk root@ROUTER:/tmp/
> ssh root@ROUTER 'opkg install /tmp/portcullis_*.ipk'
> ```

---

## 0. ⚠️ Read first — the hard part

`mipsel-unknown-linux-musl` is a **Rust tier-3 target**: `rustup` ships **no
prebuilt `std`** for it. You cannot just `cargo build --target …`; `std` must be
built from source. There are two supported routes (pick one):

| Route | How | When |
|---|---|---|
| **A — OpenWrt `rust` feed (recommended)** | Use the feed's `rust-package.mk`, which provisions a matching Rust toolchain + target sysroot and drives cargo for you. | If the `rust` feed builds for your SDK. Most reliable. |
| **B — manual `-Z build-std`** | Nightly Rust + `rust-src`, link against the SDK's musl toolchain. This is what the committed [`Makefile`](./Makefile) does. | Fallback if the feed is unavailable / too old. |

This is the single biggest packaging risk and the gate for the field rollout
(see the project's design notes). `protoc` is **not** a concern — it's vendored
by the build script and runs on the build host.

---

## 1. Prerequisites (build host)

- A **Linux x86_64** build host (the OpenWrt SDK is Linux-only). On macOS/Windows,
  run it in a Linux container/VM. ~10 GB free disk.
- Standard build tooling: `build-essential gcc g++ make git unzip wget python3
  libncurses-dev zlib1g-dev gawk gettext rsync file`.
- The **RutOS SDK** matching your router's firmware version. Get it from the
  Teltonika wiki ("RUTOS Software Development Kit") for the RUTM11 / `ramips
  mt7621` target. (An upstream OpenWrt **21.02 `ramips/mt7621` SDK** is a usable
  base if you only need the package mechanics; for production, use the genuine
  RutOS SDK so the toolchain/libc match the device exactly.)

---

## 2. Get & unpack the SDK

```sh
# Example — replace with the exact SDK tarball for your RutOS version.
# RUTM11 (MT7621):
wget <RUTOS_SDK_URL>/openwrt-sdk-*-ramips-mt7621_*.tar.xz
tar xf openwrt-sdk-*-ramips-mt7621_*.tar.xz
cd openwrt-sdk-*-ramips-mt7621*/
# RUT200 (MT7628): use the ramips/mt76x8 SDK instead —
#   openwrt-sdk-*-ramips-mt76x8_*.tar.xz
```

Everything below runs **from the SDK root**. The recipe is subtarget-agnostic
(same `mipsel-unknown-linux-musl` triple); only the SDK you unpack differs.

---

## 3. Wire in the package + feeds

The committed [`Makefile`](./Makefile) lives in `deploy/` and expects the
workspace root one level up (`deploy/..`). Expose `deploy/` to the SDK as a
package named `portcullis`:

```sh
ln -s /abs/path/to/portcullis-rust/deploy package/portcullis
```

Update feeds (this pulls `nftables`, `dnsmasq-full`, and — for route A — `rust`):

```sh
./scripts/feeds update -a
./scripts/feeds install -a
# Route A only — make sure the rust host-compiler package is selectable:
./scripts/feeds install rust
```

> If `kmod-nft-*` / `nftables` / `dnsmasq-full` are **absent** from your SDK's
> feeds, build them from the SDK too (they're declared as package `DEPENDS`, so
> selecting `portcullis` pulls them into the build).

---

## 4. Configure the target

```sh
make defconfig                 # seeds .config for the SDK's ramips/mt7621 target
make menuconfig                # optional: navigate to
                               #   Network ---> portcullis  → <M> (build as module/.ipk)
```

Confirm the architecture is `mipsel_24kc` (both mt7621 and mt76x8 use it). Save
and exit.

---

## 5. Build the package

```sh
make package/portcullis/compile V=s
# Teltonika SDKs often wrap the toolchain in Docker — then use:
# ./scripts/dockerbuild make package/portcullis/compile V=s
```

Output:

```
bin/packages/mipsel_24kc/base/portcullis_0.1.0-1_mipsel_24kc.ipk
```

(arch string may differ slightly by SDK; `ls bin/packages/*/*/portcullis_*.ipk`).

### 5.1 Size — the RUT200 16 MB flash budget

The RUT200's 16 MB SPI NOR leaves only a few MB of writable overlay after RutOS,
so the package is built small by default:

- **`release-min` cargo profile** (`--profile release-min`, `panic = "abort"`),
  plus `-Z build-std-features=panic_immediate_abort` to drop the panic-format
  machinery from `std` — a sizeable win on MIPS. The `Build/Compile` step already
  passes both.
- **UPX compression** of the final binary (`PORTCULLIS_UPX=1`, the default). This
  keeps the on-flash binary ~1 MB no matter how well (or poorly) the device's
  overlay filesystem compresses. The packed binary self-decompresses into RAM at
  start — negligible on the RUT200's 128 MB. Install `upx`/`upx-ucl` on the build
  host; if it's missing the build warns and ships the uncompressed binary.

```sh
# roomy RUTM11 NAND — packing optional:
make package/portcullis/compile V=s PORTCULLIS_UPX=0
# RUT200 (tight flash) — default:
make package/portcullis/compile V=s            # PORTCULLIS_UPX=1
```

Measured on the x86_64 host proxy (device numbers differ but track the same way):
`release` 3.49 MB → `release-min` 3.09 MB → `release-min` + UPX **1.12 MB** (−68 %).

### Route A note (rust feed)

If you prefer the feed-based build, replace the `Build/Compile` block in the
Makefile with the feed helper instead of the manual cargo call:

```make
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk
# ...
RUST_PKG_FEATURES:=
define Build/Compile
	$(call Build/Compile/Cargo)
endef
```

and add `+rust/host` to build deps. The feed handles the target sysroot + linker,
which sidesteps most of the manual `-Z build-std` friction in §0.

---

## 6. Install on the RUTM11

Copy the `.ipk` to the router's tmpfs and install:

```sh
scp bin/packages/*/base/portcullis_*.ipk root@ROUTER_IP:/tmp/
ssh root@ROUTER_IP
opkg update                              # so deps can resolve from the feed
opkg install /tmp/portcullis_*.ipk
```

`opkg` pulls the declared deps (`nftables`, `kmod-nft-*`, `dnsmasq-full`). If a
dep isn't in the device's opkg feed, `scp` and `opkg install` it manually first.

The install lays down:

| Path | From |
|---|---|
| `/usr/sbin/portcullis` | the cross-compiled binary |
| `/etc/init.d/portcullis` | [`portcullis.init`](./portcullis.init) (procd) |
| `/etc/config/portcullis` | [`config/portcullis`](./config/portcullis) (UCI defaults) |
| `/etc/capabilities/portcullis.json` | [`capabilities/portcullis.json`](./capabilities/portcullis.json) |
| `/etc/uci-defaults/99-portcullis` | [`uci-defaults/99-portcullis`](./uci-defaults/99-portcullis) (runs once, then deleted) |

---

## 7. Provision the site (per-router)

The package ships **no secrets and no per-site identity** — provision them after
install (the fleet pipeline does this automatically; here are the manual steps):

```sh
# 7a. Identity + control endpoint (the engine DIALS this outbound — CGNAT-safe,
#     no inbound port is exposed on the router).
uci set portcullis.main.store_id='SITE-0042'
uci set portcullis.main.control_endpoint='https://cp.example.internal:8443'
uci set portcullis.main.cp_server_ca_file='/etc/portcullis/tls/cp-ca.crt'
uci set portcullis.main.cp_server_name='cp.example.internal'
uci commit portcullis

# 7b. Per-site HMAC key (signs the redirect identity tuple)
install -d -m700 -o portcullis -g portcullis /etc/portcullis
head -c32 /dev/urandom > /etc/portcullis/hmac.key
chmod 600 /etc/portcullis/hmac.key && chown portcullis:portcullis /etc/portcullis/hmac.key

# 7c. mTLS material for the control channel (provisioned, not generated here).
#     The engine is the CLIENT: it presents client.{crt,key} and verifies the
#     control plane's server cert against cp-ca.crt.
install -d -m700 -o portcullis -g portcullis /etc/portcullis/tls
#   place: client.crt  client.key  cp-ca.crt   (all 0600, owned by portcullis)

# 7d. dnsmasq-full must be the active resolver for the walled-garden nftset to
#     work. No overlay/tunnel is needed — outbound egress to the control plane
#     endpoint is sufficient (allow it in the site firewall if egress-filtered).
```

> Until the mTLS material is present the daemon **disables the control channel**
> (no new grants) rather than dialing without an identity — fail-closed.

---

## 8. Enable, start, verify

```sh
/etc/init.d/portcullis enable
/etc/init.d/portcullis start

# Logs (procd → syslog):
logread -e portcullis -f

# Process is up and unprivileged:
ps w | grep portcullis

# The engine's table exists and the gate is in place:
nft list table inet wifihub

# Redirect responder is listening on :8080:
ss -tlnp | grep 8080
```

**Functional check:** join the public SSID on a test client *without* a grant →
an HTTP request should be redirected (302) to the portal. After a `GrantSession`
from the control plane, the client's MAC appears in the `auth` set
(`nft list set inet wifihub auth`) and traffic forwards.

### Flash-write audit (important on NAND)

State is tmpfs-only by design. Confirm nothing writes to NAND under load:

```sh
mount | grep /tmp                 # /tmp must be tmpfs
ls -la /tmp/portcullis/           # runtime state lives here
# watch for unexpected writes to /overlay or /etc during operation
```

---

## 9. Upgrade & uninstall

```sh
# Upgrade (kernel keeps the auth set across the daemon restart → no client dropped):
opkg install --force-reinstall /tmp/portcullis_<newver>_*.ipk
/etc/init.d/portcullis restart

# Uninstall:
/etc/init.d/portcullis stop
opkg remove portcullis
# (config in /etc/config/portcullis and secrets in /etc/portcullis are kept; remove manually if desired)
```

---

## 10. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `make package/portcullis/compile` fails in `std`/`cargo` | tier-3 `build-std` (§0). Ensure nightly + `rust-src`, or switch to the rust-feed route A. |
| `nft: command not found` / table not created | `nftables` userspace / `kmod-nft-*` not installed on the device — `opkg install nftables kmod-nft-core kmod-nft-nat`. |
| Redirect/garden not working | `dnsmasq-full` not active (stock dnsmasq lacks `nftset`); check `/etc/dnsmasq.d/portcullis-garden.conf` and `/etc/init.d/dnsmasq reload`. |
| No new grants accepted | mTLS material missing/incorrect under `/etc/portcullis/tls/` (fail-closed by design). |
| Coexistence weirdness with the firewall | RutOS uses **fw3 (iptables)**, not fw4. Our `inet wifihub` table runs alongside it at hook priorities `dstnat-50` / `filter-50`; verify ordering with `nft list ruleset`. |
| Daemon won't start as non-root | check `/etc/capabilities/portcullis.json` (needs `CAP_NET_ADMIN`) and that the `portcullis` user exists (first-boot script). |

See also [`../.claude/skills/openwrt-build`](../.claude/skills/openwrt-build) for
the toolchain/packaging engineering notes, and [`README.md`](./README.md) for the
file/role overview.
