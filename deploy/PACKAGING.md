# 📦 Building & installing the portcullis `.ipk` on RutOS

End-to-end guide to turn this Rust workspace into an OpenWrt package and install
it on a **Teltonika RUTM11** (RutOS 7.x = OpenWrt 21.02, `ramips/mt7621`,
`mipsel-unknown-linux-musl`).

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
# Example — replace with the exact SDK tarball for your RutOS version:
wget <RUTOS_SDK_URL>/openwrt-sdk-*-ramips-mt7621_*.tar.xz
tar xf openwrt-sdk-*-ramips-mt7621_*.tar.xz
cd openwrt-sdk-*-ramips-mt7621*/
```

Everything below runs **from the SDK root**.

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

Confirm the architecture is `mipsel_24kc` (mt7621). Save and exit.

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

## 5.5 Enforcement backend — ipset + iptables (NOT nftables NAT) ⚠️

**Why this matters (the §18 platform risk, confirmed on-device — RUTM11, kernel
6.6.126):** stock RutOS builds `nf_tables` modularly and ships `nft_ct`,
`nft_redir`, `nft_reject*`, … but **omits `nft_nat` / `nft_chain_nat` /
`nft_masq`** (`CONFIG_NFT_NAT` unset; the feed has no `kmod-nft-nat`). So a
`type nat hook prerouting` redirect chain fails ENOENT in both `inet` and `ip`
families — the pure-nft backend cannot run.

**Resolution:** the production backend is
[`portcullis_nft::IpsetIptablesBackend`] — `ipset` + `iptables`/`ip6tables`
(TDD §17 "option B", the same mechanism fw3/openNDS use). All of it is supported
on **stock firmware**, so there is **no custom kernel/firmware and no reflash** —
portcullis deploys fleet-wide as a plain `.ipk`. (`NftJsonBackend` remains in the
tree for hosts that do have nft NAT, but is not the default.)

Enforcement shape:

```text
ipset wifihub_auth  hash:mac (per-elem timeout)          authorized MACs
ipset wifihub_g4/g6 hash:net inet/inet6                  walled garden (dnsmasq ipset=)
iptables nat  wifihub_pre (PREROUTING): RETURN authed/garden ; else tcp:80 REDIRECT :8080
iptables filt wifihub_fwd (FORWARD)   : RETURN established/authed/garden ; else DROP
```

Verify a candidate router is ready **before** installing (or run
[`preflight.sh`](./preflight.sh), which checks all of this and prints GO/NO-GO):

```sh
sh /tmp/preflight.sh          # -> "PREFLIGHT: GO"
```

Everything the backend needs (ipset hash:mac+timeout, `-m set`, nat REDIRECT,
conntrack) is already present on a healthy RutOS unit because fw3 uses the same
subsystems — a stock RUTM11 passes preflight out of the box.

---

## 6. Install on the RUTM11

> ⚠️ **Always install via the `.ipk` + `opkg`** — never `make install` into a
> `/usr/local` prefix. opkg is what pulls the declared deps (`ipset`, `iptables`,
> `iptables-mod-ipset`, `iptables-mod-nat-extra`, `dnsmasq-full`) and registers
> the package for upgrades. A manual
> `/usr/local` drop skips deps entirely (missing `dnsmasq-full` → no garden;
> a `/usr/sbin/portcullis` the init `PROG` can't find → service never starts).

Copy the `.ipk` to the router's tmpfs and install:

```sh
scp bin/packages/*/base/portcullis_*.ipk root@ROUTER_IP:/tmp/
ssh root@ROUTER_IP
opkg update                              # so deps can resolve from the feed
opkg install /tmp/portcullis_*.ipk
```

`opkg` pulls the declared deps (`ipset`, `iptables`, `ip6tables`,
`iptables-mod-ipset`, `iptables-mod-nat-extra`, `dnsmasq-full`). These are stock
RutOS packages (fw3 already uses them), so no custom firmware is involved. If a
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
# 7a. Identity + control endpoint
uci set portcullis.main.store_id='SITE-0042'
uci set portcullis.main.control_endpoint='https://cp.example.internal:8443'
uci set portcullis.main.wg_interface='wg-hub'
uci commit portcullis

# 7b. Per-site HMAC key (signs the redirect identity tuple)
install -d -m700 -o portcullis -g portcullis /etc/portcullis
head -c32 /dev/urandom > /etc/portcullis/hmac.key
chmod 600 /etc/portcullis/hmac.key && chown portcullis:portcullis /etc/portcullis/hmac.key

# 7c. WireGuard overlay (wg-hub) must be up: the gRPC control server binds ONLY
#     on the WG interface address, and WG peer auth + encryption is the
#     authorization gate (§13). No app-layer mTLS material is needed.
#     dnsmasq-full must be the active resolver for the walled-garden ipset to work.
```

> The gRPC control server binds **only** on the WireGuard interface address. If
> that interface has no address yet (WG down / not provisioned) the daemon
> **disables the control plane** (no new grants) rather than exposing enforcement
> on another interface — fail-closed. App-layer mTLS was dropped: rustls' only
> pure-Rust crypto provider is alpha-grade and its C/asm providers (ring,
> aws-lc-rs) don't build for MIPS; WireGuard is the sufficient gate for this
> point-to-point link.

---

## 8. Enable, start, verify

```sh
/etc/init.d/portcullis enable
/etc/init.d/portcullis start

# Logs (procd → syslog):
logread -e portcullis -f

# Process is up and unprivileged:
ps w | grep portcullis

# The engine's sets + chains exist and the gate is in place:
ipset list wifihub_auth                 # auth set (empty until first grant)
ipset list -n | grep wifihub            # wifihub_auth, wifihub_g4, wifihub_g6
iptables -t nat -S wifihub_pre          # RETURN authed/garden ; REDIRECT :80->:8080
iptables -S wifihub_fwd                 # RETURN established/authed/garden ; DROP

# Redirect responder is listening on :8080:
ss -tlnp | grep 8080
```

**Functional check:** join the public SSID on a test client *without* a grant →
an HTTP request should be redirected (302) to the portal. After a `GrantSession`
from the control plane, the client's MAC appears in the `auth` set
(`ipset list wifihub_auth`) and traffic forwards.

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
| `ipset`/`iptables` not found, or ensure_base errors | backend deps missing — `opkg install ipset iptables iptables-mod-ipset iptables-mod-nat-extra` (all stock RutOS). Run `preflight.sh` to pinpoint. |
| Redirect/garden not populating | `dnsmasq-full` not active (stock dnsmasq lacks `ipset=`); check `/etc/dnsmasq.d/portcullis-garden.conf` and `/etc/init.d/dnsmasq reload`. |
| No new grants accepted | mTLS material missing/incorrect under `/etc/portcullis/tls/` (fail-closed by design). |
| Coexistence weirdness with the firewall | RutOS uses **fw3 (iptables)**. Our `wifihub_pre`/`wifihub_fwd` chains are jumped in at position 1 of `PREROUTING`/`FORWARD` (ahead of fw3); allow branches `RETURN` so traffic falls through to fw3, only unauth is `DROP`/`REDIRECT`. Inspect with `iptables -t nat -S PREROUTING` / `iptables -S FORWARD`. |
| Daemon won't start as non-root | check `/etc/capabilities/portcullis.json` (needs `CAP_NET_ADMIN`) and that the `portcullis` user exists (first-boot script). |
| `nat` chain add fails ENOENT (only if you switch to `NftJsonBackend`) | kernel has no nftables NAT support (`nft_nat`/`nft_chain_nat` absent on stock RutOS) — use the default `IpsetIptablesBackend` (§5.5), which needs no custom firmware. |

See also [`../.claude/skills/openwrt-build`](../.claude/skills/openwrt-build) for
the toolchain/packaging engineering notes, and [`README.md`](./README.md) for the
file/role overview.
