#!/usr/bin/env bash
#
# pack-ipk.sh — package an already-cross-compiled portcullis binary into an
# OpenWrt `.ipk`, WITHOUT the OpenWrt SDK. Uses `opkg-build` (from opkg-utils).
#
# The engine is a static-musl userspace daemon with NO kernel module, so a plain
# cross toolchain + this script fully replace the SDK for packaging. DEPENDS are
# declared as strings and resolved by opkg ON the device at install time (they
# don't need the SDK's feeds at build time).
#
# Usage:
#   deploy/ci/pack-ipk.sh <opkg_arch> <binary_path> <version> [out_dir]
# e.g.
#   deploy/ci/pack-ipk.sh mipsel_24kc target/mipsel-unknown-linux-musl/release/portcullis 0.2.0 dist
#
# Produces: <out_dir>/portcullis_<version>-1_<opkg_arch>.ipk

set -euo pipefail

ARCH="${1:?opkg arch, e.g. mipsel_24kc}"
BIN="${2:?path to the cross-compiled portcullis binary}"
VERSION="${3:?package version, e.g. 0.2.0}"
OUT="${4:-dist}"

# deploy/ = parent of this script's dir (deploy/ci/..).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -f "$BIN" ] || { echo "error: binary not found: $BIN" >&2; exit 2; }
command -v opkg-build >/dev/null 2>&1 || {
	echo "error: opkg-build not found (install opkg-utils)" >&2; exit 2; }

STAGE="$(mktemp -d)/portcullis"
trap 'rm -rf "$(dirname "$STAGE")"' EXIT

# Lay out exactly what the SDK Makefile's Package/install installs.
install -d "$STAGE/CONTROL" \
	"$STAGE/usr/sbin" "$STAGE/etc/init.d" "$STAGE/etc/config" \
	"$STAGE/etc/capabilities" "$STAGE/etc/uci-defaults"

install -m0755 "$BIN"                                   "$STAGE/usr/sbin/portcullis"
install -m0755 "$DEPLOY_DIR/portcullis.init"            "$STAGE/etc/init.d/portcullis"
install -m0644 "$DEPLOY_DIR/config/portcullis"          "$STAGE/etc/config/portcullis"
install -m0644 "$DEPLOY_DIR/capabilities/portcullis.json" "$STAGE/etc/capabilities/portcullis.json"
install -m0755 "$DEPLOY_DIR/uci-defaults/99-portcullis" "$STAGE/etc/uci-defaults/99-portcullis"

# Control metadata. DEPENDS mirror deploy/Makefile (ipset + iptables backend).
cat > "$STAGE/CONTROL/control" <<EOF
Package: portcullis
Version: ${VERSION}-1
Architecture: ${ARCH}
Maintainer: The portcullis authors
Section: net
Priority: optional
Depends: ipset, iptables, ip6tables, iptables-mod-ipset, iptables-mod-nat-extra, dnsmasq-full
Description: Per-store captive-portal edge enforcement engine. Holds the internet
 gate shut until the WiFi Hub control plane authorizes a client, then enforces,
 meters, and expires that grant via ipset + iptables (TDD §17 option B). RAM-only
 state; CAP_NET_ADMIN, non-root.
EOF

# /etc/config/portcullis is a conffile (preserved across upgrades).
echo "/etc/config/portcullis" > "$STAGE/CONTROL/conffiles"

mkdir -p "$OUT"
opkg-build -o root -g root "$STAGE" "$OUT"
echo ">> built: $OUT/portcullis_${VERSION}-1_${ARCH}.ipk"
