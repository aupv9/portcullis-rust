#!/usr/bin/env bash
#
# pack-ipk.sh — package an already-cross-compiled portcullis binary into an
# OpenWrt `.ipk`, using only `ar` + `tar` + `gzip` (no OpenWrt SDK, no
# opkg-utils). The engine is a static-musl userspace daemon with NO kernel
# module, so this fully replaces the SDK for packaging.
#
# An `.ipk` is an `ar` archive (like a .deb) of three members, in this order:
#   debian-binary      -> "2.0\n"
#   control.tar.gz     -> the CONTROL metadata (./control, ./conffiles) at root
#   data.tar.gz        -> the install tree (./usr/sbin/portcullis, ./etc/...)
# DEPENDS are declared as strings and resolved by opkg ON the device at install
# time (they don't need any feed at build time).
#
# Usage:
#   deploy/ci/pack-ipk.sh <opkg_arch> <binary_path> <version> [out_dir]
# Produces: <out_dir>/portcullis_<version>-1_<opkg_arch>.ipk

set -euo pipefail

ARCH="${1:?opkg arch, e.g. mipsel_24kc}"
BIN="${2:?path to the cross-compiled portcullis binary}"
VERSION="${3:?package version, e.g. 0.2.0}"
OUT="${4:-dist}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -f "$BIN" ] || { echo "error: binary not found: $BIN" >&2; exit 2; }
command -v ar  >/dev/null 2>&1 || { echo "error: 'ar' not found (install binutils)" >&2; exit 2; }

# Reproducible timestamps.
: "${SOURCE_DATE_EPOCH:=0}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DATA="$WORK/data"
CTRL="$WORK/control"

# --- install tree (data) — mirrors deploy/Makefile Package/install ---
install -d "$DATA/usr/sbin" "$DATA/etc/init.d" "$DATA/etc/config" \
	"$DATA/etc/capabilities" "$DATA/etc/uci-defaults"
install -m0755 "$BIN"                                    "$DATA/usr/sbin/portcullis"
install -m0755 "$DEPLOY_DIR/portcullis.init"             "$DATA/etc/init.d/portcullis"
install -m0644 "$DEPLOY_DIR/config/portcullis"           "$DATA/etc/config/portcullis"
install -m0644 "$DEPLOY_DIR/capabilities/portcullis.json" "$DATA/etc/capabilities/portcullis.json"
install -m0755 "$DEPLOY_DIR/uci-defaults/99-portcullis"  "$DATA/etc/uci-defaults/99-portcullis"

# --- control metadata (DEPENDS mirror deploy/Makefile) ---
install -d "$CTRL"
cat > "$CTRL/control" <<EOF
Package: portcullis
Version: ${VERSION}-1
Architecture: ${ARCH}
Maintainer: The portcullis authors
Section: net
Priority: optional
Depends: ipset, iptables, ip6tables, iptables-mod-ipset, iptables-mod-nat-extra, dnsmasq-full
Description: Per-store captive-portal edge enforcement engine. Holds the internet
 gate shut until the WiFi Hub control plane authorizes a client, then enforces,
 meters, and expires that grant via ipset + iptables (TDD 17 option B). RAM-only
 state; CAP_NET_ADMIN, non-root.
EOF
# /etc/config/portcullis is a conffile (preserved across upgrades).
echo "/etc/config/portcullis" > "$CTRL/conffiles"

# --- assemble the .ipk ---
TAR_REPRO=(--numeric-owner --owner=0 --group=0 --sort=name --mtime="@${SOURCE_DATE_EPOCH}")
tar "${TAR_REPRO[@]}" -C "$DATA" -czf "$WORK/data.tar.gz" .
tar "${TAR_REPRO[@]}" -C "$CTRL" -czf "$WORK/control.tar.gz" .
printf '2.0\n' > "$WORK/debian-binary"

mkdir -p "$OUT"
OUT_ABS="$(cd "$OUT" && pwd)"
IPK="$OUT_ABS/portcullis_${VERSION}-1_${ARCH}.ipk"
rm -f "$IPK"
# Order matters: debian-binary first. `ar` on OpenWrt/opkg reads this layout.
( cd "$WORK" && ar rc "$IPK" debian-binary control.tar.gz data.tar.gz )

echo ">> built: $IPK"
