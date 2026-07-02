#!/usr/bin/env bash
#
# pack-ipk.sh — package an already-cross-compiled portcullis binary into an
# OpenWrt/RutOS `.ipk`, using only `tar` + `gzip` (no SDK, no opkg-utils).
#
# An OpenWrt/RutOS `.ipk` is a GZIPPED TAR (NOT an `ar`/deb archive — opkg-lede
# rejects ar as "Malformed package file"). It holds:
#   debian-binary   -> "2.0\n"
#   data.tar.gz     -> the install tree
#   control.tar.gz  -> control + maintainer scripts (postinst/prerm)
#
# RutOS installs to the /usr/local overlay AND does not reliably place a
# package's own /etc/* files, so we ship the init script + default config under
# /usr/lib/portcullis (a usr/ path, which lands reliably) and a **postinst**
# (run as root by opkg) copies them into the real /etc, seeds the dnsmasq garden,
# and enables the service. `prerm` reverses it. The daemon runs as root: procd's
# non-root capability path doesn't grant an effective CAP_NET_ADMIN for the
# ipset/iptables netlink calls on RutOS.
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
: "${SOURCE_DATE_EPOCH:=0}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DATA="$WORK/data"
CTRL="$WORK/control"

# --- install tree (data): binary + payload the postinst deploys into /etc ---
install -d "$DATA/usr/sbin" "$DATA/usr/lib/portcullis"
install -m0755 "$BIN"                          "$DATA/usr/sbin/portcullis"
install -m0755 "$DEPLOY_DIR/portcullis.init"   "$DATA/usr/lib/portcullis/portcullis.init"
install -m0644 "$DEPLOY_DIR/config/portcullis" "$DATA/usr/lib/portcullis/config.default"

# --- control metadata ---
install -d "$CTRL"
cat > "$CTRL/control" <<EOF
Package: portcullis
Version: ${VERSION}-1
Architecture: ${ARCH}
Maintainer: The portcullis authors
Section: net
Priority: optional
Depends: ipset, iptables, ip6tables, kmod-ipt-ipset
Description: Per-store captive-portal edge enforcement engine. Holds the internet
 gate shut until the WiFi Hub control plane authorizes a client, then enforces,
 meters, and expires that grant via ipset + iptables (TDD 17 option B).
EOF

# postinst: place init + config into the real /etc, seed garden, enable service.
cat > "$CTRL/postinst" <<'EOF'
#!/bin/sh
LIB=/usr/local/usr/lib/portcullis
[ -d "$LIB" ] || LIB=/usr/lib/portcullis            # generic OpenWrt (dest=/)
# busybox on RutOS has no `install`; use cp + chmod.
mkdir -p /etc/init.d /etc/config
cp "$LIB/portcullis.init" /etc/init.d/portcullis && chmod 0755 /etc/init.d/portcullis
[ -f /etc/config/portcullis ] || { cp "$LIB/config.default" /etc/config/portcullis && chmod 0644 /etc/config/portcullis; }
mkdir -p /tmp/portcullis /etc/dnsmasq.d
if [ ! -f /etc/dnsmasq.d/portcullis-garden.conf ]; then
	echo 'ipset=/portal.wifihub.vn/cdn.wifihub.vn/otp.gateway/pay.example/wifihub_g4,wifihub_g6' \
		> /etc/dnsmasq.d/portcullis-garden.conf
	/etc/init.d/dnsmasq reload 2>/dev/null || true
fi
/etc/init.d/portcullis enable 2>/dev/null || true
exit 0
EOF
chmod 0755 "$CTRL/postinst"

# prerm: stop + disable + remove the /etc init (keep /etc/config as user data).
cat > "$CTRL/prerm" <<'EOF'
#!/bin/sh
/etc/init.d/portcullis stop 2>/dev/null || true
/etc/init.d/portcullis disable 2>/dev/null || true
rm -f /etc/init.d/portcullis
exit 0
EOF
chmod 0755 "$CTRL/prerm"

# --- assemble the .ipk (gzipped tar of the three members) ---
TAR_REPRO=(--numeric-owner --owner=0 --group=0 --sort=name --mtime="@${SOURCE_DATE_EPOCH}")
tar "${TAR_REPRO[@]}" -C "$DATA" -czf "$WORK/data.tar.gz" .
tar "${TAR_REPRO[@]}" -C "$CTRL" -czf "$WORK/control.tar.gz" .
printf '2.0\n' > "$WORK/debian-binary"

mkdir -p "$OUT"
OUT_ABS="$(cd "$OUT" && pwd)"
IPK="$OUT_ABS/portcullis_${VERSION}-1_${ARCH}.ipk"
rm -f "$IPK"
( cd "$WORK" && tar "${TAR_REPRO[@]}" -czf "$IPK" ./debian-binary ./data.tar.gz ./control.tar.gz )

echo ">> built: $IPK"
