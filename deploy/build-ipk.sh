#!/usr/bin/env bash
#
# build-ipk.sh — build the portcullis .ipk inside an already-extracted
# RutOS/OpenWrt SDK (ramips/mt7621). Convenience wrapper around the steps in
# PACKAGING.md; run it from anywhere.
#
# Usage:
#   SDK_DIR=/path/to/openwrt-sdk-...-ramips-mt7621 ./deploy/build-ipk.sh
#   ./deploy/build-ipk.sh /path/to/sdk            # SDK dir as first arg
#
# Env:
#   SDK_DIR    path to the extracted SDK root (required)
#   JOBS       parallel build jobs (default: nproc)
#   DOCKER=1   use the SDK's ./scripts/dockerbuild wrapper (Teltonika SDKs)
#
# Prereqs: a Linux x86_64 host with the SDK's build deps installed. This script
# does NOT download the SDK (its URL is version-specific — see PACKAGING.md §2).

set -euo pipefail

# Repo root = parent of this script's dir (deploy/..).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="$SCRIPT_DIR"

SDK_DIR="${SDK_DIR:-${1:-}}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

if [[ -z "$SDK_DIR" ]]; then
	echo "error: set SDK_DIR (or pass the SDK path as arg 1). See deploy/PACKAGING.md §2." >&2
	exit 2
fi
if [[ ! -x "$SDK_DIR/scripts/feeds" ]]; then
	echo "error: '$SDK_DIR' does not look like an OpenWrt/RutOS SDK (no scripts/feeds)." >&2
	exit 2
fi

echo ">> repo:  $REPO_ROOT"
echo ">> sdk:   $SDK_DIR"
echo ">> jobs:  $JOBS"

cd "$SDK_DIR"

# 1. Expose deploy/ as the 'portcullis' package (the Makefile reads deploy/.. as
#    the workspace root). Symlink is idempotent.
if [[ ! -e package/portcullis ]]; then
	ln -s "$DEPLOY_DIR" package/portcullis
	echo ">> linked package/portcullis -> $DEPLOY_DIR"
fi

# 2. Feeds (idempotent).
./scripts/feeds update -a
./scripts/feeds install -a
./scripts/feeds install rust 2>/dev/null || true   # route A (rust feed), best-effort

# 3. Config + build.
make defconfig

run() {
	if [[ "${DOCKER:-0}" == "1" && -x ./scripts/dockerbuild ]]; then
		./scripts/dockerbuild make "$@"
	else
		make "$@"
	fi
}

echo ">> building package/portcullis ..."
run "package/portcullis/compile" "V=s" "-j${JOBS}"

# 4. Report the artifact(s).
echo ">> done. artifacts:"
find bin/packages -name 'portcullis_*.ipk' -printf '   %p\n' 2>/dev/null \
	|| find bin/packages -name 'portcullis_*.ipk' 2>/dev/null

cat <<EOF

Next:
  scp \$(find $SDK_DIR/bin/packages -name 'portcullis_*.ipk' | head -1) root@ROUTER:/tmp/
  ssh root@ROUTER 'opkg install /tmp/portcullis_*.ipk'
See deploy/PACKAGING.md §6–§8 for install, provisioning, and verification.
EOF
