#!/usr/bin/env bash
#
# build-golden-image.sh — bake a ZTP golden firmware (.bin) for a Teltonika
# router from a pre-built portcullis .ipk, using the RutOS/OpenWrt Image Builder.
#
# "Zero-touch" = flash this .bin once (WebUI / RMS / bench) → plug power + WAN →
# the first-boot claim agent (portcullis-enroll, START=94) reads the device
# serial, signs it with the baked FLEET_SECRET, POSTs /api/enroll/claim, gets its
# mTLS bundle, and the engine dials the control plane. No SSH, no token.
#
# This automates ZTP-GOLDEN-IMAGE.md §2–3 (previously manual). One .ipk
# (mipsel_24kc, ipset backend — TDD §17 opt B) runs on BOTH models; the only
# fork is the Image Builder target/profile:
#   RUTM11 -> ramips/mt7621   RUT200 -> ramips/mt7628
#
# Usage:
#   deploy/build-golden-image.sh --model rutm11|rut200 \
#       --secret <FLEET_SECRET hex> \
#       [--cp-domain cp.wifihub.internal] \
#       [--claim-url https://<domain>/api/enroll/claim] \
#       [--resolve-ip <CP host IP>]        # dev/LAN only; prod uses real DNS \
#       [--ipk <path/to/portcullis_*.ipk>] # default: newest under dist/ \
#       [--imagebuilder <dir>]             # or IB_ROOT env; auto-detects per target \
#       [--profile <device profile>]       # override; verify with `make info` \
#       [--extra-packages "pkg1 pkg2"] \
#       [--batch <id>]                     # output label; default: timestamp \
#       [--out <dir>]                      # default: dist/golden \
#       [--dry-run]
#
# SECURITY: the FLEET_SECRET is baked into the image's /etc/portcullis/bootstrap.conf.
# It is written only into a temp overlay (never into the repo) and this script prints
# only a fingerprint, never the secret. Do NOT commit generated overlays or .bin.

set -euo pipefail

die()  { echo "error: $*" >&2; exit 2; }
info() { echo ">> $*" >&2; }
warn() { echo "!! $*" >&2; }

# ---- defaults -------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL=""
SECRET=""
CP_DOMAIN="cp.wifihub.internal"
CLAIM_URL=""
RESOLVE_IP=""
IPK=""
IB_ROOT="${IB_ROOT:-}"
PROFILE=""
EXTRA_PACKAGES=""
BATCH=""
OUT="$SCRIPT_DIR/dist/golden"
DRY_RUN=0
WAN_IF="wan"

# ---- args -----------------------------------------------------------------
while [ $# -gt 0 ]; do
	case "$1" in
		--model)          MODEL="$2"; shift 2 ;;
		--secret)         SECRET="$2"; shift 2 ;;
		--cp-domain)      CP_DOMAIN="$2"; shift 2 ;;
		--claim-url)      CLAIM_URL="$2"; shift 2 ;;
		--resolve-ip)     RESOLVE_IP="$2"; shift 2 ;;
		--ipk)            IPK="$2"; shift 2 ;;
		--imagebuilder)   IB_ROOT="$2"; shift 2 ;;
		--profile)        PROFILE="$2"; shift 2 ;;
		--extra-packages) EXTRA_PACKAGES="$2"; shift 2 ;;
		--batch)          BATCH="$2"; shift 2 ;;
		--out)            OUT="$2"; shift 2 ;;
		--wan-if)         WAN_IF="$2"; shift 2 ;;
		--dry-run)        DRY_RUN=1; shift ;;
		-h|--help)        sed -n '2,45p' "$0"; exit 0 ;;
		*)                die "unknown arg: $1 (see --help)" ;;
	esac
done

# ---- model -> target/profile ---------------------------------------------
case "$MODEL" in
	rutm11|RUTM11)
		TARGET="ramips/mt7621"; TARGET_DIR="ramips-mt7621"
		DEFAULT_PROFILE="teltonika_rutm11" ;;
	rut200|RUT200)
		TARGET="ramips/mt7628"; TARGET_DIR="ramips-mt7628"
		DEFAULT_PROFILE="teltonika_rut200" ;;
	"") die "--model is required (rutm11 | rut200)" ;;
	*)  die "unsupported --model: $MODEL (expected rutm11 | rut200)" ;;
esac
PROFILE="${PROFILE:-$DEFAULT_PROFILE}"

# ---- validate secret ------------------------------------------------------
[ -n "$SECRET" ] || die "--secret (FLEET_SECRET) is required; it must equal ONE entry in the CP's FLEET_BOOTSTRAP_SECRETS"
case "$SECRET" in
	*[!0-9a-fA-F]*) die "--secret must be hex (e.g. openssl rand -hex 32)" ;;
esac
[ "${#SECRET}" -ge 32 ] || warn "FLEET_SECRET is only ${#SECRET} hex chars; recommend 64 (openssl rand -hex 32)"
# Fingerprint for the manifest — NEVER echo the secret itself.
if command -v sha256sum >/dev/null 2>&1; then
	SECRET_FP="$(printf '%s' "$SECRET" | sha256sum | cut -c1-12)"
elif command -v shasum >/dev/null 2>&1; then
	SECRET_FP="$(printf '%s' "$SECRET" | shasum -a 256 | cut -c1-12)"
else
	SECRET_FP="(no sha256 tool)"
fi

# ---- claim URL default ----------------------------------------------------
[ -n "$CLAIM_URL" ] || CLAIM_URL="https://${CP_DOMAIN}/api/enroll/claim"

# ---- locate the .ipk ------------------------------------------------------
if [ -z "$IPK" ]; then
	# newest mipsel_24kc .ipk under dist/ (CI artifact naming: portcullis_<ver>-1_<arch>.ipk)
	IPK="$(ls -t "$SCRIPT_DIR"/dist/portcullis_*_mipsel_24kc.ipk 2>/dev/null | head -n1 || true)"
	[ -n "$IPK" ] || die "no .ipk found under $SCRIPT_DIR/dist — pass --ipk, or fetch the mipsel_24kc CI release asset"
fi
[ -f "$IPK" ] || die ".ipk not found: $IPK"
# Filename: portcullis_<version>-<release>_<arch>.ipk (arch itself contains a '_',
# e.g. mipsel_24kc; version/release do not). Split on the first '_' after the name.
IPK_REST="$(basename "$IPK" .ipk)"; IPK_REST="${IPK_REST#portcullis_}"  # <ver>-<rel>_<arch>
IPK_ARCH="${IPK_REST#*_}"                                              # mipsel_24kc
VERSION="${IPK_REST%%_*}"; VERSION="${VERSION%-*}"                     # <ver>-<rel> -> <ver>
VERSION="${VERSION:-unknown}"
[ "$IPK_ARCH" = "mipsel_24kc" ] || warn "ipk arch is '$IPK_ARCH', expected 'mipsel_24kc' for MT7621/MT7628 — double-check"

# ---- locate the Image Builder --------------------------------------------
# Accept an explicit --imagebuilder/IB_ROOT, else try to auto-detect a dir whose
# name contains the target (e.g. *imagebuilder*-ramips-mt7621*).
if [ -z "$IB_ROOT" ]; then
	IB_ROOT="$(ls -d "$SCRIPT_DIR"/imagebuilder*"$TARGET_DIR"* /opt/*imagebuilder*"$TARGET_DIR"* 2>/dev/null | head -n1 || true)"
fi
[ -n "$IB_ROOT" ] || die "Image Builder for $TARGET not found — download the RutOS/OpenWrt Image Builder for $TARGET_DIR and pass --imagebuilder <dir> (or set IB_ROOT)"
[ -f "$IB_ROOT/Makefile" ] || die "$IB_ROOT does not look like an Image Builder root (no Makefile)"

# ---- batch label ----------------------------------------------------------
BATCH="${BATCH:-$(date +%Y%m%d-%H%M%S)}"

# ---- build the FILES overlay (bootstrap.conf with the baked secret) -------
OVERLAY="$(mktemp -d)"
trap 'rm -rf "$OVERLAY"' EXIT
mkdir -p "$OVERLAY/etc/portcullis"
cat > "$OVERLAY/etc/portcullis/bootstrap.conf" <<EOF
# WifiHub ZTP batch bootstrap config — GENERATED by build-golden-image.sh.
# Baked into the golden image (NOT per-device). Do NOT commit this file.
# batch=$BATCH model=$MODEL secret_fp=$SECRET_FP
CP_DOMAIN="$CP_DOMAIN"
CP_RESOLVE_IP="$RESOLVE_IP"
CLAIM_URL="$CLAIM_URL"
FLEET_SECRET="$SECRET"
WAN_IF="$WAN_IF"
EOF
chmod 0644 "$OVERLAY/etc/portcullis/bootstrap.conf"

# ---- packages: portcullis (deps come from its .ipk control) + dnsmasq-full -
# Stock RutOS ships slim dnsmasq (no ipset=/nftset= directive) → the walled
# garden needs dnsmasq-full; -dnsmasq removes the conflicting slim build (dnsmasq-full
# is NOT a hard .ipk dep precisely because that swap can't be expressed as a Depends).
# Everything else resolves from the .ipk's own Depends (see deploy/ci/pack-ipk.sh) —
# incl. the critical `iptables-mod-ipset` (libxt_set.so for `iptables -m set`),
# `kmod-ipt-ipset`, `conntrack` (the CLI package — NOT conntrack-tools/conntrackd),
# curl/ca-bundle/openssl-util for the ZTP agent.
PACKAGES="portcullis dnsmasq-full -dnsmasq"
[ -n "$EXTRA_PACKAGES" ] && PACKAGES="$PACKAGES $EXTRA_PACKAGES"

# ---- manifest -------------------------------------------------------------
cat >&2 <<EOF

  ZTP golden image
  ----------------
  model        : $MODEL  ($TARGET, profile=$PROFILE)
  ipk          : $(basename "$IPK")  (v$VERSION, $IPK_ARCH)
  imagebuilder : $IB_ROOT
  cp domain    : $CP_DOMAIN
  claim url    : $CLAIM_URL
  resolve ip   : ${RESOLVE_IP:-<real DNS>}
  fleet secret : fp=$SECRET_FP  (len ${#SECRET})
  packages     : $PACKAGES
  batch        : $BATCH
  out          : $OUT

EOF

# ---- stage the .ipk so Image Builder's opkg can see it --------------------
mkdir -p "$IB_ROOT/packages"
cp "$IPK" "$IB_ROOT/packages/"

MAKE_ARGS=(image "PROFILE=$PROFILE" "PACKAGES=$PACKAGES" "FILES=$OVERLAY")

if [ "$DRY_RUN" -eq 1 ]; then
	info "dry-run — would run in $IB_ROOT:"
	echo "    make image PROFILE=$PROFILE PACKAGES=\"$PACKAGES\" FILES=$OVERLAY" >&2
	exit 0
fi

# ---- bake -----------------------------------------------------------------
info "running Image Builder (this can take a few minutes)…"
( cd "$IB_ROOT" && make "${MAKE_ARGS[@]}" )

# ---- collect the sysupgrade image -----------------------------------------
SRC_BIN="$(ls -t "$IB_ROOT"/bin/targets/$TARGET/*sysupgrade.bin 2>/dev/null | head -n1 || true)"
[ -n "$SRC_BIN" ] || die "no *-sysupgrade.bin produced under $IB_ROOT/bin/targets/$TARGET — check Image Builder output above (profile name? run 'make info')"

mkdir -p "$OUT"
DST_BIN="$OUT/portcullis-golden-${MODEL}-v${VERSION}-${BATCH}-sysupgrade.bin"
cp "$SRC_BIN" "$DST_BIN"

info "built golden image: $DST_BIN"
info "next: register the router serial(s) in the CP, then flash + power + WAN → online (no SSH)."
