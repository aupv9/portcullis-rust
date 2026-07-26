#!/bin/sh
# B0 — free designated LAN ports from br-lan so the portcullis engine can claim them
# into a device bridge (device-network feature: wired members of an owned SSID subnet).
#
# OPERATOR-INVOKED provisioning step — deliberately NOT an automatic first-boot default.
# Removing LAN ports from br-lan removes LOCAL WIRED ADMIN ACCESS: after this the router
# is managed only via the control-plane / 4G path. Run this only once you have:
#   1. verified the control-plane / 4G management channel is up, and
#   2. (recommended) an admin Wi-Fi still bound to br-lan as a fallback door.
#
# On these routers (RUT906 / RUTM11, DSA switch layout) the LAN ports are individual
# netdevs `lan1`..`lan3` that are, by default, members of the `br-lan` bridge device.
# A netdev can belong to only one bridge, so a port must be removed from br-lan HERE
# before the engine's SetWirelessConfig can add it to the device bridge (`pc_<slug>_dev`).
# The engine itself never touches br-lan (a hard invariant) — that is why this lives in
# the provisioning layer, not the daemon.
#
# Idempotent. Safe to re-run. Usage:
#   free-device-lan-ports.sh lan1 lan2 lan3
# Guard: refuses to remove the LAST port from br-lan unless FORCE=1 is set (prevents a
# total management lockout on a device with no admin Wi-Fi).
#
# NOTE: not yet verified on real hardware — validate on a bench device before fleet-wide
# rollout, and retrofit already-enrolled routers only after confirming their CP link.

set -eu

[ "$#" -ge 1 ] || { echo "usage: $0 <lanX> [lanY ...]" >&2; exit 2; }

# Locate the br-lan bridge-device section (DSA: `config device` with option name 'br-lan').
sec=""
i=0
while name=$(uci -q get "network.@device[$i].name" 2>/dev/null); do
	if [ "$name" = "br-lan" ]; then
		sec="@device[$i]"
		break
	fi
	i=$((i + 1))
done
[ -n "$sec" ] || { echo "error: br-lan bridge-device section not found in /etc/config/network" >&2; exit 1; }

# Stage the removals (validate each port name first; only LAN ports, never the WAN).
for port in "$@"; do
	case "$port" in
		lan[0-9]*) ;;
		*) echo "error: refusing non-LAN port '$port' (only lanN may be freed)" >&2; exit 1 ;;
	esac
	uci -q del_list "network.$sec.ports=$port" 2>/dev/null || true
done

# Guard: never leave br-lan with zero ports unless explicitly forced.
remaining=$(uci -q get "network.$sec.ports" 2>/dev/null | wc -w | tr -d ' ')
if [ "${remaining:-0}" = "0" ] && [ "${FORCE:-0}" != "1" ]; then
	uci -q revert network
	echo "REFUSING: br-lan would have no ports left. Ensure an admin Wi-Fi exists, then re-run with FORCE=1." >&2
	exit 1
fi

uci commit network
/etc/init.d/network reload 2>/dev/null || true
echo "freed from br-lan: $* (remaining br-lan ports: ${remaining})"
