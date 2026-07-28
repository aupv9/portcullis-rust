#!/bin/sh
# =============================================================================
#  hostapd-scope-spike.sh  --  P0 feasibility spike for "scoped hostapd reconfigure"
# =============================================================================
#
#  WHAT THIS IS
#  ------------
#  A read-mostly, self-restoring probe you run ON a Teltonika RUT906 (RutOS =
#  OpenWrt 21.02, mt76 / mac80211, a SINGLE 2.4 GHz radio "radio0" that carries
#  several BSSes: the admin RUT906_* SSIDs on br-lan plus the pc_* portcullis
#  SSIDs on br-ss1/2/3).
#
#  It answers ONE question for the "scoped apply" feature (P2):
#
#      Can we add / change / remove a SINGLE BSS on radio0 WITHOUT bouncing the
#      whole radio -- i.e. without knocking the OTHER BSSes' beacons offline and
#      without deauthenticating the stations already associated to them?
#
#  It tries four candidate mechanisms, least-invasive first, each INDEPENDENTLY,
#  measuring the state of the *other* (non-test) BSSes before and after:
#
#      1. `wifi reconf`                 -- netifd incremental reconfigure
#      2. hostapd config_add/remove     -- add then remove a THROWAWAY test BSS
#      3. hostapd.<vif> reload          -- change SSID/key on the throwaway BSS
#      4. iw dev phy0 interface add     -- raw mac80211 VIF add (lowest level)
#
#  !!  SAFETY  !!
#  -------------
#  * This script BRIEFLY PERTURBS radio0. It snapshots /etc/config/wireless,
#    network and firewall at startup and installs a trap that -- on ANY exit,
#    error, or Ctrl-C -- restores those files and runs `wifi reload radio0` so
#    the router is returned to a known-good state. It never intentionally leaves
#    a dangling test BSS.
#  * Even so: RUN IT WHEN FEW CLIENTS ARE CONNECTED. Probe #1 (`wifi reconf`)
#    and the final `wifi reload` momentarily touch the radio; a well-behaved
#    build keeps other BSSes up, but that is exactly what we are here to find
#    out, so treat a brief blip as possible.
#  * It writes NOTHING permanent. The only test SSID it creates is an OPEN,
#    passwordless, throwaway BSS named "SCOPE_SPIKE_TMP" that is removed before
#    the script exits.
#
#  HOW TO RUN  (over SSH, as root):
#      scp hostapd-scope-spike.sh root@<router-ip>:/tmp/
#      ssh root@<router-ip> 'sh /tmp/hostapd-scope-spike.sh'
#  Or paste-and-run:
#      ssh root@<router-ip>
#      sh /tmp/hostapd-scope-spike.sh
#
#  OUTPUT: a matrix to stdout AND to /tmp/hostapd-scope-spike.log
#      operation | api_present | op_succeeded | other_beacons_up |
#      other_stations_kept | verdict | notes
#
#  READING IT:  see the "HOW TO READ THIS" block printed at the end.
# =============================================================================

# NOTE: busybox ash. No bash-isms (no arrays, no `local -a`, no `[[ ]]`).
# We keep everything POSIX-ish and defensive: every external tool is probed
# with have() before use, so a missing tool downgrades an op to "unavailable"
# instead of aborting the run.

set -u   # catch unset-variable typos. We deliberately DO NOT `set -e`:
         # we want to observe failures, not die on them.

LOG=/tmp/hostapd-scope-spike.log
TEST_SSID="SCOPE_SPIKE_TMP"
RADIO="radio0"
PHY="phy0"
# Scratch VIF name for the iw-level probe (#4). Chosen to not collide with the
# netifd-managed wlan0-* names.
SCRATCH_VIF="wlanSPIKE"

# Snapshot locations (tmpfs; wiped on reboot -- fine, they are only for restore).
SNAP_DIR="/tmp/hostapd-scope-spike.snap.$$"

# -----------------------------------------------------------------------------
#  Tiny logging helpers -- everything goes to BOTH stdout and the log file.
# -----------------------------------------------------------------------------
log() {
	# $*  -> a line, timestamped, to stdout + logfile
	printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOG"
}
raw() {
	# raw text (no timestamp) to stdout + logfile, e.g. captured command output
	printf '%s\n' "$*" | tee -a "$LOG"
}
hr() { raw "-------------------------------------------------------------------------------"; }

# have <cmd>  -> 0 if the command exists in PATH, else 1
have() { command -v "$1" >/dev/null 2>&1; }

# ubus_has <object>  -> 0 if the ubus object is registered, else 1.
# Used to tell "hostapd not exposing ubus" (older builds) from "ubus missing".
ubus_has() {
	have ubus || return 1
	ubus list 2>/dev/null | grep -qx "$1"
}

# =============================================================================
#  RESTORE TRAP  -- the safety net. Runs on EXIT (normal or via signal).
# =============================================================================
restore() {
	# Disable further trapping so a failure inside restore() cannot loop.
	trap - EXIT INT TERM HUP
	hr
	log "[restore] cleaning up and returning radio0 to known-good state..."

	# 1) Tear down the raw scratch VIF from probe #4, if it lingered.
	if have iw; then
		iw dev "$SCRATCH_VIF" del >/dev/null 2>&1 && \
			log "[restore] removed scratch VIF $SCRATCH_VIF"
	fi

	# 2) Remove the throwaway hostapd BSS from probe #2/#3, if it lingered.
	#    We do not know which ubus bss id it got, so we try the common ones.
	if ubus_has hostapd; then
		for cand in "$TEST_SSID" "$SCRATCH_VIF" wlan0-spk; do
			ubus call hostapd config_remove "{\"iface\":\"$cand\"}" \
				>/dev/null 2>&1 && log "[restore] hostapd config_remove $cand"
		done
	fi

	# 3) Restore the config files from the snapshot (authoritative).
	if [ -d "$SNAP_DIR" ]; then
		for f in wireless network firewall; do
			if [ -f "$SNAP_DIR/$f" ]; then
				cp "$SNAP_DIR/$f" "/etc/config/$f" 2>/dev/null && \
					log "[restore] restored /etc/config/$f"
			fi
		done
	fi

	# 4) Reload the radio so the restored config is actually on-air. This is the
	#    one intentional radio bounce; it is the *known-good* end state.
	if have wifi; then
		log "[restore] wifi reload $RADIO ..."
		wifi reload "$RADIO" >/dev/null 2>&1 || wifi reload >/dev/null 2>&1
	fi

	# 5) Clean the snapshot dir.
	[ -d "$SNAP_DIR" ] && rm -rf "$SNAP_DIR"

	log "[restore] done. Router should be in its pre-spike state."
	hr
}

# =============================================================================
#  Discovery helpers: which VIFs exist, and which are the "other" (non-test)
#  BSSes whose survival we care about.
# =============================================================================

# list_hostapd_vifs -> newline list of hostapd ubus sub-objects, e.g.
#   hostapd.wlan0-1  ->  we strip the "hostapd." prefix to get the VIF name.
list_hostapd_vifs() {
	ubus_has hostapd || return 0
	ubus list 2>/dev/null | sed -n 's/^hostapd\.//p' | grep -v '^$'
}

# list_wdev_aps -> AP-mode netdevs from `iw dev` as a fallback when hostapd
# ubus is not present (e.g. hostapd built without the ubus glue).
list_wdev_aps() {
	have iw || return 0
	iw dev 2>/dev/null | awk '
		/Interface/ { ifc=$2 }
		/type AP/   { if (ifc!="") print ifc }
	'
}

# other_vifs -> the VIFs we must NOT disturb: every AP VIF that is not our
# throwaway/scratch one. Prefer hostapd's own list; fall back to iw.
other_vifs() {
	_all="$(list_hostapd_vifs)"
	[ -z "$_all" ] && _all="$(list_wdev_aps)"
	for v in $_all; do
		case "$v" in
			"$SCRATCH_VIF"|*SPIKE*|*spk*|*SCOPE_SPIKE*) : ;;  # skip our own
			*) printf '%s\n' "$v" ;;
		esac
	done
}

# beacon_up <vif> -> "up" if hostapd reports the BSS ENABLED, "down" if not,
# "unknown" if we cannot tell. Reads `get_status` and looks for the state.
beacon_up() {
	_v="$1"
	if ubus_has "hostapd.$_v"; then
		_st="$(ubus call "hostapd.$_v" get_status 2>/dev/null)"
		# hostapd get_status returns JSON containing e.g. "state":"ENABLED".
		if printf '%s' "$_st" | grep -qi 'ENABLED'; then
			echo up; return
		fi
		if printf '%s' "$_st" | grep -qiE 'DISABLED|UNINITIALIZED|COUNTRY_UPDATE'; then
			echo down; return
		fi
	fi
	# Fallback: does the netdev exist and is it up per iw?
	if have iw && iw dev "$_v" info >/dev/null 2>&1; then
		echo up; return
	fi
	echo unknown
}

# sta_count <vif> -> number of associated stations on that VIF (0 if none/unknown).
# `iw dev <vif> station dump` prints one "Station <mac>" line per client.
sta_count() {
	_v="$1"
	if have iw; then
		iw dev "$_v" station dump 2>/dev/null | grep -c '^Station'
		return
	fi
	# Fallback via hostapd ubus get_clients if iw is absent.
	if ubus_has "hostapd.$_v"; then
		ubus call "hostapd.$_v" get_clients 2>/dev/null \
			| grep -c '"[0-9a-fA-F:]\{17\}"'
		return
	fi
	echo 0
}

# snapshot_others -> writes a "vif beaconstate stacount" line per other VIF into
# the file named by $1. Used to compare before vs after an op.
snapshot_others() {
	_out="$1"
	: > "$_out"
	for v in $(other_vifs); do
		printf '%s %s %s\n' "$v" "$(beacon_up "$v")" "$(sta_count "$v")" >> "$_out"
	done
}

# logread marker: capture the current tail position so we only scan NEW lines
# produced during an op window.
LOG_MARK=0
mark_logread() {
	if have logread; then
		LOG_MARK="$(logread 2>/dev/null | wc -l)"
	else
		LOG_MARK=0
	fi
}
# scan_logread_since_mark -> prints matching disruptive lines that appeared
# AFTER the mark. We look for the tell-tale signs of a radio-wide bounce or
# client deauth.
scan_logread_since_mark() {
	have logread || { echo ""; return; }
	logread 2>/dev/null | tail -n "+$((LOG_MARK + 1))" | \
		grep -Ei 'AP-STA-DISCONNECTED|deauth|disassoc|radio0 is now down|link is down|CTRL-EVENT-TERMINATING|Interface .* DISABLED' \
		| head -n 12
}

# =============================================================================
#  Comparison: given before/after snapshots, decide whether OTHER BSSes held.
#  Sets two globals for the caller to fold into the matrix:
#    OTHERS_BEACONS  = "yes" | "no" | "n/a"
#    OTHERS_STATIONS = "yes" | "no" | "n/a"
#  plus DISRUPT_NOTE from logread.
# =============================================================================
compare_others() {
	_before="$1"; _after="$2"
	OTHERS_BEACONS=yes
	OTHERS_STATIONS=yes
	DISRUPT_NOTE=""

	# No other BSSes at all? Then this dimension is not applicable.
	if [ ! -s "$_before" ]; then
		OTHERS_BEACONS=n/a
		OTHERS_STATIONS=n/a
		return
	fi

	# Walk the "before" lines and look each VIF up in "after".
	while read -r v b_state b_sta; do
		[ -z "$v" ] && continue
		a_line="$(grep "^$v " "$_after" 2>/dev/null)"
		if [ -z "$a_line" ]; then
			# VIF vanished entirely from the after-snapshot = beacon gone.
			OTHERS_BEACONS=no
			DISRUPT_NOTE="$DISRUPT_NOTE ${v}:gone"
			continue
		fi
		a_state="$(printf '%s' "$a_line" | awk '{print $2}')"
		a_sta="$(printf '%s'  "$a_line" | awk '{print $3}')"

		# Beacon check: was up, now not-up -> disruption.
		if [ "$b_state" = up ] && [ "$a_state" != up ]; then
			OTHERS_BEACONS=no
			DISRUPT_NOTE="$DISRUPT_NOTE ${v}:beacon($b_state->$a_state)"
		fi

		# Station check: fewer associated stations than before -> clients dropped.
		# (We only flag DROPS; a station roaming IN is not a disruption.)
		if [ "${a_sta:-0}" -lt "${b_sta:-0}" ] 2>/dev/null; then
			OTHERS_STATIONS=no
			DISRUPT_NOTE="$DISRUPT_NOTE ${v}:sta($b_sta->$a_sta)"
		fi
	done < "$_before"

	# Fold in anything logread saw during the window.
	_llog="$(scan_logread_since_mark)"
	if [ -n "$_llog" ]; then
		# A disconnect line about an OTHER vif is strong evidence of a drop.
		DISRUPT_NOTE="$DISRUPT_NOTE logread:seen"
	fi
}

# =============================================================================
#  Matrix accumulation. We collect one row per operation and print the table
#  at the very end (so the operator gets a single clean summary).
# =============================================================================
MATRIX_FILE="$SNAP_DIR/matrix.tsv"

# add_row op api_present op_ok beacons stations verdict notes
add_row() {
	# tab-separated; printed through column-ish formatting at the end.
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$MATRIX_FILE"
}

# verdict_for api_present op_ok beacons stations -> GO / NO-GO / NA
# Logic:
#   - api missing            -> NA (mechanism not available on this build)
#   - op failed              -> NO-GO (mechanism does not work here)
#   - beacons or stations of OTHERS dropped -> NO-GO (radio-wide bounce)
#   - everything held         -> GO
#   - "n/a" others (nothing else on air) -> GO-ish but flagged as UNPROVEN
verdict_for() {
	_api="$1"; _ok="$2"; _bea="$3"; _sta="$4"
	if [ "$_api" != yes ]; then echo NA; return; fi
	if [ "$_ok"  != yes ]; then echo NO-GO; return; fi
	if [ "$_bea" = no ] || [ "$_sta" = no ]; then echo NO-GO; return; fi
	if [ "$_bea" = n/a ] && [ "$_sta" = n/a ]; then echo GO?; return; fi
	echo GO
}

# =============================================================================
#  START
# =============================================================================
: > "$LOG"   # truncate log for a fresh run
hr
log "hostapd scoped-reconfigure spike -- RUT906 / RutOS 21.02 / radio0"
log "Log file: $LOG"
log "This will briefly perturb radio0 and then restore it. Best run with few clients."
hr

# Make snapshot dir and ARM THE TRAP as early as possible (before any perturbation).
mkdir -p "$SNAP_DIR" || { echo "cannot create $SNAP_DIR"; exit 1; }
: > "$MATRIX_FILE"
trap restore EXIT INT TERM HUP

# --- Snapshot the three config files we might disturb ---
for f in wireless network firewall; do
	if [ -f "/etc/config/$f" ]; then
		cp "/etc/config/$f" "$SNAP_DIR/$f" && log "[snapshot] saved /etc/config/$f"
	else
		log "[snapshot] /etc/config/$f absent (skipping)"
	fi
done

# --- Tool inventory (informational; ops self-detect too) ---
hr
log "[env] tool inventory:"
for t in ubus iw iwinfo uci wifi logread hostapd_cli; do
	if have "$t"; then log "[env]   $t: present"; else log "[env]   $t: MISSING"; fi
done
if ubus_has hostapd; then
	log "[env]   ubus 'hostapd' object: present"
else
	log "[env]   ubus 'hostapd' object: absent (config_add/remove & per-vif reload unavailable)"
fi

# --- Baseline picture of the OTHER BSSes we must protect ---
hr
log "[baseline] AP VIFs currently on radio0:"
for v in $(other_vifs); do
	log "[baseline]   $v  beacon=$(beacon_up "$v")  stations=$(sta_count "$v")"
done
if [ -z "$(other_vifs)" ]; then
	log "[baseline]   (no other AP VIFs detected -- 'other-BSS' checks will be n/a)"
	log "[baseline]   NOTE: with nothing else on air, a GO can only be marked GO? (unproven)."
fi

# Files reused across ops for before/after snapshots.
BEFORE="$SNAP_DIR/before"
AFTER="$SNAP_DIR/after"

# =============================================================================
#  PROBE 1 -- `wifi reconf`
#  netifd's incremental reconfigure. It is supposed to only re-apply changed
#  interfaces. We invoke it with NO config change, so ideally it is a near-noop
#  and touches nothing. If even a no-change reconf bounces the radio, that is a
#  strong NO-GO signal for using wifi-reconf as the scoped-apply vehicle.
# =============================================================================
probe_wifi_reconf() {
	OP="wifi_reconf"
	hr; log "[$OP] netifd incremental reconfigure (no config change)"
	if ! have wifi; then
		log "[$OP] 'wifi' not present -> unavailable"
		add_row "$OP" no na na na NA "wifi cmd missing"
		return
	fi
	snapshot_others "$BEFORE"
	mark_logread
	# `wifi reconf` = ubus call network.wireless reconf under the hood.
	if wifi reconf >/dev/null 2>&1; then op_ok=yes; else op_ok=no; fi
	# Give hostapd a moment to settle before we re-measure.
	sleep 3
	snapshot_others "$AFTER"
	compare_others "$BEFORE" "$AFTER"
	log "[$OP] op_succeeded=$op_ok other_beacons_up=$OTHERS_BEACONS other_stations_kept=$OTHERS_STATIONS"
	[ -n "$DISRUPT_NOTE" ] && log "[$OP] disruption:$DISRUPT_NOTE"
	v="$(verdict_for yes "$op_ok" "$OTHERS_BEACONS" "$OTHERS_STATIONS")"
	add_row "$OP" yes "$op_ok" "$OTHERS_BEACONS" "$OTHERS_STATIONS" "$v" "no-change reconf;${DISRUPT_NOTE:- clean}"
}

# =============================================================================
#  PROBE 2 -- hostapd config_add / config_remove
#  The most promising mechanism for scoped apply: ask hostapd (via ubus) to add
#  a brand-new BSS to the already-running radio, then remove it. If this adds a
#  beacon and later removes it WITHOUT disturbing the other BSSes, scoped apply
#  is feasible at the hostapd level.
#
#  We build a minimal hostapd bss config for an OPEN test SSID. netifd's
#  hostapd expects a config blob describing the bss; the exact accepted schema
#  varies by build, so we try the documented `config_add` form and record
#  whatever it returns.
# =============================================================================
probe_config_add_remove() {
	OP="hostapd_config_add_remove"
	hr; log "[$OP] add+remove throwaway OPEN BSS '$TEST_SSID' via hostapd ubus"
	if ! ubus_has hostapd; then
		log "[$OP] ubus 'hostapd' object absent -> unavailable"
		add_row "$OP" no na na na NA "hostapd ubus object absent"
		return
	fi

	snapshot_others "$BEFORE"
	mark_logread

	# We need a hostapd config file for the new bss. Write a minimal OPEN one to
	# tmpfs. This mirrors what netifd generates per-bss. We attach it to no
	# bridge (br=none-ish) so it can't touch existing L2 domains; if the build
	# insists on a bridge we note that in the failure.
	BSSCONF="$SNAP_DIR/${TEST_SSID}.conf"
	cat > "$BSSCONF" <<EOF
driver=nl80211
interface=wlan0-spk
ctrl_interface=/var/run/hostapd
ssid=$TEST_SSID
channel=0
hw_mode=g
ignore_broadcast_ssid=0
EOF
	# config_add signature (netifd hostapd): {"iface":"<name>","config":"<path>"}
	add_out="$(ubus call hostapd config_add \
		"{\"iface\":\"$TEST_SSID\",\"config\":\"$BSSCONF\"}" 2>&1)"
	if printf '%s' "$add_out" | grep -qiE 'error|not found|invalid|failed'; then
		op_add=no
	elif [ -n "$add_out" ] || ubus_has "hostapd.$TEST_SSID"; then
		op_add=yes
	else
		op_add=no
	fi
	raw "[$OP] config_add returned: ${add_out:-<empty>}"
	sleep 3

	# Measure OTHERS after the add.
	snapshot_others "$AFTER"
	compare_others "$BEFORE" "$AFTER"
	add_beacons="$OTHERS_BEACONS"; add_stations="$OTHERS_STATIONS"
	add_note="$DISRUPT_NOTE"

	# Now REMOVE the test bss regardless of add outcome (idempotent cleanup).
	rm_out="$(ubus call hostapd config_remove "{\"iface\":\"$TEST_SSID\"}" 2>&1)"
	raw "[$OP] config_remove returned: ${rm_out:-<empty>}"
	sleep 2

	# op_succeeded = the add worked (remove is best-effort cleanup, always tried).
	op_ok="$op_add"
	log "[$OP] op_succeeded=$op_ok other_beacons_up=$add_beacons other_stations_kept=$add_stations"
	[ -n "$add_note" ] && log "[$OP] disruption:$add_note"
	v="$(verdict_for yes "$op_ok" "$add_beacons" "$add_stations")"
	add_row "$OP" yes "$op_ok" "$add_beacons" "$add_stations" "$v" "add+remove;${add_note:- clean}"
}

# =============================================================================
#  PROBE 3 -- hostapd.<vif> reload  (change SSID/key on an existing BSS)
#  This is the "change" case for scoped apply: mutate one BSS's parameters in
#  place. We do it on a THROWAWAY BSS we create for the purpose so we never
#  mutate a real SSID. If config_add (probe 2) is unavailable, we cannot create
#  the throwaway safely, so this probe is marked unavailable.
# =============================================================================
probe_vif_reload() {
	OP="hostapd_vif_reload"
	hr; log "[$OP] change SSID on a throwaway BSS via 'hostapd.<vif> reload'"
	if ! ubus_has hostapd; then
		log "[$OP] ubus 'hostapd' object absent -> unavailable"
		add_row "$OP" no na na na NA "hostapd ubus object absent"
		return
	fi

	# Create the throwaway BSS first (reuses probe 2's config path but keeps it).
	BSSCONF="$SNAP_DIR/${TEST_SSID}.reload.conf"
	cat > "$BSSCONF" <<EOF
driver=nl80211
interface=wlan0-spk
ctrl_interface=/var/run/hostapd
ssid=$TEST_SSID
channel=0
hw_mode=g
ignore_broadcast_ssid=0
EOF
	add_out="$(ubus call hostapd config_add \
		"{\"iface\":\"$TEST_SSID\",\"config\":\"$BSSCONF\"}" 2>&1)"
	if ! ubus_has "hostapd.$TEST_SSID"; then
		log "[$OP] could not create throwaway BSS (config_add failed) -> unavailable"
		raw "[$OP] config_add returned: ${add_out:-<empty>}"
		ubus call hostapd config_remove "{\"iface\":\"$TEST_SSID\"}" >/dev/null 2>&1
		add_row "$OP" no na na na NA "throwaway BSS create failed"
		return
	fi
	sleep 2

	snapshot_others "$BEFORE"
	mark_logread

	# Mutate: rewrite the bss config with a NEW ssid, then ask that vif to reload.
	cat > "$BSSCONF" <<EOF
driver=nl80211
interface=wlan0-spk
ctrl_interface=/var/run/hostapd
ssid=${TEST_SSID}_2
channel=0
hw_mode=g
ignore_broadcast_ssid=0
EOF
	rl_out="$(ubus call "hostapd.$TEST_SSID" reload 2>&1)"
	# Some builds want reload via update_beacon or config_add-again; record raw.
	raw "[$OP] reload returned: ${rl_out:-<empty>}"
	if printf '%s' "$rl_out" | grep -qiE 'error|not found|invalid|failed|method'; then
		op_ok=no
	else
		op_ok=yes
	fi
	sleep 3

	snapshot_others "$AFTER"
	compare_others "$BEFORE" "$AFTER"

	# Cleanup the throwaway BSS.
	ubus call hostapd config_remove "{\"iface\":\"$TEST_SSID\"}" >/dev/null 2>&1
	sleep 1

	log "[$OP] op_succeeded=$op_ok other_beacons_up=$OTHERS_BEACONS other_stations_kept=$OTHERS_STATIONS"
	[ -n "$DISRUPT_NOTE" ] && log "[$OP] disruption:$DISRUPT_NOTE"
	v="$(verdict_for yes "$op_ok" "$OTHERS_BEACONS" "$OTHERS_STATIONS")"
	add_row "$OP" yes "$op_ok" "$OTHERS_BEACONS" "$OTHERS_STATIONS" "$v" "in-place SSID change;${DISRUPT_NOTE:- clean}"
}

# =============================================================================
#  PROBE 4 -- iw dev phy0 interface add  (raw mac80211 VIF add)
#  Lowest level: ask the driver/mac80211 to add another AP-type netdev to phy0.
#  This tests whether mt76 permits an extra VIF at all (chip/driver VIF-count
#  limits) WITHOUT going through hostapd. It does not start a beacon (no
#  hostapd on it), so its value is: does adding a VIF perturb the running BSSes?
#  We add, then immediately delete.
# =============================================================================
probe_iw_vif_add() {
	OP="iw_vif_add"
	hr; log "[$OP] raw mac80211 VIF add on $PHY via iw"
	if ! have iw; then
		log "[$OP] 'iw' not present -> unavailable"
		add_row "$OP" no na na na NA "iw missing"
		return
	fi
	if ! iw phy "$PHY" info >/dev/null 2>&1; then
		log "[$OP] $PHY not visible to iw -> unavailable"
		add_row "$OP" no na na na NA "$PHY not found"
		return
	fi

	snapshot_others "$BEFORE"
	mark_logread

	add_out="$(iw phy "$PHY" interface add "$SCRATCH_VIF" type __ap 2>&1)"
	# Some iw versions spell it "type ap"; retry once if the enum name was rejected.
	if printf '%s' "$add_out" | grep -qiE 'invalid|usage|unknown'; then
		add_out="$(iw phy "$PHY" interface add "$SCRATCH_VIF" type managed 2>&1)"
	fi
	if iw dev "$SCRATCH_VIF" info >/dev/null 2>&1; then
		op_ok=yes
	else
		op_ok=no
	fi
	raw "[$OP] iw interface add returned: ${add_out:-<ok/empty>}"
	sleep 2

	snapshot_others "$AFTER"
	compare_others "$BEFORE" "$AFTER"

	# Cleanup the scratch VIF.
	iw dev "$SCRATCH_VIF" del >/dev/null 2>&1

	log "[$OP] op_succeeded=$op_ok other_beacons_up=$OTHERS_BEACONS other_stations_kept=$OTHERS_STATIONS"
	[ -n "$DISRUPT_NOTE" ] && log "[$OP] disruption:$DISRUPT_NOTE"
	v="$(verdict_for yes "$op_ok" "$OTHERS_BEACONS" "$OTHERS_STATIONS")"
	add_row "$OP" yes "$op_ok" "$OTHERS_BEACONS" "$OTHERS_STATIONS" "$v" "raw VIF add;${DISRUPT_NOTE:- clean}"
}

# =============================================================================
#  RUN ALL PROBES, least-invasive first.
# =============================================================================
probe_wifi_reconf
probe_config_add_remove
probe_vif_reload
probe_iw_vif_add

# =============================================================================
#  FINAL MATRIX
# =============================================================================
hr
log "================================ RESULT MATRIX ================================"
{
	printf 'operation\tapi_present\top_ok\tother_beacons_up\tother_stations_kept\tverdict\tnotes\n'
	cat "$MATRIX_FILE"
} | (
	# Pretty-print with column if available, else raw TSV.
	if have column; then column -t -s '	'; else cat; fi
) | tee -a "$LOG"
hr

# =============================================================================
#  HOW TO READ THIS  (printed so an operator on the wire understands the output)
# =============================================================================
cat <<'EOF' | tee -a "$LOG"

HOW TO READ THIS
----------------
Each row is one candidate mechanism for "scoped apply" (change ONE BSS on the
shared radio0 without bouncing the others):

  api_present          Was the mechanism even available on this build?
  op_ok                Did the operation itself succeed?
  other_beacons_up     Did every OTHER BSS keep its beacon ENABLED? (yes = good)
  other_stations_kept  Did associated stations on OTHER BSSes stay associated?
  verdict:
     GO     mechanism worked AND other BSSes were undisturbed  -> usable for P2
     GO?    worked, but there were no other BSSes on air to prove non-disruption
            -> re-run with a real second SSID + a connected client to confirm
     NO-GO  mechanism failed here, OR it bounced/deauthed the other BSSes
     NA     mechanism not available on this build

DECISION FOR P2 (scoped apply):
  * Prefer the LEAST-invasive row that is GO. In practice we want
    'hostapd_config_add_remove' = GO (add/remove a BSS live) and
    'hostapd_vif_reload' = GO (mutate a BSS live). Those two GO means P2 can do
    true per-SSID apply with no radio-wide bounce -> proceed with P2.
  * If BOTH hostapd rows are NO-GO/NA but 'wifi_reconf' is GO, scoped apply is
    still possible but only via netifd's incremental path (coarser; verify it
    really is per-interface and not a disguised full reload).
  * If every row is NO-GO/NA, scoped apply is NOT feasible on this build: P2
    must fall back to a full 'wifi reload radio0' (accept the bounce) or an
    engine/firmware change. That is the NO-GO outcome for the P0 question.
  * Any GO? rows are INCONCLUSIVE -- re-run this spike while a second SSID has a
    real client associated, so the other_stations_kept column is meaningful.

The full per-op detail (raw ubus/iw output, logread disruption lines) is above
and in /tmp/hostapd-scope-spike.log. The router has been restored to its
pre-spike state by the exit trap.
EOF

# The EXIT trap (restore) fires here and returns the radio to known-good.
exit 0
