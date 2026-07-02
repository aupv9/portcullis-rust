#!/bin/sh
# teardown.sh — temporarily remove the portcullis engine's enforcement from a
# router so all clients reach the internet again. Run ON the router (busybox
# ash / POSIX sh). Idempotent and safe to re-run.
#
# It does three things, in order:
#   1. stop + disable the procd service so it neither runs nor respawns;
#   2. remove the engine's firewall gate — the FORWARD/PREROUTING jumps, the
#      wifihub_pre / wifihub_fwd chains (v4 + v6), and the wifihub_* ipsets
#      (also drops a stale `inet wifihub` nft table if a prior nft build left one);
#   3. verify nothing wifihub remains and the WAN is reachable.
#
# The binary + init + config are left in place (this is a *temporary* removal —
# reinstalling the new build re-enables it). To uninstall entirely afterwards:
#   opkg remove portcullis   # if installed as .ipk
#   rm -f /usr/sbin/portcullis /usr/local/usr/sbin/portcullis /etc/init.d/portcullis

echo "=== portcullis teardown ==="

echo "-- before --"
iptables -t filter -C FORWARD -j wifihub_fwd 2>/dev/null && echo "FORWARD jump: present" || echo "FORWARD jump: absent"
ipset list -n 2>/dev/null | grep -q wifihub && echo "wifihub ipsets: present" || echo "wifihub ipsets: absent"

echo "-- 1. stop + disable service --"
[ -x /etc/init.d/portcullis ] && { /etc/init.d/portcullis stop 2>/dev/null; /etc/init.d/portcullis disable 2>/dev/null; }
[ -f /var/run/portcullis.pid ] && kill "$(cat /var/run/portcullis.pid)" 2>/dev/null
killall portcullis 2>/dev/null
sleep 1
if pgrep -f '[p]ortcullis' >/dev/null 2>&1; then echo "  WARNING: process still running"; else echo "  stopped"; fi

echo "-- 2. remove firewall gate (ipset+iptables backend) --"
for IPT in iptables ip6tables; do
	while $IPT -t nat    -C PREROUTING -j wifihub_pre 2>/dev/null; do $IPT -t nat    -D PREROUTING -j wifihub_pre; done
	while $IPT -t filter -C FORWARD    -j wifihub_fwd 2>/dev/null; do $IPT -t filter -D FORWARD    -j wifihub_fwd; done
	$IPT -t nat    -F wifihub_pre 2>/dev/null; $IPT -t nat    -X wifihub_pre 2>/dev/null
	$IPT -t filter -F wifihub_fwd 2>/dev/null; $IPT -t filter -X wifihub_fwd 2>/dev/null
done
for S in wifihub_auth wifihub_g4 wifihub_g6; do ipset destroy "$S" 2>/dev/null; done
# stale nft build (RUTM11 lacks NFT_NAT, but be defensive)
nft delete table inet wifihub 2>/dev/null || true
echo "  rules + sets removed"

echo "-- 3. verify --"
iptables -t filter -C FORWARD -j wifihub_fwd 2>/dev/null && { echo "  FAIL: FORWARD jump still present"; rc=1; } || echo "  ok: no FORWARD jump"
ipset list -n 2>/dev/null | grep -q wifihub && { echo "  FAIL: wifihub ipset still present"; rc=1; } || echo "  ok: no wifihub ipsets"
if ping -c2 -W2 1.1.1.1 >/dev/null 2>&1; then echo "  ok: router WAN reaches 1.1.1.1"; else echo "  NOTE: router itself can't reach 1.1.1.1 (WAN issue, not the engine)"; fi

echo "=== done ${rc:+ (with warnings)} ==="
exit "${rc:-0}"
