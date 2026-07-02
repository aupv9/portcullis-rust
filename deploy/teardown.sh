#!/bin/sh
# teardown.sh — temporarily remove the portcullis engine's enforcement from a
# router so all clients reach the internet again. Run ON the router (busybox
# ash / POSIX sh). Idempotent and safe to re-run.
#
# It does three things, in order:
#   1. stop + disable the procd service so it neither runs nor respawns;
#   2. remove the engine's firewall gate — the FORWARD/PREROUTING jumps, the
#      portcullis_pre / portcullis_fwd chains (v4 + v6), and the portcullis_* ipsets
#      (also drops a stale `inet portcullis` nft table if a prior nft build left one);
#   3. verify nothing portcullis remains and the WAN is reachable.
#
# The binary + init + config are left in place (this is a *temporary* removal —
# reinstalling the new build re-enables it). To uninstall entirely afterwards:
#   opkg remove portcullis   # if installed as .ipk
#   rm -f /usr/sbin/portcullis /usr/local/usr/sbin/portcullis /etc/init.d/portcullis

echo "=== portcullis teardown ==="

echo "-- before --"
iptables -t filter -C FORWARD -j portcullis_fwd 2>/dev/null && echo "FORWARD jump: present" || echo "FORWARD jump: absent"
ipset list -n 2>/dev/null | grep -q portcullis && echo "portcullis ipsets: present" || echo "portcullis ipsets: absent"

echo "-- 1. stop + disable service --"
[ -x /etc/init.d/portcullis ] && { /etc/init.d/portcullis stop 2>/dev/null; /etc/init.d/portcullis disable 2>/dev/null; }
[ -f /var/run/portcullis.pid ] && kill "$(cat /var/run/portcullis.pid)" 2>/dev/null
killall portcullis 2>/dev/null
sleep 1
if pgrep -f '[p]ortcullis' >/dev/null 2>&1; then echo "  WARNING: process still running"; else echo "  stopped"; fi

echo "-- 2. remove firewall gate (ipset+iptables backend) --"
for IPT in iptables ip6tables; do
	while $IPT -t nat    -C PREROUTING -j portcullis_pre 2>/dev/null; do $IPT -t nat    -D PREROUTING -j portcullis_pre; done
	while $IPT -t filter -C FORWARD    -j portcullis_fwd 2>/dev/null; do $IPT -t filter -D FORWARD    -j portcullis_fwd; done
	$IPT -t nat    -F portcullis_pre 2>/dev/null; $IPT -t nat    -X portcullis_pre 2>/dev/null
	$IPT -t filter -F portcullis_fwd 2>/dev/null; $IPT -t filter -X portcullis_fwd 2>/dev/null
done
for S in portcullis_auth portcullis_g4 portcullis_g6; do ipset destroy "$S" 2>/dev/null; done
# stale nft build (RUTM11 lacks NFT_NAT, but be defensive)
nft delete table inet portcullis 2>/dev/null || true
echo "  rules + sets removed"

echo "-- 3. verify --"
iptables -t filter -C FORWARD -j portcullis_fwd 2>/dev/null && { echo "  FAIL: FORWARD jump still present"; rc=1; } || echo "  ok: no FORWARD jump"
ipset list -n 2>/dev/null | grep -q portcullis && { echo "  FAIL: portcullis ipset still present"; rc=1; } || echo "  ok: no portcullis ipsets"
if ping -c2 -W2 1.1.1.1 >/dev/null 2>&1; then echo "  ok: router WAN reaches 1.1.1.1"; else echo "  NOTE: router itself can't reach 1.1.1.1 (WAN issue, not the engine)"; fi

echo "=== done ${rc:+ (with warnings)} ==="
exit "${rc:-0}"
