#!/bin/sh
# preflight.sh — go/no-go gate for onboarding a router before installing the
# portcullis .ipk. Run ON the router (busybox sh). Exits non-zero on the first
# HARD prerequisite that is missing, printing a machine-greppable "FAIL: <what>"
# so a fleet loop can flag/skip that unit. Soft issues print "WARN:".
#
#   scp deploy/preflight.sh root@ROUTER:/tmp/ && ssh root@ROUTER sh /tmp/preflight.sh
#
# portcullis enforces with ipset + iptables/ip6tables (TDD §17 option B) because
# stock RutOS ships no nftables NAT chain support. Everything checked here is
# already used by fw3, so a healthy RutOS unit passes with no custom firmware.
#
# HARD prereqs (engine cannot run without them):
#   - ipset (hash:mac with per-element timeout)
#   - iptables + ip6tables with the `-m set` match and the nat REDIRECT target
# SOFT prereqs (engine starts, a feature degrades):
#   - conntrack state match; dnsmasq-full with ipset= (walled-garden population).

IPSET="${IPSET:-ipset}"
IPT="${IPT:-iptables}"
IPT6="${IPT6:-ip6tables}"
fail=0

say()  { echo "$1"; }
hard() { echo "FAIL: $1"; fail=1; }
soft() { echo "WARN: $1"; }

# 1) ipset userspace + hash:mac with per-element timeout (the auth set).
if ! command -v "$IPSET" >/dev/null 2>&1; then
	hard "ipset binary not found"
elif "$IPSET" create _pf_auth hash:mac timeout 0 2>/dev/null; then
	if "$IPSET" add _pf_auth 00:11:22:33:44:55 timeout 60 2>/dev/null; then
		say "OK: ipset hash:mac + timeout ($($IPSET --version 2>/dev/null | head -1))"
	else
		hard "ipset hash:mac add-with-timeout failed"
	fi
	"$IPSET" destroy _pf_auth 2>/dev/null
else
	hard "ipset cannot create hash:mac (kernel ip_set_hash_mac missing)"
fi

# 2) iptables + ip6tables present.
for b in "$IPT" "$IPT6"; do
	command -v "$b" >/dev/null 2>&1 && say "OK: $b present" || hard "$b not found"
done

# 3) The full nat REDIRECT + match-set mechanism (the captive-portal bounce and
#    the auth/garden exemptions). Build a throwaway set + nat chain and tear down.
if command -v "$IPT" >/dev/null 2>&1 && command -v "$IPSET" >/dev/null 2>&1; then
	"$IPSET" create _pf_g hash:net family inet 2>/dev/null
	ok=1
	"$IPT" -t nat -N _PF_PRE 2>/dev/null || ok=0
	"$IPT" -t nat -A _PF_PRE -m set --match-set _pf_g dst -j RETURN 2>/dev/null || ok=0
	"$IPT" -t nat -A _PF_PRE -p tcp --dport 80 -j REDIRECT --to-ports 8080 2>/dev/null || ok=0
	[ "$ok" = 1 ] && say "OK: iptables nat REDIRECT + -m set match" \
		|| hard "iptables nat REDIRECT / -m set unsupported (need iptables-mod-ipset + iptables-mod-nat-extra)"
	"$IPT" -t nat -F _PF_PRE 2>/dev/null; "$IPT" -t nat -X _PF_PRE 2>/dev/null
	"$IPSET" destroy _pf_g 2>/dev/null
fi

# 4) conntrack state match (soft — usually present via fw3).
if [ -f /proc/net/nf_conntrack ] || grep -q nf_conntrack /proc/modules 2>/dev/null; then
	say "OK: conntrack available"
else
	soft "conntrack not detected (ct state RETURN rule may not match)"
fi

# 5) dnsmasq-full with ipset= for the walled garden (soft).
if dnsmasq --version 2>/dev/null | grep -qiw 'ipset'; then
	dnsmasq --version 2>/dev/null | grep -qi 'no-ipset' \
		&& soft "dnsmasq built WITHOUT ipset — install dnsmasq-full for the garden" \
		|| say "OK: dnsmasq supports ipset"
else
	soft "could not confirm dnsmasq-full (ipset) — garden may not populate"
fi

echo "---"
if [ "$fail" -ne 0 ]; then
	echo "PREFLIGHT: NO-GO (fix the FAIL lines before installing portcullis)"
	exit 1
fi
echo "PREFLIGHT: GO"
exit 0
