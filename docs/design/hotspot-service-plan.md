# Design: CP-managed Hotspot service (RUTOS-Hotspot-equivalent) on portcullis

Status: **Plan** — 2026-07-07. Core enforce + CP-control already implemented &
verified E2E on a real RUT200 (MT7628, ipset backend, enroll→Attach→grant→ipset).
This plan closes the gaps to make it behave like the RUTOS Hotspot service, but
managed by the control plane.

## Goal
Build a hotspot like Teltonika RUTOS Hotspot, but **CP-managed**: the portcullis
engine enforces on the router's PUBLIC SSID; the control plane owns everything
else (splash/portal, auth modes, session policy, user-groups, per-router config,
clients dashboard, accounting). RADIUS is intentionally dropped platform-wide
(accounting is written straight to Postgres).

## Architecture (the split — this is what "CP-managed" means)
```
[Public SSID on router] ──gated by──> ENGINE (portcullis, on-router)
  new client → DROP / redirect :8080 (HMAC-signed 302)
  ENGINE: gate · redirect · grant/revoke · TTL/quota/rate/idle · garden · accounting
          ONLY on the hotspot interface (NOT br-lan)
                         │ Attach mTLS bidi stream (engine dials CP)
                         ▼
CP (cloud) = "Hotspot Service" management:
  portal/splash · auth modes (clickthrough/OTP/voucher/password) · user-groups (tiers)
  · session policy · per-router hotspot config push · clients dashboard · accounting sink
```
Engine = kernel-level enforcement primitives (done). CP = the hotspot product
(portal/OTP/voucher/tiers already exist). Proto superset already carries the
config-over-stream ControlFrame/EngineFrame variants.

### Router-config: single agent, bounded provisioning subsystem (decision 2026-07-07)
The hotspot also needs the router's PUBLIC network provisioned (SSID + bridge +
DHCP). Options weighed: (RMS — rejected: not self-hosted), (openwisp-config —
off-the-shelf but a 2nd process + its own Django controller), (a separate
self-hosted router-agent — cleanest isolation but 2 agents to operate). Chosen:
**extend portcullis into a SINGLE agent** with a new, strictly-isolated
`portcullis-provision` subsystem — because the operator does not want two agents
to maintain, and portcullis is uniquely safe to extend here thanks to
**kernel-as-truth** (a provision-subsystem fault or a full daemon crash does NOT
drop authorized clients — the nft/ipset ruleset + per-element timeouts persist in
the kernel and are re-adopted on restart).

This is **scoped to hotspot only** (provision the hotspot network + a few
targeted UCI sections), NOT a general RMS/openwisp-style whole-router manager.
Boundary is redefined, not abandoned:
- **Enforcement subsystem** keeps ALL invariants intact: owns only the
  `inet wifihub` table, fail-CLOSED, kernel-as-truth, single nft-writer. Untouched.
- **`portcullis-provision` subsystem** (new crate) owns a fixed allowlist of UCI
  sections, is fail-OPEN with commit-confirm, and shares ONLY the process + the
  Attach mTLS channel + the enroll identity with enforcement.
See P0.5 for the design.

## Feature map: RUTOS Hotspot → engine/CP + status

| RUTOS Hotspot feature | Engine (Rust) | CP (Go/Next) | Status | Phase |
|---|---|---|---|---|
| **Provision hotspot network** (SSID/bridge/DHCP) | `portcullis-provision` renders UCI (wireless/network/dhcp) + commit-confirm | push hotspot spec in hotspot-config | ❌ missing | **P0.5** |
| Enable + **select hotspot interface** | rule bind `-i <iface>` + config `hotspot_iface` (fed by provision) | push iface in hotspot-config | ❌ missing | **P0** |
| Captive gate + redirect to splash | `wifihub_fwd` + `:8080` HMAC 302 | portal FQDN | ✅ | — |
| Auth: click-through (accept T&C) | — | `/captive/auth/instant` → grant | ✅ CP | P2 |
| Auth: SMS OTP | — | `/captive/otp/*` | ✅ CP | P2 wire |
| Auth: voucher | — | `/portal/voucher/*` | ✅ CP | P2 wire |
| Auth: password | — | `/captive/login` | ✅ CP | P2 wire |
| Auth: RADIUS | — | dropped by design | n/a | — |
| Splash/landing customize | — | portal_pages (admin/portal) | ✅ CP | P2 |
| Session timeout | grant TTL + kernel timeout | tier/policy | ✅ | — |
| **Idle timeout** | session idle-kill | policy | ⚠️ proto only, engine TODO | **P1** |
| Data quota | quota_bytes | tier | ✅ (aggregate) | P1 (split up/down opt) |
| **Per-user bandwidth limit** | `TcShaper` (wired `NoopShaper`) | tier rate_bps | ⚠️ code exists, unwired | **P1** |
| **User-groups** (diff limits) | apply tier on grant | `tiers` + SetTierPolicies | ❌ engine `unimplemented` | **P1** |
| Walled garden | garden ipset/nft | SetGarden + FQDN | ⚠️ `nftset=` vs ipset bug | **P1** |
| Clients list + disconnect | GetSession/List + Revoke | dashboard + revoke API | ✅ engine; CP API | P3 (UI) |
| Accounting/usage | conntrack → SessionEvent | captive_sessions sink | ✅ (needs `conntrack` pkg) | P1 (dep) |
| Clean enable/disable | teardown chains on stop | SetEnforcement toggle | ⚠️ stop leaves rules | **P1** |
| Scheduling (time-based) | (kernel timeout) | policy scheduler | ❌ | P3 |

## Roadmap (prioritized)

### P0 — Interface/SSID scoping (engine) — HIGHEST PRIORITY
Also fixes the root cause of the whole-LAN-block incident (see
[[feedback_portcullis_lan_block]] in operator notes): today the `wifihub_fwd`
jump is `-I FORWARD 1` with **no `-i` match** → blankets br-lan.
- Add config `hotspot_iface` (UCI list; e.g. `wlan0-1` / `br-hotspot` / a VLAN).
- Both backends chain the FORWARD jump + PREROUTING redirect with `-i <hotspot_iface>`
  → gate ONLY ingress from the public SSID; br-lan (admin) untouched.
- Files: `crates/portcullis-nft/src/{ipset_iptables.rs,nftables_json.rs,backend.rs}`,
  `crates/portcullis-config/src/lib.rs`, `deploy/config/portcullis`.
- Router prep: a dedicated Public SSID (own bridge/VLAN) — provisioned by P0.5
  (or, until P0.5 lands, created by hand / a uci-defaults snippet); engine binds to it.
- Verify: public-SSID client gated; br-lan/admin internet unaffected.

### P0.5 — Hotspot network provisioning (engine `portcullis-provision` subsystem)
Give the SINGLE agent the ability to CREATE the hotspot interface it then scopes
enforcement to (P0), so one CP push sets up the network AND the captive. Scoped
to hotspot, strictly isolated from enforcement (see Architecture decision above).

**Bounded config surface — a fixed, owned allowlist (NOT arbitrary UCI):**
| UCI | Section (owned, tagged `owner='portcullis-hotspot'`) | Purpose |
|---|---|---|
| `network` | `network.hotspot` + device `br-hotspot` | bridge + subnet (e.g. 10.0.0.1/24) |
| `wireless` | `wireless.wifi_hotspot` (wifi-iface) | public SSID, attached to hotspot network |
| `dhcp` | `dhcp.hotspot` | DHCP pool + lease for guests |
| `firewall` | `firewall.hotspot` (zone) | secure captive zone (input/forward REJECT) |
| `firewall` | `firewall.hotspot_fwd` (forwarding) | hotspot → `wan` (NAT breakout) |
| `firewall` | `firewall.hotspot_dhcp` (rule) | allow guest DHCP (udp/67) |
| `firewall` | `firewall.hotspot_dns` (rule) | allow guest DNS (tcp+udp/53) |
| `firewall` | `firewall.hotspot_portal` (rule) | allow the redirect responder (`Config.responder_port`) |

Hard allowlist: the subsystem may read/write ONLY these **nine** named sections
(all NAMED, so `uci set` is idempotent). NEVER touches `network.lan`, admin
config, the existing `firewall.lan` / `firewall.wan` / anonymous fw zones, or the
enforcement `inet wifihub` table. Firmware/opkg = out of scope (note for later).

The firewall zone is provisioned (not optional): with no fw zone, the hotspot
interface can't forward to the internet at all. Posture is **secure captive**:
zone `input=REJECT` (guests can't reach router admin) + `forward=REJECT`, then the
`hotspot→wan` forwarding + the three allow-rules open exactly DHCP, DNS, and the
portal responder. **No `masq` on the hotspot zone** — the existing `wan` zone
already carries `masq '1'` (RUTOS default, network `wan wan6 mob1s1a1`), so
`hotspot→wan` is masqueraded by the wan zone. The wan-zone name is a fixed
`const WAN_ZONE = "wan"` (RUTOS default; adjust for non-RUTOS OpenWrt). The portal
rule opens `Config.responder_port` (default 8080) — a LOCAL engine setting,
injected at subsystem construction, NOT carried on the wire.

**Transport:** a new `ProvisionHotspot` ControlFrame variant on the EXISTING
Attach mTLS stream (distinct from enforcement Grant/Revoke frames; proto superset
already carries config-over-stream variants). CP pushes the desired hotspot spec
(ssid, band, subnet, dhcp_range, iface_name, encryption…). No new channel/agent.

**Commit-confirm state machine (the anti-brick core — CGNAT has no inbound rescue):**
```
CP ── ProvisionHotspot(desired) ──▶ engine
  1. snapshot: uci show {network,wireless,dhcp,firewall}, filtered to owned → /tmp/portcullis/provision/
  2. render + apply ONLY allowlisted sections (uci batch set/commit)
  3. reload (order): network reload · firewall reload · wifi reload <hotspot-radio> · dnsmasq restart
  4. ARM local watchdog (~90s) + send heartbeat over Attach
       ├─ CP re-sees engine online + sends CONFIRM  → commit permanent, report "applied"
       └─ watchdog fires w/o CONFIRM (apply severed connectivity) → uci revert /tmp/hs.bak
          + reload → report "rolled_back"
```
The watchdog is LOCAL on the router (CP cannot reach in over CGNAT to fix a bad
apply). Test = "can the engine still reach CP over Attach after apply?" — mirrors
openwisp-config's `test_config=contact-controller` + restore-on-failure.

**Isolation guardrails (load-bearing):**
- New crate `portcullis-provision`, separate async task; enforcement crates untouched.
- Apply via shell-out to on-device `uci`/`wifi`/`/etc/init.d/*` (already present),
  panic-guarded → a bug here cannot take down the enforcement task.
- Fail-OPEN + rollback (opposite of enforcement's fail-CLOSED, but isolated).
- Enforcement keeps kernel-as-truth: even a full crash preserves granted MACs.

**Seam with P0:** on `applied`, hand the resulting iface name (`br-hotspot`) to the
enforcement config → it binds `-i br-hotspot`. Provision creates the iface; P0
scopes captive to it — composed, br-lan never touched.

- Files: NEW `crates/portcullis-provision/` (uci render + commit-confirm SM),
  `crates/portcullis-control/{channel,service}.rs` (route `ProvisionHotspot` frame),
  `crates/portcullis-config` (hotspot-network spec type), `proto/enforcement.proto`
  (frame variant — keep in sync with `domain/server/proto`), `portcullis-engined`
  (compose the subsystem as a separate task).
- Flash: mostly logic + shell-out to existing binaries → measure it still fits the
  RUT200 2.2 MB overlay (UPX).

**Reference desired-state UCI (RUT200, on-device facts verified 2026-07-07):**
RUT200 = MT7628 **single 2.4 GHz radio `radio0`** (no 5 GHz); admin SSID
`RUT200_E74C` already on radio0/`network=lan`. Only `br-lan` exists. The subsystem
renders (open captive SSID on radio0 + a new `br-hotspot` 10.0.0.1/24 + DHCP):
```
# owned sections (fixed-name allowlist, nine): network.{hotspot,br_hotspot} · wireless.wifi_hotspot · dhcp.hotspot · firewall.{hotspot,hotspot_fwd,hotspot_dhcp,hotspot_dns,hotspot_portal}
network.br_hotspot=device ; .name='br-hotspot' ; .type='bridge'
network.hotspot=interface ; .device='br-hotspot' ; .proto='static' ; .ipaddr='10.0.0.1' ; .netmask='255.255.255.0'
wireless.wifi_hotspot=wifi-iface ; .device='radio0' ; .mode='ap' ; .network='hotspot' ; .ssid='<CP>' ; .encryption='none' ; .isolate='1'
dhcp.hotspot=dhcp ; .interface='hotspot' ; .start='10' ; .limit='200' ; .leasetime='2h' ; .dhcpv6='disabled'
# firewall — secure captive zone + hotspot→wan forwarding + 3 allow-rules (NO masq here; the wan zone masqs)
firewall.hotspot=zone ; .name='hotspot' ; .network='hotspot' ; .input='REJECT' ; .output='ACCEPT' ; .forward='REJECT'
firewall.hotspot_fwd=forwarding ; .src='hotspot' ; .dest='wan'
firewall.hotspot_dhcp=rule ; .name='Allow-hotspot-DHCP' ; .src='hotspot' ; .proto='udp' ; .dest_port='67' ; .target='ACCEPT'
firewall.hotspot_dns=rule ; .name='Allow-hotspot-DNS' ; .src='hotspot' ; .proto='tcp udp' ; .dest_port='53' ; .target='ACCEPT'
firewall.hotspot_portal=rule ; .name='Allow-hotspot-portal' ; .src='hotspot' ; .proto='tcp' ; .dest_port='<Config.responder_port, default 8080>' ; .target='ACCEPT'
```
Apply/reload order (matters — network before firewall (zone refs the iface)
before wifi before dhcp):
`uci commit {network,wireless,dhcp,firewall}` (one config per invocation — busybox
`uci commit` takes a single config) → `/etc/init.d/network reload` → `/etc/init.d/firewall reload` → `/sbin/wifi reload <hotspot-radio>` → `/etc/init.d/dnsmasq restart`.
The wifi reload is **scoped to the hotspot's radio** (`spec.radio`, default
`radio0`) — NEVER a bare `wifi reload` (all radios). On a dual-band router the
hotspot AP is on one radio while the admin + control-plane WiFi is on the other;
bouncing all radios would drop the engine↔CP link so the CP could never send the
confirm and every provision would roll back. Rollback (incl. the boot-time
reconcile, which reads the radio from the tmpfs marker) reloads only that radio too.
The `wan` zone (RUTOS default, `masq '1'`, network `wan wan6 mob1s1a1`)
masquerades the `hotspot→wan` forwarding — the hotspot zone sets no masq.
Ownership = the fixed section NAMES above (single-radio: hotspot AP coexists with
admin SSID on radio0). Note: RUT200 also still carries **stale `network.wg_fleet`
+ peer `hub`** from the pre-pivot WireGuard era — unrelated, leave untouched.

### P1 — Port feat v0.6.0 onto the engine + bug-fixes (engine-branch merge)
Port from `feat/k3d-dataplane-deploy` (exists there; currently `unimplemented`/
`Noop` on the merge branch), re-expressed as ControlFrame variants on Attach
(proto superset already has them):
- **TcShaper wiring** (per-user bandwidth), **SetTierPolicies** (user-groups),
  **idle-timeout enforcement** in `portcullis-session`.
- **Fix garden**: emit `ipset=` when backend=ipset (not `nftset=`); `nftset=`
  only for nft + dnsmasq-full.
- **Teardown-on-stop**: init `stop`/prerm + engine graceful shutdown remove the
  `wifihub_*` chains (fail-OPEN on a deliberate stop only) so disabling doesn't
  brick the LAN.
- **conntrack**: add to `.ipk` Depends (accounting) or document `opkg install`.
- Files: `crates/portcullis-{accounting/shaper.rs,session,control/{channel,service}.rs,garden/lib.rs}`,
  `deploy/portcullis.init`, `deploy/ci/pack-ipk.sh` (Depends + teardown + the
  PROG=`/usr/local/usr/sbin/portcullis` + USER=root fixes from the install run).

### P2 — CP "Hotspot Service" management + wire auth modes
- Model: per-router (or fleet-default) `hotspot_config`: `iface`, `auth_mode`
  (clickthrough|otp|voucher|password), session_timeout, idle_timeout, quota,
  rate up/down, garden[], group/tier defaults.
- Push: on save → CP dispatches to the engine over Attach (SetEngineParameters +
  SetGarden + SetTierPolicies + SetEnforcement) via `internal/edge/dispatch`.
- Portal: wire the existing OTP/voucher/login/instant flows by `auth_mode`; after
  auth → CP `grant` (already runs E2E).
- Admin UI: a "Hotspot" page (RUTOS-like): iface, auth mode, limits, garden,
  groups — per router.
- Files (CP, `domain/server`): `internal/{models,repository,handlers,services}`
  (hotspot config), `cmd/cplane/main.go` (routes), `frontend/app/admin/hotspot/`.

### P3 — Ops: dashboard + accounting + scheduling
- Clients dashboard (per-router session list, manual disconnect = revoke), usage
  view (captive_sessions), time-based scheduling, richer landing-page customization.

## Verification (E2E "Hotspot" on RUT200)
0. `ProvisionHotspot` from CP → `br-hotspot` + public SSID + DHCP appear; a bad
   spec that severs connectivity → local watchdog **rolls back** to /tmp/hs.bak and
   the router stays reachable (P0.5 commit-confirm).
1. Dedicated Public SSID → engine scoped to its iface → **br-lan/admin internet
   unaffected** (P0).
2. Public-SSID client → redirect portal → auth (OTP/voucher/clickthrough) → CP
   grant → internet; br-lan untouched.
3. Bandwidth limit applied (tc), quota/idle-timeout expiry → re-gate.
4. Garden domains reachable pre-auth; disable hotspot → chains removed cleanly,
   LAN flows.

## Risks
- **P0.5 provisioning is the highest-consequence new code**: a bad UCI apply on a
  CGNAT router = brick with no inbound rescue. Commit-confirm + LOCAL watchdog +
  the fixed allowlist are mandatory, not optional. Test rollback FIRST, on-device.
- **P0.5 shared-process fate**: config bug must not panic enforcement (separate
  task + shell-out + panic guard); rely on kernel-as-truth so a crash preserves
  granted clients. `:8080` responder stays hardened; config-write must be
  unreachable from its request path.
- **P0.5 RUTOS config conflict**: RUTOS has its own config layer (vuci); the
  provision subsystem must only touch its owned sections and coexist (same lesson
  as the openwisp-config `unmanaged` requirement).
- **P0 iface**: must confirm the actual public-SSID interface name on RUTM11/
  RUT200 (bridge/VLAN) on-device.
- **P1** = feat→merge-branch port: proto/transport conflicts; do per-feature +
  verify mipsel `.ipk` + on-device.
- Garden needs `ipset=` (stock dnsmasq) or dnsmasq-full — confirm on RUT200.
- Teardown-on-stop must fail-OPEN only on a deliberate stop, never on a crash
  (preserve fail-closed / kernel-as-truth otherwise).

## References
- Current engine capability assessment + gaps: this session's analysis.
- Enforcement contract: `proto/enforcement.proto` (superset), `docs/design/cgnat-bidi-control-channel.md`.
- CP edge/dispatch + PKI enroll: `domain/server/STRUCTURE.md`.
- Flash budget (RUT200): Tier-0 + UPX (0.89MB) — see the release-ipk workflow.
