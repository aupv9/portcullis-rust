# Design: CP-managed wireless (SSID) config — single router → fleet

Status: **Plan / draft** — 2026-07-07. Supersedes the single-SSID scope of
`hotspot-service-plan.md §P0.5`, which becomes a special case of this model.
No code yet — this is for review.

## Goal
Let the control plane **declaratively manage the wireless SSIDs** on a store's
router — **arbitrary N SSIDs**, not just the one public hotspot — and roll a
config out to **one router or a group of stores (fleet)** safely, without ever
bricking a CGNAT router that has no inbound rescue.

Two capabilities are in scope:
1. **Arbitrary SSIDs**: CP defines a set of SSIDs (public captive, staff/home,
   retail POS, guest, …) with their radio/band, encryption, network binding
   (bridge/VLAN/subnet), DHCP, firewall zone + **egress/uplink** (this is where
   "public→4G, home/retail→cable" becomes expressible), and whether portcullis
   **gates** the SSID (captive) or leaves it open/trusted.
2. **Fleet**: CP renders a **template** (parameterised by store) and pushes it to
   a **group** of routers, staged (canary → wave → fleet), with per-router
   confirm/rollback and a fleet status/drift view.

## The core tension (and how we resolve it)
Today `portcullis-provision` is safe because it owns a **fixed 9-section name
allowlist** and refuses anything else (`bridge_name` must literally be
`br-hotspot`). Arbitrary SSIDs breaks "fixed names". We keep the safety by moving
the boundary from **fixed names** to an **ownership namespace + reserved
denylist** — the same idea as openwisp-config's `unmanaged` list, but retaining
our commit-confirm / tmpfs / single-agent / mTLS-Attach architecture:

- **Owned namespace**: every UCI section portcullis creates is stamped
  `option owner 'portcullis-wireless'` **and** named with a `pc_<slug>` prefix.
  The engine owns *exactly* the set it created; it is the only thing it may
  modify or delete.
- **Reserved denylist (hard, non-overridable)**: the engine **refuses** to
  create/modify/delete any section that touches protected config —
  `network.lan` / `br-lan`, the **admin SSID + admin radio**, `network.wan*` /
  the `wan` zone members, the enforcement `inet wifihub` table, and the
  **radio/SSID carrying the engine↔CP uplink**. A desired-state that names any
  reserved target is rejected wholesale (fail-OPEN reject: nothing applied).
- **Declarative desired-state + reconcile**: CP pushes the *full* desired set of
  owned SSIDs; the engine diffs against its current owned state and computes the
  minimal set/delete batch. Add / modify / remove all flow through one path.

This preserves every load-bearing invariant: no-brick (reserved never touched),
bounded teardown (delete all `owner=portcullis-wireless`), provable ownership,
kernel-as-truth for enforcement, tmpfs-only state, single-owner actor.

## Architecture (where each piece lives)
```
CP (Go, domain/server)                          Engine (Rust, this repo)
─────────────────────                           ────────────────────────
Wireless Template  ──render(store vars)──▶ per-router WirelessDesiredState
Group / assignment                               │  (over the existing Attach
Staged rollout (canary→wave→fleet)               │   mTLS bidi stream — CGNAT-safe)
Per-router confirm within watchdog window        ▼
Fleet status + drift dashboard          portcullis-provision (generalised)
                                          validate → snapshot → apply →
                                          commit-confirm watchdog →
                                          confirm|rollback → WirelessStatus ▲
                                        gated SSIDs' ifaces ─▶ enforcement scoping
```
- The **transport already exists** (Attach). No new inbound path; fleet fan-out
  is CP dialling-out per engine that is already connected.
- The **engine side** is a generalisation of `portcullis-provision`.
- The **fleet side** (templates/groups/rollout/status) is **CP-side (Go)** —
  out of scope for this repo except the shared proto contract.

## Data model — one SSID (the unit CP defines)
```
WirelessSsid {
  slug            // owner-namespaced id, e.g. "public","staff" -> sections pc_<slug>_*
  ssid            // advertised name (may embed store code via CP template)
  radios[]        // one or more wifi-device (2.4/5 GHz); band selection
  encryption      // none | psk2 | sae | ...  (+ key/secret when not none)
  hidden, isolate
  network {
    mode          // bridged-to-existing | own-bridge+subnet | vlan
    bridge/vlan_id
    ipaddr/netmask (own-bridge only)
    dhcp { start, limit, leasetime } | none
  }
  firewall {
    zone          // owner-namespaced zone
    egress_zone   // e.g. "wan" (cable) or a cellular zone  ← per-SSID uplink
    input/forward policy, allow-rules (dhcp/dns/portal…)
  }
  gated           // true = portcullis captive-gates this SSID; false = trusted/open
}
```
Notes:
- `egress_zone` per SSID directly answers the earlier "public→4G, home→cable"
  question — for true per-tier uplink you still need PBR/mwan3 at the router
  level (a follow-up), but the zone/forwarding split is expressible here.
- `gated` decides whether the SSID's resulting L2 iface is fed into enforcement
  interface-scoping. This requires enforcement to gate a **set** of ifaces
  (today it scopes to a single `hotspot_iface`) — see Engine changes.

## Proto contract (additive to `wifihub.enforcement.v1`)
Keep the wire-compat rule: new tags only, mirror into the Go copy.
```
// ControlFrame variants (+ unary twins for on-net/dev)
SetWirelessConfigRequest  set_wireless_config = 15;  // full desired-state push -> CommandAck (applied-pending)
ConfirmWirelessRequest    confirm_wireless    = 16;  // CP confirms a pending push
Empty                     get_wireless_config = 17;  // -> EngineFrame.wireless_config (introspection/drift)

// EngineFrame variant
WirelessStatus            wireless_status     = 11;  // per-SSID + overall; unsolicited on watchdog rollback

message SetWirelessConfigRequest {
  string config_version = 1;      // CP-issued; echoed in status + confirm (cursor/idempotency)
  repeated WirelessSsid ssids = 2;
  uint32 confirm_timeout_secs = 3; // commit-confirm window; 0=default 90, bounds [15,600]
}
message WirelessStatus {
  string config_version = 1;
  ProvisionState state = 2;        // reuse: APPLIED_PENDING|COMMITTED|ROLLED_BACK|FAILED
  repeated SsidResult per_ssid = 3; // slug -> ok/msg/iface
  string message = 4;
}
```
`ProvisionHotspot*` (P0.5) becomes a **special case** (one `gated=true` SSID);
keep it for back-compat, then migrate the CP to `SetWirelessConfig`.
`EngineInfo` gains a `wireless_config_hash` (mirrors the existing `*_hash` fields)
so the CP can detect drift cheaply.

## Engine-side changes (this repo, generalise `portcullis-provision`)
1. **`uci.rs`**: replace the fixed allowlist with a **desired-state renderer**
   over owned sections + the **reserved denylist** guard + validation (no
   reserved targets, valid radio/vlan/encryption/subnet, radio capacity ≤ N SSIDs
   per device on mt76). Ownership = `owner='portcullis-wireless'` + `pc_<slug>_*`.
2. **`sm.rs`**: snapshot/diff now enumerates owned sections **from the device**
   (`uci show` filtered by owner) ∪ tmpfs marker, computes minimal set/delete.
   Commit-confirm core is unchanged.
3. **`handle.rs`**: handle `SetWirelessConfig`/`ConfirmWireless`; supersede rule
   (reject a second push while one is pending); emit per-SSID `WirelessStatus`.
4. **Multi-radio reload scoping**: reload only the affected radios, and **never
   the control-uplink radio** (generalise today's single-radio scoping). Critical:
   a fleet push must not bounce the radio the engine's own CP link rides on.
5. **Enforcement seam**: `with_hotspot_iface(String)` → `with_gated_ifaces(Vec)`
   in both `NftJsonBackend` and `IpsetIptablesBackend`; the composition root
   feeds the set of `gated=true` ifaces on each COMMITTED config.

## Fleet-side (CP / Go — contract only in this repo)
- **Template**: parameterised desired-state (`{{store_code}}`, brand, bands,
  egress policy). **Group**: routers by region/brand/tier. **Assignment**:
  template→group + per-store overrides. CP renders concrete per-router state.
- **Staged rollout**: canary (1–2 stores) → wave (%) → fleet, with health gates
  between stages; concurrency-capped fan-out over the already-open Attach streams.
- **Fleet safety = commit-confirm at the edge**: CP applies, re-observes each
  engine healthy, then sends `ConfirmWireless` inside the window. If a router
  drops off after apply (bad SSID knocked its uplink), **it auto-rolls-back on
  its own** — a broken template cannot take out the fleet.
- **Status/drift**: aggregate `WirelessStatus` + compare `wireless_config_hash`
  per router; surface applied-version, pending, rolled-back, drifted.

## Invariants preserved / new risks
Preserved: no flash writes · commit-confirm per apply · reserved denylist (never
lan/wan/admin/uplink) · kernel-as-truth enforcement untouched · single-owner
actor · bounded teardown · idempotent + boot-time reconcile.

New risks to validate on-hardware (RUTM11/RUT200, RutOS 21.02):
- **Radio capacity** (max SSIDs/VIFs per mt76 radio) — validate + reject overflow.
- **VLAN/bridge model** on OpenWrt 21.02 (DSA vs swconfig on the target).
- **Admin/uplink protection** — the denylist MUST include the radio/SSID the
  engine↔CP link uses, or a push can sever the confirm path (watchdog rescues,
  but avoid the churn).
- **Secrets** (PSKs) live in the CP DB + travel the wire — mTLS covers transport;
  treat keys as secrets at rest on the CP.

## Rollout phases
- **P-W1** (engine + proto, single router): reserved-denylist + owner-namespace
  model, desired-state renderer/reconcile, `SetWirelessConfig`/`ConfirmWireless`
  /`WirelessStatus`, multi-gated-iface enforcement. Hotspot = gated special case.
- **P-W2** (CP, Go): templates + groups + per-store render + `wireless_config_hash`
  drift.
- **P-W3** (CP, Go): staged fleet rollout (canary/wave) + fleet status dashboard.
- **P-W4**: advanced — per-SSID egress via PBR/mwan3 (the 4G/cable split), band
  steering, VLAN trunking.

## Decisions (locked 2026-07-07)
1. **Day-1 SSIDs**: **`public`** (gated captive, `encryption=none`) + **`home`**
   and **`retail`** (WPA2/3 PSK, trusted, NOT gated). Only `public` is gated.
   *guest vs VIP is NOT a separate SSID* — both connect to `public`; the
   guest/VIP difference is a **grant/tier-policy** decision at grant time (CP),
   not a wireless-provisioning concern.
2. **Isolation**: **bridge + firewall zones (L3)** for P-W1. VLAN deferred to
   P-W4 (only if a wired-segmentation / PCI need appears).
3. **Engine↔CP uplink**: **cable / 4G, never WiFi.** ⇒ radio reloads never
   threaten the CP link, so the uplink-radio guard collapses to: protect the
   **admin/management radio + admin SSID** only (plus lan/wan). Reload scoping is
   simple.
4. **Migration**: **migrate fully** to `SetWirelessConfig`; the CP (Go) will be
   re-coded onto the new frames. `ProvisionHotspot*` handling is **removed** from
   the engine once the CP cuts over; the proto **tags stay reserved** (never
   reused). `ProvisionState` enum is retained (reused by `WirelessStatus`).
5. **Secrets (PSK)**: CP is source-of-truth — per-store PSK, encrypted at rest in
   the CP DB, pushed over Attach (mTLS-protected), rotation = re-push. The engine
   writes the key to UCI and **NEVER logs it**; `WirelessStatus` / `GetWireless`
   **redact** the key. `public` is `encryption=none` ⇒ no secret.

---

# P-W1 implementation plan (engine + proto, single router)

## Concrete proto (`proto/enforcement.proto`, additive — mirror to Go copy)
```protobuf
// ControlFrame oneof (next free tags after confirm_provision=14):
SetWirelessConfigRequest set_wireless_config = 15; // -> CommandAck (applied-pending)
ConfirmWirelessRequest   confirm_wireless    = 16; // -> CommandAck (committed)
Empty                    get_wireless_config = 17; // -> EngineFrame.wireless_config

// EngineFrame oneof (next free after provision_status=10):
WirelessStatus wireless_status = 11; // per-SSID; unsolicited on watchdog rollback
WirelessConfig wireless_config = 12; // reply to get_wireless_config (keys redacted)

message WirelessSsid {
  string slug        = 1; // [a-z0-9_]{1,16}; sections named pc_<slug>_*
  string ssid        = 2; // advertised, 1..32
  repeated string radios = 3; // wifi-device names, e.g. ["radio0","radio1"]
  string encryption  = 4; // "none" | "psk2" | "sae" | "sae-mixed"
  string key         = 5; // PSK when encryption != none — SECRET, never logged/echoed
  bool   hidden      = 6;
  bool   isolate     = 7;
  bool   gated       = 8; // true = portcullis captive-gates the resulting iface
  WirelessNetwork  network  = 9;
  WirelessFirewall firewall = 10;
}
message WirelessNetwork {          // own-bridge+subnet is the ONLY day-1 mode
  string bridge_name    = 1;       // owner-namespaced, e.g. "br-public"
  string ipaddr         = 2;       // gateway host addr
  string netmask        = 3;
  string dhcp_start     = 4;
  string dhcp_limit     = 5;
  string dhcp_leasetime = 6;
  bool   dhcp_disabled  = 7;       // (rare; bridged-no-dhcp)
}
message WirelessFirewall {
  string egress_zone = 1;          // "wan" day-1 (cable/4g); per-tier uplink later
}
message SetWirelessConfigRequest {
  string config_version = 1;       // CP-issued; echoed in status + confirm
  repeated WirelessSsid ssids = 2;
  uint32 confirm_timeout_secs = 3; // 0=default 90, bounds [15,600]
}
message ConfirmWirelessRequest { string config_version = 1; }
message SsidResult {
  string slug = 1; bool ok = 2; string message = 3; string iface = 4;
}
message WirelessStatus {
  string config_version = 1;
  ProvisionState state = 2;        // reuse: APPLIED_PENDING|COMMITTED|ROLLED_BACK|FAILED
  repeated SsidResult per_ssid = 3;
  string message = 4;
}
message WirelessConfig {           // introspection; keys REDACTED
  string config_version = 1;
  repeated WirelessSsid ssids = 2;
}
// EngineInfo gains:  string wireless_config_hash = 10;  (drift detection)
// ProvisionHotspotRequest/ConfirmProvisionRequest/ProvisionStatus: mark DEPRECATED
// (comment only); keep tags reserved.
```

## Engine changes (files, in dependency order)
1. **`proto/enforcement.proto`** + `buf generate` → reg_en `portcullis-control/src/gen/`.
2. **`portcullis-types/src/lib.rs`**: `WirelessDesiredState{config_version, ssids,
   confirm_timeout_secs}`, `SsidSpec`, `SsidResult`, `WirelessStatus`. Broaden the
   `Provisioner` trait → `set_wireless(state)` / `confirm_wireless(version)` /
   `get_wireless()`. Remove `provision`/`confirm` (CP re-coded).
3. **`portcullis-provision/src/uci.rs`** (biggest, pure/TDD first):
   - per-SSID desired-state renderer → owner-namespaced sections `pc_<slug>_*`
     stamped `owner='portcullis-wireless'`.
   - **reserved denylist guard**: reject any SSID whose bridge/zone/section would
     collide with `lan`/`br-lan`/`wan*`/admin-SSID/admin-radio or the `inet
     wifihub` table; reject non-`pc_*` owned names.
   - per-SSID validation (as today) + **cross-SSID**: unique slugs, unique
     bridges, **non-overlapping subnets**, **radio VIF capacity** (≤ N per mt76).
   - `render_teardown()` → delete ALL owned sections.
4. **`portcullis-provision/src/sm.rs`**:
   - `snapshot()` enumerates owned sections **from the device** (`uci show`
     filtered by `owner`) ∪ tmpfs marker (today it snapshots the fixed allowlist).
   - `apply()` computes the minimal **set/delete diff** desired-vs-owned.
   - **multi-radio reload scoping** (`reload_sequence(radios)`), never the admin
     radio. Marker carries `config_version` + the owned-set.
5. **`portcullis-provision/src/handle.rs`**: handle `SetWireless`/`Confirm`/`Get`;
   supersede rule (reject a 2nd push while pending); emit per-SSID `WirelessStatus`.
6. **`portcullis-nft/src/{ruleset,nftables_json,ipset_iptables}.rs`**:
   `with_hotspot_iface(String)` → **`with_gated_ifaces(Vec<String>)`**; scope the
   FORWARD/PREROUTING gate to the **set** (`iifname { a, b }` / multiple `-i`).
   Empty set ⇒ no gate (fail-OPEN, unchanged).
7. **`portcullis-control/src/{channel,service,convert}.rs`**: route the 3 new
   ControlFrame variants → `Provisioner`; unary twins for on-net/dev; **redact
   `key`** in every outbound status/config; remove `ProvisionHotspot*` routing.
8. **`portcullis-engined/src/compose.rs`** — the **dynamic gated-iface loop**
   (the one genuinely new integration): on a `COMMITTED` `WirelessStatus`, collect
   the ifaces of `gated=true` SSIDs and call **`writer.set_gated_ifaces(set)`** →
   the writer re-applies ONLY the scoped jump rules. **Must NOT flush the `auth`
   set** (kernel-as-truth); re-scope jumps only. This replaces today's static
   boot-time `hotspot_iface`.
9. **`portcullis-config/src/lib.rs`**: reserved-name inputs for the denylist
   (admin radio + admin SSID names); keep a bootstrap default.

## Implementation order & gates
`proto → types → uci (pure, unit-tested) → sm → handle → nft multi-iface →
control/convert (redaction) → compose feedback loop → delete hotspot path`.
- Run `proto-contract-guard` after step 1, `portcullis-reviewer` after 3–8,
  `security-auditor` on the redaction + denylist before merge.
- **netns integration tests** (netns-harness): multi-SSID gate (only `gated`
  ifaces redirect; `home`/`retail` pass), **add/remove a gated SSID re-scopes
  enforcement live** (auth set survives), commit-confirm rollback, reserved-
  denylist reject applies nothing, boot-time reconcile of a mid-window marker.

## Risks specific to P-W1
- **Dynamic re-scoping without flushing auth** (step 8) is the sharp edge — must
  re-apply jumps idempotently while the `auth` set / per-element timeouts persist.
- **Radio VIF capacity** on mt76 — validate + reject overflow rather than let
  `wifi reload` half-fail.
- **Subnet overlap / DHCP pool collisions** across the N SSIDs — validation must
  catch before apply.
