# Design: CP-owned config boundary — "thin engine"

Status: **Reference / architecture doctrine** — 2026-07-18. Describes the intended
config-ownership split between the **control plane (CP, Go, `domain/server`)** and
the **engine (Rust, this repo)**, and the rule the whole team uses to classify any
new config key. Mostly **describes what already exists** (~90% of the target is
built); the small remainder + the tensions are called out explicitly. No new code
mandated by this doc — it's the boundary contract, and the roadmap that follows it.

## TL;DR

Goal: the engine holds only what it needs to **phone home and describe itself**;
the CP is the **source of truth for all policy/behavior** and pushes it down.

This is already substantially true. The engine does **not** hold garden/tier/
enforcement/params/wireless as authoritative local config — those are CP-pushed at
runtime and seeded from static UCI only until the first Attach. But "engine keeps
**only** the edge endpoint" is the wrong target: the irreducible local minimum is a
**bootstrap kit** (endpoint + identity + a few device-capability descriptors), not
a single line.

Every on-device config key falls into exactly one of **three tiers**:

| Tier | Owner | Direction | Lives | Example |
|---|---|---|---|---|
| **1. Bootstrap kit** | CP mints, engine caches | CP→engine at **enroll** (once) | flash (`/etc/portcullis/`) | client cert, `store_id`, `hmac_key`, `control_endpoint` |
| **2. Device descriptors** | engine (hardware truth) | engine→CP **advertise** | flash (`/etc/config/portcullis`) | `firewall_backend`, `hotspot_iface`, `shape_iface` |
| **3. Policy / behavior** | CP (authoritative) | CP→engine over **Attach** (runtime) | tmpfs (`/tmp/portcullis/runtime.json`) | garden, tiers, enforcement gate, engine params, wireless |

The rest of this doc defines each tier, the **classification rule** for new keys,
the current gaps, and how this coexists with the engine's load-bearing invariants
(no-brick, no-flash-state, fail-closed).

---

## Tier 1 — Bootstrap kit (irreducible local, but CP is source-of-truth)

The engine cannot ask the CP how to reach the CP. So a minimum must exist on the
device **before the first Attach dial**. The subtle point: **CP still owns these**
— they are *minted by the CP at ZTP enroll* and merely cached on the device. The
channel is enroll (once), not Attach (continuous).

| Key | Purpose | Provisioned by | Loaded by |
|---|---|---|---|
| `control_endpoint` | gRPC address the engine dials (CGNAT-safe, outbound) | enroll → UCI | `portcullis-config/src/lib.rs:38` |
| `cp_server_ca_file` | pin CP's server CA for mTLS verify | enroll → `/etc/portcullis/tls/cp-ca.crt` | `compose.rs:412` (`load_client_tls`) |
| `cp_server_name` | SNI / cert CN·SAN to verify | enroll → UCI | `lib.rs` config |
| **client cert + key** | engine's mTLS identity to CP | enroll → `/etc/portcullis/tls/client.{crt,key}` | `compose.rs:412` |
| `store_id` | site identity, signed into redirect HMAC; bound to cert CN·SAN | enroll → UCI | validated `lib.rs:322` |
| `hmac_key` | signs redirect URIs for **pre-auth** clients at `:8080` | enroll → `/etc/portcullis/hmac.key` | `compose.rs:456` |

**Why none of these move to Attach-push:** each is required to *establish or trust*
the Attach connection itself (endpoint/CA/SNI/cert), or to serve pre-auth clients
before any CP round-trip (`hmac_key`, `store_id`). Chicken-and-egg.

**What is baked at manufacture (before enroll):** only the batch bootstrap —
`CP_DOMAIN`, `CLAIM_URL`, `FLEET_SECRET` (batch-shared HMAC), `WAN_IF`, optional
`CP_RESOLVE_IP` (dev DNS pin). See `deploy/portcullis-enroll.init` and
`docs/../ztp-serial-enrollment` (CP side: `domain/server/docs/ztp-serial-enrollment.md`).
A fresh device holds **no** cert, **no** `hmac_key`, **no** `store_id` — it earns
them by proving `HMAC-SHA256(FLEET_SECRET, "serial|mac|ts")` to `POST /api/enroll/claim`,
which returns the bundle it then persists (`enroll.init:73-99`).

> **Failure modes** (`compose.rs:434`): no client cert → control channel disabled,
> existing kernel sessions keep being enforced, no new grants. No `hmac_key` →
> responder starts but every redirect signature fails. No `store_id` → daemon
> refuses to boot. These are fail-closed by design.

---

## Tier 2 — Device descriptors (local, engine advertises to CP — never CP→push)

These describe **what the router *can* do** (hardware/topology), not **what it
*should* do** (policy). They belong on the device because only the device knows
them; the CP learns them by reading `GetEngineInfo`, and must never try to set them.

| Key | Meaning | Why local |
|---|---|---|
| `firewall_backend` (`nft`/`ipset`/`auto`) | kernel capability, probed at boot | CP can't know the router's kernel; wrong value = no enforcement |
| `hotspot_iface` | L2 bridge the gate scopes to (`""` = fleet-wide) | device topology; couples to wireless provisioning |
| `shape_bandwidth` + `shape_iface` | whether tc/HTB shaping is available + on which egress iface | device capability (has `tc`? which iface?) |
| `reap_conntrack` | whether `conntrack` binary exists for flow reaping | device capability |
| `wireless_protected_radios` | admin radios CP-managed wireless must never touch | on-site safety guard (protect admin SSID) |
| `responder_port`, `metrics_port` | local listener bindings | device-local plumbing, not a feature knob |
| `reconcile_interval` | kernel drift-sweep cadence | low-level device tuning, not policy |

**Rule:** the engine **advertises** these as `capabilities` in `EngineInfo`
(`proto enforcement.proto:264` → `GetEngineInfo`); the CP **reads** them to decide
what it may push (e.g. don't push a rate cap to a router that reports no `shaper`
capability). The CP does **not** push them back down. Pushing Tier-2 from CP is an
anti-pattern — it would let a CP that's wrong about the hardware brick enforcement.

> Two keys **straddle** Tier 2/3 and are the only real "could-move" candidates:
> `hotspot_iface` and `responder_port`. They're device-topology today (Tier 2) but
> could be folded into the wireless-provisioning push. Deferred — they couple to
> firewall rules and provisioning, and changing them needs a restart. Not worth the
> risk for keys that never change after install.

---

## Tier 3 — Policy / behavior (CP-owned, pushed over Attach, already built)

This is everything an operator tunes. **The CP is authoritative.** Static UCI
values are only a *seed* used until the first Attach; the CP's push then overwrites
them and the merged state is persisted to tmpfs so it survives a **daemon restart**
(not a power cycle — see Gaps).

| Policy | CP frame | Engine apply / persist | CP source of truth |
|---|---|---|---|
| Walled garden FQDNs | `SetGarden` (`proto:239`) | `channel.rs:368` → `runtime.rs` → `runtime.json` | `routers.garden_fqdns` + fleet Zalo defaults (`dispatch.go:375`) |
| Tier policies (ttl/quota/rate) | `SetTierPolicies` (`proto:250`) | `channel.rs:358` | `tiers` table, `dispatch.go:377` |
| Enforcement gate | `SetEnforcement` (`proto:235`) | `channel.rs:375` | `routers.enforcement_enabled`, `dispatch.go:378` |
| Engine params (accounting/idle/max_sessions) | `SetEngineParameters` (`proto:254`) | `channel.rs:382` | `routers.engine_params` jsonb, `dispatch.go:447` |
| Wireless / SSID (N SSIDs, peer-rules) | `SetWirelessConfig` (`proto:410`) | provisioner + watchdog, `/tmp/portcullis/provision/` | `store_ssids` + `store_ssid_peer_rules`, `services/wireless.go` |

Every write path: validate → lock `RuntimeConfig` → update field → **persist to
`/tmp/portcullis/runtime.json`** (best-effort, never fatal) → publish on a
`watch::channel` so effect loops hot-reload without restart (`runtime.rs:163-222`).
On reconnect the CP re-pushes via `Reconcile*` (`dispatch.go`) and, for wireless,
the manual-apply drift model (`DetectWirelessDrift`, see
`project_wireless_manual_apply` / this repo's confirm-on-reconnect doc).

**One deliberate exception — segment policies stay CP-side and are *not* pushed.**
Guest/member segmentation, `allowed_windows` (opening hours), and daily guest
budgets are evaluated **at grant time in the CP** (`hotspot.go:243-262`, `333-341`);
the engine only receives the *resolved* ttl/quota/rate inside the `Grant`. This is
**correct for a thin engine** — complex temporal policy lives where it's easy to
edit/audit, and the engine stays a dumb enforcer. Trade-off: if the CP is
unreachable the engine can't enforce opening-hours/budget for *new* sessions (it
keeps enforcing existing grants via kernel-as-truth). Accepted.

---

## The classification rule (use this for every NEW config key)

When someone adds a config knob, decide its tier with three questions:

```
Is it needed to establish/trust the Attach connection, or to serve
pre-auth clients before any CP round-trip?
        └── YES → TIER 1 (bootstrap kit). Provision via enroll, cache on flash.
        └── NO ↓
Does it describe what the hardware CAN do (capability/topology),
rather than what it SHOULD do (policy)?
        └── YES → TIER 2 (device descriptor). Local seed; advertise in EngineInfo;
                  CP reads, never pushes.
        └── NO ↓
It's policy/behavior an operator tunes.
        └── TIER 3 (CP-owned). Add a Set* frame + Reconcile*; CP is source of
            truth; engine seeds from UCI, persists CP value to tmpfs, hot-reloads.
```

**Default bias:** new operator-facing knobs are Tier 3. Only drop to Tier 2 if the
CP genuinely cannot know the value. Only Tier 1 if it's load-bearing for
bootstrap. Resist adding Tier-1/2 keys — every one is another thing to bake or
enroll and another drift surface.

---

## Current state vs target

**Already achieved (the 90%):**
- All Tier-3 policy is CP-pushed over Attach and hot-reloads without restart.
- Tier-3 survives a **daemon restart** (tmpfs `runtime.json` reload, `runtime.rs:128`)
  and wireless survives via `/tmp/portcullis/provision/` (`compose.rs:117`).
- Sessions survive restart via kernel-as-truth adoption (`compose.rs:55`), not config.
- Tier-1 identity is CP-minted at enroll, not baked per-device.
- The seam scales: adding a Tier-3 type is one `Set*`/`Reconcile*` pair.

**Gaps / open decisions:**

1. **Cold-boot-while-CP-offline degrades to seed.** `runtime.json` is **tmpfs**, so
   a *power cycle* (not just daemon restart) wipes CP-pushed Tier-3; the engine boots
   on the static UCI seed (empty garden, default tiers) until Attach re-syncs.
   **This is a consequence of engine invariant #1 (no runtime state on flash — NAND
   wear bricks routers), not a bug.** Do **not** "fix" it by persisting live snapshots
   to flash on every `Set*`. Options, in preference order:
   - **(a) Accept it (recommended).** The engine dials out immediately on boot; the
     degraded window is seconds when the CP is up. The only real exposure is
     *simultaneous* router power-loss **and** CP outage — rare, and fail-closed
     (enforcement default-on means the seed blocks, it doesn't open).
   - **(b) Richer safe seed.** Bake a sensible default garden (Zalo) + a
     conservative default tier into the UCI seed so a cold-boot-offline router is
     usable-but-safe, not empty. Cheap, no invariant conflict.
   - **(c) Low-frequency flash snapshot** *only if* (a)+(b) prove insufficient.
     Config changes at operator cadence (a few writes/day), **not** session cadence,
     so it does not violate the *spirit* of invariant #1 (which targets per-packet/
     per-session churn). Would need an explicit **ADR** amending invariant #1 to
     distinguish "config state" from "session/runtime state", plus wear budgeting.
     Not recommended unless a real offline-cold-boot requirement appears.

2. **N separate frames, no atomic snapshot.** CP pushes `SetGarden` + `SetTierPolicies`
   + `SetEnforcement` + `SetEngineParameters` + `SetWirelessConfig` as independent
   commands, each persisted + drift-detected per-subsystem. Fine today; the roadmap
   below tightens it.

3. **`hotspot_iface`/`responder_port` straddle Tier 2/3** (see Tier 2 note). Left local.

---

## Roadmap (optional, if we want the last 10%)

**R1 — Richer safe seed (small, no invariant change).** Ship a default garden +
conservative default tier in the UCI seed. Closes gap #1 for the common case.

**R2 — `ApplyConfigSnapshot` (medium).** Add one CP→engine frame carrying the full
Tier-3 desired-state with a single `config_version`:
- Apply atomically (all-or-nothing), reuse the wireless commit-confirm/watchdog so a
  bad snapshot rolls back — no brick.
- Drift detection collapses from N per-subsystem hashes to **one** `config_version`
  compared against `EngineInfo` (`proto:264`). The manual-apply ledger
  (`router_wireless_state`) generalizes from wireless-only to whole-device.
- Keeps the existing `Set*` frames for incremental live edits; the snapshot is the
  authoritative reconcile path on connect.

**R3 — (only if required) config-on-flash ADR.** Decide (c) above under a written
ADR if an offline-cold-boot durability requirement is ever real.

Do **R1 first** — highest safety-per-effort. R2 is the clean long-term shape but is
not blocking anything today.

---

## Invariants this doctrine preserves

- **No-brick:** Tier 2 (hardware truth) never comes from the CP; a wrong CP can't
  mis-scope enforcement. Tier-3 snapshots ride the wireless commit-confirm watchdog.
- **No runtime state on flash (#1):** Tier-3 lives in tmpfs. This doc explicitly
  refuses to persist live config to flash absent an ADR (see gap #1).
- **Kernel-as-truth (#2):** sessions survive restart via `@auth` adoption, never via
  config persistence — orthogonal to this boundary.
- **Fail-closed (#5):** every missing Tier-1 key and every degraded seed fails
  closed (block new grants / block traffic), never open.
- **Single wire contract:** Tier-3 additions go through `proto/enforcement.proto`
  (`package wifihub.enforcement.v1`), kept in sync with `domain/server/proto/`.

## Non-goals

- Pushing Tier-2 device capabilities from the CP (anti-pattern).
- Making the engine stateless — it caches Tier-1 on flash and Tier-3 in tmpfs by
  design; "thin" ≠ "stateless".
- Removing static UCI — it remains the boot seed and the offline fallback.
- Changing the segment-policy-at-grant model — CP-side evaluation is the right thin-
  engine choice.
