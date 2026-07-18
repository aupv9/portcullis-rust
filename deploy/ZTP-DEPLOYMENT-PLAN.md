# ZTP Deployment Plan — RUTM11 & RUT200

> Zero-touch provisioning: flash a golden `.bin` once (bench/RMS, no SSH) → plug
> power + WAN → the router self-claims by serial and the engine dials the control
> plane → **online**. This plan covers both models and what remains to make it
> production-ready. Companion docs: `ZTP-GOLDEN-IMAGE.md` (step-by-step runbook),
> `PACKAGING.md` (build toolchain), `docs/design/hotspot-service-plan.md` (P0/P0.5).

## TL;DR

- **The hard parts are DONE and tested**: router first-boot claim agent
  (`portcullis-enroll.init`), CP `POST /api/enroll/claim` (HMAC + phase-gate +
  factory-reset self-heal, unit + E2E tests), admin register-serial, and the
  `.ipk` cross-build (one `mipsel_24kc` artifact runs on **both** models).
- **The real gap is packaging/ops, not design**: baking the golden `.bin`
  (Image Builder) was manual → now scripted (`build-golden-image.sh`), but the
  full "flash → power → online" flow is **not yet validated end-to-end on
  hardware**, and a few device gates are open (below).
- **Sequencing**: prove the pipeline on **RUT200 first** (already E2E-verified
  enforcement 2026-07-07, ipset backend = lower risk), then RUTM11.

## A. Current state — DONE vs TODO

| Component | State | Where |
|---|---|---|
| Router first-boot claim agent | ✅ DONE (idempotent, retry backoff) | `deploy/portcullis-enroll.init` |
| CP claim endpoint `/api/enroll/claim` | ✅ DONE + tests | `domain/server/internal/{handlers/enroll.go,services/enrollment.go}` |
| Admin register serial | ✅ DONE (409 on dup) | `handlers/admin_routers.go` |
| `.ipk` cross-build (mipsel_24kc) | ✅ DONE (zig 0.13 + cargo-zigbuild + build-std + soft-float + UPX) | `.github/workflows/release-ipk.yml` |
| FLEET_SECRET verify (rotation) | ✅ DONE (`FLEET_BOOTSTRAP_SECRETS`) | `internal/config/config.go`, `enrollment.go` |
| Golden-image bake automation | ✅ NEW (this plan) | `deploy/build-golden-image.sh` |
| Bulk register serial (CSV/QR) | ⚠️ verify endpoint exists | — |
| Full ZTP flow on hardware | ❌ not yet validated | pilot (Phase 3) |

## B. Key finding — one .ipk, one backend, both models

Both RUTM11 (MT7621) and RUT200 (MT7628) are MediaTek MIPS little-endian →
**same `mipsel-unknown-linux-musl` binary, same `mipsel_24kc` .ipk**. The shipping
firewall backend is **ipset+iptables** (TDD §17 opt B): stock RutOS lacks
`CONFIG_NFT_NAT`, so the engine auto-probes and uses ipset on both. The nft path
in the old `Makefile` DEPENDS was stale and has been reconciled to ipset (matching
`deploy/ci/pack-ipk.sh`). **The only per-model fork is the Image Builder target:**

| | RUTM11 | RUT200 |
|---|---|---|
| SoC / target | MT7621 / `ramips/mt7621` | MT7628 / `ramips/mt7628` |
| Rust target / .ipk arch | `mipsel-unknown-linux-musl` / `mipsel_24kc` | **same** |
| Firewall backend | ipset+iptables (auto) | ipset+iptables (auto) |
| Garden (dnsmasq) | `ipset=` (needs `dnsmasq-full`) | `ipset=` (needs `dnsmasq-full`) |
| Flash | 16 MB, roomy | **~2.2 MB overlay, tight** (keep UPX) |
| Radio | dual (assumed) | **single 2.4 GHz `radio0`**, SSID `RUT200_E74C` |
| Hardware-tested | ❌ (nft-on-fw3 was the historical risk; ipset avoids it) | ✅ enforcement core E2E 2026-07-07 |
| Stale config | — | leftover `network.wg_fleet` (pre-pivot) — leave untouched |

## C. End-to-end flow (works at code level today)

```
[bench] build-golden-image.sh --model <m> --secret <FLEET> → golden .bin
        flash via WebUI / RMS (NO SSH)
[field] power + WAN
        portcullis-enroll (START=94, before engine 95):
          enrolled marker? → exit (idempotent)
          serial (mnf_info) + WAN MAC + ts
          sig = HMAC-SHA256(FLEET_SECRET, "serial|mac|ts")   (openssl)
          POST {serial,mac,ts,sig} → CP /api/enroll/claim     (curl, retry ∞)
[CP]    verify HMAC ±300s → serial must be `provisioning` → issue bundle
          (mTLS cert CN=serial, CP CA, hmac.key, SSID, dial coords)
        router: write tls/ + hmac.key + UCI + marker → restart engine
        engine dials mTLS Attach → ONLINE
```

Preconditions on CP: serial pre-registered (state `provisioning`) and
`FLEET_BOOTSTRAP_SECRETS` contains the baked secret. Power-on may precede
registration (agent retries forever → order-independent).

## D. Phased plan

### Phase 0 — Package & deps hygiene *(code, ~1 day)*
- [x] Reconcile `Makefile` DEPENDS nft → ipset, matching `pack-ipk.sh`.
- [x] **Add `iptables-mod-ipset` to DEPENDS** (Makefile + pack-ipk.sh). The engine
  runs `iptables/ip6tables -m set --match-set` (`ipset_iptables.rs`), which needs the
  userspace extension libxt_set.so — this is SEPARATE from `kmod-ipt-ipset` (kernel
  modules). Missing it = `-m set` fails to load, gate silently never installs.
  (Stock RutOS usually has it via fw3/openNDS, so it "worked" untested — but an
  Image-Builder golden image won't include it unless declared.)
- [x] **Keep `dnsmasq-full` OUT of DEPENDS** — it conflicts with the pre-installed
  `dnsmasq` (opkg install would fail). It's swapped in at bake time via Image Builder
  `PACKAGES="dnsmasq-full -dnsmasq"` (`build-golden-image.sh`). Needed for the `ipset=`
  garden directive (stock slim dnsmasq lacks it).
- [ ] Confirm `mnf_info` serial flag on each model (one-time SSH): `-s` / `--sn` / `sn` (agent has fallback; confirm for clean logs).
- [x] **Fix `conntrack-tools` → `conntrack`** (Makefile + pack-ipk.sh). The package
  providing the `conntrack` CLI (flow reaper, invariant #9) is `conntrack`;
  `conntrack-tools` is conntrackd (the daemon) — the wrong name never resolves and
  aborts `opkg install` (verified on-device 2026-07-11).
- [ ] Confirm `ip neigh` (busybox `ip` or `ip-full`) runs on each model.
- [x] `bootstrap.conf` template ships `FLEET_SECRET=""` (ZTP off) — unchanged.

**Correct .ipk DEPENDS** (hard deps, no conflict):
`+ipset +iptables +ip6tables +kmod-ipt-ipset +iptables-mod-ipset +conntrack +curl +ca-bundle +openssl-util`
Bake-time only (Image Builder PACKAGES, not .ipk deps): `dnsmasq-full -dnsmasq`.
Opt-in (only if per-SSID QoS used): `tc sqm-scripts kmod-sched-cake`.
⚠️ `kmod-ipt-ipset` must come from the **RutOS** package repo (Image Builder), not the
generic OpenWrt feed — kernel vermagic/hash differs and OpenWrt kmods fail to install
on RutOS; on stock RutOS the ip_set/xt_set modules are usually already present.

### Phase 1 — Golden-image build automation *(ops, ~2 days)* ← main gap
- [x] `deploy/build-golden-image.sh` — param by model, bakes secret into a temp
  overlay (never committed), stages the .ipk, runs Image Builder, emits a
  versioned `.bin`. `--dry-run` prints the `make` command.
- [ ] Obtain the RutOS/OpenWrt Image Builder for `ramips-mt7621` and `ramips-mt7628`
  (Teltonika, firmware-matched). Confirm the device **profile** names with `make info`
  (defaults `teltonika_rutm11` / `teltonika_rut200` are guesses — override with `--profile`).
- [ ] (Optional) CI job: bake `.bin` on tag, FLEET_SECRET from a CI secret variable, upload artifact.

### Phase 2 — CP fleet prep *(ops, ~0.5 day)*
- [ ] Set `FLEET_BOOTSTRAP_SECRETS` on CP = baked secret (list → rotation-friendly).
- [ ] Register serials: `POST /api/admin/routers/register`. **Verify/add a bulk endpoint** (CSV/JSON) for fleet scale.
- [ ] Serial intake process: box label / QR → CSV → import.

### Phase 3 — Hardware pilot *(1–2 days)* — RUT200 first
**RUT200** (lower risk, already enforcement-verified):
- [ ] Bake golden `.bin` (mt7628) → flash 2 units via WebUI.
- [ ] Register serials → power + WAN → **verify ONLINE without SSH**.
- [ ] Evidence: `logread | grep portcullis-enroll`, `/etc/portcullis/enrolled`, `tls/`, engine dial + dashboard online.
- [ ] **RUT200 gates**: (a) UPX-packed binary execs under procd? (if not, drop UPX — flash still fits with ipset); (b) `dnsmasq-full` + `conntrack` present; (c) garden `ipset=` fills; (d) overlay headroom measured.

**RUTM11** (after RUT200 green):
- [ ] Bake golden `.bin` (mt7621) → flash → register → verify.
- [ ] **RUTM11 gate**: with ipset backend the historical nft-on-fw3 risk is avoided; confirm ipset+iptables coexists with fw3 and garden `ipset=` works.

### Phase 4 — Validation gates & hardening
- [ ] Clock skew: fresh boot may fail first claim (±300s); retry loop covers it — ensure NTP syncs early.
- [ ] DNS: prod resolves `CP_DOMAIN` via real DNS; dev pins via `CP_RESOLVE_IP`. Agent pins domain post-claim for reconnect safety.
- [ ] mTLS EKU: issued client cert must carry EKU clientAuth (else TLS alert 46 that looks like a dial timeout).

### Phase 5 — Scale / RMA / rotation *(runbook)*
- [ ] RMA: reset-claim / replace-device → serial back to `provisioning`; replacement uses the same golden image, self-claims new serial.
- [ ] Rotation: add new secret to `FLEET_BOOTSTRAP_SECRETS` (list) → bake new batch → retire old after batch drains.
- [ ] Fleet scale: bulk-flash via Teltonika RMS (no per-device SSH).

## E. Risk / gate matrix

| Gate | Model | Severity | Handling |
|---|---|---|---|
| Golden-image pipeline never run on real HW | both | **CRITICAL** | Phase 1 + Phase 3 pilot |
| ipset+iptables ⟷ fw3 coexistence | RUTM11 | Med | validate on-device (ipset avoids the old nft-nat risk) |
| UPX exec under procd on MIPS | RUT200 | Med | `upx -t` + real exec; drop UPX if it fails |
| `dnsmasq-full` / `conntrack` missing (empty feeds) | both | Med | pre-bake into golden image (`PACKAGES`) |
| `mnf_info` flag | both | Low | confirm once; fallback exists |
| WAN iface name on RUT200 | RUT200 | Low | agent falls back to UCI + `WAN_IF` |
| Bulk register serial | both | Low | add endpoint if missing |

## F. Scope note

**ZTP "online" ≠ working hotspot.** ZTP only enrolls the engine and gets it
dialing Attach. A production hotspot also needs **P0 interface-scoping** (else
fail-open / over-block the whole LAN) and **P0.5 provisioning** — see
`docs/design/hotspot-service-plan.md`. Run this plan alongside P0/P0.5, not
instead of them.
