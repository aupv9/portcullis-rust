# Design: conntrack reaping on de-auth — closing the established-flow leak

Status: **Proposed** — not yet implemented.
Scope: `portcullis-session`, `portcullis-accounting`, `portcullis-nft`
(`FirewallBackend`), `portcullis-types`, composition root. No proto/wire change.

---

## 1. Problem

An authorized client that is later **revoked / expired / quota-capped** keeps its
**already-open connections alive indefinitely**. Removing the client's MAC from
the `auth` set only gates *new* connections; existing flows leak straight through
the gate.

### Observed symptom (RUT200, iptables+ipset backend)

When the engine started enforcing while a laptop's MAC was **not** authorized:

- **Browser → dead.** Every page needs a *new* connection to a *new* host → all
  dropped → "no internet".
- **Claude Code + Telegram → kept working.** Both hold **long-lived** sockets
  opened *before* the gate went up (Claude Code: ~25 persistent HTTP/2 conns to
  the API; Telegram: one persistent MTProto socket to a hard-coded DC IP). These
  are `ESTABLISHED` and sail through untouched.

DNS was never the cause: `dnsmasq` runs *on* the router, so client queries hit the
`INPUT` chain, not `forward` — resolution kept working; only *new* connections to
the resolved IPs were dropped.

### Root cause (in the ruleset, both backends)

The `forward` chain's **first** rule unconditionally passes established traffic:

- iptables backend — `crates/portcullis-nft/src/ipset_iptables.rs:233`:
  ```
  1. -m conntrack --ctstate ESTABLISHED,RELATED  -j RETURN   # no MAC check
  2. -m set --match-set wifihub_auth src          -j RETURN
  3. -m set --match-set <garden> dst              -j RETURN
  4.                                              -j DROP
  ```
- nft backend — `crates/portcullis-nft/src/ruleset.rs:167` (`ct_established_accept`
  at `ruleset.rs:98`) is the first `forward` rule, same shape.

Rule #1 does **not** consult the `auth` set. So the *only* traffic it uniquely
permits — beyond what rules #2/#3 already allow for authed/garden — is
**established flows from a MAC that is no longer authed, to a non-garden host**.
That is exactly the leak.

De-auth today (`del_auth`) only mutates the set; nothing tears down live flows:

- `revoke_internal` → `del_auth` — `crates/portcullis-session/src/lib.rs:296`
- `tick_expiry` → `del_auth` — `crates/portcullis-session/src/lib.rs:336`
- No `conntrack -D` / flush exists anywhere in the workspace.

This violates the spirit of invariant #6 (**dual-path expiry**): expiry is
supposed to *end* a session, but a client holding a socket open (VPN, download,
streaming, Telegram) retains internet after their grant is gone.

## 2. Decision

**De-authorization must reap the client's conntrack entries**, so established
state disappears and the next packet is re-evaluated as `NEW` → falls to the
terminal `DROP`. Reap at three hooks, plus a background reconciler:

1. **Revoke** (`revoke_internal`) — after `del_auth`, reap the MAC's flows.
2. **Expiry** (`tick_expiry`) — same, per expired MAC.
3. **Cold-start / adoption** — reap flows for any neighbour MAC not in `@auth`.
4. **Reconciler backstop** — the metering loop already dumps the full conntrack
   table each tick; in the same pass, reap any flow whose source MAC ∉ `@auth`.

Conntrack is a single kernel table shared by nft and iptables, so **one reaper
implementation covers both backends** (RUTM11 and RUT200 alike).

### Why not fix it in the ruleset instead

The tempting "just drop rule #1, or gate it on the auth set" **does not work**,
because the `auth` set is keyed by **MAC** (`hash:mac` / nft `ether saddr`):

- **Reply traffic** (internet → client) carries the **upstream/gateway** source
  MAC, never the client's. So it can never match rule #2
  (`--match-set wifihub_auth src`).
- Rule #1 (`ESTABLISHED,RELATED accept`) is the *only* thing that lets the reply
  direction of an authed client's flow back in. Remove or MAC-gate it and authed
  clients lose all return traffic.
- Matching on `ether daddr` for the reply direction is unreliable: the
  destination MAC is generally **not resolved yet** at the `forward` hook.

With a MAC-keyed set, `ESTABLISHED,RELATED accept` is **load-bearing** and cannot
be conditioned on the client MAC. Therefore the leak cannot be closed at the rule
layer — it must be closed by removing the *state* (conntrack entry) that makes a
packet "established". Reaping is the correct mechanism, not rule surgery.

### Alternatives considered (rejected)

| Option | Pro | Con — why rejected |
|---|---|---|
| **Remove / MAC-gate rule #1** | No new moving parts | Breaks reply traffic for authed clients (see above). Fatal. |
| **Match `ether daddr` for replies** | Avoids conntrack | `daddr` not populated at `forward` hook → unreliable; two rules to keep in sync |
| **Short set timeouts + rely on re-auth** | Simple | Doesn't cut *live* flows at all; only shrinks the grant window. Leak persists within the window |
| **`conntrack -F` (flush all) on any change** | One-liner | Nukes the router's **own** mTLS control stream + all other clients. Never scope-flush the whole table |
| **Netlink `NFCT_Q_DESTROY` directly** | No CLI dep | `conntrack` CLI is **already** a runtime dep (metering, §3); netlink adds code + `unsafe`/FFI for zero dependency saving |

## 3. Reuse: the plumbing already exists

Nothing new needs to be packaged onto the RUT200's tiny flash.

| Building block | Already in tree | Reuse for reaping |
|---|---|---|
| `conntrack` fork/exec | `ConntrackReader`/`ConntrackCli` shell out `conntrack -L` — `crates/portcullis-accounting/src/conntrack.rs:32,43` (binary is already a runtime dep) | Add `conntrack -D -s <ip>` behind the same trait pattern |
| Neigh table parse | `parse_neigh_table -> Vec<(IpAddr, MacAddr)>` — `crates/portcullis-redirect/src/resolver.rs:88` | Build the reverse map (MAC → IPs) for reap-by-MAC |
| conntrack ↔ neigh join | metering `CounterSource` maps IP → MAC every tick — `crates/portcullis-accounting/src/conntrack.rs:147` | Piggyback the reconciler on the existing dump (no extra `conntrack -L`) |
| Auth-set membership | backend `list_auth()` (used for restart adoption) — e.g. `crates/portcullis-nft/src/ipset_iptables.rs:264` | Source of truth for "which MACs are still authed" |

## 4. Mechanism

### Trait (backend-independent, mockable)

```rust
// portcullis-types
#[async_trait]
pub trait FlowReaper: Send + Sync {
    /// Destroy every conntrack flow whose ORIGINAL source is `ip`.
    /// Idempotent: deleting when nothing matches is success, not error.
    async fn reap_by_ip(&self, ip: IpAddr) -> Result<usize>;
}
```

- Prod impl runs `conntrack -D -s <ip>` for v4 and `conntrack -f ipv6 -D -s <ip>`
  for v6. `conntrack -D` matching **original src** is correct: masquerade only
  rewrites the reply/postrouting tuple, so a forwarded client flow's original
  source stays the client's LAN IP — the same key metering already aggregates on
  (`conntrack.rs` comment: "per original source IP").
- "0 flow entries deleted" (conntrack's non-zero exit when nothing matched) is
  mapped to `Ok(0)`, mirroring `del_auth`'s idempotent `-exist` semantics
  (`crates/portcullis-session/src/lib.rs:257`).
- `MockReaper` records calls for unit tests; no kernel needed.

### Reap-by-MAC (session-facing)

The session manager keys on MAC, conntrack keys on IP. The reaper (or a thin
helper) resolves **MAC → IP(s)** via the neigh table (a MAC may have both a v4 and
a v6 neighbour) and calls `reap_by_ip` for each. This reuses `parse_neigh_table`;
the reverse lookup is exposed as a small addition to the shared resolver rather
than duplicated.

### Ordering (race-safe)

On revoke/expiry the order is **`del_auth` first, then reap**:

1. `del_auth(mac)` — removes the MAC from `@auth`; new packets now hit `DROP`.
2. `reap(mac)` — tears down live flows.

Reversed, an in-flight packet could recreate the conntrack entry *while the MAC is
still authed*, resurrecting the flow. `del_auth`-first closes that window: any
packet that recreates state after the reap is already unauthed → dropped, and its
(short-lived) entry is caught by the next reconciler pass.

After reap, mid-stream packets are seen as `NEW`/`INVALID`; rule #1 matches only
`ESTABLISHED,RELATED`, so they fall through to the terminal `DROP`. The client's
socket hangs/resets — the flow is genuinely severed.

### Cold-start / adoption

On restart the engine adopts `@auth` from the kernel (invariant #2, never flush
the set). Pre-existing conntrack flows for MACs **not** in the adopted set would
otherwise be grandfathered (this is precisely the observed RUT200 case). So after
adoption: enumerate the **neigh table**, and for each MAC ∉ `@auth`, reap its
IP(s). Scoping to known neighbour MACs guarantees we **never** touch the router's
own flows — in particular the outbound mTLS control stream to the CP originates
from the *router's* IP, not a client IP, so it is never a reap target.

### Reconciler backstop (free)

The metering loop already produces `(client_ip, mac, bytes)` tuples every tick
from one `conntrack -L` + neigh join. In the same pass, any tuple whose `mac ∉
list_auth()` → `reap_by_ip(client_ip)`. This absorbs cold-start leftovers, missed
reaps (retry on the next tick), and any orphaned flow — enforcing the invariant
below continuously, with zero extra conntrack dumps. It embodies kernel-as-truth
(§7.8): conntrack is periodically forced to agree with `@auth`.

## 5. Failure semantics — no fail-open (invariant #5) preserved

| Situation | Behaviour |
|---|---|
| `reap` fails (conntrack error / missing binary / no perms) | **Log + `metrics.incr(ReapFailed)`, mark degraded. Never fail open.** The gate (`DROP` on `NEW`) still holds; only pre-existing established flows leak — bounded — and the reconciler retries next tick. `del_auth` still succeeds regardless. |
| `reap` disabled by config | Same as above: degraded, explicit, logged once. |
| Neigh lookup returns no IP for a MAC | Nothing to reap this pass (client not in ARP/ND cache); reconciler retries when the neighbour reappears. |
| Reconciler mid-pass churn (a grant lands while reaping) | `del_auth`-first ordering + per-tick recheck against `list_auth()` converge; a freshly authed MAC is skipped. |

Reaping is **strictly additive** to enforcement: it can only *tighten* (cut a
flow), never *open* one. A reap failure degrades toward the current (leaky)
behaviour, never toward granting access.

## 6. Invariant established

> **Invariant #9 (new): conntrack ⊆ auth.** A client conntrack flow may exist only
> while its source MAC is in `@auth`. De-authorization (revoke / expiry / quota)
> and cold-start MUST reap the MAC's flows; a background reconciler continuously
> re-establishes this. `ESTABLISHED,RELATED accept` in the `forward` chain is a
> performance fast-path for **authed** clients and is kept safe *only* by this
> invariant — it must never be relied on to gate access.

Add to `CLAUDE.md`'s invariant list and cross-reference from the `forward`-chain
comments in both backends.

## 7. Implementation plan

Phased; each phase compiles and `cargo test --workspace` stays green on the host.
TDD per crate, as the existing code does.

### Phase 0 — trait + reverse resolver (`portcullis-types`, shared resolver)
- Add `FlowReaper` trait (`reap_by_ip`). Add `MockReaper`.
- Expose MAC → IPs reverse lookup reusing `parse_neigh_table`
  (`crates/portcullis-redirect/src/resolver.rs:88`); decide its home
  (promote the parser to `portcullis-types`, or a shared `neigh` module both
  redirect and the reaper import) to avoid duplication.
- Add metrics `Metric::FlowsReaped` (with a reason label) and `Metric::ReapFailed`.

### Phase 1 — prod reaper (`portcullis-accounting`, alongside `conntrack.rs`)
- `ConntrackReaper`: `conntrack -D -s <ip>` per family; tolerate the "0 deleted"
  exit; overridable binary path (mirror `ConntrackCli`).
- Unit tests over an injected command runner: correct args per family; "0 deleted"
  → `Ok(0)`; command error → `Err` (caller degrades, never panics).

### Phase 2 — wire into de-auth (`portcullis-session`)
- Inject `Arc<dyn FlowReaper>` + the reverse resolver into `SessionManager`.
- `revoke_internal` (`lib.rs:285`) and `tick_expiry` (`lib.rs:321`): after
  `del_auth`, resolve MAC → IP(s) and `reap_by_ip` each; failures → warn +
  `ReapFailed`, never propagate as a fail-open.
- Unit tests (mock reaper): revoke/expiry call reap **after** del_auth; reap error
  does not abort revoke; multi-IP (dual-stack) MAC reaps all IPs.

### Phase 3 — reconciler in the metering loop (`portcullis-accounting`)
- In the existing per-tick conntrack+neigh pass, `reap_by_ip` any IP whose MAC ∉
  `list_auth()`. Bound work to the tuples already dumped (no extra `conntrack -L`).
- Tests: authed MAC not reaped; orphan MAC reaped; reap failure logged, loop
  continues.

### Phase 4 — cold-start reap (`portcullis-engined` composition root)
- After adoption of `@auth`, walk the neigh table and reap MACs ∉ set. Assert the
  router's own IP is never a candidate.

### Phase 5 — config + docs
- `[enforcement] reap_conntrack = true` (default on), `reap_binary` override,
  `reconcile_interval` (reuse metering tick if aligned). `#[serde(default)]` under
  `deny_unknown_fields` for back-compat.
- `CLAUDE.md` invariant #9; comments in both `forward`-chain builders.

### Phase 6 — integration tests (`netns-harness`)
- **Revoke cuts a live flow:** authorize a client, open a long-lived TCP flow,
  revoke → assert the flow **stops** (not just that new connections fail).
- **Cold-start reaps pre-existing flow:** open a flow while unauth, (re)start the
  engine → flow is severed.
- **No collateral:** an authed client's flow and the control-plane stream are
  **not** reaped.
- **No fail-open on reap failure:** stub reaper to error → session still revoked,
  degraded metric set, gate still blocks new connections.

## 8. Risks & open questions

1. **conntrack CLI availability / accounting flag.** Reaping shares the metering
   dependency on the `conntrack` binary; on a device missing it, reaping degrades
   (§5) — but so does metering. Confirm the package dep is declared for both.
2. **Reverse-resolver placement.** Moving `parse_neigh_table` out of
   `portcullis-redirect` touches an inbound-surface crate (invariant #8); keep the
   move mechanical and re-run the redirect parser tests.
3. **Reconciler cost at scale.** Full-table scan per tick is fine at per-store
   churn, but confirm on-device against the <30 MB RSS / CPU budget; if needed,
   only run the reap branch when a recent de-auth flagged it dirty.
4. **UDP / connectionless flows** (QUIC, WireGuard client traffic). conntrack
   tracks UDP pseudo-flows; `-D -s <ip>` removes them too, but verify QUIC clients
   actually re-gate (they should, since the pseudo-flow is gone).
5. **`RELATED` children** (FTP data, ICMP errors). Reaping by source IP covers the
   parent; confirm no orphaned child entries survive on-device.

## 9. Summary of touched surfaces

| Crate / path | Change |
|---|---|
| `portcullis-types` | +`FlowReaper` trait, `MockReaper`, MAC→IP reverse lookup, `FlowsReaped`/`ReapFailed` metrics |
| `portcullis-accounting` | +`ConntrackReaper` (`conntrack -D`); reconciler branch in the metering loop |
| `portcullis-session` | reap after `del_auth` in `revoke_internal` + `tick_expiry`; inject reaper + resolver |
| `portcullis-engined` | cold-start reap after adoption; wire reaper into composition root |
| `portcullis-config` | `[enforcement] reap_conntrack` / `reap_binary` / `reconcile_interval` |
| `portcullis-nft` (both backends) | comment-only: mark `ESTABLISHED,RELATED` fast-path as invariant-#9-dependent |
| `deploy/*` | confirm `conntrack` (conntrack-tools) dep declared |
| netns integration | live-flow-cut, cold-start reap, no-collateral, no-fail-open tests |
| **unchanged** | proto/wire contract, `-control`, `-garden`, `-redirect` behaviour, all other invariants |
