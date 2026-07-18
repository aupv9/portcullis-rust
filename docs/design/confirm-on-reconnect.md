# Design: Confirm-on-reconnect for CP-managed wireless commit-confirm

Status: proposed (target: next `.ipk`)
Scope: `portcullis-provision`, `portcullis-control`
Related: [`cp-managed-wireless-fleet.md`](cp-managed-wireless-fleet.md), [`cgnat-bidi-control-channel.md`](cgnat-bidi-control-channel.md), ADR-0003 (engine dials CP), ADR-0006 (no flash writes)

## 1. Problem

The CP-managed wireless push (P-W1) uses **commit-confirm** to guard against a config
that breaks the router's dial-out path (CGNAT = no inbound rescue): apply → arm a
watchdog (`window_secs`, default 90) → the CP sends `ConfirmProvision` while the Attach
stream is still live → engine commits; otherwise the watchdog fires and rolls back to the
pre-apply snapshot.

The confirm signal **shares fate with the config channel** — both ride the one Attach
stream. So the watchdog cannot distinguish:

- **"the config broke my dial-out"** (must roll back), from
- **"the Attach stream is flaky for a reason unrelated to the config"** (must NOT roll back).

Observed in the field: a healthy wireless push (clients demonstrably got DHCP leases on
the new bridge) was **repeatedly rolled back** purely because the transport under the
Attach stream flapped inside the 90 s window. Each false rollback also reloads Wi-Fi →
kicks connected clients. Net effect: a CP-managed SSID (e.g. `br-ss1`) never stays up,
while a router-native `lan` SSID (never part of commit-confirm) is rock-solid.

A wireless-SSID change on an owned bridge **cannot** break the WAN dial-out (independent
paths), so for these changes the rollback is both unnecessary and actively harmful.

## 2. Principle

> The question commit-confirm actually needs to answer is **"did this change break my
> dial-out?"** — not **"did the CP manage to push a frame back within 90 s of one
> continuous stream session?"**
>
> The engine **re-establishing its outbound control channel after the apply is direct,
> local proof that the dial-out survived the change.** Use that as the confirmation
> signal.

This keeps the safety property intact (a change that genuinely kills the dial-out → the
engine can never redial → no self-confirm → watchdog still fires → rollback) while
removing the false-positive on a flaky-but-recovering link.

## 3. Mechanism

Add a **local self-confirm** path to the provision actor, driven by a new
control-channel signal. The CP's explicit `ConfirmProvision` remains valid and takes the
faster path when the stream is continuously healthy; self-confirm is the fallback that
fires whenever the engine observes a healthy dial-out post-apply.

### 3.1 New internal signal (no wire/proto change)

`portcullis-control::channel` already flips an `established` flag on the **down→up
transition** of the stream (it "only signals ... on the transition — not on every failed
dial"). At that transition point, notify the provision subsystem:

```
// channel.rs, at the established-transition (near the existing rescope_enforcement call)
cfg.provisioner.notify_channel_established().await;   // fire-and-forget
```

Add to the `Provisioner` trait (default no-op so mocks/`reaper` fakes are unaffected):

```rust
trait Provisioner {
    // ...existing: get_wireless, set_wireless, confirm_wireless...
    /// The outbound control channel just (re)established. Proof the dial-out is alive.
    async fn notify_channel_established(&self) { /* default: no-op */ }
}
```

`ProvisionHandle::notify_channel_established()` sends a new `Command::ChannelEstablished`
(fire-and-forget; no reply channel).

### 3.2 Provision actor handling

New arm in the `ProvisionActor::run` select loop:

```rust
Some(Command::ChannelEstablished) => {
    self.handle_channel_established().await;
}
```

```rust
async fn handle_channel_established(&mut self) {
    let Some(p) = self.pending_wireless.as_ref() else { return };   // nothing pending
    if Instant::now() >= p.deadline { return }                      // window already lost → let watchdog own it
    let version = p.config_version.clone();
    tracing::info!(
        config_version = %version,
        "control channel (re)established within confirm window; self-confirming (dial-out survived the change)"
    );
    // Reuse the exact commit path the CP-confirm uses → identical committed state + marker.
    let _ = self.handle_confirm_wireless(&version).await;
    // handle_confirm_wireless already emits a COMMITTED WirelessStatus upward so the CP
    // learns the push committed even though it did not send ConfirmProvision (keeps the
    // CP's per-store wireless status in sync — message e.g. "self-confirmed on reconnect").
}
```

Key correctness points:

- **No spurious confirm on the delivering session.** `Command::Set` arrives over an
  already-established stream, so that session's `established` transition fired *before*
  the push (pending was `None` then → no-op). A self-confirm can only be triggered by a
  *later* re-establishment, i.e. an actual drop+redial. The stable path is untouched:
  the CP's `ConfirmProvision` still commits it and no new transition occurs.
- **Idempotent commit.** `handle_confirm_wireless` must be safe when called twice / when
  nothing is pending (already the case: it checks `pending_wireless`). Both the CP path
  and self-confirm route through it.
- **Watchdog unchanged.** It still fires and rolls back iff *neither* a CP-confirm *nor*
  a post-apply re-establishment occurred before `deadline` — i.e. the dial-out is
  genuinely down. Lockout protection (ADR-0003) preserved.
- **Status sync upward.** Emitting the COMMITTED `WirelessStatus` on self-confirm is
  required so the CP does not keep showing `rolled_back`/`pending` while the engine has
  committed. Reuse the existing `wireless_status_tx` unsolicited path.

### 3.3 Restart interaction (crash-recovery)

`reconcile_wireless_on_start` already resumes the watchdog for the remaining window when a
persisted `WirelessMarker` is still within its deadline. With this change, the startup
redial produces the first `established` transition → `ChannelEstablished` → self-confirm
of the resumed pending. So **a restart mid-window that successfully redials self-confirms**
instead of waiting on the CP — strictly better, and consistent with ADR-0004
(kernel-as-truth, adopt-never-flush) and ADR-0006 (marker on tmpfs, not flash).

## 4. Optional hardening

- **Stability grace (recommended, small).** Instead of confirming on the raw transition,
  self-confirm only after the channel has stayed up for a short grace `G` (reuse/mirror
  the CP `confirmGrace`, default ~3–5 s) — avoids committing on a re-establishment that
  instantly drops again in a flap storm. Implement as a one-shot timer in the select
  loop: on `ChannelEstablished` schedule self-confirm at `now+G`; cancel it if a
  `ChannelLost` signal (add symmetric to `established`) arrives first. If the extra
  `ChannelLost` signal is undesired, ship the immediate variant first — a single
  successful redial is already valid proof; a later flap is external, not the config.
- **Sustained-health generalization (CP-independent).** Self-confirm also when the
  channel is *continuously* healthy for `G` after apply (not only on a transition). This
  additionally covers "stream stayed up but the CP failed to send `ConfirmProvision`"
  (CP crash / bug). Turns the CP's confirm into a pure fast-path bonus. Needs the same
  `ChannelLost` reset signal.
- **Risk differentiation (future).** Wireless-only pushes on non-WAN bridges can never
  break dial-out; confirm-on-reconnect already handles them correctly with no special
  case. If ever needed, tag pushes that touch WAN/routing/firewall to keep the strict
  window and let wireless-only pushes lean entirely on self-confirm.

## 5. Code touch points

| File | Change |
|---|---|
| `crates/portcullis-provision/src/handle.rs` | `Command::ChannelEstablished` variant; `ProvisionHandle::notify_channel_established()`; `handle_channel_established()`; new select arm; ensure `handle_confirm_wireless` is idempotent + emits COMMITTED status |
| `crates/portcullis-control/src/channel.rs` | at the `established` down→up transition, call `provisioner.notify_channel_established()` |
| `Provisioner` trait (control/ports) | add `notify_channel_established()` default no-op; impl on the real provisioner handle; mocks inherit the no-op |
| (optional) | `ChannelLost` signal + one-shot self-confirm timer for the stability-grace / sustained-health variants |

No `proto/enforcement.proto` change. Fully backward-compatible: an old CP that still
sends `ConfirmProvision` works unchanged; a CP that never sends it now still results in a
committed push once the engine's dial-out is proven healthy.

## 6. Tests

- apply → simulate stream drop → `ChannelEstablished` within window ⇒ **committed** (not rolled back); COMMITTED status emitted upward.
- apply → no confirm, no re-establishment before deadline ⇒ **rolled back** (unchanged safety).
- apply → `ChannelEstablished` *after* deadline ⇒ already rolled back; self-confirm is a no-op (guarded by the deadline check).
- restart mid-window → `reconcile_wireless_on_start` resumes → startup `ChannelEstablished` ⇒ self-confirmed.
- double confirm (CP `ConfirmProvision` **and** `ChannelEstablished`) ⇒ single committed state, no panic (idempotency).
- (hardening) flap storm: `ChannelEstablished` then `ChannelLost` before grace `G` ⇒ no premature self-confirm.
- netns integration: extend the existing commit-confirm suite with a "drop + redial inside window" case asserting the SSID/bridge survives.

## 7. Why this is the right shape

- Tests the **actual lockout risk** (dial-out survival), measured **locally**, instead of
  a proxy ("CP delivered a frame on one continuous session").
- **Preserves** the commit-confirm safety net (ADR-0003) — a change that kills dial-out
  still rolls back, because the engine can never redial to self-confirm.
- **Engine-owned**: no dependency on CP timing/reachability for the *common, safe* case
  (wireless SSID edits), which is exactly where the false rollbacks bite.
- Minimal + backward-compatible: one internal signal, one actor arm, no wire change.
