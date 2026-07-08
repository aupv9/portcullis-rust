//! Pure-ish domain crate: the [`Session`] model and the [`SessionManager`] that
//! owns the in-RAM session view and funnels every nftables mutation through the
//! injected [`RulesetWriter`] port (TDD §7.4, §7.8, §7.9).
//!
//! This crate performs **no I/O** and never touches the kernel or a process
//! directly. All side effects flow through two injected ports:
//! [`RulesetWriter`] (nftables mutations) and [`EventSink`] (lifecycle events).
//! Everything else is deterministic in-memory state, which makes the whole
//! lifecycle unit-testable with mock ports and an injected `now: Instant`.
//!
//! ## Load-bearing invariants (CLAUDE.md / TDD §5, §7)
//!
//! * **No fail-open (G2):** on `grant`, the writer's `add_auth` is called
//!   *first*; only if it succeeds is the session inserted and `GRANTED` emitted.
//!   A writer error means the session never becomes active and the error
//!   propagates — the client stays gated.
//! * **Kernel-as-truth (§7.8):** [`SessionManager::adopt`] rebuilds the in-RAM
//!   view from the kernel `auth` set after a restart, so no authorized client is
//!   dropped across a daemon upgrade. Adopted sessions do **not** emit `GRANTED`.
//! * **Dual-path expiry (§7.4):** the kernel set-element `timeout` is the
//!   backstop; [`SessionManager::tick_expiry`] is the daemon-side path that emits
//!   the accounting `EXPIRED` record and (belt-and-suspenders) calls `del_auth`.
//! * **Single nft writer (§7.9):** the manager only ever talks to the one
//!   injected `RulesetWriter`; serialization of mutations is that adapter's job.
//!
//! ## Deterministic time
//!
//! The public trait methods read `Instant::now()` and delegate to internal
//! `*_at(..., now)` methods ([`grant_at`](SessionManager::grant_at),
//! [`apply_counters_at`](SessionManager::apply_counters_at),
//! [`tick_expiry`](SessionManager::tick_expiry)). Tests drive those directly with
//! a fixed `now`, so the lifecycle is fully reproducible.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use portcullis_types::{
    AuthElement, Counters, Enforcer, Error, EventKind, EventSink, FlowReaper, GrantParams,
    HealthStatus, MacAddr, Metric, MeteringSink, MetricsSink, NoopMetrics, NoopReaper, NoopShaper,
    ReconcileReport, Result, RevokeReason, RulesetWriter, SessionEvent, SessionId, SessionInfo,
    Shaper, Tier, UnknownKernelPolicy,
};

/// Minimum remaining TTL for the reconciler to bother re-adding a kernel-missing
/// element (TDD §7.8). Below this the session is expiring imminently — let the
/// daemon expiry sweep handle it rather than racing a re-add against removal.
const RECONCILE_MIN_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bound on concurrently-tracked sessions held in RAM.
///
/// One RUTM11 serves a single site/venue; realistic concurrent client counts
/// are in the low hundreds. The cap is a defensive ceiling against a runaway
/// control plane or a memory-exhaustion attack via the grant path — each
/// [`Session`] is a handful of words, so 4096 is roughly a few hundred KB,
/// comfortably inside the <30 MB RSS budget (TDD §5, embedded-perf). Grants past
/// the cap are rejected ([`Error::Backend`]) and logged; nothing is evicted, so
/// existing authorized clients are never silently dropped.
pub const MAX_SESSIONS: usize = 4096;

/// In-RAM per-client session record (TDD §7.4).
///
/// `bytes_in`/`bytes_out` are *per-session* totals. The kernel/conntrack source
/// reports *absolute* monotonic counters, so we keep a `baseline_*` captured at
/// grant/adopt time and report `absolute - baseline`. If an absolute counter
/// ever drops below its baseline (conntrack flush / counter reset), we
/// re-baseline to the new absolute value instead of underflowing.
#[derive(Clone, Debug)]
pub struct Session {
    pub session_id: SessionId,
    pub mac: MacAddr,
    pub ip: Option<std::net::IpAddr>,
    pub tier: Tier,
    pub granted_at: Instant,
    pub expires_at: Instant,
    /// Last time a positive byte delta was observed for this session (G6). Seeded
    /// at grant/adopt; the idle sweep de-auths sessions quiet past the threshold.
    pub last_activity: Instant,
    pub quota_bytes: u64,
    pub rate_bps: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Raw kernel counter at grant/adopt time; absolute counters are converted
    /// to per-session deltas relative to this. `None` until the first snapshot
    /// that mentions this MAC establishes the baseline.
    baseline_in: Option<u64>,
    baseline_out: Option<u64>,
    /// Captured at grant time so `SessionInfo.granted_at_unix` can be reported
    /// without converting an `Instant` (which has no wall-clock anchor).
    granted_at_unix: i64,
}

impl Session {
    fn total(&self) -> u64 {
        self.bytes_in.saturating_add(self.bytes_out)
    }

    fn to_info(&self, now: Instant) -> SessionInfo {
        let expires_in = self.expires_at.saturating_duration_since(now);
        SessionInfo {
            session_id: self.session_id.clone(),
            mac: self.mac,
            ip: self.ip,
            tier: self.tier,
            granted_at_unix: self.granted_at_unix,
            expires_in,
            quota_bytes: self.quota_bytes,
            rate_bps: self.rate_bps,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
        }
    }
}

/// Current wall-clock as a Unix timestamp (seconds), used only for event
/// `ts_unix` and `granted_at_unix`. Falls back to 0 if the clock is before the
/// epoch (impossible in practice).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Owns the in-RAM session view and the two injected ports (TDD §7.9).
///
/// Construct with [`SessionManager::new`]. The integrator wires it as the
/// `Enforcer` (control-plane facing) and the `MeteringSink` (accounting facing).
pub struct SessionManager {
    writer: Arc<dyn RulesetWriter>,
    sink: Arc<dyn EventSink>,
    sessions: Mutex<HashMap<MacAddr, Session>>,
    /// Health flags the integrator can flip (e.g. the reconciler sets
    /// `kernel_table_present`, the control task sets `cp_connected`). Defaults to
    /// `backend_ok = true`; the rest default to `false`.
    health: Mutex<HealthStatus>,
    /// Metrics recorder (TDD §12). Defaults to [`NoopMetrics`]; the composition
    /// root installs the real atomic-backed recorder via [`set_metrics`]. Held
    /// behind a mutex because it is set once at startup and read cheaply
    /// thereafter (an `Arc` clone), avoiding a hard dependency in `new`.
    metrics: Mutex<Arc<dyn MetricsSink>>,
    /// conntrack flow reaper (invariant #9). Defaults to [`NoopReaper`]; the
    /// composition root installs the real [`ConntrackReaper`] via [`set_reaper`]
    /// when `reap_conntrack` is enabled. Held behind a mutex (set once at
    /// startup, cloned cheaply on the de-auth path) — same pattern as `metrics`.
    ///
    /// [`ConntrackReaper`]: portcullis_types::FlowReaper
    /// [`set_reaper`]: SessionManager::set_reaper
    reaper: Mutex<Arc<dyn FlowReaper>>,
    /// Per-session bandwidth shaper (G5). Defaults to [`NoopShaper`]; the
    /// composition root installs the real `TcShaper` via [`set_shaper`] when
    /// bandwidth shaping is enabled. Applied on grant, cleared on de-auth.
    ///
    /// [`set_shaper`]: SessionManager::set_shaper
    shaper: Mutex<Arc<dyn Shaper>>,
}

impl SessionManager {
    /// Build a manager over the injected nft writer and event sink.
    pub fn new(writer: Arc<dyn RulesetWriter>, sink: Arc<dyn EventSink>) -> Self {
        SessionManager {
            writer,
            sink,
            sessions: Mutex::new(HashMap::new()),
            health: Mutex::new(HealthStatus {
                backend_ok: true,
                kernel_table_present: false,
                cp_connected: false,
                last_reconcile_ok: false,
            }),
            metrics: Mutex::new(Arc::new(NoopMetrics)),
            reaper: Mutex::new(Arc::new(NoopReaper)),
            shaper: Mutex::new(Arc::new(NoopShaper)),
        }
    }

    /// Install the bandwidth shaper (composition root, once at startup). Without
    /// this, grants carry `rate_bps` but no cap is applied (NoopShaper).
    pub fn set_shaper(&self, shaper: Arc<dyn Shaper>) {
        *self.shaper.lock().expect("shaper mutex poisoned") = shaper;
    }

    fn shaper(&self) -> Arc<dyn Shaper> {
        self.shaper.lock().expect("shaper mutex poisoned").clone()
    }

    /// Install the conntrack flow reaper (composition root, once at startup).
    /// Without this the manager de-auths without reaping (NoopReaper), i.e. the
    /// pre-invariant-#9 behaviour — safe, but established flows leak.
    pub fn set_reaper(&self, reaper: Arc<dyn FlowReaper>) {
        *self.reaper.lock().expect("reaper mutex poisoned") = reaper;
    }

    /// Clone the current reaper handle (cheap `Arc` clone).
    fn reaper(&self) -> Arc<dyn FlowReaper> {
        self.reaper.lock().expect("reaper mutex poisoned").clone()
    }

    /// Reap the established conntrack flows for `ip` (invariant #9). Called after
    /// `del_auth` on every de-auth path. Fail-closed: a reap error is logged +
    /// metered and swallowed — it never aborts the revoke or unblocks the gate.
    async fn reap_flows(&self, ip: std::net::IpAddr) {
        match self.reaper().reap_by_ip(ip).await {
            Ok(n) => {
                if n > 0 {
                    self.metrics().incr(Metric::FlowsReaped);
                    tracing::debug!(%ip, reaped = n, "reaped conntrack flows on de-auth");
                }
            }
            Err(e) => {
                tracing::warn!(%ip, error = %e, "conntrack reap failed; gate still holds (fail-closed)");
                self.metrics().incr(Metric::ReapFailed);
            }
        }
    }

    /// Apply the per-session bandwidth cap (G5). Best-effort: a shaper error
    /// degrades bandwidth control but never fails the grant or the gate.
    async fn shape(&self, mac: MacAddr, rate_bps: u64) {
        if let Err(e) = self.shaper().apply(mac, rate_bps).await {
            tracing::warn!(mac = %mac, error = %e, "shaper apply failed; session proceeds uncapped");
            self.metrics().incr(Metric::ShaperFailure);
        }
    }

    /// Drop the per-session bandwidth cap on de-auth (idempotent, best-effort).
    async fn unshape(&self, mac: MacAddr) {
        if let Err(e) = self.shaper().clear(mac).await {
            tracing::warn!(mac = %mac, error = %e, "shaper clear failed");
            self.metrics().incr(Metric::ShaperFailure);
        }
    }

    /// Install the metrics recorder (composition root, once at startup).
    pub fn set_metrics(&self, metrics: Arc<dyn MetricsSink>) {
        *self.metrics.lock().expect("metrics mutex poisoned") = metrics;
    }

    /// Clone the current metrics handle (cheap `Arc` clone).
    fn metrics(&self) -> Arc<dyn MetricsSink> {
        self.metrics.lock().expect("metrics mutex poisoned").clone()
    }

    /// Overwrite the health snapshot the integrator reports over gRPC.
    pub fn set_health(&self, status: HealthStatus) {
        *self.health.lock().expect("health mutex poisoned") = status;
    }

    /// Set the reconcile-derived health flags (`last_reconcile_ok`,
    /// `kernel_table_present`) without disturbing the others (TDD §12).
    pub fn mark_reconcile(&self, ok: bool, table_present: bool) {
        let mut h = self.health.lock().expect("health mutex poisoned");
        h.last_reconcile_ok = ok;
        h.kernel_table_present = table_present;
    }

    /// Set the `cp_connected` health flag (flipped by the control-plane liveness
    /// poll in the composition root — a live `StreamEvents` subscriber, TDD §12).
    pub fn set_cp_connected(&self, connected: bool) {
        self.health.lock().expect("health mutex poisoned").cp_connected = connected;
    }

    /// Number of sessions currently tracked in RAM (test/observability helper).
    pub fn len(&self) -> usize {
        self.sessions.lock().expect("sessions mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn build_event(
        session_id: SessionId,
        mac: MacAddr,
        kind: EventKind,
        bytes_in: u64,
        bytes_out: u64,
    ) -> SessionEvent {
        SessionEvent {
            session_id,
            mac,
            kind,
            bytes_in,
            bytes_out,
            ts_unix: now_unix(),
        }
    }

    /// Time-injected grant. The trait method calls this with `Instant::now()`.
    ///
    /// Fail-closed ordering (G2): `add_auth` runs **first**. Only on success do
    /// we insert the session and emit `GRANTED`. If the writer errors, no session
    /// exists and the error propagates — the client is never let through.
    pub async fn grant_at(&self, params: GrantParams, now: Instant) -> Result<SessionId> {
        // Reject past the RAM cap before touching the kernel. Re-granting an
        // existing MAC is allowed (it refreshes the element) and does not count
        // against the cap.
        {
            let map = self.sessions.lock().expect("sessions mutex poisoned");
            if !map.contains_key(&params.mac) && map.len() >= MAX_SESSIONS {
                tracing::warn!(
                    mac = %params.mac,
                    cap = MAX_SESSIONS,
                    "session cap reached; rejecting grant (fail-closed, no eviction)"
                );
                return Err(Error::Backend(format!(
                    "session cap {MAX_SESSIONS} reached"
                )));
            }
        }

        // Kernel mutation first — fail closed on error.
        self.writer.add_auth(params.mac, params.ttl).await?;

        let session_id = params.session_id.clone();
        let session = Session {
            session_id: session_id.clone(),
            mac: params.mac,
            ip: params.ip,
            tier: params.tier,
            granted_at: now,
            expires_at: now + params.ttl,
            last_activity: now,
            quota_bytes: params.quota_bytes,
            rate_bps: params.rate_bps,
            bytes_in: 0,
            bytes_out: 0,
            baseline_in: None,
            baseline_out: None,
            granted_at_unix: now_unix(),
        };

        {
            let mut map = self.sessions.lock().expect("sessions mutex poisoned");
            map.insert(params.mac, session);
        }

        // G5: apply the per-session bandwidth cap (no-op when rate_bps == 0 or the
        // NoopShaper is installed). After the kernel grant so a shaper hiccup can
        // never block the gate opening.
        self.shape(params.mac, params.rate_bps).await;

        self.sink
            .emit(Self::build_event(
                session_id.clone(),
                params.mac,
                EventKind::Granted,
                0,
                0,
            ))
            .await;
        self.metrics().incr(Metric::Grant);

        Ok(session_id)
    }

    /// Remove a session and tear down its kernel element, emitting the event that
    /// corresponds to `reason` with the session's final byte totals.
    ///
    /// `del_auth` is best-effort/idempotent: a writer error is logged but does
    /// not block removal of the in-RAM view (we never want a stale in-RAM
    /// session to outlive a tear-down request).
    async fn revoke_internal(&self, mac: MacAddr, reason: RevokeReason) -> Result<()> {
        let removed = {
            let mut map = self.sessions.lock().expect("sessions mutex poisoned");
            map.remove(&mac)
        };

        let session = match removed {
            Some(s) => s,
            None => return Err(Error::SessionNotFound(mac.to_string())),
        };

        if let Err(e) = self.writer.del_auth(mac).await {
            tracing::warn!(mac = %mac, error = %e, "del_auth failed during revoke; in-RAM session already removed");
        }

        // Invariant #9: gating the MAC only stops *new* connections — sever the
        // client's already-established flows so a revoked client actually drops.
        if let Some(ip) = session.ip {
            self.reap_flows(ip).await;
        }
        // G5: drop the client's bandwidth cap.
        self.unshape(mac).await;

        self.sink
            .emit(Self::build_event(
                session.session_id.clone(),
                mac,
                EventKind::from(reason),
                session.bytes_in,
                session.bytes_out,
            ))
            .await;
        self.metrics().incr(match reason {
            RevokeReason::Quota => Metric::QuotaExceeded,
            RevokeReason::IdleTimeout => Metric::IdleKill,
            RevokeReason::Admin | RevokeReason::MacChange => Metric::Revoke,
        });

        Ok(())
    }

    /// Daemon-side expiry path (TDD §7.4 dual-path). Removes every session whose
    /// `expires_at <= now`, calls `del_auth` (idempotent belt-and-suspenders in
    /// case the kernel timeout has not fired yet), and emits `EXPIRED` with final
    /// bytes. Returns the number of sessions expired.
    pub async fn tick_expiry(&self, now: Instant) -> usize {
        let expired: Vec<Session> = {
            let mut map = self.sessions.lock().expect("sessions mutex poisoned");
            let macs: Vec<MacAddr> = map
                .iter()
                .filter(|(_, s)| now >= s.expires_at)
                .map(|(m, _)| *m)
                .collect();
            macs.into_iter()
                .filter_map(|m| map.remove(&m))
                .collect()
        };

        let metrics = self.metrics();
        for session in &expired {
            if let Err(e) = self.writer.del_auth(session.mac).await {
                tracing::warn!(mac = %session.mac, error = %e, "del_auth failed during expiry tick");
            }
            // Invariant #9: sever any established flow so an expired client's
            // long-lived sockets stop, not just its new connections.
            if let Some(ip) = session.ip {
                self.reap_flows(ip).await;
            }
            // G5: drop the client's bandwidth cap.
            self.unshape(session.mac).await;
            self.sink
                .emit(Self::build_event(
                    session.session_id.clone(),
                    session.mac,
                    EventKind::Expired,
                    session.bytes_in,
                    session.bytes_out,
                ))
                .await;
            metrics.incr(Metric::Expire);
        }

        expired.len()
    }

    /// Idle-timeout sweep (G6). De-auths every session with no byte activity for
    /// longer than `idle_timeout`, emitting `IDLE_TIMEOUT` with final bytes.
    /// `idle_timeout == 0` (Duration::ZERO) disables the sweep entirely. Reaps
    /// flows + clears shaping via the shared de-auth path. Returns the count.
    pub async fn sweep_idle(&self, now: Instant, idle_timeout: Duration) -> usize {
        if idle_timeout.is_zero() {
            return 0;
        }
        let idle: Vec<MacAddr> = {
            let map = self.sessions.lock().expect("sessions mutex poisoned");
            map.iter()
                .filter(|(_, s)| now.saturating_duration_since(s.last_activity) > idle_timeout)
                .map(|(m, _)| *m)
                .collect()
        };
        let mut n = 0;
        for mac in idle {
            // revoke_internal emits IDLE_TIMEOUT (via RevokeReason), reaps flows,
            // clears shaping, and counts Metric::IdleKill. A racing removal
            // (SessionNotFound) is benign.
            match self.revoke_internal(mac, RevokeReason::IdleTimeout).await {
                Ok(()) => n += 1,
                Err(e) => tracing::debug!(mac = %mac, error = %e, "idle sweep: session already gone"),
            }
        }
        n
    }

    /// Time-injected counter application (TDD §7.6/§7.7). For each `(mac,
    /// Counters)` we update per-session byte totals from the absolute kernel
    /// counter (`absolute - baseline`, re-baselining on counter reset), emit an
    /// `INTERIM` event, and collect any session whose total exceeds its quota.
    /// Quota breaches are revoked *after* releasing the lock (revoke takes the
    /// lock itself and awaits the writer).
    pub async fn apply_counters_at(
        &self,
        snapshot: Vec<(MacAddr, Counters)>,
        now: Instant,
    ) -> Result<()> {
        let mut interim: Vec<SessionEvent> = Vec::new();
        let mut quota_breached: Vec<MacAddr> = Vec::new();

        {
            let mut map = self.sessions.lock().expect("sessions mutex poisoned");
            for (mac, counters) in snapshot {
                let Some(session) = map.get_mut(&mac) else {
                    // No tracked session for this MAC (e.g. garden traffic, or a
                    // session already torn down). Ignore.
                    continue;
                };

                let prior_total = session.total();
                session.bytes_in = delta(&mut session.baseline_in, counters.bytes_in);
                session.bytes_out = delta(&mut session.baseline_out, counters.bytes_out);
                // G6: any forward progress in bytes is "activity" — stamp it so the
                // idle sweep only reaps genuinely-quiet sessions.
                if session.total() > prior_total {
                    session.last_activity = now;
                }

                interim.push(Self::build_event(
                    session.session_id.clone(),
                    mac,
                    EventKind::Interim,
                    session.bytes_in,
                    session.bytes_out,
                ));

                if session.quota_bytes != 0 && session.total() > session.quota_bytes {
                    quota_breached.push(mac);
                }
            }
        }

        for event in interim {
            self.sink.emit(event).await;
        }

        for mac in quota_breached {
            // Revoke emits the QUOTA_EXCEEDED final-byte event. If the session was
            // already gone (raced expiry), `SessionNotFound` is benign here.
            if let Err(e) = self.revoke_internal(mac, RevokeReason::Quota).await {
                tracing::debug!(mac = %mac, error = %e, "quota revoke skipped (session already gone)");
            }
        }

        Ok(())
    }

    /// Restart adoption (TDD §7.8). Rebuilds the in-RAM session view from the
    /// kernel `auth` set so no authorized client is dropped across a daemon
    /// upgrade. Each element's `remaining` is used as time-to-expiry; a
    /// placeholder `session_id` of `adopted:<mac>` is synthesized because the
    /// real control-plane session_id is not stored in the kernel. Adopted
    /// sessions do **not** emit `GRANTED` (they were granted before the restart).
    /// Accounting baselines are left unset and established by the next snapshot,
    /// which is the re-baseline behaviour §7.6 requires. Returns the number
    /// adopted (capped at [`MAX_SESSIONS`]).
    pub fn adopt(&self, elements: Vec<AuthElement>, now: Instant) -> usize {
        let mut map = self.sessions.lock().expect("sessions mutex poisoned");
        let mut adopted = 0usize;
        let granted_at_unix = now_unix();
        for el in elements {
            if !map.contains_key(&el.mac) && map.len() >= MAX_SESSIONS {
                tracing::warn!(
                    mac = %el.mac,
                    cap = MAX_SESSIONS,
                    "session cap reached during adoption; skipping element"
                );
                continue;
            }
            let session = Self::synth_session(el.mac, el.remaining, now, granted_at_unix);
            if map.insert(el.mac, session).is_none() {
                adopted += 1;
            }
        }
        adopted
    }

    /// Build a synthetic (adopted) session for a kernel `auth` element whose
    /// control-plane metadata we don't have. Shared by [`adopt`](Self::adopt) and
    /// the reconciler's Adopt branch. No quota (0 = unlimited) and a placeholder
    /// `adopted:<mac>` id — the control plane re-issues a real grant to restore
    /// quota/tier; until then the kernel timeout bounds it.
    fn synth_session(mac: MacAddr, remaining: Duration, now: Instant, granted_at_unix: i64) -> Session {
        Session {
            session_id: SessionId::from(format!("adopted:{mac}")),
            mac,
            ip: None,
            tier: Tier::default(),
            granted_at: now,
            expires_at: now + remaining,
            last_activity: now,
            quota_bytes: 0,
            rate_bps: 0,
            bytes_in: 0,
            bytes_out: 0,
            baseline_in: None,
            baseline_out: None,
            granted_at_unix,
        }
    }

    /// Periodic drift reconciliation against the kernel `auth` set (TDD §7.8).
    ///
    /// Diff/repair rules (chosen to NOT fight the kernel-timeout expiry backstop):
    /// - **in RAM, missing from kernel** → the kernel dropped an element the daemon
    ///   still believes active: re-add with the session's *remaining* TTL, but only
    ///   if that remaining exceeds [`RECONCILE_MIN_TTL`] (else it is expiring this
    ///   instant — leave it to `tick_expiry`).
    /// - **in kernel, unknown to RAM** → `Adopt` (default; never drop an authorized
    ///   client, and a just-granted element whose in-RAM insert hasn't committed is
    ///   preserved) or `Delete` (strict desired-state, opt-in).
    /// - **in both** → no-op (crucially, we do NOT refresh the timeout — that would
    ///   defeat kernel expiry).
    ///
    /// The plan is computed under a single `sessions` lock; writer ops run after the
    /// lock is released. Writer errors are tallied, never fatal, never fail open.
    pub async fn reconcile_at(
        &self,
        kernel: Vec<AuthElement>,
        policy: UnknownKernelPolicy,
        now: Instant,
    ) -> ReconcileReport {
        let mut report = ReconcileReport { kernel_count: kernel.len(), ..Default::default() };
        let kernel_macs: HashSet<MacAddr> = kernel.iter().map(|e| e.mac).collect();

        let mut to_readd: Vec<(MacAddr, Duration)> = Vec::new();
        let mut to_delete: Vec<MacAddr> = Vec::new();

        // Build the repair plan under a single lock; execute writer ops after.
        {
            let mut map = self.sessions.lock().expect("sessions mutex poisoned");
            report.ram_count = map.len();

            // RAM-believed-active but kernel-dropped → schedule re-add (unless it
            // is expiring imminently, in which case leave it to tick_expiry).
            for (mac, s) in map.iter() {
                if !kernel_macs.contains(mac) {
                    let remaining = s.expires_at.saturating_duration_since(now);
                    if remaining > RECONCILE_MIN_TTL {
                        to_readd.push((*mac, remaining));
                    }
                }
            }

            // Kernel elements unknown to RAM → adopt (default) or delete.
            let unknown_els: Vec<AuthElement> =
                kernel.iter().copied().filter(|e| !map.contains_key(&e.mac)).collect();
            match policy {
                UnknownKernelPolicy::Adopt => {
                    let granted_at_unix = now_unix();
                    for el in &unknown_els {
                        if !map.contains_key(&el.mac) && map.len() >= MAX_SESSIONS {
                            continue;
                        }
                        let s = Self::synth_session(el.mac, el.remaining, now, granted_at_unix);
                        if map.insert(el.mac, s).is_none() {
                            report.adopted += 1;
                        }
                    }
                }
                UnknownKernelPolicy::Delete => {
                    to_delete = unknown_els.iter().map(|e| e.mac).collect();
                }
            }
        }

        // Execute writer mutations outside the lock (writer calls await + retry).
        for (mac, remaining) in to_readd {
            match self.writer.add_auth(mac, remaining).await {
                Ok(()) => report.readded += 1,
                Err(e) => {
                    report.errors += 1;
                    tracing::warn!(mac = %mac, error = %e, "reconcile re-add failed");
                }
            }
        }
        for mac in to_delete {
            match self.writer.del_auth(mac).await {
                Ok(()) => report.deleted += 1,
                Err(e) => {
                    report.errors += 1;
                    tracing::warn!(mac = %mac, error = %e, "reconcile delete failed");
                }
            }
        }

        let metrics = self.metrics();
        metrics.incr(Metric::Reconcile);
        if report.repaired() {
            metrics.incr(Metric::ReconcileRepair);
        }
        report
    }
}

/// Convert an absolute monotonic counter into a per-session delta against a
/// stored baseline, re-baselining on counter reset (current < baseline) so the
/// subtraction never underflows. On first sight the baseline is set to the
/// current absolute value, yielding a 0 delta for that tick.
fn delta(baseline: &mut Option<u64>, current: u64) -> u64 {
    match *baseline {
        None => {
            *baseline = Some(current);
            0
        }
        Some(b) if current >= b => current - b,
        Some(_) => {
            // Counter reset (conntrack flush / wrap). Re-baseline.
            *baseline = Some(current);
            0
        }
    }
}

#[async_trait]
impl Enforcer for SessionManager {
    async fn grant(&self, params: GrantParams) -> Result<SessionId> {
        self.grant_at(params, Instant::now()).await
    }

    async fn revoke(&self, mac: MacAddr, reason: RevokeReason) -> Result<()> {
        self.revoke_internal(mac, reason).await
    }

    async fn get(&self, mac: MacAddr) -> Result<Option<SessionInfo>> {
        let now = Instant::now();
        let map = self.sessions.lock().expect("sessions mutex poisoned");
        Ok(map.get(&mac).map(|s| s.to_info(now)))
    }

    async fn list(&self) -> Result<Vec<SessionInfo>> {
        let now = Instant::now();
        let map = self.sessions.lock().expect("sessions mutex poisoned");
        Ok(map.values().map(|s| s.to_info(now)).collect())
    }

    async fn health(&self) -> HealthStatus {
        *self.health.lock().expect("health mutex poisoned")
    }
}

#[async_trait]
impl MeteringSink for SessionManager {
    async fn apply_counters(&self, snapshot: Vec<(MacAddr, Counters)>) -> Result<()> {
        self.apply_counters_at(snapshot, Instant::now()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    // ---- mock ports -------------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum WriterOp {
        AddAuth(MacAddr, Duration),
        DelAuth(MacAddr),
    }

    /// Records every writer op. `fail` makes `add_auth` fail (to exercise the
    /// fail-closed grant path).
    struct MockWriter {
        ops: StdMutex<Vec<WriterOp>>,
        fail_add: bool,
    }

    impl MockWriter {
        fn new() -> Self {
            MockWriter { ops: StdMutex::new(Vec::new()), fail_add: false }
        }
        fn failing() -> Self {
            MockWriter { ops: StdMutex::new(Vec::new()), fail_add: true }
        }
        fn ops(&self) -> Vec<WriterOp> {
            self.ops.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl RulesetWriter for MockWriter {
        async fn ensure_base(&self) -> Result<()> {
            Ok(())
        }
        async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()> {
            if self.fail_add {
                return Err(Error::NftTransaction("injected failure".into()));
            }
            self.ops.lock().unwrap().push(WriterOp::AddAuth(mac, ttl));
            Ok(())
        }
        async fn del_auth(&self, mac: MacAddr) -> Result<()> {
            self.ops.lock().unwrap().push(WriterOp::DelAuth(mac));
            Ok(())
        }
        async fn list_auth(&self) -> Result<Vec<AuthElement>> {
            Ok(Vec::new())
        }
    }

    /// Captures every emitted event.
    struct CapturingSink {
        events: StdMutex<Vec<SessionEvent>>,
    }
    impl CapturingSink {
        fn new() -> Self {
            CapturingSink { events: StdMutex::new(Vec::new()) }
        }
        fn events(&self) -> Vec<SessionEvent> {
            self.events.lock().unwrap().clone()
        }
        fn kinds(&self) -> Vec<EventKind> {
            self.events().iter().map(|e| e.kind).collect()
        }
    }

    #[async_trait]
    impl EventSink for CapturingSink {
        async fn emit(&self, event: SessionEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    // ---- helpers ----------------------------------------------------------

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0xaa, 0xbb, 0xcc, 0x00, 0x00, n])
    }

    fn grant_params(m: MacAddr, ttl_secs: u64, quota: u64) -> GrantParams {
        GrantParams {
            store_id: "store-1".into(),
            mac: m,
            ip: None,
            ttl: Duration::from_secs(ttl_secs),
            quota_bytes: quota,
            rate_bps: 0,
            tier: Tier::Public,
            session_id: SessionId::from(format!("sess-{}", m)),
        }
    }

    fn mgr() -> (SessionManager, Arc<MockWriter>, Arc<CapturingSink>) {
        let writer = Arc::new(MockWriter::new());
        let sink = Arc::new(CapturingSink::new());
        let m = SessionManager::new(writer.clone(), sink.clone());
        (m, writer, sink)
    }

    /// Records every IP handed to the reaper; optionally errors (to prove a reap
    /// failure never aborts the de-auth — fail-closed, invariant #9).
    #[derive(Default)]
    struct RecordingReaper {
        reaped: std::sync::Mutex<Vec<std::net::IpAddr>>,
        fail: bool,
    }
    impl RecordingReaper {
        fn failing() -> Self {
            RecordingReaper { fail: true, ..Default::default() }
        }
        fn ips(&self) -> Vec<std::net::IpAddr> {
            self.reaped.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl FlowReaper for RecordingReaper {
        async fn reap_by_ip(&self, ip: std::net::IpAddr) -> Result<usize> {
            self.reaped.lock().unwrap().push(ip);
            if self.fail {
                Err(Error::Counter("boom".into()))
            } else {
                Ok(1)
            }
        }
    }

    fn grant_params_ip(m: MacAddr, ip: &str, ttl_secs: u64) -> GrantParams {
        GrantParams { ip: Some(ip.parse().unwrap()), ..grant_params(m, ttl_secs, 0) }
    }

    // ---- tests ------------------------------------------------------------

    #[tokio::test]
    async fn grant_adds_element_inserts_and_emits_granted() {
        let (m, writer, sink) = mgr();
        let now = Instant::now();
        let id = m.grant_at(grant_params(mac(1), 60, 0), now).await.unwrap();

        assert_eq!(id, SessionId::from(format!("sess-{}", mac(1))));
        assert_eq!(m.len(), 1);
        // add_auth was called with the right mac + ttl.
        assert_eq!(
            writer.ops(),
            vec![WriterOp::AddAuth(mac(1), Duration::from_secs(60))]
        );
        // GRANTED emitted, with zero bytes.
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Granted);
        assert_eq!(events[0].mac, mac(1));
        assert_eq!(events[0].bytes_in, 0);
    }

    #[tokio::test]
    async fn grant_fails_closed_when_writer_errors() {
        let writer = Arc::new(MockWriter::failing());
        let sink = Arc::new(CapturingSink::new());
        let m = SessionManager::new(writer.clone(), sink.clone());

        let res = m.grant_at(grant_params(mac(2), 60, 0), Instant::now()).await;
        assert!(res.is_err(), "grant must propagate writer error");
        // No session was inserted (fail closed) and no GRANTED was emitted.
        assert_eq!(m.len(), 0);
        assert!(sink.events().is_empty());
    }

    #[tokio::test]
    async fn expiry_removes_session_and_emits_expired() {
        let (m, writer, sink) = mgr();
        let now = Instant::now();
        m.grant_at(grant_params(mac(3), 10, 0), now).await.unwrap();

        // Not yet expired.
        assert_eq!(m.tick_expiry(now + Duration::from_secs(5)).await, 0);
        assert_eq!(m.len(), 1);

        // Past expiry.
        let n = m.tick_expiry(now + Duration::from_secs(10)).await;
        assert_eq!(n, 1);
        assert_eq!(m.len(), 0);

        // del_auth called (belt-and-suspenders) and EXPIRED emitted.
        assert!(writer.ops().contains(&WriterOp::DelAuth(mac(3))));
        assert!(sink.kinds().contains(&EventKind::Expired));
    }

    #[tokio::test]
    async fn revoke_reaps_flows_after_del_auth() {
        let (m, writer, _sink) = mgr();
        let reaper = Arc::new(RecordingReaper::default());
        m.set_reaper(reaper.clone());
        let now = Instant::now();
        m.grant_at(grant_params_ip(mac(5), "10.0.0.5", 60), now).await.unwrap();

        m.revoke(mac(5), RevokeReason::Admin).await.unwrap();
        // Invariant #9: del_auth happened AND the client's IP was reaped.
        assert!(writer.ops().contains(&WriterOp::DelAuth(mac(5))));
        assert_eq!(reaper.ips(), vec!["10.0.0.5".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn revoke_without_recorded_ip_does_not_reap() {
        let (m, _writer, _sink) = mgr();
        let reaper = Arc::new(RecordingReaper::default());
        m.set_reaper(reaper.clone());
        let now = Instant::now();
        m.grant_at(grant_params(mac(6), 60, 0), now).await.unwrap(); // ip = None
        m.revoke(mac(6), RevokeReason::Admin).await.unwrap();
        assert!(reaper.ips().is_empty(), "no recorded IP -> nothing to reap");
    }

    #[tokio::test]
    async fn reap_failure_does_not_abort_revoke() {
        let (m, _writer, sink) = mgr();
        m.set_reaper(Arc::new(RecordingReaper::failing()));
        let now = Instant::now();
        m.grant_at(grant_params_ip(mac(7), "10.0.0.7", 60), now).await.unwrap();
        // The revoke still completes and emits despite the reaper erroring:
        // a reap failure is a degradation, never a fail-open that blocks tear-down.
        m.revoke(mac(7), RevokeReason::Admin).await.unwrap();
        assert_eq!(m.len(), 0);
        assert!(sink.kinds().contains(&EventKind::Revoked));
    }

    #[tokio::test]
    async fn expiry_reaps_flows() {
        let (m, _writer, _sink) = mgr();
        let reaper = Arc::new(RecordingReaper::default());
        m.set_reaper(reaper.clone());
        let now = Instant::now();
        m.grant_at(grant_params_ip(mac(8), "10.0.0.8", 10), now).await.unwrap();
        m.tick_expiry(now + Duration::from_secs(10)).await;
        assert_eq!(reaper.ips(), vec!["10.0.0.8".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[derive(Default)]
    struct RecordingShaper {
        applied: std::sync::Mutex<Vec<(MacAddr, u64)>>,
        cleared: std::sync::Mutex<Vec<MacAddr>>,
    }
    #[async_trait]
    impl Shaper for RecordingShaper {
        async fn apply(&self, mac: MacAddr, rate_bps: u64) -> Result<()> {
            self.applied.lock().unwrap().push((mac, rate_bps));
            Ok(())
        }
        async fn clear(&self, mac: MacAddr) -> Result<()> {
            self.cleared.lock().unwrap().push(mac);
            Ok(())
        }
    }

    #[tokio::test]
    async fn grant_applies_and_revoke_clears_shaper() {
        let (m, _writer, _sink) = mgr();
        let shaper = Arc::new(RecordingShaper::default());
        m.set_shaper(shaper.clone());
        let now = Instant::now();
        let p = GrantParams { rate_bps: 5_000_000, ..grant_params(mac(9), 60, 0) };
        m.grant_at(p, now).await.unwrap();
        assert_eq!(&*shaper.applied.lock().unwrap(), &[(mac(9), 5_000_000)]);

        m.revoke(mac(9), RevokeReason::Admin).await.unwrap();
        assert_eq!(&*shaper.cleared.lock().unwrap(), &[mac(9)]);
    }

    #[tokio::test]
    async fn idle_sweep_kills_quiet_and_spares_active() {
        let (m, _w, sink) = mgr();
        let t0 = Instant::now();
        m.grant_at(grant_params_ip(mac(11), "10.0.0.11", 3600), t0).await.unwrap();

        // First snapshot establishes the baseline (no activity registered yet);
        // the second shows forward progress -> stamps last_activity at t0+250.
        m.apply_counters_at(vec![(mac(11), Counters { bytes_in: 10, bytes_out: 0 })], t0 + Duration::from_secs(50)).await.unwrap();
        m.apply_counters_at(vec![(mac(11), Counters { bytes_in: 100, bytes_out: 0 })], t0 + Duration::from_secs(250)).await.unwrap();

        // 150s since activity (< 300) -> spared.
        assert_eq!(m.sweep_idle(t0 + Duration::from_secs(400), Duration::from_secs(300)).await, 0);
        assert_eq!(m.len(), 1);
        // 350s since activity (> 300) -> idle-killed with IDLE_TIMEOUT.
        assert_eq!(m.sweep_idle(t0 + Duration::from_secs(600), Duration::from_secs(300)).await, 1);
        assert_eq!(m.len(), 0);
        assert!(sink.kinds().contains(&EventKind::IdleTimeout));
    }

    #[tokio::test]
    async fn idle_sweep_disabled_when_zero() {
        let (m, _w, _s) = mgr();
        let t0 = Instant::now();
        m.grant_at(grant_params_ip(mac(12), "10.0.0.12", 3600), t0).await.unwrap();
        // idle_timeout = 0 disables the sweep entirely, no matter how quiet.
        assert_eq!(m.sweep_idle(t0 + Duration::from_secs(99_999), Duration::ZERO).await, 0);
        assert_eq!(m.len(), 1);
    }

    #[tokio::test]
    async fn shaper_failure_does_not_fail_grant() {
        struct FailingShaper;
        #[async_trait]
        impl Shaper for FailingShaper {
            async fn apply(&self, _m: MacAddr, _r: u64) -> Result<()> {
                Err(Error::Backend("tc down".into()))
            }
            async fn clear(&self, _m: MacAddr) -> Result<()> {
                Err(Error::Backend("tc down".into()))
            }
        }
        let (m, writer, _sink) = mgr();
        m.set_shaper(Arc::new(FailingShaper));
        // The grant still succeeds (kernel gate opened) despite the shaper erroring
        // — shaping is best-effort, never gates. add_auth still ran.
        let p = GrantParams { rate_bps: 1_000, ..grant_params(mac(10), 60, 0) };
        m.grant_at(p, Instant::now()).await.unwrap();
        assert_eq!(m.len(), 1);
        assert!(writer.ops().iter().any(|o| matches!(o, WriterOp::AddAuth(mm, _) if *mm == mac(10))));
    }

    #[tokio::test]
    async fn quota_breach_revokes_and_emits_quota_exceeded() {
        let (m, writer, sink) = mgr();
        let now = Instant::now();
        // 1000-byte quota.
        m.grant_at(grant_params(mac(4), 60, 1000), now).await.unwrap();

        // First snapshot establishes baseline (delta 0).
        m.apply_counters_at(vec![(mac(4), Counters { bytes_in: 100, bytes_out: 100 })], now)
            .await
            .unwrap();
        assert_eq!(m.len(), 1, "still under quota after baseline");

        // Second snapshot: delta now 900+900 = 1800 > 1000 -> revoke.
        m.apply_counters_at(
            vec![(mac(4), Counters { bytes_in: 1000, bytes_out: 1000 })],
            now,
        )
        .await
        .unwrap();

        assert_eq!(m.len(), 0, "quota breach must revoke the session");
        assert!(writer.ops().contains(&WriterOp::DelAuth(mac(4))));
        let kinds = sink.kinds();
        assert!(kinds.contains(&EventKind::QuotaExceeded));
        // The final QUOTA_EXCEEDED event carries the final bytes.
        let final_ev = sink
            .events()
            .into_iter()
            .find(|e| e.kind == EventKind::QuotaExceeded)
            .unwrap();
        assert_eq!(final_ev.bytes_in, 900);
        assert_eq!(final_ev.bytes_out, 900);
    }

    #[tokio::test]
    async fn revoke_emits_final_bytes() {
        let (m, _writer, sink) = mgr();
        let now = Instant::now();
        m.grant_at(grant_params(mac(5), 60, 0), now).await.unwrap();
        m.apply_counters_at(vec![(mac(5), Counters { bytes_in: 10, bytes_out: 20 })], now)
            .await
            .unwrap();
        // Second snapshot to produce a non-zero delta past the baseline.
        m.apply_counters_at(vec![(mac(5), Counters { bytes_in: 510, bytes_out: 1020 })], now)
            .await
            .unwrap();

        m.revoke(mac(5), RevokeReason::Admin).await.unwrap();

        let final_ev = sink
            .events()
            .into_iter()
            .rev()
            .find(|e| e.kind == EventKind::Revoked)
            .unwrap();
        assert_eq!(final_ev.bytes_in, 500);
        assert_eq!(final_ev.bytes_out, 1000);
        assert_eq!(m.len(), 0);
    }

    #[tokio::test]
    async fn revoke_unknown_mac_is_not_found() {
        let (m, _writer, _sink) = mgr();
        let res = m.revoke(mac(9), RevokeReason::Admin).await;
        assert!(matches!(res, Err(Error::SessionNotFound(_))));
    }

    #[tokio::test]
    async fn apply_counters_computes_deltas_and_emits_interim() {
        let (m, _writer, sink) = mgr();
        let now = Instant::now();
        m.grant_at(grant_params(mac(6), 60, 0), now).await.unwrap();

        // Baseline 1000/2000 -> delta 0.
        m.apply_counters_at(vec![(mac(6), Counters { bytes_in: 1000, bytes_out: 2000 })], now)
            .await
            .unwrap();
        // Next absolute 1500/2500 -> delta 500/500.
        m.apply_counters_at(vec![(mac(6), Counters { bytes_in: 1500, bytes_out: 2500 })], now)
            .await
            .unwrap();

        let info = m.get(mac(6)).await.unwrap().unwrap();
        assert_eq!(info.bytes_in, 500);
        assert_eq!(info.bytes_out, 500);

        // Two INTERIM events emitted (one per snapshot), after the GRANTED.
        let interims: Vec<_> = sink
            .events()
            .into_iter()
            .filter(|e| e.kind == EventKind::Interim)
            .collect();
        assert_eq!(interims.len(), 2);
        assert_eq!(interims[0].bytes_in, 0); // baseline tick
        assert_eq!(interims[1].bytes_in, 500);
    }

    #[tokio::test]
    async fn apply_counters_rebaselines_on_counter_reset() {
        let (m, _writer, _sink) = mgr();
        let now = Instant::now();
        m.grant_at(grant_params(mac(7), 60, 0), now).await.unwrap();

        m.apply_counters_at(vec![(mac(7), Counters { bytes_in: 5000, bytes_out: 5000 })], now)
            .await
            .unwrap();
        m.apply_counters_at(vec![(mac(7), Counters { bytes_in: 6000, bytes_out: 6000 })], now)
            .await
            .unwrap();
        let info = m.get(mac(7)).await.unwrap().unwrap();
        assert_eq!(info.bytes_in, 1000);

        // Counter reset: absolute drops below baseline -> re-baseline, delta 0.
        m.apply_counters_at(vec![(mac(7), Counters { bytes_in: 100, bytes_out: 100 })], now)
            .await
            .unwrap();
        let info = m.get(mac(7)).await.unwrap().unwrap();
        assert_eq!(info.bytes_in, 0, "must re-baseline, not underflow");

        // And it counts up from the new baseline.
        m.apply_counters_at(vec![(mac(7), Counters { bytes_in: 350, bytes_out: 100 })], now)
            .await
            .unwrap();
        let info = m.get(mac(7)).await.unwrap().unwrap();
        assert_eq!(info.bytes_in, 250);
    }

    #[tokio::test]
    async fn adopt_rebuilds_sessions_without_granted() {
        let (m, _writer, sink) = mgr();
        let now = Instant::now();
        let elements = vec![
            AuthElement { mac: mac(10), remaining: Duration::from_secs(120) },
            AuthElement { mac: mac(11), remaining: Duration::from_secs(300) },
        ];
        let adopted = m.adopt(elements, now);
        assert_eq!(adopted, 2);
        assert_eq!(m.len(), 2);

        // Placeholder session_id and remaining-as-ttl.
        let info = m.get(mac(10)).await.unwrap().unwrap();
        assert_eq!(info.session_id, SessionId::from(format!("adopted:{}", mac(10))));
        // expires_in computed against `now` is roughly the remaining.
        assert!(info.expires_in <= Duration::from_secs(120));

        // No GRANTED emitted for adopted sessions.
        assert!(sink.events().is_empty());

        // Adopted sessions still expire via the daemon path.
        let n = m.tick_expiry(now + Duration::from_secs(120)).await;
        assert_eq!(n, 1, "mac(10) expired, mac(11) still active");
        assert_eq!(m.len(), 1);
    }

    #[tokio::test]
    async fn grant_rejected_past_cap_without_eviction() {
        let (m, _writer, _sink) = mgr();
        let now = Instant::now();
        // Fill to the cap.
        for i in 0..MAX_SESSIONS {
            let octets = [
                0xaa,
                0xbb,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
                0x01,
            ];
            let params = GrantParams {
                store_id: "s".into(),
                mac: MacAddr::new(octets),
                ip: None,
                ttl: Duration::from_secs(60),
                quota_bytes: 0,
                rate_bps: 0,
                tier: Tier::Public,
                session_id: SessionId::from(format!("sess-{i}")),
            };
            m.grant_at(params, now).await.unwrap();
        }
        assert_eq!(m.len(), MAX_SESSIONS);

        // One more distinct MAC is rejected (fail closed), nothing evicted.
        let over = MacAddr::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        let res = m.grant_at(grant_params(over, 60, 0), now).await;
        assert!(matches!(res, Err(Error::Backend(_))));
        assert_eq!(m.len(), MAX_SESSIONS, "no eviction past cap");

        // Re-granting an existing MAC is still allowed (refresh, not new slot).
        let existing = MacAddr::new([0xaa, 0xbb, 0x00, 0x00, 0x00, 0x01]);
        m.grant_at(grant_params(existing, 120, 0), now).await.unwrap();
        assert_eq!(m.len(), MAX_SESSIONS);
    }

    #[tokio::test]
    async fn health_defaults_backend_ok_and_is_settable() {
        let (m, _writer, _sink) = mgr();
        let h = m.health().await;
        assert!(h.backend_ok);
        assert!(!h.cp_connected);

        m.set_health(HealthStatus {
            backend_ok: true,
            kernel_table_present: true,
            cp_connected: true,
            last_reconcile_ok: true,
        });
        let h = m.health().await;
        assert!(h.cp_connected);
        assert!(h.kernel_table_present);
    }

    #[tokio::test]
    async fn mark_reconcile_and_cp_connected_set_individual_flags() {
        let (m, _w, _s) = mgr();
        m.mark_reconcile(true, true);
        m.set_cp_connected(true);
        let h = m.health().await;
        assert!(h.backend_ok && h.last_reconcile_ok && h.kernel_table_present && h.cp_connected);

        // mark_reconcile must not clobber cp_connected.
        m.mark_reconcile(false, false);
        let h = m.health().await;
        assert!(!h.last_reconcile_ok && !h.kernel_table_present);
        assert!(h.cp_connected, "cp_connected must be untouched by mark_reconcile");
    }

    fn auth_el(m: MacAddr, secs: u64) -> AuthElement {
        AuthElement { mac: m, remaining: Duration::from_secs(secs) }
    }

    #[tokio::test]
    async fn reconcile_readds_mac_missing_from_kernel() {
        let (m, writer, _s) = mgr();
        let now = Instant::now();
        m.grant_at(grant_params(mac(1), 60, 0), now).await.unwrap();

        // Kernel lost the element → reconcile must re-add it with remaining TTL.
        let report = m.reconcile_at(vec![], UnknownKernelPolicy::Adopt, now).await;
        assert_eq!(report.readded, 1);
        assert_eq!(report.adopted, 0);
        assert!(report.ok() && report.repaired());

        let adds = writer
            .ops()
            .into_iter()
            .filter(|o| matches!(o, WriterOp::AddAuth(x, _) if *x == mac(1)))
            .count();
        assert_eq!(adds, 2, "one AddAuth from grant + one from reconcile re-add");
    }

    #[tokio::test]
    async fn reconcile_skips_readd_when_ttl_below_floor() {
        let (m, writer, _s) = mgr();
        let now = Instant::now();
        m.grant_at(grant_params(mac(1), 10, 0), now).await.unwrap();

        // 2s remaining (< RECONCILE_MIN_TTL) → let tick_expiry handle it, don't re-add.
        let report = m
            .reconcile_at(vec![], UnknownKernelPolicy::Adopt, now + Duration::from_secs(8))
            .await;
        assert_eq!(report.readded, 0);
        let adds = writer
            .ops()
            .into_iter()
            .filter(|o| matches!(o, WriterOp::AddAuth(x, _) if *x == mac(1)))
            .count();
        assert_eq!(adds, 1, "only the original grant's AddAuth; no reconcile re-add");
    }

    #[tokio::test]
    async fn reconcile_adopts_unknown_kernel_mac() {
        let (m, _writer, sink) = mgr();
        let now = Instant::now();
        let report = m
            .reconcile_at(vec![auth_el(mac(9), 120)], UnknownKernelPolicy::Adopt, now)
            .await;
        assert_eq!(report.adopted, 1);
        assert_eq!(m.len(), 1);
        let info = m.get(mac(9)).await.unwrap().unwrap();
        assert_eq!(info.session_id, SessionId::from(format!("adopted:{}", mac(9))));
        assert!(sink.events().is_empty(), "adoption must NOT emit GRANTED");
    }

    #[tokio::test]
    async fn reconcile_deletes_unknown_when_policy_delete() {
        let (m, writer, _s) = mgr();
        let now = Instant::now();
        let report = m
            .reconcile_at(vec![auth_el(mac(9), 120)], UnknownKernelPolicy::Delete, now)
            .await;
        assert_eq!(report.deleted, 1);
        assert_eq!(m.len(), 0);
        assert!(writer.ops().contains(&WriterOp::DelAuth(mac(9))));
    }

    #[tokio::test]
    async fn reconcile_noops_when_in_sync() {
        let (m, writer, _s) = mgr();
        let now = Instant::now();
        m.grant_at(grant_params(mac(1), 60, 0), now).await.unwrap();

        let report = m
            .reconcile_at(vec![auth_el(mac(1), 60)], UnknownKernelPolicy::Adopt, now)
            .await;
        assert!(!report.repaired(), "in-sync set needs no repair");
        assert_eq!(report.readded + report.adopted + report.deleted, 0);
        // Crucially, no refresh AddAuth beyond the original grant (don't fight expiry).
        let adds = writer
            .ops()
            .into_iter()
            .filter(|o| matches!(o, WriterOp::AddAuth(x, _) if *x == mac(1)))
            .count();
        assert_eq!(adds, 1);
    }

    #[tokio::test]
    async fn reconcile_report_flags_writer_errors() {
        // Failing writer + a session present via adopt (adopt does not call the
        // writer) → reconcile's re-add hits the failing add_auth.
        let writer = Arc::new(MockWriter::failing());
        let sink = Arc::new(CapturingSink::new());
        let m = SessionManager::new(writer, sink);
        let now = Instant::now();
        m.adopt(vec![auth_el(mac(1), 60)], now);

        let report = m.reconcile_at(vec![], UnknownKernelPolicy::Adopt, now).await;
        assert_eq!(report.errors, 1);
        assert_eq!(report.readded, 0);
        assert!(!report.ok());
    }
}
