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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use portcullis_types::{
    AuthElement, Counters, Enforcer, Error, EventKind, EventSink, GardenControl, GrantParams,
    HealthStatus, MacAddr, MeteringSink, Result, RevokeReason, RulesetWriter, SessionEvent,
    SessionId, SessionInfo, Tier,
};

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
    /// Global enforcement gate mirror. Source of truth is the kernel ruleset
    /// (via the writer); this caches the last-applied value for `health()` and
    /// `enforcement_enabled()`. Boots `true` (fail-closed, §11/G5).
    enforcement_enabled: Mutex<bool>,
    /// Control-plane-managed walled garden, wired by the composition root.
    /// `None` until `set_garden_control` is called (then `set_garden` works).
    garden: Mutex<Option<Arc<dyn GardenControl>>>,
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
                enforcement_enabled: true,
            }),
            enforcement_enabled: Mutex::new(true),
            garden: Mutex::new(None),
        }
    }

    /// Wire the control-plane-managed walled-garden controller (composition root).
    pub fn set_garden_control(&self, g: Arc<dyn GardenControl>) {
        *self.garden.lock().expect("garden mutex poisoned") = Some(g);
    }

    /// Set the global enforcement gate through the writer, then mirror the new
    /// state into the health snapshot. Fail-closed: if the writer errors the
    /// prior state is untouched and the error propagates (§11/G2).
    pub async fn set_enforcement_at(&self, enabled: bool) -> Result<()> {
        self.writer.set_enforcement(enabled).await?;
        *self.enforcement_enabled.lock().expect("enforcement mutex poisoned") = enabled;
        self.health
            .lock()
            .expect("health mutex poisoned")
            .enforcement_enabled = enabled;
        Ok(())
    }

    /// Overwrite the health snapshot the integrator reports over gRPC.
    pub fn set_health(&self, status: HealthStatus) {
        *self.health.lock().expect("health mutex poisoned") = status;
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

        self.sink
            .emit(Self::build_event(
                session_id.clone(),
                params.mac,
                EventKind::Granted,
                0,
                0,
            ))
            .await;

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

        self.sink
            .emit(Self::build_event(
                session.session_id.clone(),
                mac,
                EventKind::from(reason),
                session.bytes_in,
                session.bytes_out,
            ))
            .await;

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

        for session in &expired {
            if let Err(e) = self.writer.del_auth(session.mac).await {
                tracing::warn!(mac = %session.mac, error = %e, "del_auth failed during expiry tick");
            }
            self.sink
                .emit(Self::build_event(
                    session.session_id.clone(),
                    session.mac,
                    EventKind::Expired,
                    session.bytes_in,
                    session.bytes_out,
                ))
                .await;
        }

        expired.len()
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
        _now: Instant,
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

                session.bytes_in = delta(&mut session.baseline_in, counters.bytes_in);
                session.bytes_out = delta(&mut session.baseline_out, counters.bytes_out);

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
            let session = Session {
                session_id: SessionId::from(format!("adopted:{}", el.mac)),
                mac: el.mac,
                ip: None,
                tier: Tier::default(),
                granted_at: now,
                expires_at: now + el.remaining,
                quota_bytes: 0,
                rate_bps: 0,
                bytes_in: 0,
                bytes_out: 0,
                baseline_in: None,
                baseline_out: None,
                granted_at_unix,
            };
            if map.insert(el.mac, session).is_none() {
                adopted += 1;
            }
        }
        adopted
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

    async fn set_enforcement(&self, enabled: bool) -> Result<()> {
        self.set_enforcement_at(enabled).await
    }

    async fn enforcement_enabled(&self) -> bool {
        *self.enforcement_enabled.lock().expect("enforcement mutex poisoned")
    }

    async fn set_garden(&self, fqdns: Vec<String>) -> Result<()> {
        let garden = self.garden.lock().expect("garden mutex poisoned").clone();
        match garden {
            Some(g) => g.set_fqdns(fqdns).await,
            None => Err(Error::BadRequest("garden control not configured".into())),
        }
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
        SetEnforcement(bool),
    }

    /// Records every writer op. `fail_add` makes `add_auth` fail (to exercise the
    /// fail-closed grant path); `fail_set` makes `set_enforcement` fail.
    struct MockWriter {
        ops: StdMutex<Vec<WriterOp>>,
        fail_add: bool,
        fail_set: bool,
    }

    impl MockWriter {
        fn new() -> Self {
            MockWriter { ops: StdMutex::new(Vec::new()), fail_add: false, fail_set: false }
        }
        fn failing() -> Self {
            MockWriter { ops: StdMutex::new(Vec::new()), fail_add: true, fail_set: false }
        }
        fn failing_set() -> Self {
            MockWriter { ops: StdMutex::new(Vec::new()), fail_add: false, fail_set: true }
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
        async fn set_enforcement(&self, enabled: bool) -> Result<()> {
            if self.fail_set {
                return Err(Error::NftTransaction("injected failure".into()));
            }
            self.ops.lock().unwrap().push(WriterOp::SetEnforcement(enabled));
            Ok(())
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
            enforcement_enabled: true,
        });
        let h = m.health().await;
        assert!(h.cp_connected);
        assert!(h.kernel_table_present);
    }

    #[tokio::test]
    async fn enforcement_defaults_enabled_fail_closed() {
        let (m, _writer, _sink) = mgr();
        assert!(m.enforcement_enabled().await, "boots enabled (fail-closed)");
        assert!(m.health().await.enforcement_enabled);
    }

    #[tokio::test]
    async fn set_enforcement_toggles_writer_and_state() {
        let (m, writer, _sink) = mgr();

        m.set_enforcement(false).await.unwrap();
        assert!(!m.enforcement_enabled().await);
        assert!(!m.health().await.enforcement_enabled);

        m.set_enforcement(true).await.unwrap();
        assert!(m.enforcement_enabled().await);

        assert_eq!(
            writer.ops(),
            vec![WriterOp::SetEnforcement(false), WriterOp::SetEnforcement(true)],
        );
    }

    #[tokio::test]
    async fn set_enforcement_does_not_disturb_sessions() {
        // Toggling the gate must never add/remove auth elements — session state
        // is orthogonal to the global gate.
        let (m, writer, _sink) = mgr();
        m.grant(grant_params(mac(1), 1800, 0)).await.unwrap();
        m.set_enforcement(false).await.unwrap();
        assert_eq!(m.len(), 1, "session survives a gate toggle");
        // No DelAuth was issued by the toggle.
        assert!(!writer.ops().iter().any(|o| matches!(o, WriterOp::DelAuth(_))));
    }

    #[tokio::test]
    async fn set_enforcement_fails_closed_keeps_prior_state() {
        // Writer error -> state unchanged, error propagates (§11/G2).
        let writer = Arc::new(MockWriter::failing_set());
        let sink = Arc::new(CapturingSink::new());
        let m = SessionManager::new(writer.clone(), sink.clone());
        let before = m.enforcement_enabled().await;
        let err = m.set_enforcement(false).await.unwrap_err();
        assert!(matches!(err, Error::NftTransaction(_)));
        assert_eq!(m.enforcement_enabled().await, before, "state unchanged on error");
    }
}
