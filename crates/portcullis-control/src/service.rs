//! The tonic `Enforcement` gRPC service and the [`GrpcEventSink`] that fans
//! domain [`SessionEvent`]s out to streaming control-plane clients (TDD §7.5).
//!
//! ## No fail-open (§11, §13)
//! - A `grant_session` whose request fails conversion/validation, or whose
//!   `Enforcer::grant` returns an error, is answered with a `tonic::Status`.
//!   It is **never** silently accepted and never panics.
//! - The event fan-out uses a **bounded** `tokio::sync::broadcast` channel. If
//!   the control plane is a slow or broken consumer the channel never grows
//!   without limit: the oldest buffered events are dropped (the subscriber
//!   observes a `Lagged` and we skip past it) rather than the engine blocking
//!   on enforcement or growing RAM until OOM.

// tonic's service API forces `Result<_, tonic::Status>` everywhere, and
// `Status` is a large enum by design — boxing every gRPC return to satisfy this
// lint would only obscure the generated-trait signatures. Allow it crate-wide
// for the service surface.
#![allow(clippy::result_large_err)]

use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use portcullis_types::{Enforcer, EventSink, MetricsRegistry, SessionEvent};
use tonic::{Request, Response, Status};

use crate::convert;
use crate::event_log::EventLog;
use crate::pb;

/// Default bound on the in-RAM event replay buffer (number of events).
///
/// This is the at-least-once replay window: a control-plane outage shorter
/// than the buffer covers loses nothing (§7.6). 4096 events ≈ 10 minutes on a
/// busy router (100 clients × one INTERIM per 15 s) at ~100 B/event ≈ 400 KB
/// RAM — comfortably inside the <30 MB budget (§14). The engine never blocks
/// enforcement to push an event; overflow evicts the oldest.
pub const DEFAULT_EVENT_BUFFER: usize = 4096;

/// Base capabilities every 0.4+ engine advertises via `GetEngineInfo`. The
/// composition root appends conditional ones (e.g. `"shaper"`).
pub const BASE_CAPABILITIES: &[&str] = &["tier_policies", "engine_params", "event_replay"];

/// The gRPC server state: the domain [`Enforcer`] plus the shared replayable
/// [`EventLog`]. Construct via [`EnforcementService::new`], which also hands
/// back a [`GrpcEventSink`] wired to the same log.
#[derive(Clone)]
pub struct EnforcementService {
    enforcer: Arc<dyn Enforcer>,
    events: Arc<EventLog>,
    capabilities: Arc<Vec<String>>,
    metrics: Arc<MetricsRegistry>,
}

fn base_capabilities() -> Vec<String> {
    BASE_CAPABILITIES.iter().map(|s| s.to_string()).collect()
}

impl EnforcementService {
    /// Build the service and its paired [`GrpcEventSink`] sharing one bounded
    /// [`EventLog`] of `buffer` capacity.
    ///
    /// The sink is what `portcullis-session` calls to `emit`; every event sent
    /// through it is sequenced, retained for replay, and reaches every live
    /// `StreamEvents` subscriber.
    pub fn new(enforcer: Arc<dyn Enforcer>, buffer: usize) -> (Self, GrpcEventSink) {
        let log = Arc::new(EventLog::new(buffer));
        let svc = EnforcementService {
            enforcer,
            events: log.clone(),
            capabilities: Arc::new(base_capabilities()),
            metrics: Arc::new(MetricsRegistry::new()),
        };
        let sink = GrpcEventSink { log };
        (svc, sink)
    }

    /// Convenience constructor with [`DEFAULT_EVENT_BUFFER`].
    pub fn with_default_buffer(enforcer: Arc<dyn Enforcer>) -> (Self, GrpcEventSink) {
        Self::new(enforcer, DEFAULT_EVENT_BUFFER)
    }

    /// Build a service from an existing enforcer and a shared [`EventLog`]
    /// produced by [`event_channel`].
    ///
    /// The composition root uses this to break the `SessionManager` <-> sink
    /// construction cycle: the manager needs the [`GrpcEventSink`] at
    /// construction time, while the service needs the *already-built* manager as
    /// its `Enforcer`. So we mint the log + sink first ([`event_channel`]),
    /// hand the sink to the session layer, then assemble the service here from
    /// the same log. `capabilities` is what `GetEngineInfo` advertises — start
    /// from [`BASE_CAPABILITIES`] and append conditional ones. `metrics` is the
    /// daemon-wide counter registry `GetMetrics` reports (the same one the
    /// session layer and redirect responder increment).
    pub fn from_parts(
        enforcer: Arc<dyn Enforcer>,
        events: Arc<EventLog>,
        capabilities: Vec<String>,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        EnforcementService { enforcer, events, capabilities: Arc::new(capabilities), metrics }
    }

    /// The shared event log (used by tests and `GetEngineInfo`).
    pub fn event_log(&self) -> Arc<EventLog> {
        self.events.clone()
    }

    /// The metrics registry `GetMetrics` reads (used by tests).
    pub fn metrics(&self) -> Arc<MetricsRegistry> {
        self.metrics.clone()
    }
}

/// Mint a standalone bounded [`EventLog`] and its paired [`GrpcEventSink`],
/// decoupled from any [`EnforcementService`].
///
/// Pair with [`EnforcementService::from_parts`] in the composition root: the
/// sink is wired into `portcullis-session` (which emits lifecycle events into
/// it) before the `SessionManager` — the service's `Enforcer` — exists. The
/// returned log and the sink are the same store, so events emitted by the
/// session layer are replayable to every `StreamEvents` subscriber.
pub fn event_channel(buffer: usize) -> (Arc<EventLog>, GrpcEventSink) {
    let log = Arc::new(EventLog::new(buffer));
    (log.clone(), GrpcEventSink { log })
}

/// `EventSink` adapter: pushes domain events into the bounded [`EventLog`] so
/// gRPC `StreamEvents` subscribers receive them (with replay). Pushing never
/// blocks and never fails the caller — with no live subscriber the event just
/// waits in the ring until evicted (§11: bounded RAM, no fail-open).
#[derive(Clone)]
pub struct GrpcEventSink {
    log: Arc<EventLog>,
}

#[tonic::async_trait]
impl EventSink for GrpcEventSink {
    async fn emit(&self, event: SessionEvent) {
        self.log.push(event);
    }
}

type EventStream =
    Pin<Box<dyn Stream<Item = Result<pb::SessionEvent, Status>> + Send + 'static>>;
type SessionInfoStream =
    Pin<Box<dyn Stream<Item = Result<pb::SessionInfo, Status>> + Send + 'static>>;

/// Turn a domain `Error` into a `tonic::Status` with an appropriate code. The
/// guiding rule: validation/identity problems are `InvalidArgument`, a missing
/// session is `NotFound`, control-plane-unreachable / backend faults are
/// `Unavailable` or `Internal` — but in all cases the grant is *rejected*,
/// never silently accepted.
fn status_from_domain(err: portcullis_types::Error) -> Status {
    use portcullis_types::Error as E;
    match err {
        E::InvalidMac(_) | E::InvalidTier(_) | E::BadRequest(_) => {
            Status::invalid_argument(err.to_string())
        }
        E::SessionNotFound(_) => Status::not_found(err.to_string()),
        E::ControlPlaneUnreachable(_) => Status::unavailable(err.to_string()),
        E::BadSignature => Status::unauthenticated(err.to_string()),
        E::Config(_) => Status::failed_precondition(err.to_string()),
        // Backend / nft / counter / neigh / io / other: an internal fault. We
        // fail closed (return an error) rather than pretend the grant took.
        _ => Status::internal(err.to_string()),
    }
}

#[tonic::async_trait]
impl pb::enforcement_server::Enforcement for EnforcementService {
    async fn grant_session(
        &self,
        request: Request<pb::GrantRequest>,
    ) -> Result<Response<pb::GrantReply>, Status> {
        // 1. Validate/convert the wire request. A bad MAC/tier/IP is rejected
        //    here as InvalidArgument — no fail-open default.
        let params = convert::grant_request_to_params(request.into_inner())
            .map_err(status_from_domain)?;

        // 2. Hand to the domain enforcer. Any error becomes a Status; we never
        //    return accepted=true on failure.
        let session_id = self
            .enforcer
            .grant(params)
            .await
            .map_err(status_from_domain)?;

        Ok(Response::new(pb::GrantReply {
            session_id: session_id.0.into(),
            accepted: true,
        }))
    }

    async fn revoke_session(
        &self,
        request: Request<pb::RevokeRequest>,
    ) -> Result<Response<pb::Ack>, Status> {
        let req = request.into_inner();
        let mac = convert::parse_mac(&req.client_mac).map_err(status_from_domain)?;
        let reason = convert::revoke_reason_from_pb(req.reason());

        self.enforcer
            .revoke(mac, reason)
            .await
            .map_err(status_from_domain)?;

        Ok(Response::new(pb::Ack { ok: true, message: String::new() }))
    }

    async fn get_session(
        &self,
        request: Request<pb::Key>,
    ) -> Result<Response<pb::SessionInfo>, Status> {
        let mac = convert::parse_mac(&request.into_inner().client_mac)
            .map_err(status_from_domain)?;

        match self.enforcer.get(mac).await.map_err(status_from_domain)? {
            Some(info) => Ok(Response::new(convert::session_info_to_pb(&info))),
            None => Err(Status::not_found(format!("session not found: {mac}"))),
        }
    }

    type ListSessionsStream = SessionInfoStream;

    async fn list_sessions(
        &self,
        _request: Request<pb::ListRequest>,
    ) -> Result<Response<Self::ListSessionsStream>, Status> {
        // The snapshot is taken up front (the session table is small, §14), so
        // the stream cannot wedge enforcement while a slow client drains it.
        let sessions = self.enforcer.list().await.map_err(status_from_domain)?;
        let items: Vec<Result<pb::SessionInfo, Status>> = sessions
            .iter()
            .map(|s| Ok(convert::session_info_to_pb(s)))
            .collect();
        let stream = futures::stream::iter(items);
        Ok(Response::new(Box::pin(stream)))
    }

    type StreamEventsStream = EventStream;

    async fn stream_events(
        &self,
        request: Request<pb::StreamReq>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        // Replay-then-tail against the bounded EventLog (at-least-once, §7.6).
        // A valid cursor (matching boot_id) resumes after it; anything else —
        // no cursor, a cursor from a previous boot — replays everything still
        // retained (the CP detects gaps by the first seq jumping past
        // cursor+1). A slow consumer only ever re-reads the ring; enforcement
        // never blocks and RAM never grows unbounded (§11).
        let req = request.into_inner();
        let cursor = if req.boot_id == self.events.boot_id() { req.resume_after_seq } else { 0 };
        let stream = event_log_stream(self.events.clone(), cursor);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_engine_info(
        &self,
        _request: Request<pb::Empty>,
    ) -> Result<Response<pb::EngineInfo>, Status> {
        let cs = self.enforcer.config_state().await;
        Ok(Response::new(pb::EngineInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            boot_id: self.events.boot_id().to_string(),
            event_latest_seq: self.events.latest_seq(),
            event_oldest_seq: self.events.oldest_seq(),
            capabilities: self.capabilities.as_ref().clone(),
            enforcement_enabled: cs.enforcement_enabled,
            tier_policies_hash: cs.tier_policies_hash,
            engine_params_hash: cs.engine_params_hash,
            garden_hash: cs.garden_hash,
        }))
    }

    async fn get_metrics(
        &self,
        _request: Request<pb::Empty>,
    ) -> Result<Response<pb::MetricsReply>, Status> {
        // Assemble the reply from its owners: the shared registry (session +
        // redirect counters), the enforcer (active-session gauge), the event
        // log (emitted == latest seq, evicted), and the kernel (RSS).
        let snap = self.metrics.snapshot();
        let sessions_active = self.enforcer.active_sessions().await as u64;
        Ok(Response::new(pb::MetricsReply {
            sessions_active,
            grants_total: snap.grants,
            grant_failures_total: snap.grant_failures,
            revokes_total: snap.revokes,
            expires_total: snap.expires,
            quota_kills_total: snap.quota_kills,
            events_emitted_total: self.events.latest_seq(),
            events_evicted_total: self.events.evicted_total(),
            shaper_failures_total: snap.shaper_failures,
            redirect_rejections_total: snap.redirect_rejections,
            rss_bytes: portcullis_types::rss_bytes(),
            uptime_secs: snap.uptime_secs,
            idle_kills_total: snap.idle_kills,
        }))
    }

    async fn health(
        &self,
        _request: Request<pb::Empty>,
    ) -> Result<Response<pb::HealthReply>, Status> {
        let h = self.enforcer.health().await;
        Ok(Response::new(convert::health_to_pb(h)))
    }

    async fn set_enforcement(
        &self,
        request: Request<pb::SetEnforcementRequest>,
    ) -> Result<Response<pb::Ack>, Status> {
        let enabled = request.into_inner().enabled;
        self.enforcer
            .set_enforcement(enabled)
            .await
            .map_err(status_from_domain)?;
        Ok(Response::new(pb::Ack { ok: true, message: String::new() }))
    }

    async fn set_garden(
        &self,
        request: Request<pb::SetGardenRequest>,
    ) -> Result<Response<pb::Ack>, Status> {
        let fqdns = request.into_inner().fqdns;
        self.enforcer
            .set_garden(fqdns)
            .await
            .map_err(status_from_domain)?;
        Ok(Response::new(pb::Ack { ok: true, message: String::new() }))
    }

    async fn set_tier_policies(
        &self,
        request: Request<pb::SetTierPoliciesRequest>,
    ) -> Result<Response<pb::Ack>, Status> {
        // Validate at the wire boundary; the enforcer is never called with a
        // malformed policy set (unknown/duplicate tier -> InvalidArgument).
        let policies =
            convert::tier_policies_from_pb(request.into_inner()).map_err(status_from_domain)?;
        self.enforcer
            .set_tier_policies(policies)
            .await
            .map_err(status_from_domain)?;
        Ok(Response::new(pb::Ack { ok: true, message: String::new() }))
    }

    async fn set_engine_parameters(
        &self,
        request: Request<pb::SetEngineParametersRequest>,
    ) -> Result<Response<pb::Ack>, Status> {
        // 0 -> built-in default substitution + bounds check happen at the wire
        // boundary; the enforcer only ever sees a valid concrete snapshot.
        let params =
            convert::engine_params_from_pb(request.into_inner()).map_err(status_from_domain)?;
        self.enforcer
            .set_engine_parameters(params)
            .await
            .map_err(status_from_domain)?;
        Ok(Response::new(pb::Ack { ok: true, message: String::new() }))
    }
}

/// Adapt the [`EventLog`] into a replay-then-tail `Stream` of wire
/// `SessionEvent`s using only `futures` (no `tokio-stream` dependency).
///
/// Each poll drains everything retained past the cursor (batched into a local
/// queue so the log lock is held only for the snapshot), then awaits the log's
/// watch channel for new pushes. The watch never misses a wakeup: `changed()`
/// compares against the last version this receiver has seen, so a push racing
/// the empty-snapshot check still resolves it immediately.
fn event_log_stream(
    log: Arc<EventLog>,
    cursor: u64,
) -> impl Stream<Item = Result<pb::SessionEvent, Status>> + Send + 'static {
    struct State {
        log: Arc<EventLog>,
        cursor: u64,
        rx: tokio::sync::watch::Receiver<u64>,
        pending: std::collections::VecDeque<(u64, SessionEvent)>,
    }
    let rx = log.subscribe();
    let state = State { log, cursor, rx, pending: Default::default() };

    futures::stream::unfold(state, |mut st| async move {
        loop {
            if let Some((seq, ev)) = st.pending.pop_front() {
                st.cursor = seq;
                let mut item = convert::session_event_to_pb(&ev);
                item.seq = seq;
                return Some((Ok(item), st));
            }
            let batch = st.log.snapshot_after(st.cursor);
            if !batch.is_empty() {
                st.pending = batch.into();
                continue;
            }
            if st.rx.changed().await.is_err() {
                // Log dropped (daemon shutdown): end the stream cleanly.
                return None;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use portcullis_types::{
        EventKind, GrantParams, HealthStatus, MacAddr, Result as PResult, RevokeReason,
        SessionId, SessionInfo,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tonic::Code;

    /// In-test mock Enforcer. `fail` flips grant/revoke/get/list into a domain
    /// error so we can assert error -> Status propagation.
    struct MockEnforcer {
        fail: bool,
        grants: AtomicUsize,
        tier_pushes: AtomicUsize,
        param_pushes: AtomicUsize,
    }

    impl MockEnforcer {
        fn ok() -> Arc<Self> {
            Arc::new(MockEnforcer {
                fail: false,
                grants: AtomicUsize::new(0),
                tier_pushes: AtomicUsize::new(0),
                param_pushes: AtomicUsize::new(0),
            })
        }
        fn failing() -> Arc<Self> {
            Arc::new(MockEnforcer {
                fail: true,
                grants: AtomicUsize::new(0),
                tier_pushes: AtomicUsize::new(0),
                param_pushes: AtomicUsize::new(0),
            })
        }
    }

    #[tonic::async_trait]
    impl Enforcer for MockEnforcer {
        async fn grant(&self, params: GrantParams) -> PResult<SessionId> {
            self.grants.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(portcullis_types::Error::Backend("boom".into()));
            }
            Ok(params.session_id)
        }
        async fn revoke(&self, _mac: MacAddr, _reason: RevokeReason) -> PResult<()> {
            if self.fail {
                return Err(portcullis_types::Error::SessionNotFound("x".into()));
            }
            Ok(())
        }
        async fn get(&self, mac: MacAddr) -> PResult<Option<SessionInfo>> {
            if self.fail {
                return Ok(None);
            }
            Ok(Some(SessionInfo {
                session_id: SessionId("s1".into()),
                mac,
                ip: None,
                tier: portcullis_types::Tier::public(),
                granted_at_unix: 1,
                expires_in: Duration::from_secs(60),
                quota_bytes: 0,
                rate_bps: 0,
                bytes_in: 0,
                bytes_out: 0,
            }))
        }
        async fn list(&self) -> PResult<Vec<SessionInfo>> {
            Ok(vec![SessionInfo {
                session_id: SessionId("s1".into()),
                mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
                ip: None,
                tier: portcullis_types::Tier::public(),
                granted_at_unix: 1,
                expires_in: Duration::from_secs(60),
                quota_bytes: 0,
                rate_bps: 0,
                bytes_in: 0,
                bytes_out: 0,
            }])
        }
        async fn health(&self) -> HealthStatus {
            HealthStatus { backend_ok: true, ..Default::default() }
        }
        async fn active_sessions(&self) -> usize {
            // Fixed gauge value so get_metrics assertions are unambiguous.
            3
        }
        async fn set_enforcement(&self, _enabled: bool) -> PResult<()> {
            if self.fail {
                return Err(portcullis_types::Error::Backend("boom".into()));
            }
            Ok(())
        }
        async fn enforcement_enabled(&self) -> bool {
            true
        }
        async fn set_garden(&self, _fqdns: Vec<String>) -> PResult<()> {
            if self.fail {
                return Err(portcullis_types::Error::Backend("boom".into()));
            }
            Ok(())
        }
        async fn set_tier_policies(
            &self,
            _policies: Vec<portcullis_types::TierPolicy>,
        ) -> PResult<()> {
            self.tier_pushes.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(portcullis_types::Error::Backend("boom".into()));
            }
            Ok(())
        }
        async fn set_engine_parameters(
            &self,
            _params: portcullis_types::EngineParams,
        ) -> PResult<()> {
            self.param_pushes.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(portcullis_types::Error::Backend("boom".into()));
            }
            Ok(())
        }
        async fn config_state(&self) -> portcullis_types::ConfigState {
            portcullis_types::ConfigState {
                tier_policies_hash: "1111111111111111".into(),
                engine_params_hash: "2222222222222222".into(),
                garden_hash: "3333333333333333".into(),
                enforcement_enabled: true,
            }
        }
    }

    use pb::enforcement_server::Enforcement;

    fn sample_grant() -> pb::GrantRequest {
        pb::GrantRequest {
            store_id: "store-1".into(),
            client_mac: "aa:bb:cc:dd:ee:ff".into(),
            client_ip: "".into(),
            ttl_seconds: 60,
            quota_bytes: 0,
            rate_bps: 0,
            tier: "public".into(),
            session_id: "sess-1".into(),
        }
    }

    #[tokio::test]
    async fn grant_session_accepts_on_success() {
        let (svc, _sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let reply = svc
            .grant_session(Request::new(sample_grant()))
            .await
            .unwrap()
            .into_inner();
        assert!(reply.accepted);
        assert_eq!(reply.session_id, "sess-1");
    }

    #[tokio::test]
    async fn grant_session_propagates_enforcer_error_as_status() {
        let (svc, _sink) =
            EnforcementService::with_default_buffer(MockEnforcer::failing());
        let status = svc
            .grant_session(Request::new(sample_grant()))
            .await
            .unwrap_err();
        // Backend error -> Internal; crucially NOT a silent accept.
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn grant_session_invalid_mac_is_invalid_argument_not_accept() {
        let (svc, _sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let mut g = sample_grant();
        g.client_mac = "garbage".into();
        let status = svc.grant_session(Request::new(g)).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn revoke_session_ok_and_error() {
        let (ok, _s1) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let ack = ok
            .revoke_session(Request::new(pb::RevokeRequest {
                client_mac: "aa:bb:cc:dd:ee:ff".into(),
                reason: pb::RevokeReason::RevokeQuota as i32,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(ack.ok);

        let (bad, _s2) = EnforcementService::with_default_buffer(MockEnforcer::failing());
        let status = bad
            .revoke_session(Request::new(pb::RevokeRequest {
                client_mac: "aa:bb:cc:dd:ee:ff".into(),
                reason: pb::RevokeReason::RevokeAdmin as i32,
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn set_enforcement_ok_and_error() {
        let (ok, _s1) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let ack = ok
            .set_enforcement(Request::new(pb::SetEnforcementRequest { enabled: false }))
            .await
            .unwrap()
            .into_inner();
        assert!(ack.ok);

        let (bad, _s2) = EnforcementService::with_default_buffer(MockEnforcer::failing());
        let status = bad
            .set_enforcement(Request::new(pb::SetEnforcementRequest { enabled: false }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn set_tier_policies_ok_and_error() {
        let req = || {
            Request::new(pb::SetTierPoliciesRequest {
                policies: vec![pb::TierPolicy {
                    tier: "public".into(),
                    ttl_seconds: 300,
                    quota_bytes: 0,
                    rate_bps: 0,
                }],
            })
        };

        let enf = MockEnforcer::ok();
        let (ok, _s1) = EnforcementService::with_default_buffer(enf.clone());
        let ack = ok.set_tier_policies(req()).await.unwrap().into_inner();
        assert!(ack.ok);
        assert_eq!(enf.tier_pushes.load(Ordering::SeqCst), 1);

        let (bad, _s2) = EnforcementService::with_default_buffer(MockEnforcer::failing());
        let status = bad.set_tier_policies(req()).await.unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn set_tier_policies_novel_tier_accepted() {
        // Tiers are data-driven now: a well-formed but previously-unknown name
        // like "platinum" is accepted (the control plane owns the tier set).
        let enf = MockEnforcer::ok();
        let (svc, _sink) = EnforcementService::with_default_buffer(enf.clone());
        let ack = svc
            .set_tier_policies(Request::new(pb::SetTierPoliciesRequest {
                policies: vec![pb::TierPolicy {
                    tier: "platinum".into(),
                    ttl_seconds: 0,
                    quota_bytes: 0,
                    rate_bps: 0,
                }],
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(ack.ok);
        assert_eq!(enf.tier_pushes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn set_tier_policies_malformed_tier_rejected_before_enforcer() {
        // A malformed name (bad charset) is still rejected at the wire boundary.
        let enf = MockEnforcer::ok();
        let (svc, _sink) = EnforcementService::with_default_buffer(enf.clone());
        let status = svc
            .set_tier_policies(Request::new(pb::SetTierPoliciesRequest {
                policies: vec![pb::TierPolicy {
                    tier: "plat!num".into(),
                    ttl_seconds: 0,
                    quota_bytes: 0,
                    rate_bps: 0,
                }],
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        // The malformed request never reached the enforcer.
        assert_eq!(enf.tier_pushes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn set_engine_parameters_ok_and_error() {
        let req = || {
            Request::new(pb::SetEngineParametersRequest {
                accounting_interval_secs: 60,
                garden_tick_secs: 30,
                expiry_tick_secs: 5,
                max_sessions: 4096,
                idle_timeout_secs: 0,
            })
        };

        let enf = MockEnforcer::ok();
        let (ok, _s1) = EnforcementService::with_default_buffer(enf.clone());
        let ack = ok.set_engine_parameters(req()).await.unwrap().into_inner();
        assert!(ack.ok);
        assert_eq!(enf.param_pushes.load(Ordering::SeqCst), 1);

        let (bad, _s2) = EnforcementService::with_default_buffer(MockEnforcer::failing());
        let status = bad.set_engine_parameters(req()).await.unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn set_engine_parameters_out_of_bounds_rejected_before_enforcer() {
        let enf = MockEnforcer::ok();
        let (svc, _sink) = EnforcementService::with_default_buffer(enf.clone());
        let status = svc
            .set_engine_parameters(Request::new(pb::SetEngineParametersRequest {
                accounting_interval_secs: 3601, // past the [1, 3600] bound
                garden_tick_secs: 0,
                expiry_tick_secs: 0,
                max_sessions: 0,
                idle_timeout_secs: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(enf.param_pushes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn get_session_found_and_not_found() {
        let (ok, _s1) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let info = ok
            .get_session(Request::new(pb::Key {
                client_mac: "aa:bb:cc:dd:ee:ff".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.client_mac, "aa:bb:cc:dd:ee:ff");

        let (miss, _s2) = EnforcementService::with_default_buffer(MockEnforcer::failing());
        let status = miss
            .get_session(Request::new(pb::Key {
                client_mac: "aa:bb:cc:dd:ee:ff".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn list_sessions_streams_snapshot() {
        let (svc, _sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let resp = svc
            .list_sessions(Request::new(pb::ListRequest {
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap();
        let items: Vec<_> = resp.into_inner().collect().await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_ref().unwrap().session_id, "s1");
    }

    #[tokio::test]
    async fn health_maps_through() {
        let (svc, _sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let h = svc
            .health(Request::new(pb::Empty {}))
            .await
            .unwrap()
            .into_inner();
        assert!(h.backend_ok);
    }

    fn sample_event(n: u8, kind: EventKind) -> SessionEvent {
        SessionEvent {
            session_id: SessionId::from(format!("s{n}")),
            mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            kind,
            bytes_in: u64::from(n),
            bytes_out: 0,
            ts_unix: i64::from(n),
        }
    }

    fn stream_req(resume_after: u64, boot_id: &str) -> pb::StreamReq {
        pb::StreamReq {
            store_id: "s".into(),
            resume_after_seq: resume_after,
            boot_id: boot_id.into(),
        }
    }

    #[tokio::test]
    async fn event_sink_event_lands_in_log_with_seq() {
        let (svc, sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        sink.emit(sample_event(1, EventKind::Granted)).await;

        let log = svc.event_log();
        let snap = log.snapshot_after(0);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, 1);
        assert_eq!(snap[0].1.kind, EventKind::Granted);
    }

    #[tokio::test]
    async fn stream_events_replays_then_tails() {
        let (svc, sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        // Emitted BEFORE subscribing: the log replays it.
        sink.emit(sample_event(1, EventKind::Granted)).await;

        let resp = svc.stream_events(Request::new(stream_req(0, ""))).await.unwrap();
        let mut stream = resp.into_inner();

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(first.kind, pb::EventKind::Granted as i32);

        // Emitted AFTER subscribing: the tail picks it up.
        sink.emit(sample_event(2, EventKind::Interim)).await;
        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(second.kind, pb::EventKind::Interim as i32);
        assert_eq!(second.bytes_in, 2);
    }

    #[tokio::test]
    async fn stream_events_resumes_after_cursor_with_matching_boot_id() {
        let (svc, sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        for n in 1..=3u8 {
            sink.emit(sample_event(n, EventKind::Interim)).await;
        }
        let boot_id = svc.event_log().boot_id().to_string();

        // Matching boot_id + cursor 2 => only seq 3 is replayed.
        let resp = svc.stream_events(Request::new(stream_req(2, &boot_id))).await.unwrap();
        let mut stream = resp.into_inner();
        assert_eq!(stream.next().await.unwrap().unwrap().seq, 3);

        // Mismatching boot_id => the cursor is void; replay from the oldest.
        let resp = svc.stream_events(Request::new(stream_req(2, "other-boot"))).await.unwrap();
        let mut stream = resp.into_inner();
        assert_eq!(stream.next().await.unwrap().unwrap().seq, 1);
    }

    #[tokio::test]
    async fn event_buffer_is_bounded_and_gap_is_detectable() {
        // Capacity 2, 10 events pushed: the ring holds only the newest two —
        // RAM stays bounded — and a resuming client sees the seq jump (gap).
        let (svc, sink) = EnforcementService::new(MockEnforcer::ok(), 2);
        for n in 0..10u8 {
            sink.emit(sample_event(n, EventKind::Interim)).await;
        }
        let log = svc.event_log();
        assert_eq!(log.latest_seq(), 10);
        assert_eq!(log.oldest_seq(), 9);

        let resp = svc.stream_events(Request::new(stream_req(3, log.boot_id()))).await.unwrap();
        let mut stream = resp.into_inner();
        // Cursor 3 was evicted: the first item jumps to 9 — the client's gap signal.
        assert_eq!(stream.next().await.unwrap().unwrap().seq, 9);
    }

    #[tokio::test]
    async fn get_metrics_assembles_registry_gauge_and_event_log() {
        // Capacity 2 so pushing 3 events evicts one (events_evicted_total).
        let (svc, sink) = EnforcementService::new(MockEnforcer::ok(), 2);
        for n in 1..=3u8 {
            sink.emit(sample_event(n, EventKind::Interim)).await;
        }
        svc.metrics().inc_grants();
        svc.metrics().inc_grants();
        svc.metrics().inc_grant_failures();
        svc.metrics().inc_revokes();
        svc.metrics().inc_expires();
        svc.metrics().inc_quota_kills();
        svc.metrics().inc_shaper_failures();
        svc.metrics().inc_redirect_rejections();

        let m = svc
            .get_metrics(Request::new(pb::Empty {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(m.sessions_active, 3, "MockEnforcer gauge");
        assert_eq!(m.grants_total, 2);
        assert_eq!(m.grant_failures_total, 1);
        assert_eq!(m.revokes_total, 1);
        assert_eq!(m.expires_total, 1);
        assert_eq!(m.quota_kills_total, 1);
        assert_eq!(m.events_emitted_total, 3);
        assert_eq!(m.events_evicted_total, 1);
        assert_eq!(m.shaper_failures_total, 1);
        assert_eq!(m.redirect_rejections_total, 1);
        // rss_bytes: >0 on Linux, 0 on other dev hosts (see types::rss_bytes).
        if cfg!(target_os = "linux") {
            assert!(m.rss_bytes > 0);
        } else {
            assert_eq!(m.rss_bytes, 0);
        }
        // uptime is measured from registry creation — just sanity-bound it.
        assert!(m.uptime_secs < 60);
    }

    #[tokio::test]
    async fn get_engine_info_reports_version_cursor_and_hashes() {
        let (svc, sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        sink.emit(sample_event(1, EventKind::Granted)).await;

        let info = svc
            .get_engine_info(Request::new(pb::Empty {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.boot_id, svc.event_log().boot_id());
        assert_eq!(info.event_latest_seq, 1);
        assert_eq!(info.event_oldest_seq, 1);
        assert!(info.capabilities.contains(&"event_replay".to_string()));
        assert!(info.enforcement_enabled);
        assert_eq!(info.tier_policies_hash, "1111111111111111");
        assert_eq!(info.engine_params_hash, "2222222222222222");
        assert_eq!(info.garden_hash, "3333333333333333");
    }
}
