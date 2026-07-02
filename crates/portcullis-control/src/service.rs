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
use portcullis_types::{Enforcer, EventSink, SessionEvent};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

use crate::convert;
use crate::pb;

/// Default bound on the in-RAM event fan-out buffer (number of events).
///
/// Sized small on purpose: the box has 256 MB RAM (§14) and the control plane
/// is the durable source of truth, so dropping the oldest events under a stuck
/// consumer is preferable to unbounded growth. The engine never blocks
/// enforcement to push an event.
pub const DEFAULT_EVENT_BUFFER: usize = 512;

/// The gRPC server state: the domain [`Enforcer`] plus the shared event
/// broadcaster. Construct via [`EnforcementService::new`], which also hands
/// back a [`GrpcEventSink`] wired to the same channel.
#[derive(Clone)]
pub struct EnforcementService {
    enforcer: Arc<dyn Enforcer>,
    events: broadcast::Sender<SessionEvent>,
}

impl EnforcementService {
    /// Build the service and its paired [`GrpcEventSink`] sharing one bounded
    /// broadcast channel of `buffer` capacity.
    ///
    /// The sink is what `portcullis-session` calls to `emit`; every event sent
    /// through it reaches every live `StreamEvents` subscriber.
    pub fn new(enforcer: Arc<dyn Enforcer>, buffer: usize) -> (Self, GrpcEventSink) {
        let buffer = buffer.max(1);
        let (tx, _rx) = broadcast::channel(buffer);
        let svc = EnforcementService { enforcer, events: tx.clone() };
        let sink = GrpcEventSink { events: tx };
        (svc, sink)
    }

    /// Convenience constructor with [`DEFAULT_EVENT_BUFFER`].
    pub fn with_default_buffer(enforcer: Arc<dyn Enforcer>) -> (Self, GrpcEventSink) {
        Self::new(enforcer, DEFAULT_EVENT_BUFFER)
    }

    /// Build a service from an existing enforcer and a shared event sender
    /// produced by [`event_channel`].
    ///
    /// The composition root uses this to break the `SessionManager` <-> sink
    /// construction cycle: the manager needs the [`GrpcEventSink`] at
    /// construction time, while the service needs the *already-built* manager as
    /// its `Enforcer`. So we mint the channel + sink first ([`event_channel`]),
    /// hand the sink to the session layer, then assemble the service here from
    /// the same `Sender`.
    pub fn from_parts(
        enforcer: Arc<dyn Enforcer>,
        events: broadcast::Sender<SessionEvent>,
    ) -> Self {
        EnforcementService { enforcer, events }
    }

    /// Subscribe to the event fan-out (used internally by `stream_events`,
    /// exposed for tests).
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }
}

/// Mint a standalone bounded event channel and its paired [`GrpcEventSink`],
/// decoupled from any [`EnforcementService`].
///
/// Pair with [`EnforcementService::from_parts`] in the composition root: the
/// sink is wired into `portcullis-session` (which emits lifecycle events into
/// it) before the `SessionManager` — the service's `Enforcer` — exists. The
/// returned `Sender` and the sink share one bounded channel, so events emitted
/// by the session layer reach every live `StreamEvents` subscriber.
pub fn event_channel(buffer: usize) -> (broadcast::Sender<SessionEvent>, GrpcEventSink) {
    let buffer = buffer.max(1);
    let (tx, _rx) = broadcast::channel(buffer);
    (tx.clone(), GrpcEventSink { events: tx })
}

/// `EventSink` adapter: pushes domain events into the bounded broadcast so that
/// gRPC `StreamEvents` subscribers receive them. Sending never blocks and never
/// fails the caller — if there are no live subscribers, or the buffer is full
/// for a lagging subscriber, the event is simply dropped from that consumer's
/// view (§11: bounded RAM, no fail-open on enforcement).
#[derive(Clone)]
pub struct GrpcEventSink {
    events: broadcast::Sender<SessionEvent>,
}

impl GrpcEventSink {
    /// Number of live `StreamEvents` subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.events.receiver_count()
    }

    /// Subscribe directly (used by tests and by `stream_events`).
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }
}

#[tonic::async_trait]
impl EventSink for GrpcEventSink {
    async fn emit(&self, event: SessionEvent) {
        // `send` errors only when there are zero receivers; that is not a
        // failure — events are best-effort fan-out and the CP is the durable
        // store. Never panic, never block.
        let _ = self.events.send(event);
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
        _request: Request<pb::StreamReq>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        // Back the stream with a fresh subscription to the BOUNDED broadcast.
        // A slow/broken consumer can only lag; when it lags past the buffer the
        // channel drops the oldest events for *that* consumer (RecvError::Lagged)
        // and we skip forward — enforcement never blocks and RAM never grows
        // unbounded (§11).
        let rx = self.events.subscribe();
        let stream = broadcast_event_stream(rx);
        Ok(Response::new(Box::pin(stream)))
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
}

/// Adapt a bounded `broadcast::Receiver<SessionEvent>` into a `Stream` of wire
/// `SessionEvent`s using only `futures` (no `tokio-stream` dependency).
///
/// - `Lagged` (slow consumer overran the buffer): skip the dropped events and
///   keep going — the client missed some events but the stream stays alive and
///   the engine never blocks.
/// - `Closed` (sender gone): end the stream cleanly.
fn broadcast_event_stream(
    rx: broadcast::Receiver<SessionEvent>,
) -> impl Stream<Item = Result<pb::SessionEvent, Status>> + Send + 'static {
    futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    return Some((Ok(convert::session_event_to_pb(&ev)), rx));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Bounded-buffer overflow: drop oldest, keep streaming.
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
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
    }

    impl MockEnforcer {
        fn ok() -> Arc<Self> {
            Arc::new(MockEnforcer { fail: false, grants: AtomicUsize::new(0) })
        }
        fn failing() -> Arc<Self> {
            Arc::new(MockEnforcer { fail: true, grants: AtomicUsize::new(0) })
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
                tier: portcullis_types::Tier::Public,
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
                tier: portcullis_types::Tier::Public,
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
        async fn set_enforcement(&self, _enabled: bool) -> PResult<()> {
            if self.fail {
                return Err(portcullis_types::Error::Backend("boom".into()));
            }
            Ok(())
        }
        async fn enforcement_enabled(&self) -> bool {
            true
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

    #[tokio::test]
    async fn event_sink_event_reaches_subscriber() {
        let (svc, sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        let mut rx = svc.subscribe();

        let ev = SessionEvent {
            session_id: SessionId("s1".into()),
            mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            kind: EventKind::Granted,
            bytes_in: 0,
            bytes_out: 0,
            ts_unix: 42,
        };
        sink.emit(ev.clone()).await;

        let got = rx.recv().await.unwrap();
        assert_eq!(got, ev);
    }

    #[tokio::test]
    async fn stream_events_yields_emitted_event() {
        let (svc, sink) = EnforcementService::with_default_buffer(MockEnforcer::ok());
        // Subscribe BEFORE emitting so the bounded channel buffers it.
        let resp = svc
            .stream_events(Request::new(pb::StreamReq { store_id: "s".into() }))
            .await
            .unwrap();
        let mut stream = resp.into_inner();

        sink.emit(SessionEvent {
            session_id: SessionId("s9".into()),
            mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            kind: EventKind::Interim,
            bytes_in: 7,
            bytes_out: 8,
            ts_unix: 99,
        })
        .await;

        let item = stream.next().await.unwrap().unwrap();
        assert_eq!(item.session_id, "s9");
        assert_eq!(item.kind, pb::EventKind::Interim as i32);
        assert_eq!(item.bytes_in, 7);
    }

    #[tokio::test]
    async fn event_buffer_is_bounded() {
        // A tiny buffer + a subscriber that never reads => the channel must NOT
        // grow unbounded. The bound is enforced by tokio::broadcast: a lagging
        // subscriber's recv yields Lagged, it does not OOM. We assert capacity
        // is honoured by observing a Lagged once we overflow.
        let (svc, sink) = EnforcementService::new(MockEnforcer::ok(), 2);
        let mut rx = svc.subscribe();
        for i in 0..10u8 {
            sink.emit(SessionEvent {
                session_id: SessionId::from(format!("s{i}")),
                mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
                kind: EventKind::Interim,
                bytes_in: u64::from(i),
                bytes_out: 0,
                ts_unix: i64::from(i),
            })
            .await;
        }
        // First recv on an overflowed receiver reports how many were dropped.
        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(n)) => assert!(n >= 1),
            other => panic!("expected Lagged, got {other:?}"),
        }
    }
}
