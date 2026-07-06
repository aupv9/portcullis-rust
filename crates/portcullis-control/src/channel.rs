//! The outbound control-channel driver (TDD §7.5, `docs/design/cgnat-bidi-control-channel.md`).
//!
//! Because sites sit behind carrier-grade NAT the engine cannot be reached
//! inbound, so it is the gRPC **client**: [`run`] dials the control plane and
//! holds the long-lived `Attach` bidirectional stream. Control commands
//! (grant/revoke/get/list/ping) arrive as [`pb::ControlFrame`]s and are
//! dispatched to the injected [`Enforcer`]; lifecycle [`SessionEvent`]s and
//! command replies flow back as [`pb::EngineFrame`]s.
//!
//! ## No fail-open (§5, §11)
//! - The engine can only be granted a session over an *established* stream, so a
//!   dropped control plane **automatically blocks new grants** — there is no code
//!   path that accepts one while disconnected. Existing sessions keep being
//!   enforced by the kernel `auth` set (kernel-as-truth).
//! - A command that fails validation or the domain `Enforcer` is answered with a
//!   `CommandAck { ok: false }` — never a silent accept, never a panic.
//! - Events are drained from **one** long-lived bounded `broadcast::Receiver`
//!   held across reconnects: while the stream is down the ring buffers up to
//!   capacity and drops the **oldest** on overflow (`Lagged`), so RAM never grows
//!   unbounded. The control plane is the durable store and re-baselines from the
//!   `Hello` snapshot on reconnect.
//! - Reconnect uses capped exponential backoff with per-store jitter to avoid a
//!   thundering herd when the control plane restarts across thousands of sites.

#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use portcullis_types::{Enforcer, SessionEvent};
use tokio::sync::broadcast;
use tonic::transport::ClientTlsConfig;
use tonic::Request;

use crate::pb::enforcement_client::EnforcementClient;
use crate::pb::{control_frame, engine_frame};
use crate::{convert, pb, transport};

/// Bound on the outbound frame channel feeding the `Attach` stream. Small on
/// purpose (§14): the sender awaits when full, applying natural backpressure
/// without unbounded RAM growth.
const OUTBOUND_BUFFER: usize = 64;

/// Static parameters for the control channel. Built by the composition root so
/// this crate stays decoupled from `portcullis-config`.
pub struct ControlChannelConfig {
    /// Endpoint to dial, e.g. `https://cp.example:8443`.
    pub endpoint: String,
    /// Mutual-TLS client config (engine identity + pinned CP server CA).
    pub tls: ClientTlsConfig,
    /// Store identity, sent in `Hello` (informational; the CP binds identity to
    /// the client cert, not this string).
    pub store_id: String,
    /// HTTP/2 keepalive interval, kept below the CGNAT idle timeout.
    pub keepalive: Duration,
    /// Cap on the reconnect backoff.
    pub reconnect_max: Duration,
}

/// Run the control channel until `events` is closed (engine shutting down).
///
/// Reconnects forever with backoff. `cp_state(true/false)` is invoked on
/// connect/disconnect so the composition root can drive the `cp_connected`
/// health flag and the disconnect metric.
pub async fn run<F>(
    cfg: ControlChannelConfig,
    enforcer: Arc<dyn Enforcer>,
    events: broadcast::Sender<SessionEvent>,
    cp_state: F,
) where
    F: Fn(bool) + Send + Sync,
{
    // Subscribe ONCE and keep the receiver across reconnects so events emitted
    // while the stream is down are buffered in the bounded ring (§11).
    let mut rx = events.subscribe();
    let mut jitter = seed_from(&cfg.store_id);
    let mut attempt: u32 = 0;

    loop {
        // `established` flips true the moment the stream opens, so we only signal
        // a disconnect (and count the metric) after an actual up->down
        // transition — not on every failed dial.
        let mut established = false;
        match connect_once(&cfg, &enforcer, &mut rx, &cp_state, &mut established).await {
            Ok(()) => tracing::info!("control channel closed; reconnecting"),
            Err(e) => tracing::warn!(error = %e, "control channel error; reconnecting"),
        }
        if established {
            cp_state(false);
            // Had a working connection: retry promptly (small backoff), don't let
            // the pre-connection backoff ramp carry over.
            attempt = 1;
        } else {
            attempt = attempt.saturating_add(1);
        }

        // NOTE: we deliberately do not poll `rx` here to detect shutdown — a
        // `try_recv` would consume (and drop) a buffered event, and this task
        // holds a `Sender` clone so the channel never reports `Closed` anyway.
        // The composition root aborts this task on SIGTERM.

        let delay = backoff(attempt, cfg.reconnect_max, &mut jitter);
        tracing::info!(delay_ms = delay.as_millis() as u64, attempt, "backing off before reconnect");
        tokio::time::sleep(delay).await;
    }
}

/// One connection lifetime: dial, send `Hello`, then multiplex inbound commands
/// and outbound events until either side ends.
async fn connect_once<F>(
    cfg: &ControlChannelConfig,
    enforcer: &Arc<dyn Enforcer>,
    rx: &mut broadcast::Receiver<SessionEvent>,
    cp_state: &F,
    established: &mut bool,
) -> portcullis_types::Result<()>
where
    F: Fn(bool) + Send + Sync,
{
    let channel = transport::connect(&cfg.endpoint, cfg.tls.clone(), cfg.keepalive).await?;
    let mut client = EnforcementClient::new(channel);

    let (mut out_tx, out_rx) = futures::channel::mpsc::channel::<pb::EngineFrame>(OUTBOUND_BUFFER);

    // First frame: Hello + a snapshot of currently-authorized sessions so the CP
    // can reconcile against kernel truth on (re)connect.
    let hello = build_hello(&cfg.store_id, enforcer).await;
    out_tx
        .send(frame(0, engine_frame::Msg::Hello(hello)))
        .await
        .map_err(|_| conn_err("outbound closed before hello"))?;

    let resp = client
        .attach(Request::new(out_rx))
        .await
        .map_err(|s| conn_err(format!("attach rpc: {s}")))?;
    let mut inbound = resp.into_inner();

    *established = true;
    cp_state(true);
    tracing::info!(store = %cfg.store_id, "control channel established");

    loop {
        tokio::select! {
            msg = inbound.message() => match msg {
                Ok(Some(ctrl)) => {
                    for out in handle_control_frame(ctrl, enforcer).await {
                        if out_tx.send(out).await.is_err() {
                            return Ok(()); // outbound half gone; reconnect
                        }
                    }
                }
                Ok(None) => return Ok(()), // peer closed the stream cleanly
                Err(status) => return Err(conn_err(format!("inbound stream: {status}"))),
            },
            ev = rx.recv() => match ev {
                Ok(e) => {
                    let f = frame(0, engine_frame::Msg::Event(convert::session_event_to_pb(&e)));
                    if out_tx.send(f).await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "event backlog overflowed; dropped oldest");
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()), // shutdown
            },
        }
    }
}

/// Dispatch one inbound [`pb::ControlFrame`] to the domain [`Enforcer`] and
/// produce the answering [`pb::EngineFrame`]s (echoing `correlation_id`).
///
/// Never panics; every error path yields an ack/list-end with `ok: false`.
async fn handle_control_frame(
    ctrl: pb::ControlFrame,
    enforcer: &Arc<dyn Enforcer>,
) -> Vec<pb::EngineFrame> {
    let cid = ctrl.correlation_id;
    let Some(msg) = ctrl.msg else {
        // Empty frame (unknown/forward-compat): ignore rather than tear down.
        return Vec::new();
    };

    match msg {
        control_frame::Msg::Grant(g) => {
            let ack = match convert::grant_request_to_params(g) {
                Err(e) => ack_err(e),
                Ok(params) => match enforcer.grant(params).await {
                    Ok(id) => pb::CommandAck { ok: true, message: String::new(), session_id: id.0.into() },
                    Err(e) => ack_err(e),
                },
            };
            vec![frame(cid, engine_frame::Msg::Ack(ack))]
        }
        control_frame::Msg::Revoke(r) => {
            let ack = match convert::parse_mac(&r.client_mac) {
                Err(e) => ack_err(e),
                Ok(mac) => {
                    let reason = convert::revoke_reason_from_pb(r.reason());
                    match enforcer.revoke(mac, reason).await {
                        Ok(()) => ok_ack(),
                        Err(e) => ack_err(e),
                    }
                }
            };
            vec![frame(cid, engine_frame::Msg::Ack(ack))]
        }
        control_frame::Msg::Get(k) => match convert::parse_mac(&k.client_mac) {
            Err(e) => vec![list_end(cid, false, e.to_string())],
            Ok(mac) => match enforcer.get(mac).await {
                Ok(Some(info)) => vec![session(cid, &info), list_end(cid, true, String::new())],
                Ok(None) => vec![list_end(cid, false, "session not found".to_string())],
                Err(e) => vec![list_end(cid, false, e.to_string())],
            },
        },
        control_frame::Msg::List(_) => match enforcer.list().await {
            Ok(sessions) => {
                let mut out: Vec<pb::EngineFrame> = sessions.iter().map(|s| session(cid, s)).collect();
                out.push(list_end(cid, true, String::new()));
                out
            }
            Err(e) => vec![list_end(cid, false, e.to_string())],
        },
        control_frame::Msg::Ping(_) => {
            let h = convert::health_to_pb(enforcer.health().await);
            vec![frame(cid, engine_frame::Msg::Health(h))]
        }
        // Config-push + introspection variants from the reconciled superset proto
        // (SetTierPolicies/SetGarden/SetEnforcement/SetEngineParameters and the
        // GetEngineInfo/GetMetrics queries). Not implemented yet: answer each Set*
        // with a rejecting CommandAck (never fail open / never silently accept a
        // config the engine won't apply) and the get_* queries likewise, so the
        // control plane learns the engine lacks the capability instead of hanging.
        control_frame::Msg::SetTierPolicies(_)
        | control_frame::Msg::SetGarden(_)
        | control_frame::Msg::SetEnforcement(_)
        | control_frame::Msg::SetEngineParameters(_)
        | control_frame::Msg::GetEngineInfo(_)
        | control_frame::Msg::GetMetrics(_) => {
            vec![frame(
                cid,
                engine_frame::Msg::Ack(ack_err(portcullis_types::Error::BadRequest(
                    "config-push / introspection command not implemented by this engine".into(),
                ))),
            )]
        }
    }
}

async fn build_hello(store_id: &str, enforcer: &Arc<dyn Enforcer>) -> pb::Hello {
    let active = enforcer
        .list()
        .await
        .unwrap_or_default()
        .iter()
        .map(convert::session_info_to_pb)
        .collect();
    pb::Hello {
        store_id: store_id.to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        active,
    }
}

// --- frame helpers ---------------------------------------------------------

fn frame(correlation_id: u64, msg: engine_frame::Msg) -> pb::EngineFrame {
    pb::EngineFrame { correlation_id, msg: Some(msg) }
}

fn session(cid: u64, info: &portcullis_types::SessionInfo) -> pb::EngineFrame {
    frame(cid, engine_frame::Msg::Session(convert::session_info_to_pb(info)))
}

fn list_end(cid: u64, ok: bool, message: String) -> pb::EngineFrame {
    frame(cid, engine_frame::Msg::ListEnd(pb::ListEnd { ok, message }))
}

fn ok_ack() -> pb::CommandAck {
    pb::CommandAck { ok: true, message: String::new(), session_id: String::new() }
}

fn ack_err(e: portcullis_types::Error) -> pb::CommandAck {
    pb::CommandAck { ok: false, message: e.to_string(), session_id: String::new() }
}

fn conn_err(msg: impl Into<String>) -> portcullis_types::Error {
    portcullis_types::Error::ControlPlaneUnreachable(msg.into())
}

// --- reconnect backoff -----------------------------------------------------

/// FNV-1a seed from the store id so each site jitters on a different sequence
/// (avoids a synchronized reconnect stampede after a control-plane restart).
fn seed_from(store_id: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in store_id.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h | 1 // xorshift state must be non-zero
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Capped exponential backoff with jitter: sleep in `[capped/2, capped]` where
/// `capped = min(2^attempt seconds, reconnect_max)`.
fn backoff(attempt: u32, max: Duration, state: &mut u64) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    let factor = 1u64.checked_shl(attempt.min(16)).unwrap_or(u64::MAX);
    let capped = Duration::from_secs(factor).min(max);
    let half = capped / 2;
    let span_ms = half.as_millis() as u64;
    let jitter = if span_ms == 0 { 0 } else { xorshift(state) % (span_ms + 1) };
    half.saturating_add(Duration::from_millis(jitter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_types::{
        Error, GrantParams, HealthStatus, MacAddr, Result as PResult, RevokeReason, SessionId,
        SessionInfo, Tier,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration as Dur;

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

    fn info(mac: &str) -> SessionInfo {
        SessionInfo {
            session_id: SessionId::from("s1"),
            mac: mac.parse().unwrap(),
            ip: None,
            tier: Tier::Public,
            granted_at_unix: 1,
            expires_in: Dur::from_secs(60),
            quota_bytes: 0,
            rate_bps: 0,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[tonic::async_trait]
    impl Enforcer for MockEnforcer {
        async fn grant(&self, params: GrantParams) -> PResult<SessionId> {
            self.grants.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(Error::Backend("boom".into()));
            }
            Ok(params.session_id)
        }
        async fn revoke(&self, _mac: MacAddr, _reason: RevokeReason) -> PResult<()> {
            if self.fail {
                return Err(Error::SessionNotFound("x".into()));
            }
            Ok(())
        }
        async fn get(&self, mac: MacAddr) -> PResult<Option<SessionInfo>> {
            if self.fail {
                return Ok(None);
            }
            Ok(Some(info(&mac.to_string())))
        }
        async fn list(&self) -> PResult<Vec<SessionInfo>> {
            if self.fail {
                return Err(Error::Backend("boom".into()));
            }
            Ok(vec![info("aa:bb:cc:dd:ee:ff"), info("11:22:33:44:55:66")])
        }
        async fn health(&self) -> HealthStatus {
            HealthStatus { backend_ok: true, ..Default::default() }
        }
    }

    fn grant_ctrl(cid: u64, mac: &str) -> pb::ControlFrame {
        pb::ControlFrame {
            correlation_id: cid,
            msg: Some(control_frame::Msg::Grant(pb::GrantRequest {
                store_id: "s".into(),
                client_mac: mac.into(),
                client_ip: String::new(),
                ttl_seconds: 60,
                quota_bytes: 0,
                rate_bps: 0,
                tier: "public".into(),
                session_id: "sess-1".into(),
            })),
        }
    }

    fn ack_of(frame: &pb::EngineFrame) -> &pb::CommandAck {
        match &frame.msg {
            Some(engine_frame::Msg::Ack(a)) => a,
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn grant_frame_acks_ok_and_echoes_correlation() {
        let out = handle_control_frame(grant_ctrl(7, "aa:bb:cc:dd:ee:ff"), &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].correlation_id, 7);
        let ack = ack_of(&out[0]);
        assert!(ack.ok);
        assert_eq!(ack.session_id, "sess-1");
    }

    #[tokio::test]
    async fn failing_grant_acks_error_not_silent_accept() {
        let out = handle_control_frame(grant_ctrl(1, "aa:bb:cc:dd:ee:ff"), &(MockEnforcer::failing() as Arc<dyn Enforcer>)).await;
        let ack = ack_of(&out[0]);
        assert!(!ack.ok);
        assert!(!ack.message.is_empty());
    }

    #[tokio::test]
    async fn invalid_mac_grant_acks_error() {
        let out = handle_control_frame(grant_ctrl(1, "garbage"), &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        let ack = ack_of(&out[0]);
        assert!(!ack.ok);
    }

    #[tokio::test]
    async fn revoke_frame_acks() {
        let ctrl = pb::ControlFrame {
            correlation_id: 3,
            msg: Some(control_frame::Msg::Revoke(pb::RevokeRequest {
                client_mac: "aa:bb:cc:dd:ee:ff".into(),
                reason: pb::RevokeReason::RevokeQuota as i32,
            })),
        };
        let out = handle_control_frame(ctrl, &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        assert_eq!(out[0].correlation_id, 3);
        assert!(ack_of(&out[0]).ok);
    }

    #[tokio::test]
    async fn get_found_yields_session_then_list_end() {
        let ctrl = pb::ControlFrame {
            correlation_id: 5,
            msg: Some(control_frame::Msg::Get(pb::Key { client_mac: "aa:bb:cc:dd:ee:ff".into() })),
        };
        let out = handle_control_frame(ctrl, &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0].msg, Some(engine_frame::Msg::Session(_))));
        match &out[1].msg {
            Some(engine_frame::Msg::ListEnd(le)) => assert!(le.ok),
            other => panic!("expected ListEnd, got {other:?}"),
        }
        assert!(out.iter().all(|f| f.correlation_id == 5));
    }

    #[tokio::test]
    async fn get_missing_yields_failed_list_end() {
        let ctrl = pb::ControlFrame {
            correlation_id: 5,
            msg: Some(control_frame::Msg::Get(pb::Key { client_mac: "aa:bb:cc:dd:ee:ff".into() })),
        };
        let out = handle_control_frame(ctrl, &(MockEnforcer::failing() as Arc<dyn Enforcer>)).await;
        assert_eq!(out.len(), 1);
        match &out[0].msg {
            Some(engine_frame::Msg::ListEnd(le)) => assert!(!le.ok),
            other => panic!("expected ListEnd, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_streams_all_then_list_end() {
        let ctrl = pb::ControlFrame {
            correlation_id: 9,
            msg: Some(control_frame::Msg::List(pb::ListRequest { page_size: 0, page_token: String::new() })),
        };
        let out = handle_control_frame(ctrl, &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        // 2 sessions + 1 list_end
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0].msg, Some(engine_frame::Msg::Session(_))));
        assert!(matches!(out[1].msg, Some(engine_frame::Msg::Session(_))));
        assert!(matches!(out[2].msg, Some(engine_frame::Msg::ListEnd(_))));
    }

    #[tokio::test]
    async fn ping_yields_health() {
        let ctrl = pb::ControlFrame {
            correlation_id: 2,
            msg: Some(control_frame::Msg::Ping(pb::Ping { ts_unix: 100 })),
        };
        let out = handle_control_frame(ctrl, &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        match &out[0].msg {
            Some(engine_frame::Msg::Health(h)) => assert!(h.backend_ok),
            other => panic!("expected Health, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_frame_is_ignored_no_panic() {
        let ctrl = pb::ControlFrame { correlation_id: 0, msg: None };
        let out = handle_control_frame(ctrl, &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn hello_carries_version_and_active_snapshot() {
        let hello = build_hello("SITE-1", &(MockEnforcer::ok() as Arc<dyn Enforcer>)).await;
        assert_eq!(hello.store_id, "SITE-1");
        assert!(!hello.engine_version.is_empty());
        assert_eq!(hello.active.len(), 2);
    }

    #[test]
    fn backoff_is_capped_and_within_jitter_window() {
        let max = Duration::from_secs(60);
        let mut s = seed_from("SITE-1");
        // attempt 0 => immediate.
        assert_eq!(backoff(0, max, &mut s), Duration::ZERO);
        // Large attempt caps at max; result stays within [max/2, max].
        let d = backoff(30, max, &mut s);
        assert!(d >= max / 2 && d <= max, "delay {d:?} out of window");
    }

    #[test]
    fn seed_differs_per_store() {
        assert_ne!(seed_from("SITE-1"), seed_from("SITE-2"));
    }
}
