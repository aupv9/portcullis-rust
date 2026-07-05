//! Prometheus text-exposition metrics endpoint (TDD §12).
//!
//! Hand-rolled to avoid the `prometheus` crate's registry/label machinery on the
//! 256 MB MIPS box: the recorder is a fixed set of atomics and the encoder is a
//! `write!` over them (~no allocation on the increment path — a counter bump is
//! one `fetch_add`). The endpoint is unauthenticated, so it is bound on
//! **loopback** only (§12) — there is no overlay network to expose it on now
//! that WireGuard is gone; scrape it locally.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use portcullis_session::SessionManager;
use portcullis_types::{Gauge, Metric, MetricsSink};

/// Atomic-backed metrics recorder. Implements [`MetricsSink`]; a shared `Arc` is
/// handed to the session manager, the nft writer, and the redirect responder.
#[derive(Default)]
pub struct Metrics {
    grants: AtomicU64,
    revokes: AtomicU64,
    expiries: AtomicU64,
    quota_exceeded: AtomicU64,
    nft_txn_errors: AtomicU64,
    dnat_redirects: AtomicU64,
    reconciles: AtomicU64,
    reconcile_repairs: AtomicU64,
    cp_disconnects: AtomicU64,
    active_sessions: AtomicU64,
}

impl Metrics {
    /// Render the current values in Prometheus text-exposition format (v0.0.4).
    /// Pure over the atomics — unit-testable without a socket.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let l = Ordering::Relaxed;
        let mut s = String::with_capacity(1024);
        // counters
        for (name, val) in [
            ("portcullis_grants_total", self.grants.load(l)),
            ("portcullis_revokes_total", self.revokes.load(l)),
            ("portcullis_expiries_total", self.expiries.load(l)),
            ("portcullis_quota_exceeded_total", self.quota_exceeded.load(l)),
            ("portcullis_nft_txn_errors_total", self.nft_txn_errors.load(l)),
            ("portcullis_dnat_redirects_total", self.dnat_redirects.load(l)),
            ("portcullis_reconcile_total", self.reconciles.load(l)),
            ("portcullis_reconcile_repairs_total", self.reconcile_repairs.load(l)),
            ("portcullis_cp_disconnects_total", self.cp_disconnects.load(l)),
        ] {
            let _ = writeln!(s, "# TYPE {name} counter");
            let _ = writeln!(s, "{name} {val}");
        }
        // gauge
        let _ = writeln!(s, "# TYPE portcullis_active_sessions gauge");
        let _ = writeln!(s, "portcullis_active_sessions {}", self.active_sessions.load(l));
        s
    }
}

impl MetricsSink for Metrics {
    fn incr(&self, metric: Metric) {
        let counter = match metric {
            Metric::Grant => &self.grants,
            Metric::Revoke => &self.revokes,
            Metric::Expire => &self.expiries,
            Metric::QuotaExceeded => &self.quota_exceeded,
            Metric::NftTxnError => &self.nft_txn_errors,
            Metric::DnatRedirect => &self.dnat_redirects,
            Metric::Reconcile => &self.reconciles,
            Metric::ReconcileRepair => &self.reconcile_repairs,
            Metric::CpDisconnect => &self.cp_disconnects,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn set_gauge(&self, gauge: Gauge, value: u64) {
        match gauge {
            Gauge::ActiveSessions => self.active_sessions.store(value, Ordering::Relaxed),
        }
    }
}

/// Shared state for the `/metrics` handler.
struct MetricsState {
    metrics: Arc<Metrics>,
    mgr: Arc<SessionManager>,
}

/// Serve `GET /metrics` on `addr` until the task is aborted. The `active_sessions`
/// gauge is refreshed from the live session count at scrape time (cheap; avoids a
/// per-op gauge update on the hot paths).
pub async fn serve(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    mgr: Arc<SessionManager>,
) -> portcullis_types::Result<()> {
    use axum::routing::get;
    use axum::Router;
    use portcullis_types::Error;

    let state = Arc::new(MetricsState { metrics, mgr });
    let app = Router::new().route("/metrics", get(handler)).with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Io(format!("metrics bind {addr}: {e}")))?;
    tracing::info!(%addr, "metrics endpoint listening");
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Io(format!("metrics serve: {e}")))
}

async fn handler(
    axum::extract::State(state): axum::extract::State<Arc<MetricsState>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    state
        .metrics
        .set_gauge(Gauge::ActiveSessions, state.mgr.len() as u64);
    let body = state.metrics.render();
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_reflects_counters_and_gauge() {
        let m = Metrics::default();
        m.incr(Metric::Grant);
        m.incr(Metric::Grant);
        m.incr(Metric::Revoke);
        m.set_gauge(Gauge::ActiveSessions, 7);

        let out = m.render();
        assert!(out.contains("# TYPE portcullis_grants_total counter"));
        assert!(out.contains("portcullis_grants_total 2"), "got:\n{out}");
        assert!(out.contains("portcullis_revokes_total 1"));
        assert!(out.contains("portcullis_expiries_total 0"));
        assert!(out.contains("# TYPE portcullis_active_sessions gauge"));
        assert!(out.contains("portcullis_active_sessions 7"));
    }

    #[test]
    fn every_metric_variant_maps_to_a_counter() {
        let m = Metrics::default();
        for metric in [
            Metric::Grant,
            Metric::Revoke,
            Metric::Expire,
            Metric::QuotaExceeded,
            Metric::NftTxnError,
            Metric::DnatRedirect,
            Metric::Reconcile,
            Metric::ReconcileRepair,
            Metric::CpDisconnect,
        ] {
            m.incr(metric);
        }
        let out = m.render();
        // 9 counters at 1 + the gauge line.
        assert_eq!(out.matches(" 1\n").count(), 9, "each counter should read 1:\n{out}");
    }
}
