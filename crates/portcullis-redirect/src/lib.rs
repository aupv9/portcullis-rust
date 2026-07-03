//! `portcullis-redirect` — the `:8080` HTTP 302 redirect responder.
//!
//! This is the **primary inbound attack surface** (TDD §7.2, §13): reachable by
//! any unauthenticated client on the SSID. Its entire job is to look up the
//! client's MAC from the kernel neighbour table, sign `<mac>|<store>|<ts>` with
//! the per-store HMAC key, and answer **one** thing — a `302` to the portal
//! splash URL. It serves no static files, no other routes, no info leak.
//!
//! Security posture (cf. openNDS CVE-2023-38314, a NULL-deref DoS from a missing
//! query param):
//! * The core decision is a **pure async function** [`respond`] taking an
//!   already-extracted source IP and a clock value, so it is fully unit-testable
//!   without a socket. Critically, we never read the request body, query, or
//!   headers for the redirect decision — the only client input that matters is
//!   the connection's source IP (kernel-supplied), so there is no query-param
//!   parsing to get wrong.
//! * Every fallible step returns a safe `4xx`/`5xx` [`RedirectOutcome`] — never a
//!   panic, `unwrap`, or out-of-bounds index on attacker-controlled input.
//! * Per-source rate limiting blunts flood/DoS before the `ip neigh` fork/exec.
//! * The axum wrapper bounds request body size.
//!
//! Module map:
//! * [`sign`] — HMAC-SHA256 sign/verify (constant-time).
//! * [`location`] — the `Location:` URL builder with query-encoding.
//! * [`resolver`] — [`IpNeighResolver`] + [`MockNeighResolver`].
//! * [`ratelimit`] — per-source token bucket.

#![forbid(unsafe_code)]

pub mod location;
pub mod ratelimit;
pub mod resolver;
pub mod sign;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use portcullis_types::{MacAddr, NeighResolver};

pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use resolver::{IpNeighResolver, MockNeighResolver};

/// Per-store configuration for the responder.
///
/// `hmac_key` is secret: it is **never** logged, and the hand-written `Debug`
/// impl redacts it (security-auditor: "flag the key in any Debug/tracing
/// output").
#[derive(Clone)]
pub struct RedirectConfig {
    /// e.g. `https://portal.wifihub.vn` (no trailing `/splash`).
    pub portal_base_url: String,
    /// This router's store identifier, included in the signed tuple.
    pub store_id: String,
    /// Per-store HMAC key, provisioned at first boot. Secret.
    pub hmac_key: Vec<u8>,
    /// TCP port to listen on (the nft `redirect to :<port>` target; 8080).
    pub listen_port: u16,
}

impl RedirectConfig {
    /// Construct a config, validating the non-secret fields. Returns `None` on
    /// an obviously-unusable config (empty portal base, store id, or key); the
    /// caller (composition root) decides how to fail — we never fail *open*.
    pub fn new(
        portal_base_url: impl Into<String>,
        store_id: impl Into<String>,
        hmac_key: Vec<u8>,
        listen_port: u16,
    ) -> Option<Self> {
        let portal_base_url = portal_base_url.into();
        let store_id = store_id.into();
        if portal_base_url.is_empty() || store_id.is_empty() || hmac_key.is_empty() {
            return None;
        }
        Some(Self { portal_base_url, store_id, hmac_key, listen_port })
    }
}

/// Custom `Debug` that redacts the key — defence against accidental leaks.
impl std::fmt::Debug for RedirectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedirectConfig")
            .field("portal_base_url", &self.portal_base_url)
            .field("store_id", &self.store_id)
            .field("hmac_key", &format_args!("<redacted {} bytes>", self.hmac_key.len()))
            .field("listen_port", &self.listen_port)
            .finish()
    }
}

/// The result of handling one request — either a 302 with a Location, or a safe
/// error status. Deliberately small and total: there is no panic path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RedirectOutcome {
    /// Issue `302 Found` with this `Location` header value.
    Redirect { location: String },
    /// Answer with a status code and a short, fixed reason. No client data is
    /// echoed back (no reflection / info leak).
    Error { status: u16, reason: &'static str },
}

impl RedirectOutcome {
    /// The HTTP status this outcome maps to.
    pub fn status(&self) -> u16 {
        match self {
            RedirectOutcome::Redirect { .. } => 302,
            RedirectOutcome::Error { status, .. } => *status,
        }
    }
}

/// The core, pure decision function (TDD §7.2). Given a resolver, config, the
/// connection's source IP, and the current unix timestamp, produce a
/// [`RedirectOutcome`]. No I/O beyond the resolver; no panics on any input.
///
/// Flow:
/// 1. Resolve `src_ip` -> MAC via the neighbour table.
/// 2. Unknown IP (no neighbour entry) -> graceful `404`; the client retries.
/// 3. Resolver error -> `503` (fail closed: no redirect, no leak of why).
/// 4. Known MAC -> sign and build the portal 302.
pub async fn respond<R: NeighResolver + ?Sized>(
    resolver: &R,
    cfg: &RedirectConfig,
    src_ip: IpAddr,
    now_ts: i64,
) -> RedirectOutcome {
    match resolver.resolve(src_ip).await {
        Ok(Some(mac)) => redirect_for(cfg, &mac, now_ts),
        Ok(None) => RedirectOutcome::Error { status: 404, reason: "unknown client" },
        Err(_) => RedirectOutcome::Error { status: 503, reason: "neighbour lookup unavailable" },
    }
}

/// Build the signed 302 for a resolved MAC.
fn redirect_for(cfg: &RedirectConfig, mac: &MacAddr, now_ts: i64) -> RedirectOutcome {
    let sig = sign::sign(&cfg.hmac_key, mac, &cfg.store_id, now_ts);
    let location = location::build_location(&cfg.portal_base_url, mac, &cfg.store_id, now_ts, &sig);
    RedirectOutcome::Redirect { location }
}

// ---------------------------------------------------------------------------
// axum 0.7 wrapper
// ---------------------------------------------------------------------------

/// Maximum request body bytes we will accept. We don't *read* the body at all,
/// but rejecting larger bodies blunts a memory-exhaustion vector.
const MAX_BODY_BYTES: usize = 8 * 1024;

/// Shared, cheaply-cloneable state for the axum handler.
struct AppState<R: NeighResolver + 'static> {
    cfg: RedirectConfig,
    resolver: R,
    limiter: RateLimiter,
    /// Daemon-wide metrics registry (`GetMetrics`): rate-limited requests also
    /// bump `redirect_rejections` there. `None` = standalone (tests, `serve`).
    metrics: Option<Arc<portcullis_types::MetricsRegistry>>,
}

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;

/// Convert a [`RedirectOutcome`] into an axum [`Response`]. Redirects set the
/// `Location` header; errors return a fixed status with an empty body.
fn into_response(outcome: RedirectOutcome) -> Response {
    match outcome {
        RedirectOutcome::Redirect { location } => {
            // The location was percent-encoded so this can't fail in practice;
            // staying total, an invalid header value degrades to 500, not panic.
            match header::HeaderValue::from_str(&location) {
                Ok(v) => {
                    let mut resp = StatusCode::FOUND.into_response();
                    resp.headers_mut().insert(header::LOCATION, v);
                    resp
                }
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        RedirectOutcome::Error { status, .. } => {
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST).into_response()
        }
    }
}

/// The single catch-all handler. Method, path, query, headers, and body are
/// ignored for the decision — the only input is the source IP from
/// `ConnectInfo`. This is the deliberate counter to query-param-deref bugs:
/// there is no query parsing to get wrong.
async fn handle<R: NeighResolver + 'static>(
    State(state): State<Arc<AppState<R>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let src_ip = peer.ip();

    // Rate-limit per source IP before doing any work (esp. the neigh fork).
    if !state.limiter.check(src_ip) {
        if let Some(m) = &state.metrics {
            m.inc_redirect_rejections();
        }
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let outcome = respond(&state.resolver, &state.cfg, src_ip, unix_now()).await;
    into_response(outcome)
}

/// Build the axum [`Router`] without binding a socket (used by `serve` and
/// constructible in tests).
fn build_router<R: NeighResolver + 'static>(state: Arc<AppState<R>>) -> Router {
    Router::new()
        .route("/", any(handle::<R>))
        .fallback(any(handle::<R>))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Bind `0.0.0.0:<listen_port>` and serve until the process exits, with the
/// built-in [`RateLimitConfig::default`] limits and no shared metrics.
pub async fn serve<R: NeighResolver + 'static>(
    cfg: RedirectConfig,
    resolver: R,
) -> portcullis_types::Result<()> {
    serve_with_limits(cfg, resolver, RateLimitConfig::default(), None).await
}

/// Bind `0.0.0.0:<listen_port>` and serve until the process exits.
///
/// `rl` is the per-source-IP token-bucket configuration (config-file backed:
/// `redirect_rl_*`, RequiresRestart §9). `metrics`, when `Some`, receives a
/// `redirect_rejections` bump for every rate-limited request (the composition
/// root passes the daemon-wide registry). The `ConnectInfo` extractor requires
/// `into_make_service_with_connect_info::<SocketAddr>()`.
pub async fn serve_with_limits<R: NeighResolver + 'static>(
    cfg: RedirectConfig,
    resolver: R,
    rl: RateLimitConfig,
    metrics: Option<Arc<portcullis_types::MetricsRegistry>>,
) -> portcullis_types::Result<()> {
    use portcullis_types::Error;

    let port = cfg.listen_port;
    let state = Arc::new(AppState {
        cfg,
        resolver,
        limiter: RateLimiter::new(rl),
        metrics,
    });
    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Io(format!("bind {addr}: {e}")))?;

    tracing::info!(%addr, "redirect responder listening");

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| Error::Io(format!("serve: {e}")))?;

    Ok(())
}

/// Current unix time in seconds, total and clamped: a clock before the epoch
/// yields `0` rather than panicking.
fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RedirectConfig {
        RedirectConfig::new("https://portal.wifihub.vn", "store-42", b"secret-key".to_vec(), 8080)
            .expect("valid config")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn respond_redirects_known_client_with_valid_signature() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let resolver = MockNeighResolver::new().with(ip("192.168.1.10"), mac);
        let cfg = cfg();
        let ts = 1_700_000_000;

        let outcome = respond(&resolver, &cfg, ip("192.168.1.10"), ts).await;

        match outcome {
            RedirectOutcome::Redirect { location } => {
                assert!(location.starts_with("https://portal.wifihub.vn/splash?"));
                assert!(location.contains("store=store-42"));
                assert!(location.contains("ts=1700000000"));
                // The embedded signature must verify against the same key/tuple.
                let sig = location.rsplit("sig=").next().expect("sig param present");
                assert!(sign::verify(&cfg.hmac_key, &mac, &cfg.store_id, ts, sig));
                // A tampered ts must NOT verify with that sig.
                assert!(!sign::verify(&cfg.hmac_key, &mac, &cfg.store_id, ts + 1, sig));
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn respond_unknown_ip_is_graceful_404_not_panic() {
        let resolver = MockNeighResolver::new(); // empty table
        let outcome = respond(&resolver, &cfg(), ip("10.9.9.9"), 1).await;
        assert_eq!(outcome, RedirectOutcome::Error { status: 404, reason: "unknown client" });
        assert_eq!(outcome.status(), 404);
    }

    #[tokio::test]
    async fn respond_resolver_error_fails_closed_503() {
        // A resolver that always errors must yield 503 — never a redirect, never
        // a panic (fail closed, no fail-open).
        struct ErrResolver;
        #[async_trait::async_trait]
        impl NeighResolver for ErrResolver {
            async fn resolve(&self, ip: IpAddr) -> portcullis_types::Result<Option<MacAddr>> {
                Err(portcullis_types::Error::NeighLookup(ip, "boom".into()))
            }
        }
        let outcome = respond(&ErrResolver, &cfg(), ip("10.0.0.1"), 1).await;
        assert_eq!(outcome.status(), 503);
        assert!(matches!(outcome, RedirectOutcome::Error { .. }));
    }

    #[tokio::test]
    async fn respond_is_total_over_adversarial_inputs() {
        // Hammer respond with assorted IPs, store ids, keys, and timestamps —
        // including empty/huge store ids and extreme ts — asserting it always
        // returns (never panics). This is the unit-level fuzz of the privileged
        // decision path (the socket layer adds no client-parsed input).
        let mac: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        let weird_stores = [
            String::new(),
            "a".repeat(4096),
            "store with spaces & = # ? \n \r \t".to_string(),
            "💥🔥".to_string(),
        ];
        let ips = [
            ip("0.0.0.0"),
            ip("255.255.255.255"),
            ip("::"),
            ip("fe80::1"),
            ip("127.0.0.1"),
        ];
        let timestamps = [i64::MIN, -1, 0, 1, i64::MAX];

        for store in &weird_stores {
            // Build directly (some store ids are empty, which `new` rejects) so
            // we still exercise the signer/builder with the hostile value.
            let cfg = RedirectConfig {
                portal_base_url: "https://p".into(),
                store_id: store.clone(),
                hmac_key: b"k".to_vec(),
                listen_port: 8080,
            };
            let resolver = MockNeighResolver::new().with(ips[0], mac);
            for &client_ip in &ips {
                for &ts in &timestamps {
                    let out = respond(&resolver, &cfg, client_ip, ts).await;
                    assert!(matches!(out.status(), 302 | 404 | 503));
                }
            }
        }
    }

    #[test]
    fn config_rejects_empty_fields_and_never_fails_open() {
        assert!(RedirectConfig::new("", "s", b"k".to_vec(), 1).is_none());
        assert!(RedirectConfig::new("https://p", "", b"k".to_vec(), 1).is_none());
        assert!(RedirectConfig::new("https://p", "s", vec![], 1).is_none());
        assert!(RedirectConfig::new("https://p", "s", b"k".to_vec(), 8080).is_some());
    }

    #[test]
    fn config_debug_redacts_hmac_key() {
        let c = cfg();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("secret-key"), "key leaked in Debug: {dbg}");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn build_router_constructs_without_binding() {
        let state = Arc::new(AppState {
            cfg: cfg(),
            resolver: MockNeighResolver::new(),
            limiter: RateLimiter::new(RateLimitConfig::default()),
            metrics: None,
        });
        let _router = build_router(state);
    }

    #[tokio::test]
    async fn rate_limited_request_bumps_shared_registry() {
        let metrics = Arc::new(portcullis_types::MetricsRegistry::new());
        let state = Arc::new(AppState {
            cfg: cfg(),
            resolver: MockNeighResolver::new(),
            // One-token bucket with no refill: the second request is denied.
            limiter: RateLimiter::new(RateLimitConfig {
                capacity: 1.0,
                refill_per_sec: 0.0,
                max_keys: 10,
            }),
            metrics: Some(metrics.clone()),
        });
        let peer: SocketAddr = "10.0.0.9:40000".parse().unwrap();

        let first = handle(State(state.clone()), ConnectInfo(peer)).await;
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(metrics.snapshot().redirect_rejections, 0);

        let second = handle(State(state.clone()), ConnectInfo(peer)).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        // Both the limiter's own counter and the shared registry advanced.
        assert_eq!(state.limiter.rejections_total(), 1);
        assert_eq!(metrics.snapshot().redirect_rejections, 1);
    }
}
