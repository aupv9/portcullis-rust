//! `portcullis` daemon — the composition root (TDD §6, §7.8, §7.9).
//!
//! Wires the focused crates into one Tokio daemon and owns process lifecycle:
//! - builds the nft backend and the single-owner writer actor (the only path to
//!   netfilter, §7.9);
//! - ensures the base `inet wifihub` ruleset exists and **adopts** the kernel
//!   `auth` set on start so no authorized client is dropped across a restart
//!   (kernel-as-truth, §7.8);
//! - constructs the `SessionManager` (the `Enforcer` + `MeteringSink`) sharing
//!   one bounded event channel with the control channel;
//! - launches the background tasks: the outbound control channel (mTLS bidi
//!   stream — the engine dials the control plane, CGNAT), :8080 redirect
//!   responder, accounting metering loop, walled-garden reconciler, expiry timer;
//! - shuts down gracefully on SIGTERM (procd stop).
//!
//! All runtime state is in RAM (tmpfs); nothing is written to NAND (§5.4).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use portcullis_config::Config;
use portcullis_types::{EventSink, RulesetWriter};

mod compose;
mod metrics;
mod runtime;

/// Default portal base for the signed redirect (§7.2). Overridable via the
/// `PORTCULLIS_PORTAL_URL` env var; the UCI config (§9) doesn't carry it.
const DEFAULT_PORTAL_URL: &str = "https://portal.wifihub.vn";
/// Directory holding the mTLS material, provisioned per store at first boot (§13).
const TLS_DIR: &str = "/etc/portcullis/tls";
/// dnsmasq conf-dir file the garden reconciler owns (§7.3). tmpfs.
const GARDEN_CONF_PATH: &str = "/tmp/dnsmasq.d/portcullis-garden.conf";

// Single-threaded scheduler (embedded-perf, TDD §14): the data plane lives in
// the kernel (nftables), so this daemon is purely control/metering — a handful
// of long-lived, I/O-bound tasks (gRPC, redirect, accounting, garden, expiry)
// with tiny per-store churn. On the 2-core RUTM11 a multi-thread runtime buys
// nothing here but costs worker-thread stacks (RSS) and the multi-thread
// scheduler code (binary). The current-thread flavour also lets the workspace
// drop tokio's `rt-multi-thread` feature.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Global max level from RUST_LOG (default INFO). We deliberately avoid
    // `EnvFilter` (per-target, regex-backed) to keep ~290 KiB of regex engine
    // out of the binary — an embedded single-purpose daemon only needs one level.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.trim().parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt().with_max_level(level).init();

    let (cfg, path) = load_config().context("load configuration")?;
    tracing::info!(store = %cfg.store_id, "portcullis starting");

    compose::run(cfg, path).await
}

/// Load config from `$PORTCULLIS_CONFIG` (UCI or TOML by extension) or the
/// conventional UCI path, falling back to defaults if absent. Returns the config
/// and the resolved path (the path is threaded to the composition root so a
/// SIGHUP can reload it live — G7).
fn load_config() -> anyhow::Result<(Config, PathBuf)> {
    let path = std::env::var("PORTCULLIS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/config/portcullis"));

    if !path.exists() {
        tracing::warn!(path = %path.display(), "config file not found; using defaults");
        return Ok((Config::default(), path));
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg = if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        Config::from_toml_str(&raw)
    } else {
        Config::from_uci_str(&raw)
    }
    .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;

    cfg.validate().map_err(|e| anyhow::anyhow!("invalid config: {e}"))?;
    Ok((cfg, path))
}

/// Build the writer + session manager + control service, returning the pieces
/// the task launcher needs. Separated so the wiring (and the cycle-break) is
/// testable without binding sockets.
pub(crate) struct Wired {
    pub mgr: Arc<portcullis_session::SessionManager>,
    pub event_tx: tokio::sync::broadcast::Sender<portcullis_types::SessionEvent>,
}

/// Assemble the core domain wiring around a given nft writer (real or mock).
///
/// Order matters for the construction cycle (§ see `control::event_channel`):
/// mint the event channel + sink first, then build the `SessionManager` with the
/// sink. The control channel task later subscribes to `event_tx` and drives
/// `mgr` as the `Enforcer`.
pub(crate) fn wire(writer: Arc<dyn RulesetWriter>) -> Wired {
    let (event_tx, grpc_sink) =
        portcullis_control::service::event_channel(portcullis_control::DEFAULT_EVENT_BUFFER);
    let sink: Arc<dyn EventSink> = Arc::new(grpc_sink);
    let mgr = Arc::new(portcullis_session::SessionManager::new(writer, sink));
    Wired { mgr, event_tx }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_nft::{spawn, MockBackend};
    use portcullis_types::Enforcer;
    use std::time::Duration;

    #[tokio::test]
    async fn wire_builds_and_grant_flows_through_to_writer() {
        // Compose the domain core over a MockBackend writer actor — no kernel,
        // no sockets — and assert a grant reaches the (mock) nft writer and the
        // session shows up. This exercises the real cross-crate wiring path that
        // `compose::run` uses on the device.
        let (handle, _join) = spawn(Box::new(MockBackend::default()));
        let writer: Arc<dyn RulesetWriter> = Arc::new(handle);
        let w = wire(writer);

        // A subscriber on the shared channel must receive the GRANTED event the
        // session layer emits — proving the cycle-break actually connects the
        // session sink to the gRPC fan-out.
        let mut rx = w.event_tx.subscribe();

        let params = portcullis_types::GrantParams {
            store_id: "SITE-0042".into(),
            mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            ip: None,
            ttl: Duration::from_secs(1800),
            quota_bytes: 0,
            rate_bps: 0,
            tier: portcullis_types::Tier::Public,
            session_id: portcullis_types::SessionId("s-1".into()),
        };
        let id = w.mgr.grant(params).await.expect("grant");
        assert_eq!(id.as_str(), "s-1");
        assert_eq!(w.mgr.len(), 1);

        let ev = rx.recv().await.expect("event");
        assert_eq!(ev.kind, portcullis_types::EventKind::Granted);
        assert_eq!(ev.session_id.as_str(), "s-1");
    }
}
