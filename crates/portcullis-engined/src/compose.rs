//! Task composition and process lifecycle for the daemon.
//!
//! `run` performs the startup sequence (ensure base ruleset → adopt kernel
//! state → wire the domain core), spawns the long-lived tasks, and blocks until
//! SIGTERM, then shuts down gracefully.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use portcullis_config::Config;
use portcullis_types::{
    CounterSource, Enforcer, Metric, MeteringSink, MetricsSink, RulesetWriter, UnknownKernelPolicy,
};

use crate::metrics::Metrics;
use crate::{wire, DEFAULT_PORTAL_URL, GARDEN_CONF_PATH, TLS_DIR};

/// How often the daemon-side expiry sweep runs. The kernel set-element timeout
/// is the authoritative backstop (§7.4); this loop only emits the accounting
/// `EXPIRED` record and cleans the in-RAM view, so 1 s is ample.
const EXPIRY_TICK: Duration = Duration::from_secs(1);
/// Walled-garden reconcile cadence.
const GARDEN_TICK: Duration = Duration::from_secs(30);

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    // 0. Metrics recorder (§12). Created first so it can be injected into the nft
    //    writer actor (for nft_txn_errors), the session manager, and the redirect
    //    responder before any of them start.
    let metrics = Arc::new(Metrics::default());

    // 1. nft backend + single-owner writer actor (§7.9). The only path to
    //    netfilter; every mutation is serialized through this actor.
    let backend = Box::new(portcullis_nft::NftJsonBackend::default());
    let (writer_handle, _writer_join) =
        portcullis_nft::spawn_with_metrics(backend, metrics.clone());
    let writer: Arc<dyn RulesetWriter> = Arc::new(writer_handle);

    // 1a. Idempotent bootstrap (create-if-missing, adopt-if-present, never
    //     flush other tables — §7.8). A backend failure here is fatal: we fail
    //     closed and let procd respawn rather than run without enforcement.
    writer
        .ensure_base()
        .await
        .context("ensure base nft ruleset (inet wifihub)")?;

    // 1b. Restart adoption: rebuild the in-RAM session view from the kernel
    //     `auth` set so no authorized client is dropped across a daemon upgrade.
    let adopted = writer.list_auth().await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "could not list auth set for adoption; starting empty");
        Vec::new()
    });

    // 2-4. Domain core: event channel + sink, SessionManager. The engine is the
    //    control-plane CLIENT (CGNAT: it cannot accept inbound), so no gRPC
    //    server is assembled here — the outbound channel task (step 5) dispatches
    //    inbound commands straight to `w.mgr` as the `Enforcer`.
    let w = wire(writer.clone());
    let adopted_n = w.mgr.adopt(adopted, Instant::now());
    tracing::info!(adopted = adopted_n, "restart adoption complete");
    w.mgr.set_metrics(metrics.clone());
    // ensure_base + adoption succeeded → the kernel table is present and the
    // initial view is consistent; the periodic reconcile loop refreshes these.
    w.mgr.mark_reconcile(true, true);

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // 5. Outbound control channel over mutual TLS (§13, CGNAT design doc). The
    //    engine dials the control plane and holds a long-lived bidirectional
    //    stream: commands arrive on it, events/acks are pushed back. It
    //    reconnects with backoff and sets the `cp_connected` health flag.
    match load_client_tls(&cfg) {
        Ok(Some(tls)) => {
            let chan_cfg = portcullis_control::ControlChannelConfig {
                endpoint: cfg.control_endpoint.clone(),
                tls,
                store_id: cfg.store_id.clone(),
                keepalive: Duration::from_secs(cfg.control_keepalive_secs.max(1)),
                reconnect_max: Duration::from_secs(cfg.control_reconnect_max_secs.max(1)),
            };
            let enforcer = w.mgr.clone() as Arc<dyn Enforcer>;
            let events = w.event_tx.clone();
            let mgr = w.mgr.clone();
            let m = metrics.clone();
            tasks.push(tokio::spawn(async move {
                tracing::info!(endpoint = %chan_cfg.endpoint, "dialing control plane (mTLS bidi stream)");
                portcullis_control::run_control_channel(chan_cfg, enforcer, events, move |up| {
                    mgr.set_cp_connected(up);
                    if !up {
                        m.incr(Metric::CpDisconnect);
                    }
                })
                .await;
            }));
        }
        Ok(None) => {
            // No cert material yet (pre-provisioning). Do NOT dial without a
            // client identity / pinned CP CA — fail closed: existing sessions
            // keep being enforced, but no new grants can arrive (§11, §13).
            tracing::warn!(
                dir = TLS_DIR,
                "mTLS material absent; control channel disabled (no new grants)"
            );
        }
        Err(e) => return Err(e).context("load mTLS client material"),
    }

    // 6. :8080 redirect responder (§7.2). Reads the per-store HMAC key.
    let hmac_key = std::fs::read(&cfg.hmac_key_file).unwrap_or_else(|e| {
        tracing::warn!(path = %cfg.hmac_key_file, error = %e, "HMAC key unreadable");
        Vec::new()
    });
    let portal_url =
        std::env::var("PORTCULLIS_PORTAL_URL").unwrap_or_else(|_| DEFAULT_PORTAL_URL.to_string());
    match portcullis_redirect::RedirectConfig::new(
        portal_url,
        cfg.store_id.clone(),
        hmac_key,
        cfg.responder_port,
    ) {
        Some(rcfg) => {
            let resolver = portcullis_redirect::IpNeighResolver::new();
            let rmetrics = metrics.clone();
            tasks.push(tokio::spawn(async move {
                tracing::info!(port = rcfg.listen_port, "redirect responder listening");
                if let Err(e) = portcullis_redirect::serve(rcfg, resolver, rmetrics).await {
                    tracing::error!(error = %e, "redirect responder exited");
                }
            }));
        }
        None => tracing::error!("redirect config invalid (empty portal/store/key); responder disabled"),
    }

    // 7. Accounting metering loop (§7.6): conntrack counters -> SessionManager
    //    (which computes deltas, emits INTERIM, enforces quota).
    {
        let source: Arc<dyn CounterSource> = Arc::new(portcullis_accounting::ConntrackSource::new(
            portcullis_redirect::IpNeighResolver::new(),
        ));
        let metering_sink: Arc<dyn MeteringSink> = w.mgr.clone();
        let interval = Duration::from_secs(cfg.accounting_interval.max(1));
        tasks.push(tokio::spawn(async move {
            portcullis_accounting::run_metering_loop(
                source,
                metering_sink,
                interval,
                std::future::pending::<()>(),
            )
            .await;
        }));
    }

    // 8. Walled-garden reconciler (§7.3): keep dnsmasq's nftset config in sync
    //    with the configured FQDN list.
    {
        let garden = portcullis_garden::GardenConfig::with_fqdns(cfg.garden_fqdn.clone());
        tasks.push(tokio::spawn(async move {
            portcullis_garden::run_garden_loop(GARDEN_CONF_PATH, garden, GARDEN_TICK).await;
        }));
    }

    // 9. Daemon-side expiry sweep (dual-path expiry, §7.4).
    {
        let mgr = w.mgr.clone();
        tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EXPIRY_TICK);
            loop {
                ticker.tick().await;
                let expired = mgr.tick_expiry(Instant::now()).await;
                if expired > 0 {
                    tracing::debug!(expired, "expiry sweep removed sessions");
                }
            }
        }));
    }

    // 9b. Drift reconciliation against the kernel `auth` set (§7.8). The
    //     `cp_connected` flag + disconnect metric are driven by the control
    //     channel task (step 5), not polled here.
    {
        let mgr = w.mgr.clone();
        let writer = writer.clone();
        let reconcile_interval = Duration::from_secs(cfg.reconcile_interval.max(5));
        tasks.push(tokio::spawn(async move {
            let mut recon = tokio::time::interval(reconcile_interval);
            recon.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                recon.tick().await;
                match writer.list_auth().await {
                    Ok(kernel) => {
                        let report = mgr
                            .reconcile_at(kernel, UnknownKernelPolicy::default(), Instant::now())
                            .await;
                        mgr.mark_reconcile(report.ok(), true);
                        if report.repaired() || !report.ok() {
                            tracing::info!(
                                readded = report.readded,
                                adopted = report.adopted,
                                deleted = report.deleted,
                                errors = report.errors,
                                "reconcile pass repaired drift"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "reconcile: list_auth failed");
                        mgr.mark_reconcile(false, false);
                    }
                }
            }
        }));
    }

    // 9c. Prometheus /metrics endpoint (§12), bound on loopback (no overlay to
    //     scrape over now). Disabled when metrics_port == 0.
    if cfg.metrics_port != 0 {
        let addr = metrics_listen_addr(&cfg);
        let m = metrics.clone();
        let mgr = w.mgr.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = crate::metrics::serve(addr, m, mgr).await {
                tracing::error!(error = %e, "metrics endpoint exited");
            }
        }));
    } else {
        tracing::info!("metrics endpoint disabled (metrics_port = 0)");
    }

    // 10. Block until SIGTERM (procd stop) or Ctrl-C, then shut down.
    wait_for_shutdown().await;
    tracing::info!("shutdown signal received; stopping tasks");
    for t in &tasks {
        t.abort();
    }
    // The kernel keeps the ruleset and the auth set with their timeouts, so a
    // clean daemon stop never drops authorized clients (§7.8).
    Ok(())
}

/// Metrics endpoint listen address, bound on **loopback**: without the WireGuard
/// overlay there is no private network to expose it on, and the endpoint is
/// unauthenticated (§12). Local scrape only.
fn metrics_listen_addr(cfg: &Config) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], cfg.metrics_port))
}

/// Load the engine's **client** identity + the pinned control-plane **server**
/// CA from [`TLS_DIR`] and build the mutual-TLS client config used to dial the
/// control plane. Returns `Ok(None)` if the material isn't present yet (the
/// daemon then runs without the control channel rather than failing open).
fn load_client_tls(cfg: &Config) -> anyhow::Result<Option<tonic::transport::ClientTlsConfig>> {
    let dir = std::path::Path::new(TLS_DIR);
    let cert_p = dir.join("client.crt");
    let key_p = dir.join("client.key");
    let ca_p = std::path::PathBuf::from(&cfg.cp_server_ca_file);
    if !cert_p.exists() || !key_p.exists() || !ca_p.exists() {
        return Ok(None);
    }
    let cert = std::fs::read(&cert_p).context("read client.crt")?;
    let key = std::fs::read(&key_p).context("read client.key")?;
    let ca = std::fs::read(&ca_p)
        .with_context(|| format!("read CP server CA {}", ca_p.display()))?;
    let tls = portcullis_control::client_tls_config(&cert, &key, &ca, &cfg.cp_server_name)
        .map_err(|e| anyhow::anyhow!("build mTLS client config: {e}"))?;
    Ok(Some(tls))
}

/// Wait for SIGTERM (procd stop) or Ctrl-C.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cannot install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
