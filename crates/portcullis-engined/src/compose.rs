//! Task composition and process lifecycle for the daemon.
//!
//! `run` performs the startup sequence (ensure base ruleset → adopt kernel
//! state → wire the domain core), spawns the long-lived tasks, and blocks until
//! SIGTERM, then shuts down gracefully.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use portcullis_config::Config;
use portcullis_session::SessionManager;
use portcullis_types::{CounterSource, Enforcer, EngineParams, MeteringSink, RulesetWriter};
use tokio::sync::watch;

use crate::{wire, DEFAULT_PORTAL_URL, GARDEN_CONF_PATH};

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    // 1. Firewall backend + single-owner writer actor (§7.9). The only path to
    //    netfilter; every mutation is serialized through this actor.
    //    Stock RutOS has no nftables NAT chain support (CONFIG_NFT_NAT unset), so
    //    the production backend is ipset + iptables/ip6tables (TDD §17 option B),
    //    not NftJsonBackend. Both implement the same FirewallBackend seam.
    // The tcp:80 REDIRECT must target the same port the responder listens on.
    let backend = Box::new(
        portcullis_nft::IpsetIptablesBackend::default().with_redirect_port(cfg.responder_port),
    );
    let (writer_handle, _writer_join) = portcullis_nft::spawn(backend);
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

    // 2-4. Domain core: event channel + sink, SessionManager, gRPC service.
    let w = wire(writer.clone(), &cfg);
    let adopted_n = w.mgr.adopt(adopted, Instant::now());
    tracing::info!(adopted = adopted_n, "restart adoption complete");

    // 1c. Apply the boot enforcement state. `ensure_base` already installed the
    //     gating jumps (fail-closed), so `enforcement_default = true` is an
    //     idempotent re-assert; `false` lifts the gate. The control plane later
    //     re-pushes the persisted admin choice on connect. On error we keep the
    //     fail-closed jumps from ensure_base rather than abort (§11/G5).
    if let Err(e) = w.mgr.set_enforcement_at(cfg.enforcement_default).await {
        tracing::warn!(
            error = %e,
            enforcement_default = cfg.enforcement_default,
            "could not apply boot enforcement state; staying fail-closed"
        );
    } else {
        tracing::info!(enforcement_enabled = cfg.enforcement_default, "boot enforcement state applied");
    }

    let svc = portcullis_control::EnforcementService::from_parts(
        w.mgr.clone() as Arc<dyn Enforcer>,
        w.event_tx.clone(),
    );

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // 5. gRPC control server over the WireGuard overlay (§13). Bind ONLY on the
    //    WG interface address — reachability over WG is the authorization gate
    //    (WG gives mutual auth + encryption between the two peers). If the WG
    //    interface has no address yet, fail closed: keep enforcing existing
    //    sessions but do NOT expose enforcement on any other interface (§11).
    match wg_bind_addr(&cfg) {
        Some(addr) => {
            tasks.push(tokio::spawn(async move {
                tracing::info!(%addr, "gRPC Enforcement server listening (WireGuard overlay)");
                if let Err(e) = portcullis_control::serve(addr, svc).await {
                    tracing::error!(error = %e, "gRPC server exited");
                }
            }));
        }
        None => {
            tracing::warn!(
                iface = %cfg.wg_interface,
                "WireGuard interface has no address; control plane disabled (no new grants) — fail closed"
            );
        }
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
            let rl = portcullis_redirect::RateLimitConfig {
                capacity: f64::from(cfg.redirect_rl_capacity),
                refill_per_sec: f64::from(cfg.redirect_rl_refill_per_sec),
                max_keys: cfg.redirect_rl_max_keys as usize,
            };
            tasks.push(tokio::spawn(async move {
                tracing::info!(port = rcfg.listen_port, "redirect responder listening");
                if let Err(e) = portcullis_redirect::serve_with_limits(rcfg, resolver, rl).await {
                    tracing::error!(error = %e, "redirect responder exited");
                }
            }));
        }
        None => tracing::error!("redirect config invalid (empty portal/store/key); responder disabled"),
    }

    // 7. Accounting metering loop (§7.6): conntrack counters -> SessionManager
    //    (which computes deltas, emits INTERIM, enforces quota). The cadence is
    //    runtime-adjustable (SetEngineParameters) via the params watch channel.
    {
        let source: Arc<dyn CounterSource> = Arc::new(portcullis_accounting::ConntrackSource::new(
            portcullis_redirect::IpNeighResolver::new(),
        ));
        let metering_sink: Arc<dyn MeteringSink> = w.mgr.clone();
        let rx = w.mgr.subscribe_params();
        tasks.push(tokio::spawn(async move {
            run_metering_with_params(source, metering_sink, rx).await;
        }));
    }

    // 8. Walled-garden reconciler (§7.3): keep dnsmasq's config in sync with the
    //    FQDN list. The GardenManager is control-plane-managed (SetGarden gRPC
    //    replaces the list at runtime) and guarded by dnsmasq ipset support — on
    //    a stock dnsmasq it disables itself instead of killing LAN DNS. Cadence
    //    is runtime-adjustable via the params watch channel.
    {
        let garden = portcullis_garden::GardenManager::new(
            GARDEN_CONF_PATH,
            cfg.garden_fqdn.clone(),
            Some(writer.clone()),
        );
        w.mgr.set_garden_control(garden.clone() as Arc<dyn portcullis_types::GardenControl>);
        let garden_run = garden.clone();
        let rx = w.mgr.subscribe_params();
        tasks.push(tokio::spawn(async move {
            garden_run.run_watch(rx).await;
        }));
    }

    // 9. Daemon-side expiry sweep (dual-path expiry, §7.4). Cadence is
    //    runtime-adjustable via the params watch channel.
    {
        let mgr = w.mgr.clone();
        let rx = w.mgr.subscribe_params();
        tasks.push(tokio::spawn(async move {
            run_expiry_loop(mgr, rx).await;
        }));
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

/// The daemon-side expiry sweep (dual-path expiry, §7.4). The kernel
/// set-element timeout is the authoritative backstop; this loop only emits the
/// accounting `EXPIRED` record and cleans the in-RAM view. Rebuilds its ticker
/// when the engine parameters change (`SetEngineParameters.expiry_tick_secs`).
pub(crate) async fn run_expiry_loop(
    mgr: Arc<SessionManager>,
    mut rx: watch::Receiver<EngineParams>,
) {
    // tokio's clock rather than std so the sweep follows test-util's paused
    // time; outside tests the two are the same instant.
    let sweep = |mgr: Arc<SessionManager>| async move {
        let expired = mgr.tick_expiry(tokio::time::Instant::now().into_std()).await;
        if expired > 0 {
            tracing::debug!(expired, "expiry sweep removed sessions");
        }
    };
    let mut ticker =
        tokio::time::interval(rx.borrow_and_update().expiry_tick.max(Duration::from_secs(1)));
    loop {
        tokio::select! {
            _ = ticker.tick() => sweep(mgr.clone()).await,
            res = rx.changed() => match res {
                Ok(()) => {
                    let tick = rx.borrow_and_update().expiry_tick.max(Duration::from_secs(1));
                    tracing::info!(expiry_tick_secs = tick.as_secs(), "expiry cadence updated");
                    ticker = tokio::time::interval(tick);
                }
                // Sender gone (shutdown path): a closed watch resolves
                // immediately forever — drop out of the select to a plain loop
                // on the last cadence instead of busy-spinning.
                Err(_) => break,
            },
        }
    }
    loop {
        ticker.tick().await;
        sweep(mgr.clone()).await;
    }
}

/// Drive `run_metering_loop` with a runtime-adjustable interval: each pass runs
/// the loop at the current cadence and hands it `rx.changed()` as the shutdown
/// future, so a parameter push cleanly stops the inner loop (its `biased`
/// select lets an in-flight `meter_once` — including a quota revoke — finish
/// first) and the outer loop re-arms it with the new interval. Trade-off: each
/// re-arm fires the inner loop's immediate first tick — one extra conntrack
/// snapshot per parameter push, which re-baselining makes idempotent.
pub(crate) async fn run_metering_with_params(
    source: Arc<dyn CounterSource>,
    sink: Arc<dyn MeteringSink>,
    mut rx: watch::Receiver<EngineParams>,
) {
    loop {
        let interval = rx.borrow_and_update().accounting_interval.max(Duration::from_secs(1));
        let changed = rx.changed();
        portcullis_accounting::run_metering_loop(source.clone(), sink.clone(), interval, async {
            if changed.await.is_err() {
                // Sender gone: run on the last interval forever (daemon is
                // shutting down; the task gets aborted with the rest).
                std::future::pending::<()>().await;
            }
        })
        .await;
        // Inner loop returned => the params changed; rebuild with the new value.
    }
}

/// Resolve the address to bind the gRPC control server on: the IPv4 address of
/// the configured WireGuard interface, with the control endpoint's port.
///
/// Returns `None` if the interface has no IPv4 address yet (WG down / not
/// provisioned) — the caller then fails closed and does not expose enforcement
/// on any other interface (§13). Reads the address via `ip -o -4 addr show dev
/// <iface>`, matching how the rest of the daemon shells to iproute2/nft/ipset.
fn wg_bind_addr(cfg: &Config) -> Option<std::net::SocketAddr> {
    let port = cfg
        .control_endpoint
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8443);

    let out = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", &cfg.wg_interface])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // e.g. "12: wg-hub    inet 10.88.0.7/32 scope global wg-hub\..."
    let text = String::from_utf8_lossy(&out.stdout);
    let mut toks = text.split_whitespace();
    while let Some(t) = toks.next() {
        if t == "inet" {
            let cidr = toks.next()?;
            let ip = cidr.split('/').next()?;
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                return Some(std::net::SocketAddr::from((addr, port)));
            }
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_types::{Counters, MacAddr, Result as PResult};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts snapshots served; always empty (the cadence, not the data, is
    /// under test).
    struct CountingSource(AtomicUsize);

    #[async_trait::async_trait]
    impl CounterSource for CountingSource {
        async fn snapshot(&self) -> PResult<Vec<(MacAddr, Counters)>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    struct NullSink;

    #[async_trait::async_trait]
    impl MeteringSink for NullSink {
        async fn apply_counters(&self, _snapshot: Vec<(MacAddr, Counters)>) -> PResult<()> {
            Ok(())
        }
    }

    fn params(accounting_secs: u64, expiry_secs: u64) -> EngineParams {
        EngineParams {
            accounting_interval: Duration::from_secs(accounting_secs),
            expiry_tick: Duration::from_secs(expiry_secs),
            ..EngineParams::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn metering_interval_change_takes_effect_without_restart() {
        let source = Arc::new(CountingSource(AtomicUsize::new(0)));
        let sink: Arc<dyn MeteringSink> = Arc::new(NullSink);
        let (tx, rx) = watch::channel(params(15, 1));

        let src: Arc<dyn CounterSource> = source.clone();
        let loop_task = tokio::spawn(run_metering_with_params(src, sink, rx));

        // Immediate first tick, then one per 15 s.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(source.0.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(source.0.load(Ordering::SeqCst), 2);

        // Push a 60 s cadence: the re-arm fires one immediate tick (documented
        // trade-off), then nothing until 60 s later.
        tx.send_replace(params(60, 1));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(source.0.load(Ordering::SeqCst), 3);
        tokio::time::sleep(Duration::from_secs(59)).await;
        assert_eq!(source.0.load(Ordering::SeqCst), 3, "no tick before the new 60s cadence");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(source.0.load(Ordering::SeqCst), 4);

        loop_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_tick_change_rebuilds_ticker() {
        // Real SessionManager over the mock nft backend (no kernel, no sockets).
        let (handle, _join) = portcullis_nft::spawn(Box::new(portcullis_nft::MockBackend::default()));
        let writer: Arc<dyn RulesetWriter> = Arc::new(handle);
        let w = crate::wire(writer, &Config::default());

        let (tx, rx) = watch::channel(params(15, 1));
        let loop_task = tokio::spawn(run_expiry_loop(w.mgr.clone(), rx));

        // A 5 s session is swept within ~6 s at the 1 s cadence.
        let grant = |mac: &str, sid: &str| portcullis_types::GrantParams {
            store_id: "SITE-T".into(),
            mac: mac.parse().unwrap(),
            ip: None,
            ttl: Duration::from_secs(5),
            quota_bytes: 0,
            rate_bps: 0,
            tier: portcullis_types::Tier::Public,
            session_id: portcullis_types::SessionId(sid.into()),
        };
        w.mgr.grant_at(grant("aa:bb:cc:dd:ee:01", "s-1"), tokio::time::Instant::now().into_std())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert_eq!(w.mgr.len(), 0, "1s cadence sweeps a 5s session within 6s");

        // Switch to a 30 s cadence. The rebuild fires one immediate sweep, so a
        // session granted after the switch outlives its 5 s TTL in RAM until
        // the next 30 s tick.
        tx.send_replace(params(15, 30));
        tokio::time::sleep(Duration::from_millis(10)).await;
        w.mgr.grant_at(grant("aa:bb:cc:dd:ee:02", "s-2"), tokio::time::Instant::now().into_std())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(w.mgr.len(), 1, "expired session lingers between 30s sweeps");
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(w.mgr.len(), 0, "next 30s sweep removes it");

        loop_task.abort();
    }
}
