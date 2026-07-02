//! Task composition and process lifecycle for the daemon.
//!
//! `run` performs the startup sequence (ensure base ruleset → adopt kernel
//! state → wire the domain core), spawns the long-lived tasks, and blocks until
//! SIGTERM, then shuts down gracefully.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use portcullis_config::Config;
use portcullis_types::{CounterSource, Enforcer, MeteringSink, RulesetWriter};

use crate::{wire, DEFAULT_PORTAL_URL, GARDEN_CONF_PATH};

/// How often the daemon-side expiry sweep runs. The kernel set-element timeout
/// is the authoritative backstop (§7.4); this loop only emits the accounting
/// `EXPIRED` record and cleans the in-RAM view, so 1 s is ample.
const EXPIRY_TICK: Duration = Duration::from_secs(1);
/// Walled-garden reconcile cadence.
const GARDEN_TICK: Duration = Duration::from_secs(30);

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
    let w = wire(writer.clone());
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
            tasks.push(tokio::spawn(async move {
                tracing::info!(port = rcfg.listen_port, "redirect responder listening");
                if let Err(e) = portcullis_redirect::serve(rcfg, resolver).await {
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
