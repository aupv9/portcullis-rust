//! Task composition and process lifecycle for the daemon.
//!
//! `run` performs the startup sequence (ensure base ruleset → adopt kernel
//! state → wire the domain core), spawns the long-lived tasks, and blocks until
//! SIGTERM, then shuts down gracefully.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use portcullis_config::Config;
use portcullis_nft::FirewallBackend;
use portcullis_types::{
    CounterSource, Enforcer, Metric, MeteringSink, MetricsSink, Provisioner, RulesetWriter,
    UnknownKernelPolicy,
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

    // 1. Firewall backend + single-owner writer actor (§7.9). The only path to
    //    netfilter; every mutation is serialized through this actor. The backend
    //    is config-selected (`firewall_backend`, default "auto"): stock RutOS has
    //    no nftables NAT chain support (CONFIG_NFT_NAT unset), so the auto-probe
    //    fails there and picks ipset + iptables/ip6tables (TDD §17 option B).
    //    Both implement the same FirewallBackend seam.
    let backend = detect_backend(&cfg);
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

    // 4b. Hotspot provisioning subsystem (P0.5) — spawned as an ISOLATED task,
    //     completely separate from enforcement (its own actor + tmpfs state +
    //     shell-out runner). It renders a FIXED allowlist of UCI sections and
    //     holds each apply under a LOCAL commit-confirm watchdog. Fail-OPEN
    //     (rollback), the ONE exception to the engine's fail-closed rule: it
    //     manages router config, not enforcement, and kernel-as-truth means a
    //     provision fault never drops an authorized client. Spawned BEFORE the
    //     control channel so its handle + status stream can be wired in.
    let (provisioner, provision_status_rx, provision_join) =
        portcullis_provision::run_provision_subsystem(
            portcullis_provision::ProcessRunner,
            portcullis_provision::DEFAULT_STATE_DIR,
            // The redirect-responder port opened by the hotspot_portal firewall
            // rule so pre-auth guests can reach the captive redirect. LOCAL engine
            // setting, not on the wire.
            cfg.responder_port,
        );
    let provisioner: Arc<dyn Provisioner> = Arc::new(provisioner);
    tasks.push(provision_join);
    // The control channel consumes the status stream (fans it into outbound
    // EngineFrames). Kept in an Option so it is moved into the channel task only
    // when TLS is present; otherwise the subsystem still runs (watchdog rollback
    // works without the CP) and statuses simply buffer in the mpsc.
    let mut provision_status_rx = Some(provision_status_rx);

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
                provisioner: provisioner.clone(),
            };
            let enforcer = w.mgr.clone() as Arc<dyn Enforcer>;
            let events = w.event_tx.clone();
            let mgr = w.mgr.clone();
            let m = metrics.clone();
            // Move the provision status stream into the channel task so it fans
            // ProvisionStatus (incl. unsolicited watchdog ROLLED_BACK) up to the CP.
            let status_rx = provision_status_rx
                .take()
                .expect("provision status receiver taken once");
            tasks.push(tokio::spawn(async move {
                tracing::info!(endpoint = %chan_cfg.endpoint, "dialing control plane (mTLS bidi stream)");
                portcullis_control::run_control_channel(chan_cfg, enforcer, events, status_rx, move |up| {
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

/// Metrics endpoint listen address, bound on **loopback**: the router has no
/// private management network to expose it on, and the endpoint is
/// unauthenticated (§12). Local scrape only.
fn metrics_listen_addr(cfg: &Config) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], cfg.metrics_port))
}

/// Select the firewall backend per `cfg.firewall_backend` (TDD §17 option A vs
/// B): `"nft"` / `"ipset"` force one; `"auto"` (the default) probes the running
/// kernel for nft NAT chain support and falls back to the ipset+iptables backend
/// on stock RutOS (no CONFIG_NFT_NAT). The ipset backend's tcp:80 REDIRECT is
/// wired to `cfg.responder_port` so it always targets the live responder.
fn detect_backend(cfg: &Config) -> Box<dyn FirewallBackend> {
    detect_backend_with(cfg, "nft")
}

/// [`detect_backend`] with an injectable `nft` program path for the probe (unit
/// tests stand in a fake script, cf. the shaper's `fake_tc` pattern).
fn detect_backend_with(cfg: &Config, nft_bin: &str) -> Box<dyn FirewallBackend> {
    let use_nft = match cfg.firewall_backend.as_str() {
        "nft" => true,
        "ipset" => false,
        // "auto" — the only other value config validation admits.
        _ => {
            let supported = probe_nft_nat(nft_bin);
            tracing::info!(nft_nat_supported = supported, "firewall_backend=auto kernel probe");
            supported
        }
    };
    // P0: scope the FORWARD/PREROUTING gate to the hotspot interface so only the
    // public SSID is gated (br-lan untouched). Empty `hotspot_iface` → the
    // backend installs no gate at all (fail-OPEN; see the backend docs).
    if use_nft {
        tracing::info!(
            backend = "nft",
            hotspot_iface = %cfg.hotspot_iface,
            "firewall backend selected"
        );
        Box::new(
            portcullis_nft::NftJsonBackend::default().with_hotspot_iface(cfg.hotspot_iface.clone()),
        )
    } else {
        tracing::info!(
            backend = "ipset",
            hotspot_iface = %cfg.hotspot_iface,
            "firewall backend selected"
        );
        Box::new(
            portcullis_nft::IpsetIptablesBackend::default()
                .with_redirect_port(cfg.responder_port)
                .with_hotspot_iface(cfg.hotspot_iface.clone()),
        )
    }
}

/// Probe whether the running kernel supports nftables NAT chains: add a scratch
/// table, add a `type nat hook prerouting` chain into it (the exact step that
/// fails ENOENT without CONFIG_NFT_NAT), then delete the table. Any failure —
/// including a missing `nft` binary — means "no", never an error: the caller
/// falls back to the ipset backend.
fn probe_nft_nat(program: &str) -> bool {
    let run = |args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    if !run(&["add", "table", "inet", "wifihub_probe"]) {
        return false;
    }
    let nat_ok = run(&[
        "add", "chain", "inet", "wifihub_probe", "probe", "{", "type", "nat", "hook",
        "prerouting", "priority", "-50", ";", "}",
    ]);
    // Best-effort cleanup either way: the scratch table must not linger.
    let _ = run(&["delete", "table", "inet", "wifihub_probe"]);
    nat_ok
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake `nft`: logs each invocation's args and exits 0, except (when
    /// `fail_on_chain`) any command mentioning `chain` — mimicking a kernel
    /// without CONFIG_NFT_NAT, where only the NAT chain add fails. Same
    /// temp-dir script pattern as the shaper tests' `fake_tc`.
    fn fake_nft(tag: &str, fail_on_chain: bool) -> (String, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("portcullis-nft-probe-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("nft.log");
        let script = dir.join("nft");
        let fail_branch = if fail_on_chain {
            "case \"$*\" in *chain*) exit 1;; esac\n"
        } else {
            ""
        };
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho \"$@\" >> {}\n{fail_branch}exit 0\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (script.display().to_string(), log)
    }

    fn lines(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn probe_nft_nat_passes_and_cleans_up_when_kernel_supports_nat() {
        let (nft, log) = fake_nft("nat-ok", false);
        assert!(probe_nft_nat(&nft));
        let cmds = lines(&log);
        assert_eq!(cmds[0], "add table inet wifihub_probe");
        assert_eq!(
            cmds[1],
            "add chain inet wifihub_probe probe { type nat hook prerouting priority -50 ; }"
        );
        assert_eq!(cmds[2], "delete table inet wifihub_probe");
    }

    #[test]
    fn probe_nft_nat_fails_without_nat_chain_support_but_still_cleans_up() {
        let (nft, log) = fake_nft("no-nat", true);
        assert!(!probe_nft_nat(&nft));
        // The scratch table is deleted even after the failed chain add.
        assert!(lines(&log)
            .iter()
            .any(|c| c == "delete table inet wifihub_probe"));
    }

    #[test]
    fn probe_nft_nat_fails_closed_when_nft_binary_is_missing() {
        assert!(!probe_nft_nat("/nonexistent/portcullis-test-nft"));
    }

    /// `detect_backend_with` selects the right adapter. Backends are opaque
    /// (`Box<dyn FirewallBackend>`), so we distinguish them by their error
    /// variant on a doomed `ensure_base`: the ipset backend maps a spawn/exit
    /// failure to `Error::Backend`, the nft backend to `Error::NftTransaction`.
    #[tokio::test]
    async fn detect_backend_honours_forced_choice_and_auto_probe() {
        use portcullis_types::Error;

        let cfg = |backend: &str| Config {
            store_id: "S".into(),
            firewall_backend: backend.to_string(),
            ..Config::default()
        };
        // Point both backends at a binary that always fails, so ensure_base
        // errors and reveals which adapter was chosen — without a kernel.
        async fn is_ipset(b: Box<dyn FirewallBackend>) -> bool {
            matches!(b.ensure_base().await, Err(Error::Backend(_)))
        }
        async fn is_nft(b: Box<dyn FirewallBackend>) -> bool {
            matches!(b.ensure_base().await, Err(Error::NftTransaction(_)))
        }

        // Forced choices never run the probe (the nft binary is absent here).
        let missing = "/nonexistent/portcullis-test-nft";
        assert!(is_nft(detect_backend_with(&cfg("nft"), missing)).await);
        assert!(is_ipset(detect_backend_with(&cfg("ipset"), missing)).await);

        // auto: the probe outcome decides.
        let (nat_ok, _log) = fake_nft("auto-yes", false);
        assert!(is_nft(detect_backend_with(&cfg("auto"), &nat_ok)).await);
        let (no_nat, _log) = fake_nft("auto-no", true);
        assert!(is_ipset(detect_backend_with(&cfg("auto"), &no_nat)).await);
        // ...and a box with no nft at all falls back to ipset (RUTM11 today).
        assert!(is_ipset(detect_backend_with(&cfg("auto"), missing)).await);
    }
}
