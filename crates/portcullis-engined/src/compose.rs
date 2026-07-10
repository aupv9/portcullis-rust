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

pub async fn run(cfg: Config, config_path: std::path::PathBuf) -> anyhow::Result<()> {
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
    let (backend, garden_backend) = detect_backend(&cfg);
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

    // 4c. conntrack flow reaper (invariant #9, G1): removing a MAC from `@auth`
    //     only gates NEW connections — established flows leak through the
    //     `ct established,related accept` fast path. The reaper severs a client's
    //     flows on de-auth. Injected into the SessionManager (fast path) and
    //     driven by the reconcile sweep (step 7b). `reap_conntrack = false` (or a
    //     device without `conntrack`) → NoopReaper (pre-invariant-#9 behaviour).
    let reaper: Arc<dyn portcullis_types::FlowReaper> = if cfg.reap_conntrack {
        Arc::new(portcullis_accounting::ConntrackReaper::default())
    } else {
        Arc::new(portcullis_types::NoopReaper)
    };
    w.mgr.set_reaper(reaper.clone());

    // 4d. Bandwidth shaper (G5): per-session tc/HTB cap, scoped to a LAN egress
    //     iface via config. Off → NoopShaper (grants carry rate_bps but no cap is
    //     applied). The `shaper` capability is advertised (GetEngineInfo) only
    //     when enabled, so the CP won't push a cap the engine can't honor.
    let (shaper, shaper_caps): (Arc<dyn portcullis_types::Shaper>, Vec<String>) =
        if cfg.shape_bandwidth && !cfg.shape_iface.trim().is_empty() {
            tracing::info!(iface = %cfg.shape_iface, "bandwidth shaping enabled (tc/HTB)");
            (
                Arc::new(portcullis_accounting::TcShaper::new(cfg.shape_iface.clone())),
                vec!["shaper".to_string()],
            )
        } else {
            (Arc::new(portcullis_types::NoopShaper), Vec::new())
        };
    w.mgr.set_shaper(shaper);

    // F2: restore the enforcement scope from the last committed CP-managed
    // wireless config (persisted to tmpfs on confirm). Survives a daemon restart
    // — the auth set was already adopted above (kernel-as-truth); this re-applies
    // the gated-SSID iface set so a CP-provisioned gated SSID keeps its captive
    // gate across the restart, before the CP reconnects. `None` = no committed
    // config → keep the static seed. Best-effort (never blocks startup).
    if let Some(gated) = portcullis_provision::read_committed_gated(std::path::Path::new(
        portcullis_provision::DEFAULT_STATE_DIR,
    )) {
        match writer.set_gated_ifaces(gated.clone()).await {
            Ok(()) => tracing::info!(gated_ifaces = ?gated, "restored enforcement scope from committed wireless config"),
            Err(e) => tracing::warn!(error = %e, "boot re-scope from committed wireless config failed; using static seed"),
        }
    }

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // 4b. Hotspot provisioning subsystem (P0.5) — spawned as an ISOLATED task,
    //     completely separate from enforcement (its own actor + tmpfs state +
    //     shell-out runner). It renders a FIXED allowlist of UCI sections and
    //     holds each apply under a LOCAL commit-confirm watchdog. Fail-OPEN
    //     (rollback), the ONE exception to the engine's fail-closed rule: it
    //     manages router config, not enforcement, and kernel-as-truth means a
    //     provision fault never drops an authorized client. Spawned BEFORE the
    //     control channel so its handle + status stream can be wired in.
    let (provisioner, wireless_status_rx, provision_join) =
        portcullis_provision::run_provision_subsystem_with_policy(
            portcullis_provision::ProcessRunner,
            portcullis_provision::DEFAULT_STATE_DIR,
            // The redirect-responder port opened by the per-SSID portal firewall
            // rule so pre-auth guests can reach the captive redirect. LOCAL engine
            // setting, not on the wire.
            cfg.responder_port,
            // Layer A: radios the CP may not place owned SSIDs on (admin radio).
            // Empty by default — opt-in per deployment.
            cfg.wireless_protected_radios.clone(),
        );
    let provisioner: Arc<dyn Provisioner> = Arc::new(provisioner);
    tasks.push(provision_join);
    // The control channel consumes the WirelessStatus stream (fans it into
    // outbound EngineFrames). Kept in an Option so it is moved into the channel
    // task only when TLS is present; otherwise the subsystem still runs (watchdog
    // rollback works without the CP) and statuses simply buffer in the mpsc.
    let mut wireless_status_rx = Some(wireless_status_rx);

    // 4e. Runtime control state (F0): the CP-pushed config store + EngineControl
    //     controller. Built UNCONDITIONALLY (independent of CP connectivity) — it
    //     holds local runtime state and drives the effect loops (garden/enforcement
    //     below); the control channel (step 5) only dispatches Set*/Get* into it
    //     when the CP is connected. Seeded from the static config until the CP
    //     pushes; persisted to tmpfs so it survives a restart.
    let boot_id = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:x}-{nanos:x}", std::process::id())
    };
    let seed = portcullis_types::RuntimeConfig {
        enforcement_enabled: true,
        garden_fqdns: cfg.garden_fqdn.clone(),
        tier_policies: Vec::new(),
        engine_params: portcullis_types::EngineParameters {
            accounting_interval_secs: cfg.accounting_interval.clamp(1, 3600) as u32,
            idle_timeout_secs: cfg.idle_timeout.min(86400) as u32,
            ..portcullis_types::EngineParameters::default()
        },
    };
    let controller = Arc::new(crate::runtime::RuntimeController::new(
        crate::runtime::RUNTIME_STATE_PATH,
        env!("CARGO_PKG_VERSION"),
        boot_id,
        metrics.clone(),
        seed,
        shaper_caps,
    ));

    // 5. Outbound control channel over mutual TLS (§13, CGNAT design doc). The
    //    engine dials the control plane and holds a long-lived bidirectional
    //    stream: commands arrive on it, events/acks are pushed back. It
    //    reconnects with backoff and sets the `cp_connected` health flag.
    match load_client_tls(&cfg) {
        Ok(Some(tls)) => {
            // G3/G4: the control channel dispatches Set*/Get* into the F0
            // controller and resolves tier defaults on the grant path.
            let engine_control: Arc<dyn portcullis_types::EngineControl> = controller.clone();
            let chan_cfg = portcullis_control::ControlChannelConfig {
                endpoint: cfg.control_endpoint.clone(),
                tls,
                store_id: cfg.store_id.clone(),
                keepalive: Duration::from_secs(cfg.control_keepalive_secs.max(1)),
                reconnect_max: Duration::from_secs(cfg.control_reconnect_max_secs.max(1)),
                provisioner: provisioner.clone(),
                // P-W1: lets the channel re-scope enforcement to the committed
                // wireless config's gated-SSID ifaces (never flushes the auth set).
                writer: writer.clone(),
                // G3/G4: config-push + introspection dispatch target.
                engine_control,
            };
            let enforcer = w.mgr.clone() as Arc<dyn Enforcer>;
            let events = w.event_tx.clone();
            let mgr = w.mgr.clone();
            let m = metrics.clone();
            // Move the WirelessStatus stream into the channel task so it fans
            // status (incl. unsolicited watchdog ROLLED_BACK) up to the CP.
            let wireless_rx = wireless_status_rx
                .take()
                .expect("wireless status receiver taken once");
            tasks.push(tokio::spawn(async move {
                tracing::info!(endpoint = %chan_cfg.endpoint, "dialing control plane (mTLS bidi stream)");
                portcullis_control::run_control_channel(chan_cfg, enforcer, events, wireless_rx, move |up| {
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
    //    (which computes deltas, emits INTERIM, enforces quota). The poll cadence
    //    comes from the runtime controller's engine params and RE-ARMS on change
    //    (G3a/G7): a CP SetEngineParameters or a SIGHUP reload retunes the interval
    //    live by cancelling the current loop and restarting it with the new value.
    {
        let source: Arc<dyn CounterSource> = Arc::new(portcullis_accounting::ConntrackSource::new(
            portcullis_redirect::IpNeighResolver::new(),
        ));
        let metering_sink: Arc<dyn MeteringSink> = w.mgr.clone();
        let mut params_rx = controller.watch_params();
        tasks.push(tokio::spawn(async move {
            loop {
                let interval = Duration::from_secs(
                    u64::from(params_rx.borrow_and_update().accounting_interval_secs).max(1),
                );
                // Run until the interval changes, then loop to re-arm. Cancelling
                // the metering loop mid-wait is safe — it's a stateless ticker;
                // the session layer re-baselines from the next snapshot (§7.6).
                tokio::select! {
                    _ = portcullis_accounting::run_metering_loop(
                        source.clone(),
                        metering_sink.clone(),
                        interval,
                        std::future::pending::<()>(),
                    ) => {}
                    changed = params_rx.changed() => {
                        if changed.is_err() { break; } // controller gone -> stop
                    }
                }
            }
        }));
    }

    // 7b. conntrack reconcile sweep (invariant #9, G1): periodically reap flows
    //     of any neighbour whose MAC is no longer in `@auth`. Backstops the
    //     de-auth fast path (IPs the session never recorded — dual-stack, DHCP
    //     churn) and does the COLD-START reap (the first tick fires immediately,
    //     severing flows left over from before this daemon adopted kernel state).
    //     Only LAN neighbours are candidates, so the router's own IPs and the
    //     outbound control-plane flow are never reaped. Skipped when reaping off.
    if cfg.reap_conntrack {
        let writer = writer.clone();
        let resolver = Arc::new(portcullis_redirect::IpNeighResolver::new());
        let reaper = reaper.clone();
        let interval = Duration::from_secs(cfg.reconcile_interval.max(5));
        tasks.push(tokio::spawn(async move {
            portcullis_accounting::run_reap_loop(
                writer,
                resolver,
                reaper,
                interval,
                std::future::pending::<()>(),
            )
            .await;
        }));
    }

    // 8. Walled-garden reconciler (§7.3): keep dnsmasq's garden config in sync,
    //    using the directive family (`nftset=` vs `ipset=`) that matches the
    //    backend (G2). The FQDN list comes from the runtime controller (G3b) so a
    //    CP `SetGarden` takes effect live; it also reconciles every GARDEN_TICK to
    //    repair external drift.
    //
    //    GUARD (fixes the v0.10.0 field regression): only sync dnsmasq if the
    //    local dnsmasq actually understands the directive family we'd emit. A
    //    stock/slim dnsmasq (the RutOS default, no dnsmasq-full) has no
    //    `ipset`/`nftset` support and treats such a line as a FATAL config error
    //    — it then refuses to start and takes the ENTIRE LAN's DNS down. When the
    //    directive is unsupported we DISABLE the garden and drop any stale conf a
    //    prior run/version left, so the next dnsmasq (re)start stays clean.
    //    Install dnsmasq-full to turn the garden on.
    if probe_dnsmasq_garden("dnsmasq", garden_backend) {
        let mut garden_rx = controller.watch_garden();
        tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(GARDEN_TICK);
            loop {
                let fqdns = garden_rx.borrow_and_update().clone();
                let gc = portcullis_garden::GardenConfig::with_fqdns_for(garden_backend, fqdns);
                match portcullis_garden::reconcile(GARDEN_CONF_PATH, &gc).await {
                    Ok(true) => tracing::info!("garden config reconciled (changed)"),
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "garden reconcile failed; keeping prior config")
                    }
                }
                tokio::select! {
                    _ = ticker.tick() => {}
                    r = garden_rx.changed() => { if r.is_err() { break; } }
                }
            }
        }));
    } else {
        tracing::warn!(
            backend = ?garden_backend,
            path = GARDEN_CONF_PATH,
            "dnsmasq lacks ipset/nftset support (install dnsmasq-full); walled-garden DISABLED — \
             not writing the garden conf, which a stock dnsmasq treats as fatal and would take \
             LAN DNS down. Enforcement still works; garden domains just aren't pre-allowed."
        );
        // Drop any stale garden conf so the next dnsmasq (re)start doesn't choke.
        match std::fs::remove_file(GARDEN_CONF_PATH) {
            Ok(()) => tracing::info!(path = GARDEN_CONF_PATH, "removed stale garden conf"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = GARDEN_CONF_PATH, error = %e, "could not remove stale garden conf")
            }
        }
    }

    // 8b. Enforcement toggle (G3b/G8): a CP `SetEnforcement(false)` removes the
    //     gating jumps (unauth traffic then falls through to fw3 — the gate stops
    //     blocking), and `SetEnforcement(true)` restores the gated-SSID scope.
    //     Reuses the scoped `set_gated_ifaces` path: it never flushes the auth
    //     set and never touches fw3; the table + sets persist across a toggle, so
    //     re-enabling is instant. Enforcement starts enabled + scoped at boot, so
    //     we skip the initial value and act only on subsequent changes.
    {
        let mut enf_rx = controller.watch_enforcement();
        let writer = writer.clone();
        let seed_ifaces = gated_ifaces(&cfg);
        enf_rx.borrow_and_update(); // mark the boot value seen
        tasks.push(tokio::spawn(async move {
            while enf_rx.changed().await.is_ok() {
                let enabled = *enf_rx.borrow_and_update();
                // On (re)enable, restore the currently-committed gated ifaces
                // (CP-managed wireless) if any, else the static seed.
                let target = if enabled {
                    portcullis_provision::read_committed_gated(std::path::Path::new(
                        portcullis_provision::DEFAULT_STATE_DIR,
                    ))
                    .unwrap_or_else(|| seed_ifaces.clone())
                } else {
                    Vec::new()
                };
                match writer.set_gated_ifaces(target).await {
                    Ok(()) => tracing::info!(enabled, "enforcement toggle applied"),
                    Err(e) => {
                        tracing::warn!(enabled, error = %e, "enforcement toggle failed; prior scope kept")
                    }
                }
            }
        }));
    }

    // 9. Daemon-side expiry sweep (dual-path expiry, §7.4) + idle-timeout sweep
    //    (G6). Both run on the same tick; the idle threshold comes from the
    //    runtime controller's engine params (0 = disabled), so a CP
    //    SetEngineParameters takes effect on the next tick.
    {
        let mgr = w.mgr.clone();
        let controller = controller.clone();
        tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EXPIRY_TICK);
            loop {
                ticker.tick().await;
                let now = Instant::now();
                let expired = mgr.tick_expiry(now).await;
                if expired > 0 {
                    tracing::debug!(expired, "expiry sweep removed sessions");
                }
                let idle = mgr.sweep_idle(now, controller.idle_timeout()).await;
                if idle > 0 {
                    tracing::debug!(idle, "idle sweep removed sessions");
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

    // 9d. Hot-reload on SIGHUP (G7). procd sends SIGHUP on a UCI change; reload
    //     the config file and, for a hot-reloadable diff, push the new garden +
    //     engine params through the runtime controller — the garden reconciler,
    //     the metering re-arm (step 7), and the idle sweep (step 9) react without
    //     dropping a session. A restart-only change (endpoint/TLS/port/store/
    //     backend) is logged, not partially applied.
    #[cfg(unix)]
    {
        use portcullis_config::ReloadImpact;
        use portcullis_types::EngineControl as _;
        let controller = controller.clone();
        let path = config_path.clone();
        let mut current = cfg.clone();
        tasks.push(tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "cannot install SIGHUP handler; hot-reload disabled");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                let Some(new) = reload_config(&path) else { continue };
                match portcullis_config::diff(&current, &new) {
                    ReloadImpact::HotReloadable => {
                        if new.garden_fqdn != current.garden_fqdn {
                            let _ = controller.set_garden(new.garden_fqdn.clone()).await;
                        }
                        let params = portcullis_types::EngineParameters {
                            accounting_interval_secs: new.accounting_interval.clamp(1, 3600) as u32,
                            idle_timeout_secs: new.idle_timeout.min(86400) as u32,
                            ..portcullis_types::EngineParameters::default()
                        };
                        if let Err(e) = controller.set_engine_parameters(params).await {
                            tracing::warn!(error = %e, "SIGHUP: engine params rejected; kept prior");
                        }
                        tracing::info!("SIGHUP: config hot-reloaded");
                        current = new;
                    }
                    ReloadImpact::RequiresRestart => {
                        tracing::warn!(
                            "SIGHUP: config change touches a restart-only field \
                             (endpoint/TLS/port/store/backend); NOT applied live — restart to take effect"
                        );
                    }
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
fn detect_backend(cfg: &Config) -> (Box<dyn FirewallBackend>, portcullis_garden::GardenBackend) {
    detect_backend_with(cfg, "nft")
}

/// The set of interfaces enforcement gates. Today: the single configured
/// `hotspot_iface` (empty → none, i.e. fail-OPEN inert). P-W1 chunk 4 replaces
/// this static seed with the dynamic set fed from the committed CP-managed
/// wireless config (each `gated=true` SSID's resulting iface), re-applied via the
/// writer without flushing the auth set.
fn gated_ifaces(cfg: &Config) -> Vec<String> {
    if cfg.hotspot_iface.trim().is_empty() {
        Vec::new()
    } else {
        vec![cfg.hotspot_iface.clone()]
    }
}

/// [`detect_backend`] with an injectable `nft` program path for the probe (unit
/// tests stand in a fake script, cf. the shaper's `fake_tc` pattern).
fn detect_backend_with(
    cfg: &Config,
    nft_bin: &str,
) -> (Box<dyn FirewallBackend>, portcullis_garden::GardenBackend) {
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
    //
    // The chosen backend also decides how dnsmasq syncs the walled garden
    // (`nftset=` for nft sets vs `ipset=` for ipset sets, G2) — return it so the
    // garden loop renders the matching directive family (a mismatch silently
    // empties the garden).
    if use_nft {
        tracing::info!(
            backend = "nft",
            hotspot_iface = %cfg.hotspot_iface,
            "firewall backend selected"
        );
        (
            Box::new(portcullis_nft::NftJsonBackend::default().with_gated_ifaces(gated_ifaces(cfg))),
            portcullis_garden::GardenBackend::Nft,
        )
    } else {
        tracing::info!(
            backend = "ipset",
            hotspot_iface = %cfg.hotspot_iface,
            "firewall backend selected"
        );
        (
            Box::new(
                portcullis_nft::IpsetIptablesBackend::default()
                    .with_redirect_port(cfg.responder_port)
                    .with_gated_ifaces(gated_ifaces(cfg)),
            ),
            portcullis_garden::GardenBackend::Ipset,
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

/// Probe whether the local dnsmasq understands the set directive the chosen
/// garden backend emits (`ipset` for the ipset backend, `nftset` for nft).
///
/// `dnsmasq --version` prints a "Compile time options:" line listing each enabled
/// option, or its `no-<opt>` negation on a slim build. We enable the garden ONLY
/// on a positive token match: a missing binary, an unreadable version, or an
/// explicit `no-ipset` all return false. This is the guard that stops the engine
/// from handing a stock/slim dnsmasq (the RutOS default) an `ipset=` line it
/// treats as a FATAL error — which aborts dnsmasq and takes the whole LAN's DNS
/// down. Install dnsmasq-full to flip this on.
fn probe_dnsmasq_garden(program: &str, backend: portcullis_garden::GardenBackend) -> bool {
    let want = match backend {
        portcullis_garden::GardenBackend::Ipset => "ipset",
        portcullis_garden::GardenBackend::Nft => "nftset",
    };
    let out = match std::process::Command::new(program).arg("--version").output() {
        Ok(o) => o,
        Err(_) => return false, // no dnsmasq to probe → stay safe, don't write
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    dnsmasq_advertises(&text, want)
}

/// True if a dnsmasq `--version` blob advertises `want` (e.g. "ipset"/"nftset")
/// as an ENABLED compile option. Options are whitespace-separated tokens and the
/// disabled form is `no-<opt>`, so an exact-token match makes `no-ipset` (a slim
/// build) correctly fail to satisfy `ipset`. Pure → unit-testable without dnsmasq.
fn dnsmasq_advertises(version_text: &str, want: &str) -> bool {
    version_text
        .split(|c: char| c.is_whitespace())
        .any(|tok| tok == want)
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
/// Reload + validate the config file for a SIGHUP hot-reload (G7). Any failure
/// (unreadable, malformed, invalid) is logged and returns `None` so the running
/// config stays in force — a bad edit never takes down a live daemon.
fn reload_config(path: &std::path::Path) -> Option<Config> {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "SIGHUP: config unreadable; keeping running config");
            return None;
        }
    };
    let parsed = if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        Config::from_toml_str(&raw)
    } else {
        Config::from_uci_str(&raw)
    };
    match parsed.and_then(|c| c.validate().map(|()| c)) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "SIGHUP: config invalid; keeping running config");
            None
        }
    }
}

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

    #[test]
    fn dnsmasq_advertises_enabled_but_not_negated() {
        // dnsmasq-full: `ipset`/`nftset` present as bare tokens.
        let full = "Dnsmasq version 2.90\n\
             Compile time options: IPv6 GNU-getopt DBus DHCP TFTP ipset nftset auth DNSSEC\n";
        assert!(dnsmasq_advertises(full, "ipset"));
        assert!(dnsmasq_advertises(full, "nftset"));

        // Stock/slim dnsmasq: the `no-ipset` negation must NOT satisfy `ipset`
        // (this is the exact case that took LAN DNS down in the field).
        let slim = "Dnsmasq version 2.90\n\
             Compile time options: IPv6 GNU-getopt DHCP TFTP no-ipset no-nftset auth\n";
        assert!(!dnsmasq_advertises(slim, "ipset"));
        assert!(!dnsmasq_advertises(slim, "nftset"));

        // Missing/garbage version output → not advertised (stay safe, don't write).
        assert!(!dnsmasq_advertises("", "ipset"));
        assert!(!dnsmasq_advertises("totally unrelated text", "ipset"));
    }

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
        // detect_backend_with now also returns the matching GardenBackend (G2);
        // assert both the adapter and the garden directive family line up.
        use portcullis_garden::GardenBackend;
        let missing = "/nonexistent/portcullis-test-nft";
        let (b, gb) = detect_backend_with(&cfg("nft"), missing);
        assert!(is_nft(b).await);
        assert_eq!(gb, GardenBackend::Nft);
        let (b, gb) = detect_backend_with(&cfg("ipset"), missing);
        assert!(is_ipset(b).await);
        assert_eq!(gb, GardenBackend::Ipset);

        // auto: the probe outcome decides.
        let (nat_ok, _log) = fake_nft("auto-yes", false);
        let (b, gb) = detect_backend_with(&cfg("auto"), &nat_ok);
        assert!(is_nft(b).await);
        assert_eq!(gb, GardenBackend::Nft);
        let (no_nat, _log) = fake_nft("auto-no", true);
        let (b, gb) = detect_backend_with(&cfg("auto"), &no_nat);
        assert!(is_ipset(b).await);
        assert_eq!(gb, GardenBackend::Ipset);
        // ...and a box with no nft at all falls back to ipset (RUTM11 today).
        let (b, gb) = detect_backend_with(&cfg("auto"), missing);
        assert!(is_ipset(b).await);
        assert_eq!(gb, GardenBackend::Ipset);
    }
}
