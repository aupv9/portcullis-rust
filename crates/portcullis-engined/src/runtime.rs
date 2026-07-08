//! Runtime control state store + [`EngineControl`] controller (F0).
//!
//! Holds the config the control plane pushes at runtime — tier policies, the
//! walled-garden FQDN list, the global enforcement toggle, and the tunable
//! timers/caps — in RAM, persisted to **tmpfs** (`/tmp/portcullis/`, never NAND)
//! so it survives a daemon restart and is re-adopted at startup alongside the
//! kernel `@auth` set. This is the keystone the G3/G4 handlers write through.
//!
//! Effects (garden reconcile from this state, enforcement teardown, timer
//! re-arm) are delivered over `watch` channels the relevant loops subscribe to —
//! a `set_*` mutates the state, persists it, and publishes the new value; the
//! loops pick it up without a restart. Persistence failures are logged, never
//! fatal (tmpfs is best-effort; the kernel set-element timeout is the backstop).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use portcullis_types::{
    EngineControl, EngineInfoSnapshot, EngineParameters, Error, MetricsSnapshot, Result,
    RuntimeConfig, TierPolicy,
};
use std::sync::Arc;
use tokio::sync::watch;

use crate::metrics::Metrics;

/// Persisted runtime-state path (tmpfs — invariant #1, never NAND).
pub const RUNTIME_STATE_PATH: &str = "/tmp/portcullis/runtime.json";

/// The composition-root implementation of [`EngineControl`]. Injected into the
/// control channel (Attach) and the unary gRPC server so both share one path.
pub struct RuntimeController {
    state: Mutex<RuntimeConfig>,
    path: PathBuf,
    version: String,
    boot_id: String,
    metrics: Arc<Metrics>,
    /// Capabilities beyond the always-present base set (e.g. `shaper` when
    /// bandwidth shaping is enabled) — advertised via `GetEngineInfo` so the CP
    /// only sends features the engine will honor.
    extra_caps: Vec<String>,
    params_tx: watch::Sender<EngineParameters>,
    garden_tx: watch::Sender<Vec<String>>,
    enforce_tx: watch::Sender<bool>,
}

impl RuntimeController {
    /// Build a controller, loading persisted state from `path` if present and
    /// valid, else seeding from `seed` (the static startup config). The seed lets
    /// the engine start with the config-file garden/params until the CP pushes.
    pub fn new(
        path: impl AsRef<Path>,
        version: impl Into<String>,
        boot_id: impl Into<String>,
        metrics: Arc<Metrics>,
        seed: RuntimeConfig,
        extra_caps: Vec<String>,
    ) -> Self {
        let path = path.as_ref().to_path_buf();
        let state = load_state(&path).unwrap_or(seed);
        let (params_tx, _) = watch::channel(state.engine_params);
        let (garden_tx, _) = watch::channel(state.garden_fqdns.clone());
        let (enforce_tx, _) = watch::channel(state.enforcement_enabled);
        RuntimeController {
            state: Mutex::new(state),
            path,
            version: version.into(),
            boot_id: boot_id.into(),
            metrics,
            extra_caps,
            params_tx,
            garden_tx,
            enforce_tx,
        }
    }

    // The `watch_*` subscribers are the effect side of the `set_*` handlers: a
    // `set_*` publishes on the channel, and the corresponding loop reacts —
    // metering interval (G7), garden reconcile + enforcement scope (G3b).

    /// Subscribe to engine-parameter changes (metering cadence re-arm; G7).
    pub fn watch_params(&self) -> watch::Receiver<EngineParameters> {
        self.params_tx.subscribe()
    }
    /// Subscribe to garden-FQDN changes (garden reconcile loop; G3b).
    pub fn watch_garden(&self) -> watch::Receiver<Vec<String>> {
        self.garden_tx.subscribe()
    }
    /// Subscribe to enforcement-toggle changes (gating scope; G3b).
    pub fn watch_enforcement(&self) -> watch::Receiver<bool> {
        self.enforce_tx.subscribe()
    }

    /// Snapshot the current runtime config (test/introspection helper).
    pub fn config(&self) -> RuntimeConfig {
        self.state.lock().expect("runtime state mutex poisoned").clone()
    }

    /// Current idle-timeout threshold (G6); `Duration::ZERO` = disabled. Read
    /// each expiry tick without cloning the whole config.
    pub fn idle_timeout(&self) -> Duration {
        let secs = self
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .engine_params
            .idle_timeout_secs;
        Duration::from_secs(u64::from(secs))
    }

    /// Resolve a tier's grant defaults, if any (used by the grant path, G3a).
    pub fn tier_policy(&self, tier: &str) -> Option<TierPolicy> {
        self.state
            .lock()
            .expect("runtime state mutex poisoned")
            .tier_policy(tier)
            .cloned()
    }

    /// Persist the current state to tmpfs. Best-effort: a write failure is logged,
    /// not propagated — the in-RAM state is authoritative this boot, and the
    /// kernel timeout is the backstop.
    fn persist(&self, cfg: &RuntimeConfig) {
        if let Err(e) = save_state(&self.path, cfg) {
            tracing::warn!(path = %self.path.display(), error = %e, "failed to persist runtime state (tmpfs); in-RAM state still authoritative");
        }
    }
}

/// Load + parse the persisted runtime config. Any error (missing, unreadable,
/// malformed) returns `None` so the caller falls back to the seed.
fn load_state(path: &Path) -> Option<RuntimeConfig> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<RuntimeConfig>(&text) {
        Ok(cfg) => {
            tracing::info!(path = %path.display(), "adopted persisted runtime state");
            Some(cfg)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "persisted runtime state unparseable; seeding fresh");
            None
        }
    }
}

fn save_state(path: &Path, cfg: &RuntimeConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Io(format!("create {}: {e}", parent.display())))?;
        }
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| Error::Other(format!("serialize runtime state: {e}")))?;
    std::fs::write(path, json.as_bytes())
        .map_err(|e| Error::Io(format!("write {}: {e}", path.display())))
}

/// A short, stable, non-cryptographic hash for config-drift detection (`GetEngineInfo`).
fn drift_hash(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[async_trait]
impl EngineControl for RuntimeController {
    async fn set_enforcement(&self, enabled: bool) -> Result<()> {
        let cfg = {
            let mut s = self.state.lock().expect("runtime state mutex poisoned");
            s.enforcement_enabled = enabled;
            s.clone()
        };
        self.persist(&cfg);
        // Publish; the nft teardown/rebuild effect is wired in G3b.
        let _ = self.enforce_tx.send(enabled);
        tracing::info!(enabled, "enforcement toggled by control plane");
        Ok(())
    }

    async fn set_garden(&self, fqdns: Vec<String>) -> Result<()> {
        let cfg = {
            let mut s = self.state.lock().expect("runtime state mutex poisoned");
            s.garden_fqdns = fqdns.clone();
            s.clone()
        };
        self.persist(&cfg);
        let _ = self.garden_tx.send(fqdns);
        Ok(())
    }

    async fn set_tier_policies(&self, policies: Vec<TierPolicy>) -> Result<()> {
        // Validate before applying — reject (never silently accept) a bad set.
        let mut seen = std::collections::HashSet::new();
        for p in &policies {
            if !TierPolicy::valid_tier_name(&p.tier) {
                return Err(Error::BadRequest(format!(
                    "invalid tier name '{}' (expect [a-z0-9_-]{{1,32}})",
                    p.tier
                )));
            }
            if !seen.insert(p.tier.clone()) {
                return Err(Error::BadRequest(format!("duplicate tier '{}'", p.tier)));
            }
        }
        let cfg = {
            let mut s = self.state.lock().expect("runtime state mutex poisoned");
            s.tier_policies = policies;
            s.clone()
        };
        self.persist(&cfg);
        Ok(())
    }

    async fn set_engine_parameters(&self, params: EngineParameters) -> Result<()> {
        params.validate()?; // out-of-bounds rejected, never clamped-and-applied
        let cfg = {
            let mut s = self.state.lock().expect("runtime state mutex poisoned");
            s.engine_params = params;
            s.clone()
        };
        self.persist(&cfg);
        let _ = self.params_tx.send(params);
        Ok(())
    }

    async fn engine_info(&self) -> EngineInfoSnapshot {
        let s = self.config();
        let params_json = serde_json::to_string(&s.engine_params).unwrap_or_default();
        let tiers_json = serde_json::to_string(&s.tier_policies).unwrap_or_default();
        let mut garden = s.garden_fqdns.clone();
        garden.sort();
        EngineInfoSnapshot {
            version: self.version.clone(),
            boot_id: self.boot_id.clone(),
            capabilities: {
                let mut caps = vec![
                    "tier_policies".to_string(),
                    "engine_params".to_string(),
                    "garden".to_string(),
                    "enforcement_toggle".to_string(),
                ];
                caps.extend(self.extra_caps.iter().cloned());
                caps
            },
            enforcement_enabled: s.enforcement_enabled,
            tier_policies_hash: drift_hash(&tiers_json),
            engine_params_hash: drift_hash(&params_json),
            garden_hash: drift_hash(&garden.join(",")),
        }
    }

    async fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    async fn tier_policy(&self, tier: &str) -> Option<TierPolicy> {
        RuntimeController::tier_policy(self, tier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("portcullis-runtime-test-{tag}-{nanos}.json"))
    }

    fn ctrl(path: &Path) -> RuntimeController {
        RuntimeController::new(
            path,
            "0.0.0-test",
            "boot-xyz",
            Arc::new(Metrics::default()),
            RuntimeConfig::default(),
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn extra_capabilities_are_advertised() {
        let c = RuntimeController::new(
            tmp_path("caps"),
            "0.0.0-test",
            "boot",
            Arc::new(Metrics::default()),
            RuntimeConfig::default(),
            vec!["shaper".to_string()],
        );
        let caps = c.engine_info().await.capabilities;
        assert!(caps.contains(&"shaper".to_string()));
        assert!(caps.contains(&"tier_policies".to_string()), "base caps still present");
    }

    #[tokio::test]
    async fn defaults_enforcing_and_empty() {
        let p = tmp_path("def");
        let c = ctrl(&p);
        let cfg = c.config();
        assert!(cfg.enforcement_enabled, "engine enforces from boot (fail-closed)");
        assert!(cfg.garden_fqdns.is_empty());
        assert!(cfg.tier_policies.is_empty());
    }

    #[tokio::test]
    async fn set_tier_policies_persists_and_reloads() {
        let p = tmp_path("tiers");
        let _ = std::fs::remove_file(&p);
        {
            let c = ctrl(&p);
            c.set_tier_policies(vec![TierPolicy {
                tier: "vip".into(),
                ttl_secs: 7200,
                quota_bytes: 0,
                rate_bps: 10_000_000,
            }])
            .await
            .unwrap();
            assert_eq!(c.tier_policy("vip").unwrap().ttl_secs, 7200);
        }
        // A fresh controller adopts the persisted state (survives restart).
        let c2 = ctrl(&p);
        assert_eq!(c2.tier_policy("vip").unwrap().rate_bps, 10_000_000);
        std::fs::remove_file(&p).ok();
    }

    #[tokio::test]
    async fn invalid_tier_name_is_rejected() {
        let c = ctrl(&tmp_path("badtier"));
        let r = c
            .set_tier_policies(vec![TierPolicy {
                tier: "BAD NAME!".into(),
                ttl_secs: 0,
                quota_bytes: 0,
                rate_bps: 0,
            }])
            .await;
        assert!(r.is_err(), "bad tier name must be rejected, not applied");
    }

    #[tokio::test]
    async fn duplicate_tier_is_rejected() {
        let c = ctrl(&tmp_path("duptier"));
        let dup = || TierPolicy { tier: "public".into(), ttl_secs: 60, quota_bytes: 0, rate_bps: 0 };
        assert!(c.set_tier_policies(vec![dup(), dup()]).await.is_err());
    }

    #[tokio::test]
    async fn out_of_bounds_engine_params_rejected() {
        let c = ctrl(&tmp_path("params"));
        let bad = EngineParameters { expiry_tick_secs: 999, ..EngineParameters::default() };
        assert!(c.set_engine_parameters(bad).await.is_err(), "expiry_tick > 60 rejected");
        // A valid set applies and is observable on the watch channel.
        let mut rx = c.watch_params();
        let good = EngineParameters { accounting_interval_secs: 30, ..EngineParameters::default() };
        c.set_engine_parameters(good).await.unwrap();
        assert!(rx.changed().await.is_ok());
        assert_eq!(rx.borrow().accounting_interval_secs, 30);
    }

    #[tokio::test]
    async fn set_enforcement_publishes_and_engine_info_reflects() {
        let c = ctrl(&tmp_path("enf"));
        let mut rx = c.watch_enforcement();
        c.set_enforcement(false).await.unwrap();
        assert!(rx.changed().await.is_ok());
        assert!(!*rx.borrow());
        let info = c.engine_info().await;
        assert!(!info.enforcement_enabled);
        assert_eq!(info.version, "0.0.0-test");
        assert!(info.capabilities.contains(&"tier_policies".to_string()));
    }

    #[tokio::test]
    async fn garden_change_drift_hash_moves() {
        let c = ctrl(&tmp_path("garden"));
        let h0 = c.engine_info().await.garden_hash;
        c.set_garden(vec!["portal.example".into()]).await.unwrap();
        let h1 = c.engine_info().await.garden_hash;
        assert_ne!(h0, h1, "garden hash must change so the CP detects drift");
    }
}
