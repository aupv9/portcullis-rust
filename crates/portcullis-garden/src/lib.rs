//! Walled-garden management for the `portcullis` enforcement engine (TDD §7.3).
//!
//! Pre-authentication, clients may only reach a small set of hosts: the portal /
//! splash CDN, the OTP gateway, ad-asset hosts, payment domains, plus DNS.
//! Because the client's DNS resolver is the router's own **dnsmasq**, garden
//! population is delegated to dnsmasq rather than a custom DNS snooper: dnsmasq
//! resolves each garden FQDN and injects the resulting IPs straight into the
//! `garden4` / `garden6` nftables sets, tracking CDN IP churn automatically.
//!
//! This crate owns **only the FQDN domain list** and reconciles the dnsmasq
//! config text that wires those FQDNs to the nftables sets. It writes **no DNS
//! logic** and performs no netfilter work — the `garden4`/`garden6` sets are
//! created by `portcullis-nft` and filled by dnsmasq at runtime.
//!
//! ## Fail-closed
//!
//! A stale garden is at worst a portal hiccup (a CDN host that moved IPs is
//! briefly unreachable pre-auth), never an open door: this crate cannot grant
//! internet access — it only narrows what an *un*authenticated client may reach.
//! [`reconcile`] is idempotent and only ever writes the exact rendered config,
//! so a failed reconcile leaves the previous (still-restrictive) config in place.
//!
//! ## Shape (TDD §7.3)
//!
//! ```text
//! # /etc/config/dhcp  (dnsmasq-full required — stock slim dnsmasq lacks nftset)
//! nftset=/portal.wifihub.vn/cdn.wifihub.vn/.../4#inet#wifihub#garden4
//! nftset=/portal.wifihub.vn/cdn.wifihub.vn/.../6#inet#wifihub#garden6
//! ```

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use portcullis_types::{Error, Result};

/// The set of garden FQDNs plus the nftables target (table + per-family sets)
/// that dnsmasq should populate.
///
/// `table` is the dnsmasq `nftset=` *family#name* prefix (default
/// `"inet#wifihub"`, matching the single table this engine owns); `set4` / `set6`
/// are the interval sets dnsmasq injects resolved A / AAAA records into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenConfig {
    /// The garden FQDNs (e.g. `portal.wifihub.vn`). Order is normalised on
    /// render, so the caller need not pre-sort.
    pub fqdns: Vec<String>,
    /// dnsmasq `nftset` table reference, `<family>#<name>` (default `inet#wifihub`).
    pub table: String,
    /// IPv4 nftables set name (default `garden4`).
    pub set4: String,
    /// IPv6 nftables set name (default `garden6`).
    pub set6: String,
}

impl Default for GardenConfig {
    fn default() -> Self {
        GardenConfig {
            fqdns: Vec::new(),
            table: "inet#wifihub".to_string(),
            set4: "garden4".to_string(),
            set6: "garden6".to_string(),
        }
    }
}

impl GardenConfig {
    /// Construct from a list of FQDNs with the default `inet wifihub` target.
    pub fn with_fqdns<I, S>(fqdns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        GardenConfig {
            fqdns: fqdns.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Deterministically normalised FQDN order: deduplicated, sorted, with empty
    /// entries dropped. Keeping this pure (no I/O) makes [`render_dnsmasq`]
    /// byte-stable across runs, which is what lets [`reconcile`] be idempotent.
    fn normalised_fqdns(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .fqdns
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Render the dnsmasq `nftset=` directives for the given garden config (TDD §7.3).
///
/// Produces exactly two lines — one per address family — each a single directive
/// listing every FQDN, e.g.:
///
/// ```text
/// nftset=/cdn.wifihub.vn/portal.wifihub.vn/4#inet#wifihub#garden4
/// nftset=/cdn.wifihub.vn/portal.wifihub.vn/6#inet#wifihub#garden6
/// ```
///
/// FQDN ordering is deterministic (sorted, deduplicated) so the output is
/// byte-stable for a given input set. The output ends with a trailing newline.
///
/// This is a **pure** function: no I/O, no allocation beyond the returned string.
pub fn render_dnsmasq(cfg: &GardenConfig) -> String {
    let fqdns = cfg.normalised_fqdns();
    // `/a/b/c/` — a leading and trailing slash with FQDNs slash-separated. With
    // no FQDNs this collapses to a single `/`, matching dnsmasq's "match all"
    // form; we still emit both directives so the config shape is invariant.
    let mut joined = String::from("/");
    for f in &fqdns {
        joined.push_str(f);
        joined.push('/');
    }

    let mut out = String::new();
    out.push_str(&format!("nftset={joined}4#{}#{}\n", cfg.table, cfg.set4));
    out.push_str(&format!("nftset={joined}6#{}#{}\n", cfg.table, cfg.set6));
    out
}

/// Reconcile the dnsmasq garden config at `path` with the desired [`GardenConfig`].
///
/// Renders the desired config (via [`render_dnsmasq`]), compares it to the file
/// already at `path` (if any), and writes **only if it differs**. Returns `true`
/// if the file was written (created or changed), `false` if it was already
/// up to date.
///
/// This is idempotent: calling it repeatedly with the same config writes once.
///
/// On-device, `path` lives in dnsmasq's `conf-dir` (e.g.
/// `/tmp/dnsmasq.d/portcullis-garden.conf`); a `dnsmasq` reload (SIGHUP / `/etc/init.d/dnsmasq reload`)
/// must follow a change for it to take effect — that reload is **out of scope**
/// for this crate, which only owns the config text.
///
/// Fails closed: a read or write error returns `Err` and leaves any existing
/// (still-restrictive) config untouched; callers keep prior state and never
/// fail open.
pub async fn reconcile(path: impl AsRef<Path>, cfg: &GardenConfig) -> Result<bool> {
    let path = path.as_ref();
    let desired = render_dnsmasq(cfg);

    // Compare against current contents. A missing file is "different" -> write.
    // `std::fs` is used (not `tokio::fs`) because the garden config is a tiny
    // text file reconciled at most every few seconds; the blocking cost is
    // negligible and it keeps the dependency surface minimal on MIPS. It is
    // fully cross-platform, so host (aarch64-apple-darwin) tests run unchanged.
    match std::fs::read_to_string(path) {
        Ok(current) if current == desired => return Ok(false),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::Io(format!(
                "reading garden config {}: {e}",
                path.display()
            )));
        }
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Io(format!("creating dir {}: {e}", parent.display())))?;
        }
    }

    std::fs::write(path, desired.as_bytes())
        .map_err(|e| Error::Io(format!("writing garden config {}: {e}", path.display())))?;

    Ok(true)
}

/// Periodically reconcile the garden config at `path` every `interval`.
///
/// Runs until cancelled (drop the task / abort the join handle). Each tick calls
/// [`reconcile`]; a reconcile error is logged and the loop continues — a single
/// transient I/O failure must not stop future reconciles, and (fail-closed) the
/// previous config stays in force meanwhile.
///
/// Kept intentionally simple: it does not trigger the dnsmasq reload itself
/// (out of scope, see [`reconcile`]). The first reconcile runs immediately.
pub async fn run_garden_loop(path: impl AsRef<Path>, cfg: GardenConfig, interval: Duration) {
    let path = path.as_ref();
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match reconcile(path, &cfg).await {
            Ok(true) => tracing::info!(path = %path.display(), "garden config reconciled (changed)"),
            Ok(false) => tracing::debug!(path = %path.display(), "garden config already up to date"),
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "garden reconcile failed; keeping prior config"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("portcullis-garden-test-{tag}-{nanos}.conf"))
    }

    #[test]
    fn render_known_list_exact() {
        let cfg = GardenConfig::with_fqdns(["portal.wifihub.vn", "cdn.wifihub.vn", "otp.gateway"]);
        let out = render_dnsmasq(&cfg);
        // Sorted: cdn.wifihub.vn < otp.gateway < portal.wifihub.vn
        assert_eq!(
            out,
            "nftset=/cdn.wifihub.vn/otp.gateway/portal.wifihub.vn/4#inet#wifihub#garden4\n\
             nftset=/cdn.wifihub.vn/otp.gateway/portal.wifihub.vn/6#inet#wifihub#garden6\n"
        );
    }

    #[test]
    fn render_is_deterministic_regardless_of_input_order() {
        let a = GardenConfig::with_fqdns(["b.example", "a.example", "c.example"]);
        let b = GardenConfig::with_fqdns(["c.example", "a.example", "b.example"]);
        assert_eq!(render_dnsmasq(&a), render_dnsmasq(&b));
    }

    #[test]
    fn render_dedups_and_drops_empty() {
        let cfg = GardenConfig::with_fqdns(["dup.example", "dup.example", "  ", "", "a.example"]);
        let out = render_dnsmasq(&cfg);
        assert_eq!(
            out,
            "nftset=/a.example/dup.example/4#inet#wifihub#garden4\n\
             nftset=/a.example/dup.example/6#inet#wifihub#garden6\n"
        );
    }

    #[test]
    fn render_empty_list() {
        let cfg = GardenConfig::default();
        let out = render_dnsmasq(&cfg);
        // No FQDNs -> bare `/` between `nftset=` and the family marker; both
        // family directives still present so the config shape is invariant.
        assert_eq!(
            out,
            "nftset=/4#inet#wifihub#garden4\n\
             nftset=/6#inet#wifihub#garden6\n"
        );
    }

    #[test]
    fn render_respects_custom_table_and_sets() {
        let cfg = GardenConfig {
            fqdns: vec!["x.example".into()],
            table: "inet#myt".into(),
            set4: "g4".into(),
            set6: "g6".into(),
        };
        assert_eq!(
            render_dnsmasq(&cfg),
            "nftset=/x.example/4#inet#myt#g4\n\
             nftset=/x.example/6#inet#myt#g6\n"
        );
    }

    #[test]
    fn default_is_inet_wifihub_garden() {
        let cfg = GardenConfig::default();
        assert_eq!(cfg.table, "inet#wifihub");
        assert_eq!(cfg.set4, "garden4");
        assert_eq!(cfg.set6, "garden6");
        assert!(cfg.fqdns.is_empty());
    }

    #[tokio::test]
    async fn reconcile_writes_when_absent() {
        let path = unique_temp_path("absent");
        let _ = std::fs::remove_file(&path);
        let cfg = GardenConfig::with_fqdns(["portal.wifihub.vn"]);

        let changed = reconcile(&path, &cfg).await.unwrap();
        assert!(changed, "should write when file is absent");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, render_dnsmasq(&cfg));

        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn reconcile_is_idempotent() {
        let path = unique_temp_path("idem");
        let _ = std::fs::remove_file(&path);
        let cfg = GardenConfig::with_fqdns(["a.example", "b.example"]);

        assert!(reconcile(&path, &cfg).await.unwrap(), "first write");
        assert!(
            !reconcile(&path, &cfg).await.unwrap(),
            "second call must be a no-op (no change)"
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn reconcile_rewrites_when_different() {
        let path = unique_temp_path("diff");
        let _ = std::fs::remove_file(&path);

        let cfg1 = GardenConfig::with_fqdns(["a.example"]);
        let cfg2 = GardenConfig::with_fqdns(["a.example", "b.example"]);

        assert!(reconcile(&path, &cfg1).await.unwrap());
        // Different desired config -> must write again.
        assert!(reconcile(&path, &cfg2).await.unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            render_dnsmasq(&cfg2)
        );
        // And stable again afterwards.
        assert!(!reconcile(&path, &cfg2).await.unwrap());

        std::fs::remove_file(&path).unwrap();
    }
}
