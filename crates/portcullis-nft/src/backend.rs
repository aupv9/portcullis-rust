//! The internal `FirewallBackend` port and an in-memory `MockBackend`.
//!
//! `FirewallBackend` is the narrow, object-safe seam between the writer actor
//! (§7.9) and whatever actually drives netfilter. The production adapter is
//! [`crate::nftables_json::NftJsonBackend`] (shells out to `nft -j`); tests and
//! host smoke runs use [`MockBackend`], which keeps the `auth` set in RAM and
//! records every mutation so semantics can be asserted without a kernel.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use portcullis_types::{AuthElement, MacAddr, Result};

/// The single funnel for nftables mutations, abstracted so it is mockable
/// (TDD §5.5, §7.9). Object-safe: held as `Box<dyn FirewallBackend>` by the
/// writer actor. Implementations MUST NOT fail open — an error is an error.
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Idempotently ensure the base `inet wifihub` table/chains/sets exist
    /// (create-if-missing, adopt-if-present). Never flushes other tables.
    async fn ensure_base(&self) -> Result<()>;

    /// `add element inet wifihub auth { <mac> timeout <ttl>s }`.
    async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()>;

    /// `delete element inet wifihub auth { <mac> }`.
    async fn del_auth(&self, mac: MacAddr) -> Result<()>;

    /// List the current `auth` set elements (for restart adoption / reconcile).
    async fn list_auth(&self) -> Result<Vec<AuthElement>>;

    /// Re-scope enforcement to a new set of gated-SSID interfaces AT RUNTIME
    /// (P-W1), re-applying ONLY the interface-scoped gating rules — NEVER
    /// flushing the `auth`/garden sets (kernel-as-truth: authorized clients are
    /// preserved across the re-scope). Fail-safe: a failure leaves the prior
    /// scope live. Default is a no-op (for the [`MockBackend`] / test doubles);
    /// the production backends override it.
    async fn set_gated_ifaces(&self, _ifaces: Vec<String>) -> Result<()> {
        Ok(())
    }

    /// Add resolved walled-garden IPs to the garden sets (the "engine-resolver
    /// garden", used when dnsmasq lacks the `ipset=` directive so the garden
    /// sets can't be populated by DNS — see the daemon's compose loop). Each IP
    /// lands in the family-matching set (`wifihub_g4`/`wifihub_g6`), additive and
    /// idempotent — it NEVER flushes the set (the sets are shared with the
    /// dnsmasq-populated path and with authorized state adoption). Fail-OPEN per
    /// element (a bad add is logged and skipped, never an error): this is a
    /// best-effort allowlist top-up, not enforcement — a missed garden IP only
    /// means one captive-portal asset isn't pre-allowed, it never blocks a client.
    /// Default is a no-op (the nft backend and [`MockBackend`] don't need it —
    /// the nft path populates the garden via dnsmasq `nftset=`); the ipset
    /// backend overrides it.
    async fn add_garden(&self, _ips: &[std::net::IpAddr]) -> Result<()> {
        Ok(())
    }
}

/// A mutation recorded by [`MockBackend`], for test assertions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockOp {
    EnsureBase,
    AddAuth { mac: MacAddr, ttl: Duration },
    DelAuth { mac: MacAddr },
    ListAuth,
}

/// In-memory [`FirewallBackend`] for unit tests and host smoke use.
///
/// Holds the `auth` set with per-element absolute expiry (so `list_auth`
/// reports a sensible `remaining`), and records every applied op in order.
/// Optionally fails the first `n` mutations to exercise the retry-once path.
#[derive(Default)]
pub struct MockBackend {
    inner: Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    base_ready: bool,
    /// mac -> absolute expiry instant.
    auth: HashMap<MacAddr, Instant>,
    ops: Vec<MockOp>,
    /// Remaining number of mutations to fail before they start succeeding.
    fail_remaining: usize,
}

impl MockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a backend whose next `fail_count` mutations return
    /// `Error::Backend`, after which mutations succeed. Used to test the
    /// actor's retry-once-then-error semantics.
    pub fn failing(fail_count: usize) -> Self {
        Self {
            inner: Mutex::new(MockInner {
                fail_remaining: fail_count,
                ..MockInner::default()
            }),
        }
    }

    /// All operations applied so far, in order.
    pub fn ops(&self) -> Vec<MockOp> {
        self.inner.lock().unwrap().ops.clone()
    }

    /// Whether `ensure_base` has been applied.
    pub fn base_ready(&self) -> bool {
        self.inner.lock().unwrap().base_ready
    }

    /// Current number of MACs in the in-memory `auth` set (non-expired).
    pub fn auth_len(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        Self::expire(&mut inner);
        inner.auth.len()
    }

    fn expire(inner: &mut MockInner) {
        let now = Instant::now();
        inner.auth.retain(|_, &mut expiry| expiry > now);
    }

    /// Returns Err if a scheduled failure is pending, consuming one.
    fn maybe_fail(inner: &mut MockInner, what: &str) -> Result<()> {
        if inner.fail_remaining > 0 {
            inner.fail_remaining -= 1;
            return Err(portcullis_types::Error::Backend(format!(
                "mock injected failure: {what}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl FirewallBackend for MockBackend {
    async fn ensure_base(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        Self::maybe_fail(&mut inner, "ensure_base")?;
        inner.base_ready = true;
        inner.ops.push(MockOp::EnsureBase);
        Ok(())
    }

    async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        Self::maybe_fail(&mut inner, "add_auth")?;
        inner.auth.insert(mac, Instant::now() + ttl);
        inner.ops.push(MockOp::AddAuth { mac, ttl });
        Ok(())
    }

    async fn del_auth(&self, mac: MacAddr) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        Self::maybe_fail(&mut inner, "del_auth")?;
        inner.auth.remove(&mac);
        inner.ops.push(MockOp::DelAuth { mac });
        Ok(())
    }

    async fn list_auth(&self) -> Result<Vec<AuthElement>> {
        let mut inner = self.inner.lock().unwrap();
        Self::maybe_fail(&mut inner, "list_auth")?;
        Self::expire(&mut inner);
        let now = Instant::now();
        let mut out: Vec<AuthElement> = inner
            .auth
            .iter()
            .map(|(&mac, &expiry)| AuthElement {
                mac,
                remaining: expiry.saturating_duration_since(now),
            })
            .collect();
        // Deterministic order for assertions.
        out.sort_by_key(|e| e.mac.octets());
        inner.ops.push(MockOp::ListAuth);
        Ok(out)
    }
}
