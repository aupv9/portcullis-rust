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

    /// Toggle the global enforcement gate. `true` (re)installs the jump into the
    /// gating chains; `false` removes it so traffic flows. MUST NOT touch the
    /// `auth` set or flush the gating chains — only the base-hook jump changes.
    /// Idempotent (safe to call repeatedly with the same value).
    async fn set_enforcement(&self, enabled: bool) -> Result<()>;

    /// Atomically replace the walled-garden IP sets (v4/v6) with the given
    /// resolved addresses — the engine-resolver garden path for routers whose
    /// dnsmasq can't populate the sets itself.
    async fn replace_garden(
        &self,
        v4: Vec<std::net::Ipv4Addr>,
        v6: Vec<std::net::Ipv6Addr>,
    ) -> Result<()>;
}

/// A mutation recorded by [`MockBackend`], for test assertions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockOp {
    EnsureBase,
    AddAuth { mac: MacAddr, ttl: Duration },
    DelAuth { mac: MacAddr },
    ListAuth,
    SetEnforcement { enabled: bool },
    ReplaceGarden { v4: Vec<std::net::Ipv4Addr>, v6: Vec<std::net::Ipv6Addr> },
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
    /// Last enforcement gate state applied via `set_enforcement`.
    enforcement_enabled: bool,
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

    /// Last enforcement gate state applied via `set_enforcement` (default false).
    pub fn enforcement_enabled(&self) -> bool {
        self.inner.lock().unwrap().enforcement_enabled
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

    async fn set_enforcement(&self, enabled: bool) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        Self::maybe_fail(&mut inner, "set_enforcement")?;
        inner.enforcement_enabled = enabled;
        inner.ops.push(MockOp::SetEnforcement { enabled });
        Ok(())
    }

    async fn replace_garden(
        &self,
        v4: Vec<std::net::Ipv4Addr>,
        v6: Vec<std::net::Ipv6Addr>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        Self::maybe_fail(&mut inner, "replace_garden")?;
        inner.ops.push(MockOp::ReplaceGarden { v4, v6 });
        Ok(())
    }
}
