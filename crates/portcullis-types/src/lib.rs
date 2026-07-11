//! Shared data types and **port traits** for the `portcullis` enforcement engine.
//!
//! This crate is the dependency hub: every other crate depends on it and *only*
//! it (plus the generated proto, in `portcullis-control`). The concrete adapters
//! that implement these ports — the nft writer, the neigh resolver, the conntrack
//! counter source, the gRPC event sink — live in their own crates and are wired
//! together in `portcullis-engined`. This keeps the netfilter-touching code
//! mockable (TDD §5.5, §6, §7.9) and lets the crates be developed independently.
//!
//! Nothing here performs I/O or touches the kernel.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Primitive identity types
// ---------------------------------------------------------------------------

/// A 48-bit Ethernet MAC address — the primary, stable session key (TDD §7.2).
///
/// Stored as a fixed 6-byte array (not a `String`) to keep per-session memory
/// tiny on the 256 MB RUTM11 (TDD §14, embedded-perf skill).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Render as the canonical lowercase `aa:bb:cc:dd:ee:ff` used in nft elements.
    pub fn to_canonical(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return Err(Error::InvalidMac(s.to_string()));
        }
        let mut octets = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            octets[i] =
                u8::from_str_radix(p, 16).map_err(|_| Error::InvalidMac(s.to_string()))?;
        }
        Ok(MacAddr(octets))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// SSID / policy tier (TDD §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    #[default]
    Public,
    Home,
    Retail,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Tier::Public => "public",
            Tier::Home => "home",
            Tier::Retail => "retail",
        })
    }
}

impl FromStr for Tier {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "public" | "" => Ok(Tier::Public),
            "home" => Ok(Tier::Home),
            "retail" => Ok(Tier::Retail),
            other => Err(Error::InvalidTier(other.to_string())),
        }
    }
}

/// Control-plane-issued session id (== RADIUS `Acct-Session-Id`, TDD §7.4/§7.5).
///
/// Backed by `Box<str>` rather than `String`: a session id is immutable once
/// issued, so the extra capacity word a `String` carries is dead weight, and a
/// clone allocates exactly the right size (one per buffered/emitted event).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Box<str>);

impl SessionId {
    /// Borrow as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for SessionId {
    fn from(s: String) -> Self {
        SessionId(s.into_boxed_str())
    }
}

impl From<&str> for SessionId {
    fn from(s: &str) -> Self {
        SessionId(Box::from(s))
    }
}

// ---------------------------------------------------------------------------
// Grant / event / accounting data
// ---------------------------------------------------------------------------

/// A request to authorize a client, as delivered by the control plane (TDD §7.5).
/// `quota_bytes == 0` and `rate_bps == 0` both mean *unlimited*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantParams {
    pub store_id: String,
    pub mac: MacAddr,
    pub ip: Option<IpAddr>,
    pub ttl: Duration,
    pub quota_bytes: u64,
    pub rate_bps: u64,
    pub tier: Tier,
    pub session_id: SessionId,
}

/// Why a session is being torn down (maps onto an [`EventKind`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// Control-plane admin / policy / fraud action.
    Admin,
    /// Byte quota exhausted (accounting loop, TDD §7.7).
    Quota,
    /// Client MAC changed / re-association.
    MacChange,
    /// No traffic within the idle-timeout window (G6).
    IdleTimeout,
}

/// Session lifecycle event emitted engine -> control plane (TDD §7.5).
/// The control plane translates these into RADIUS Accounting; the engine never
/// speaks RADIUS itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    Granted,
    Interim,
    Expired,
    Revoked,
    QuotaExceeded,
    IdleTimeout,
}

impl From<RevokeReason> for EventKind {
    fn from(r: RevokeReason) -> Self {
        match r {
            RevokeReason::Quota => EventKind::QuotaExceeded,
            RevokeReason::Admin | RevokeReason::MacChange => EventKind::Revoked,
            RevokeReason::IdleTimeout => EventKind::IdleTimeout,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    pub session_id: SessionId,
    pub mac: MacAddr,
    pub kind: EventKind,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ts_unix: i64,
}

/// Per-client byte counters (TDD §7.6). Monotonic from the kernel's point of
/// view; the accounting loop computes deltas and re-baselines on restart.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Counters {
    pub fn total(&self) -> u64 {
        self.bytes_in.saturating_add(self.bytes_out)
    }
}

/// One element of the kernel `auth` set, as read back during restart adoption
/// (TDD §7.8). `remaining` is the kernel-tracked timeout left on the element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthElement {
    pub mac: MacAddr,
    pub remaining: Duration,
}

/// A point-in-time view of a session, returned by `GetSession` / `ListSessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub mac: MacAddr,
    pub ip: Option<IpAddr>,
    pub tier: Tier,
    pub granted_at_unix: i64,
    pub expires_in: Duration,
    pub quota_bytes: u64,
    pub rate_bps: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Health snapshot returned over gRPC (TDD §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HealthStatus {
    pub backend_ok: bool,
    pub kernel_table_present: bool,
    pub cp_connected: bool,
    pub last_reconcile_ok: bool,
}

/// Policy for a MAC found in the kernel `auth` set but unknown to the daemon's
/// in-RAM view during reconciliation (TDD §7.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UnknownKernelPolicy {
    /// Adopt it (never drop an authorized client) — the safe default, matching
    /// restart adoption. A grant that just landed in the kernel but whose in-RAM
    /// insert has not yet committed is preserved.
    #[default]
    Adopt,
    /// Delete it from the kernel (strict desired-state). Opt-in only.
    Delete,
}

/// Outcome of one drift-reconciliation pass (TDD §7.8). Counts only — bounded,
/// no per-MAC growth — so it is cheap to log and to feed a metric.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Elements present in the kernel `auth` set.
    pub kernel_count: usize,
    /// Sessions present in the daemon's in-RAM view.
    pub ram_count: usize,
    /// In RAM but missing from the kernel → re-added with the remaining TTL.
    pub readded: usize,
    /// In the kernel but unknown to RAM → adopted.
    pub adopted: usize,
    /// In the kernel but unknown to RAM → deleted (non-default policy).
    pub deleted: usize,
    /// Writer ops that failed during this pass.
    pub errors: usize,
}

impl ReconcileReport {
    /// A pass is "ok" when every attempted repair succeeded.
    pub fn ok(&self) -> bool {
        self.errors == 0
    }

    /// Whether the pass changed anything (repaired drift).
    pub fn repaired(&self) -> bool {
        self.readded + self.adopted + self.deleted > 0
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub type Result<T> = std::result::Result<T, Error>;

/// The engine's error type. Note the design rule: an error must never cause a
/// fail-open — callers keep prior state or fail closed (TDD §11, §13).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid MAC address: {0}")]
    InvalidMac(String),

    #[error("invalid tier: {0}")]
    InvalidTier(String),

    #[error("firewall backend error: {0}")]
    Backend(String),

    #[error("nft transaction failed: {0}")]
    NftTransaction(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("control-plane unreachable: {0}")]
    ControlPlaneUnreachable(String),

    #[error("neighbour lookup failed for {0}: {1}")]
    NeighLookup(IpAddr, String),

    #[error("accounting/counter source error: {0}")]
    Counter(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("signature verification failed")]
    BadSignature,

    #[error("malformed request: {0}")]
    BadRequest(String),

    #[error("i/o error: {0}")]
    Io(String),

    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Ports (hexagonal boundaries). Adapters implement these in their own crates.
// All are object-safe (`async_trait`) so they can be held as `Box<dyn ...>`.
// ---------------------------------------------------------------------------

/// The single funnel for nftables mutations (TDD §7.1, §7.9). Implemented by the
/// `portcullis-nft` writer-actor handle; the only caller is the SessionManager.
/// Implementations MUST serialize mutations and MUST NOT fail open on error.
#[async_trait]
pub trait RulesetWriter: Send + Sync {
    /// Idempotently ensure the base `inet wifihub` table/chains/sets exist
    /// (create-if-missing, adopt-if-present). Never flushes other tables.
    async fn ensure_base(&self) -> Result<()>;

    /// `add element inet wifihub auth { <mac> timeout <ttl> }`.
    async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()>;

    /// `delete element inet wifihub auth { <mac> }`.
    async fn del_auth(&self, mac: MacAddr) -> Result<()>;

    /// List the current `auth` set elements (for restart adoption / reconcile).
    async fn list_auth(&self) -> Result<Vec<AuthElement>>;

    /// Re-scope enforcement to a new set of gated-SSID interfaces at runtime
    /// (P-W1) — re-applying only the interface-scoped gating rules, NEVER
    /// flushing the auth set (kernel-as-truth: authorized clients are preserved).
    /// Default is a no-op for test doubles; the writer actor overrides it to
    /// forward the command to the [`FirewallBackend`].
    async fn set_gated_ifaces(&self, _ifaces: Vec<String>) -> Result<()> {
        Ok(())
    }

    /// Add resolved walled-garden IPs to the garden sets (the "engine-resolver
    /// garden": used on stock dnsmasq that lacks `ipset=`, where the engine
    /// resolves each garden FQDN itself and tops up the sets so pre-auth clients
    /// can reach the portal). ADDITIVE and idempotent — never flushes the sets.
    /// Best-effort / fail-open (a missed garden IP never blocks a client, only
    /// leaves one portal asset un-pre-allowed). Default is a no-op for test
    /// doubles; the writer actor overrides it to forward to the [`FirewallBackend`].
    async fn add_garden(&self, _ips: &[IpAddr]) -> Result<()> {
        Ok(())
    }
}

/// Sink for session lifecycle events flowing engine -> control plane (TDD §7.5).
/// Implementations buffer in **bounded** RAM when the CP is unreachable (§11).
#[async_trait]
pub trait EventSink: Send + Sync {
    async fn emit(&self, event: SessionEvent);
}

/// Resolve a client source IP to its L2 MAC via the kernel neighbour table
/// (TDD §7.2). Implemented by `portcullis-redirect` (RTNETLINK / `ip neigh`).
#[async_trait]
pub trait NeighResolver: Send + Sync {
    async fn resolve(&self, ip: IpAddr) -> Result<Option<MacAddr>>;

    /// Resolve a batch of IPs to MACs in **one** shot (embedded-perf, TDD §14).
    ///
    /// The accounting loop resolves every conntrack source IP each tick; doing
    /// that one `resolve` at a time makes an adapter that forks a process (the
    /// production `ip neigh` resolver) spawn one child *per client per tick* —
    /// O(n) fork/exec on the 15 s cadence. Adapters backed by a process or
    /// socket SHOULD override this to dump the whole neighbour table once and
    /// serve all lookups from it, turning that into O(1) per tick.
    ///
    /// Contract: IPs with no neighbour entry are simply **omitted** from the
    /// result (the caller treats a missing IP as "no MAC"); a transient per-IP
    /// failure is likewise dropped rather than sinking the whole batch. An
    /// error is returned only for a whole-batch failure (e.g. the dump command
    /// itself failed), so the caller can skip the tick and fall back to the
    /// kernel set-element timeout (§11, never fail open).
    ///
    /// The default implementation calls [`resolve`](Self::resolve) per IP; it is
    /// correct but not batched — override it where the per-lookup cost matters.
    async fn resolve_many(&self, ips: &[IpAddr]) -> Result<Vec<(IpAddr, MacAddr)>> {
        let mut out = Vec::with_capacity(ips.len());
        for &ip in ips {
            if let Ok(Some(mac)) = self.resolve(ip).await {
                out.push((ip, mac));
            }
        }
        Ok(out)
    }

    /// Dump the full neighbour table as `(ip, mac)` pairs.
    ///
    /// This is the **reverse** lookup (MAC ← every IP that maps to it) used by
    /// the conntrack reaper's cold-start + reconcile sweep to find the IPs of
    /// MACs no longer in `@auth` (invariant #9, conntrack ⊆ auth). Only LAN
    /// neighbours appear here, so the router's own IPs and the outbound
    /// control-plane flow are structurally never candidates.
    ///
    /// The default returns empty — an adapter with no table dump simply
    /// contributes no reverse lookups (the de-auth fast path still reaps the
    /// session's recorded IP). A whole-dump failure returns `Err` so the caller
    /// can skip the sweep (never fail open).
    async fn table(&self) -> Result<Vec<(IpAddr, MacAddr)>> {
        Ok(Vec::new())
    }
}

/// Snapshot of per-client byte counters from conntrack (TDD §7.6). Implemented
/// by `portcullis-accounting`; aggregates on the conntrack *original source*.
#[async_trait]
pub trait CounterSource: Send + Sync {
    async fn snapshot(&self) -> Result<Vec<(MacAddr, Counters)>>;
}

/// Control-plane-facing operations, implemented by the SessionManager and called
/// by the gRPC server (`portcullis-control`). See TDD §7.5 / §8.
#[async_trait]
pub trait Enforcer: Send + Sync {
    async fn grant(&self, params: GrantParams) -> Result<SessionId>;
    async fn revoke(&self, mac: MacAddr, reason: RevokeReason) -> Result<()>;
    async fn get(&self, mac: MacAddr) -> Result<Option<SessionInfo>>;
    async fn list(&self) -> Result<Vec<SessionInfo>>;
    async fn health(&self) -> HealthStatus;
}

/// Accounting-facing sink, implemented by the SessionManager and called by the
/// `portcullis-accounting` loop. Pushing a counter snapshot updates per-session
/// byte totals, emits `INTERIM` events, and triggers a quota revoke when
/// `bytes_in + bytes_out > quota_bytes` (TDD §7.6/§7.7).
#[async_trait]
pub trait MeteringSink: Send + Sync {
    async fn apply_counters(&self, snapshot: Vec<(MacAddr, Counters)>) -> Result<()>;
}

/// Delete established conntrack flows by client source IP (invariant #9,
/// conntrack ⊆ auth). Implemented by `portcullis-accounting` (shells
/// `conntrack -D -s <ip>`); injected into the SessionManager (de-auth path) and
/// the reconcile sweep.
///
/// Closing the leak: removing a MAC from `@auth` only gates *new* connections —
/// an already-established flow sails through the `ct established,related accept`
/// fast path indefinitely. Reaping the client's flows on de-auth severs those.
///
/// Fail-closed: a reap error is a *degradation* (the leaked flow persists until
/// the next reconcile), never a fail-open — it must not abort the revoke or
/// unblock the gate. "Nothing to delete" is `Ok(0)`, not an error.
#[async_trait]
pub trait FlowReaper: Send + Sync {
    /// Delete every conntrack flow whose original source is `ip`. Returns the
    /// number of flows removed (`Ok(0)` when there was nothing to delete).
    async fn reap_by_ip(&self, ip: IpAddr) -> Result<usize>;
}

/// No-op reaper — the default when conntrack reaping is disabled or in tests
/// (mirrors [`NoopMetrics`] / the accounting `NoopShaper`). Every reap is a
/// successful `Ok(0)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopReaper;

#[async_trait]
impl FlowReaper for NoopReaper {
    async fn reap_by_ip(&self, _ip: IpAddr) -> Result<usize> {
        Ok(0)
    }
}

/// Send an 802.11 deauthentication to a client so it drops off Wi-Fi and
/// re-associates into the captive portal cleanly. Optional companion to the L3
/// revoke (removing a MAC from `@auth` + reaping conntrack): the L3 revoke leaves
/// the phone associated ("connected, no internet") until the OS re-probes the
/// portal — a deauth makes it re-onboard immediately. Implemented by
/// `portcullis-accounting`'s `UbusDeauth` (drives hostapd over ubus); injected
/// into the revoke path and used only when the control plane sets `deauth`.
///
/// Best-effort, like [`FlowReaper`]: a deauth failure is a *bonus that didn't
/// land*, never a fail-open — it must NOT abort or fail the L3 revoke, which has
/// already severed the client at the gate. "Client not associated" is `Ok(())`,
/// not an error.
#[async_trait]
pub trait Deauthenticator: Send + Sync {
    /// Deauthenticate `mac` off Wi-Fi (best-effort). `Ok(())` when the deauth was
    /// dispatched (or the client wasn't associated / no hostapd is present);
    /// `Err` only on a genuine tooling failure the caller degrades over.
    async fn deauth(&self, mac: MacAddr) -> Result<()>;
}

/// No-op deauthenticator — the default when deauth-on-revoke is disabled or in
/// tests (mirrors [`NoopReaper`]). Every deauth is a successful `Ok(())`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopDeauth;

#[async_trait]
impl Deauthenticator for NoopDeauth {
    async fn deauth(&self, _mac: MacAddr) -> Result<()> {
        Ok(())
    }
}

/// Apply / clear a per-client bandwidth cap (tc/HTB, G5). Implemented by
/// `portcullis-accounting`'s `TcShaper`; injected into the SessionManager, which
/// applies on grant and clears on revoke/expiry. `rate_bps == 0` means unlimited
/// (clear any existing cap). Best-effort like [`FlowReaper`]: a shaper error is a
/// degradation (bandwidth control), never a fail on the grant/gate.
#[async_trait]
pub trait Shaper: Send + Sync {
    async fn apply(&self, mac: MacAddr, rate_bps: u64) -> Result<()>;
    /// Remove any shaping for `mac` (idempotent — clearing an unshaped MAC is Ok).
    async fn clear(&self, mac: MacAddr) -> Result<()>;
}

/// No-op shaper — the default when bandwidth shaping is disabled or in tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopShaper;

#[async_trait]
impl Shaper for NoopShaper {
    async fn apply(&self, _mac: MacAddr, _rate_bps: u64) -> Result<()> {
        Ok(())
    }
    async fn clear(&self, _mac: MacAddr) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Runtime control state (F0) — config the control plane pushes at runtime and
// the engine holds in RAM (persisted to tmpfs, never NAND). Distinct from the
// startup `portcullis-config::Config` (foundational bindings, restart-only):
// these are the hot, CP-managed knobs — tier policies, garden list, the global
// enforcement toggle, and the tunable timers/caps.
// ---------------------------------------------------------------------------

/// Grant-policy defaults for a tier. When a grant names this `tier` but leaves a
/// field unset (`0`), the engine fills it from here (CP-pushed via
/// `SetTierPolicies`). This is how "user groups" (guest vs VIP) map to different
/// TTL / quota / rate without a separate SSID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierPolicy {
    /// Tier name, `[a-z0-9_-]{1,32}` (conventionally `public` | `home` | `retail`).
    pub tier: String,
    /// Session length; `0` = unset → engine built-in default.
    pub ttl_secs: u32,
    /// Byte quota; `0` = unlimited.
    pub quota_bytes: u64,
    /// Bandwidth cap (bits/sec); `0` = unlimited (shaping applied by G5).
    pub rate_bps: u64,
}

impl TierPolicy {
    /// A tier name is valid iff it is 1..=32 chars of `[a-z0-9_-]`.
    pub fn valid_tier_name(tier: &str) -> bool {
        !tier.is_empty()
            && tier.len() <= 32
            && tier.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    }
}

/// Runtime-tunable engine parameters (CP-pushed via `SetEngineParameters`). Held
/// as effective values; the [`Default`] is the engine's built-in default set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineParameters {
    pub accounting_interval_secs: u32,
    pub garden_tick_secs: u32,
    pub expiry_tick_secs: u32,
    pub max_sessions: u32,
    /// Idle-kill threshold; `0` = disabled (G6).
    pub idle_timeout_secs: u32,
}

impl Default for EngineParameters {
    fn default() -> Self {
        EngineParameters {
            accounting_interval_secs: 15,
            garden_tick_secs: 30,
            expiry_tick_secs: 1,
            max_sessions: 4096,
            idle_timeout_secs: 0,
        }
    }
}

impl EngineParameters {
    /// Validate against the wire-documented bounds; `Err` names the offender so
    /// the CP is told a bad param was rejected (never silently clamped).
    pub fn validate(&self) -> Result<()> {
        let check = |name: &str, v: u32, lo: u32, hi: u32| -> Result<()> {
            if v < lo || v > hi {
                Err(Error::Config(format!(
                    "{name}={v} out of bounds [{lo},{hi}]"
                )))
            } else {
                Ok(())
            }
        };
        check("accounting_interval_secs", self.accounting_interval_secs, 1, 3600)?;
        check("garden_tick_secs", self.garden_tick_secs, 5, 3600)?;
        check("expiry_tick_secs", self.expiry_tick_secs, 1, 60)?;
        check("max_sessions", self.max_sessions, 1, 16384)?;
        // idle_timeout: 0 = disabled, else [30, 86400].
        if self.idle_timeout_secs != 0 {
            check("idle_timeout_secs", self.idle_timeout_secs, 30, 86400)?;
        }
        Ok(())
    }
}

/// The full CP-pushed runtime state, persisted to tmpfs so it survives a daemon
/// restart (adopted at startup alongside the kernel `@auth` set).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Global gate. `true` (the default) = blocking unauthenticated traffic.
    pub enforcement_enabled: bool,
    /// CP-managed walled-garden FQDNs (fed to the garden renderer).
    pub garden_fqdns: Vec<String>,
    /// Per-tier grant defaults.
    pub tier_policies: Vec<TierPolicy>,
    /// Runtime-tunable timers/caps.
    pub engine_params: EngineParameters,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        // Enforcing by default — the engine gates from boot, before the CP
        // pushes anything (fail-closed).
        RuntimeConfig {
            enforcement_enabled: true,
            garden_fqdns: Vec::new(),
            tier_policies: Vec::new(),
            engine_params: EngineParameters::default(),
        }
    }
}

impl RuntimeConfig {
    /// Look up a tier's policy by name.
    pub fn tier_policy(&self, tier: &str) -> Option<&TierPolicy> {
        self.tier_policies.iter().find(|p| p.tier == tier)
    }
}

/// Point-in-time engine identity + config-drift snapshot (returned by
/// `GetEngineInfo`). Hashes let a fleet controller detect config drift.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineInfoSnapshot {
    pub version: String,
    pub boot_id: String,
    pub capabilities: Vec<String>,
    pub enforcement_enabled: bool,
    pub tier_policies_hash: String,
    pub engine_params_hash: String,
    pub garden_hash: String,
}

/// Runtime counter snapshot (returned by `GetMetrics`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub sessions_active: u64,
    pub grants_total: u64,
    pub revokes_total: u64,
    pub expires_total: u64,
    pub quota_kills_total: u64,
    pub flows_reaped_total: u64,
    pub reap_failures_total: u64,
    pub nft_txn_errors_total: u64,
    pub cp_disconnects_total: u64,
    pub shaper_failures_total: u64,
    pub idle_kills_total: u64,
}

/// Control-plane-facing configuration + introspection port (G3/G4). Implemented
/// by the composition root's runtime controller and called by both the unary
/// gRPC server and the Attach bidi-stream dispatcher, so on-net and CGNAT paths
/// share one code path. Fail-closed: a `set_*` that can't be applied returns
/// `Err` (the CP is told, never a silent accept).
#[async_trait]
pub trait EngineControl: Send + Sync {
    async fn set_enforcement(&self, enabled: bool) -> Result<()>;
    async fn set_garden(&self, fqdns: Vec<String>) -> Result<()>;
    async fn set_tier_policies(&self, policies: Vec<TierPolicy>) -> Result<()>;
    async fn set_engine_parameters(&self, params: EngineParameters) -> Result<()>;
    async fn engine_info(&self) -> EngineInfoSnapshot;
    async fn metrics_snapshot(&self) -> MetricsSnapshot;
    /// Look up a tier's grant-policy defaults (used to fill unset ttl/quota/rate
    /// on a grant that names the tier). `None` = no policy for that tier.
    async fn tier_policy(&self, tier: &str) -> Option<TierPolicy>;
}

// ---------------------------------------------------------------------------
// Provisioning lifecycle state (shared). The ISOLATED `portcullis-provision`
// subsystem (a separate crate + async task) renders owner-namespaced UCI
// sections, applies + reloads, then holds the change under a LOCAL commit-confirm
// watchdog. It is deliberately fail-OPEN (rollback), the ONE exception to the
// engine's fail-closed rule — it manages router *config*, not enforcement, and
// kernel-as-truth means a provision fault never drops an authorized client.
// ---------------------------------------------------------------------------

/// Lifecycle state of a provision (mirrors `pb::ProvisionState`); reused by
/// [`WirelessStatus`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionState {
    /// Applied + reloaded; awaiting a confirm within the watchdog window.
    AppliedPending,
    /// Confirmed before the deadline; the change is permanent.
    Committed,
    /// Watchdog fired without a confirm → reverted to the pre-apply snapshot.
    RolledBack,
    /// Validation or apply error → no change persisted (or it was reverted).
    Failed,
}

// ---------------------------------------------------------------------------
// CP-managed wireless (P-W1) — the domain value types: an arbitrary set of owned
// SSIDs the control plane can push to the engine. The wire messages
// (`pb::WirelessSsid` etc.) are translated into these by `portcullis-control` so
// the provision subsystem never touches generated code. Network + firewall are
// flattened here (the pb nests them) to keep the renderer/validator simple.
// ---------------------------------------------------------------------------

/// One SSID the engine should own. Renders to owner-namespaced `pc_<slug>_*` UCI
/// sections only; never touches lan / br-lan / admin / wan / the `inet wifihub`
/// table (enforced by the renderer's reserved denylist).
///
/// `Debug` is hand-written to REDACT [`key`](Self::key) — so a stray `?spec` in a
/// log line or a panic message can never leak the PSK (the invariant is
/// compiler-enforced, not just a convention).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SsidSpec {
    /// Owner-namespace key: `[a-z0-9_]{1,16}`. Sections are named `pc_<slug>_*`.
    pub slug: String,
    /// Advertised SSID (1..=32 chars).
    pub ssid: String,
    /// wifi-device(s) the AP attaches to, e.g. `["radio0", "radio1"]`. One
    /// `wifi-iface` section is rendered per radio. Empty => the engine default.
    pub radios: Vec<String>,
    /// `"none"` (open captive) or a WPA mode (`"psk2"`, `"sae"`, `"sae-mixed"`).
    pub encryption: String,
    /// PSK when `encryption != "none"`. SECRET — never logged; redacted upward.
    pub key: String,
    /// Hide the SSID beacon.
    pub hidden: bool,
    /// AP client isolation.
    pub isolate: bool,
    /// `true` = portcullis captive-gates the resulting iface; `false` = trusted.
    pub gated: bool,
    /// Owned L2 bridge iface, e.g. `br-public` (must NOT be `br-lan`).
    pub bridge_name: String,
    /// Gateway host addr on the subnet, e.g. `10.0.0.1`.
    pub ipaddr: String,
    /// Subnet mask, e.g. `255.255.255.0`.
    pub netmask: String,
    /// dnsmasq pool start (host part), e.g. `10`.
    pub dhcp_start: String,
    /// dnsmasq pool size, e.g. `200`.
    pub dhcp_limit: String,
    /// dnsmasq lease time, e.g. `2h`.
    pub dhcp_leasetime: String,
    /// `true` = bridged, no DHCP pool rendered.
    pub dhcp_disabled: bool,
    /// Firewall zone this SSID forwards out through, e.g. `wan` (must NOT be
    /// `lan`). Empty => the engine default (`wan`).
    pub egress_zone: String,
    /// Max associated stations (`maxassoc`); `0` = unlimited.
    pub max_clients: u32,
    /// MAC access policy: `""`/`"disable"` = off, `"allow"` = allow-list,
    /// `"deny"` = deny-list. Applied with `mac_list`.
    pub mac_policy: String,
    /// MACs for the allow/deny list (lowercase `aa:bb:cc:dd:ee:ff`).
    pub mac_list: Vec<String>,
    /// Per-SSID download cap (kbit, to client / ingress); `0` = unlimited. Rendered
    /// as an `sqm` `queue` section on this SSID's bridge (needs sqm-scripts + cake).
    pub rate_down_kbps: u32,
    /// Per-SSID upload cap (kbit, from client / egress); `0` = unlimited.
    pub rate_up_kbps: u32,
}

impl std::fmt::Debug for SsidSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsidSpec")
            .field("slug", &self.slug)
            .field("ssid", &self.ssid)
            .field("radios", &self.radios)
            .field("encryption", &self.encryption)
            .field("key", &redacted(&self.key))
            .field("hidden", &self.hidden)
            .field("isolate", &self.isolate)
            .field("gated", &self.gated)
            .field("bridge_name", &self.bridge_name)
            .field("ipaddr", &self.ipaddr)
            .field("netmask", &self.netmask)
            .field("dhcp_start", &self.dhcp_start)
            .field("dhcp_limit", &self.dhcp_limit)
            .field("dhcp_leasetime", &self.dhcp_leasetime)
            .field("dhcp_disabled", &self.dhcp_disabled)
            .field("egress_zone", &self.egress_zone)
            .field("max_clients", &self.max_clients)
            .field("mac_policy", &self.mac_policy)
            .field("mac_list", &self.mac_list)
            .field("rate_down_kbps", &self.rate_down_kbps)
            .field("rate_up_kbps", &self.rate_up_kbps)
            .finish()
    }
}

/// Render a secret for `Debug`: `<none>` when empty, else `<redacted>` — never
/// the value. Used by the hand-written `Debug` impls that carry a PSK.
fn redacted(secret: &str) -> &'static str {
    if secret.is_empty() {
        "<none>"
    } else {
        "<redacted>"
    }
}

/// A full declarative desired-state push: the complete set of owned SSIDs. The
/// engine diffs this against its currently-owned sections and applies the minimal
/// set/delete. An empty `ssids` tears down ALL owned sections.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WirelessDesiredState {
    /// Control-plane-issued version; echoed in [`WirelessStatus`] and the confirm.
    pub config_version: String,
    pub ssids: Vec<SsidSpec>,
    /// Local commit-confirm watchdog window; `0` = default (90 s), bounds
    /// `[15, 600]` (enforced during validation).
    pub confirm_timeout_secs: u32,
}

/// Per-SSID outcome within a [`WirelessStatus`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SsidResult {
    pub slug: String,
    pub ok: bool,
    pub message: String,
    /// Resulting L2 iface (feeds enforcement scoping when the SSID is gated).
    pub iface: String,
}

/// Lifecycle report for a wireless push (reuses [`ProvisionState`]). Pushed
/// upward by the subsystem; `portcullis-control` maps it to `pb::WirelessStatus`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WirelessStatus {
    pub config_version: String,
    pub state: ProvisionState,
    pub per_ssid: Vec<SsidResult>,
    pub message: String,
}

/// Provision-subsystem errors (fail-OPEN: an error rolls back / leaves prior
/// config, never drops an enforced client).
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// The spec failed validation (out-of-allowlist target, bad subnet, bad
    /// timeout, missing PSK, …) — nothing was applied.
    #[error("invalid provision spec: {0}")]
    Invalid(String),

    /// A `uci` / `wifi` / init-script command failed while applying or reloading.
    #[error("provision apply failed: {0}")]
    Apply(String),

    /// The commit-confirm rollback itself failed (the worst case — logged loudly).
    #[error("provision rollback failed: {0}")]
    Rollback(String),

    /// No pending provision matched a confirm (unknown / already resolved id).
    #[error("no pending provision for id: {0}")]
    NoPending(String),

    /// The provision actor task is gone (subsystem shut down).
    #[error("provision subsystem unavailable: {0}")]
    Unavailable(String),

    /// tmpfs snapshot / marker I/O error.
    #[error("provision i/o error: {0}")]
    Io(String),
}

/// Control-plane-facing wireless provisioning (P-W1), implemented by the
/// `portcullis-provision` handle and called by `portcullis-control` when a
/// `set_wireless_config` / `confirm_wireless` / `get_wireless_config` frame
/// arrives. Object-safe. Isolated from the [`Enforcer`]: a provision fault never
/// affects enforcement.
#[async_trait]
pub trait Provisioner: Send + Sync {
    /// Validate → snapshot → reconcile (set/delete diff) → reload → arm watchdog
    /// for a full declarative wireless desired-state. Returns once APPLIED_PENDING
    /// (the terminal COMMITTED / ROLLED_BACK outcome is delivered later as a
    /// [`WirelessStatus`] on the subsystem's upward channel), or an error if
    /// validation / apply failed (nothing durable was left / it was reverted).
    async fn set_wireless(
        &self,
        state: WirelessDesiredState,
    ) -> std::result::Result<(), ProvisionError>;

    /// Confirm a still-pending wireless push by config version → Committed.
    async fn confirm_wireless(
        &self,
        config_version: &str,
    ) -> std::result::Result<(), ProvisionError>;

    /// Return the last committed wireless desired-state (introspection / drift).
    async fn get_wireless(&self) -> std::result::Result<WirelessDesiredState, ProvisionError>;
}

/// A `u64` counter/gauge cell that works on **every** target. 32-bit MIPS (the
/// RUTM11, `mipsel-unknown-linux-musl`) has no native `AtomicU64`, so a tiny
/// `Mutex` is used instead of pulling in `portable-atomic`. Every mutation is on
/// a cold / low-frequency path (grants, revokes, expiries, reconciles, DNAT
/// redirects, gauge refresh at scrape time — all human-paced or already the slow
/// path), so lock contention is a non-issue. Replaces the `AtomicU64` metrics
/// cells that would not link for mipsel.
#[derive(Debug, Default)]
pub struct Counter(std::sync::Mutex<u64>);

impl Counter {
    /// Increment by one.
    pub fn inc(&self) {
        self.inc_by(1);
    }

    /// Increment by `n`.
    pub fn inc_by(&self, n: u64) {
        *self.0.lock().expect("counter mutex poisoned") += n;
    }

    /// Overwrite with an absolute value (for gauge-style cells).
    pub fn set(&self, n: u64) {
        *self.0.lock().expect("counter mutex poisoned") = n;
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        *self.0.lock().expect("counter mutex poisoned")
    }
}

/// A monotonically-increasing counter exported over the `/metrics` endpoint
/// (TDD §12). Kept as a small fixed enum so the sink is a couple of counter
/// cells — no label maps, no per-metric heap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metric {
    Grant,
    Revoke,
    Expire,
    QuotaExceeded,
    NftTxnError,
    DnatRedirect,
    Reconcile,
    ReconcileRepair,
    CpDisconnect,
    /// A de-auth (revoke/expiry/quota/idle) or the reconcile sweep removed at
    /// least one established conntrack flow for a no-longer-authorized client
    /// (invariant #9, conntrack ⊆ auth).
    FlowsReaped,
    /// A conntrack reap attempt errored. The gate still holds (fail-closed); the
    /// leaked flow may persist until the next reconcile tick.
    ReapFailed,
    /// A per-session bandwidth-shaping (tc/HTB) apply/clear errored. Best-effort:
    /// shaping degrades, the gate is unaffected (G5).
    ShaperFailure,
    /// A session was torn down for idle timeout (G6).
    IdleKill,
}

/// A point-in-time gauge exported over `/metrics` (TDD §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gauge {
    ActiveSessions,
}

/// Port for recording metrics. Implemented by the concrete atomic-backed
/// recorder in `portcullis-engined`; injected into the crates that have the
/// increment sites (session, nft writer, redirect). Sync + cheap on purpose —
/// an increment is one short `Mutex`-guarded `+= 1` (see [`Counter`]), always on
/// a low-frequency path, so it never meaningfully blocks the hot path.
pub trait MetricsSink: Send + Sync {
    fn incr(&self, metric: Metric);
    fn set_gauge(&self, gauge: Gauge, value: u64);
}

/// No-op metrics sink — the default when metrics are disabled or in tests
/// (mirrors the accounting `NoopShaper`).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn incr(&self, _metric: Metric) {}
    fn set_gauge(&self, _gauge: Gauge, _value: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let m: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(m.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn mac_accepts_dash_separator() {
        let m: MacAddr = "AA-BB-CC-00-11-22".parse().unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:00:11:22");
    }

    #[test]
    fn mac_rejects_garbage() {
        assert!("not-a-mac".parse::<MacAddr>().is_err());
        assert!("aa:bb:cc:dd:ee".parse::<MacAddr>().is_err());
        assert!("aa:bb:cc:dd:ee:zz".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_serde_is_string() {
        let m: MacAddr = "01:02:03:04:05:06".parse().unwrap();
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(j, "\"01:02:03:04:05:06\"");
        let back: MacAddr = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn tier_parse_and_display() {
        assert_eq!("retail".parse::<Tier>().unwrap(), Tier::Retail);
        assert_eq!(Tier::Home.to_string(), "home");
        assert_eq!("".parse::<Tier>().unwrap(), Tier::Public);
        assert!("gold".parse::<Tier>().is_err());
    }

    #[test]
    fn revoke_reason_maps_to_event() {
        assert_eq!(EventKind::from(RevokeReason::Quota), EventKind::QuotaExceeded);
        assert_eq!(EventKind::from(RevokeReason::Admin), EventKind::Revoked);
        assert_eq!(EventKind::from(RevokeReason::MacChange), EventKind::Revoked);
    }

    #[test]
    fn counters_total_saturates() {
        let c = Counters { bytes_in: u64::MAX, bytes_out: 10 };
        assert_eq!(c.total(), u64::MAX);
    }

    #[test]
    fn reconcile_report_ok_and_repaired() {
        let clean = ReconcileReport { kernel_count: 3, ram_count: 3, ..Default::default() };
        assert!(clean.ok() && !clean.repaired());
        let fixed = ReconcileReport { readded: 1, ..Default::default() };
        assert!(fixed.ok() && fixed.repaired());
        let bad = ReconcileReport { errors: 2, ..Default::default() };
        assert!(!bad.ok());
    }

    #[test]
    fn unknown_kernel_policy_defaults_to_adopt() {
        assert_eq!(UnknownKernelPolicy::default(), UnknownKernelPolicy::Adopt);
    }

    #[test]
    fn noop_metrics_is_a_noop() {
        let m = NoopMetrics;
        m.incr(Metric::Grant);
        m.set_gauge(Gauge::ActiveSessions, 42);
    }
}
