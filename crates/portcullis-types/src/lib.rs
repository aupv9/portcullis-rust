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

/// Conventional tier names (seed/config defaults). Tiers are **data-driven**:
/// these are conventions the control plane seeds, not an exhaustive set.
pub const TIER_PUBLIC: &str = "public";
pub const TIER_HOME: &str = "home";
pub const TIER_RETAIL: &str = "retail";

/// SSID / policy tier (TDD §7.4). Data-driven: any name matching
/// `^[a-z0-9_-]{1,32}$` (after trim + ASCII-lowercase normalization) is a
/// valid tier — the control plane defines the actual set. `"public"`,
/// `"home"` and `"retail"` are conventional names, not an enum.
///
/// Backed by `Box<str>` (same rationale as [`SessionId`]): immutable once
/// parsed, so a `String`'s capacity word is dead weight on the RUTM11.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tier(Box<str>);

impl Tier {
    /// The conventional default tier (`"public"`) — what an empty wire string
    /// resolves to, and what adopted sessions are tagged with.
    pub fn public() -> Self {
        Tier(Box::from(TIER_PUBLIC))
    }

    /// Borrow as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Tier {
    fn default() -> Self {
        Tier::public()
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Tier {
    type Err = Error;

    /// Normalize (trim + ASCII-lowercase), then validate. Empty string =>
    /// `"public"` (the wire's "no tier given" default, §7.5); anything not
    /// matching `^[a-z0-9_-]{1,32}$` post-normalization is rejected.
    fn from_str(s: &str) -> Result<Self> {
        let norm = s.trim().to_ascii_lowercase();
        if norm.is_empty() {
            return Ok(Tier::public());
        }
        let well_formed = norm.len() <= 32
            && norm
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !well_formed {
            return Err(Error::InvalidTier(norm));
        }
        Ok(Tier(norm.into_boxed_str()))
    }
}

impl Serialize for Tier {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Tier {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Engine defaults (single source of truth). The control plane mirrors these so
// a `0` on the wire resolves to the same fallback on both sides.
// ---------------------------------------------------------------------------

/// Built-in session TTL used when neither the grant nor the tier policy carries
/// one (see [`TierPolicy`]). Chosen to match the §9 config default (`1800s`).
pub const DEFAULT_TTL: Duration = Duration::from_secs(1800);

/// Upper bound on concurrently-tracked sessions held in RAM. See
/// `portcullis-session::MAX_SESSIONS` (which re-exports this) for the RSS-budget
/// rationale (TDD §5, §14).
pub const DEFAULT_MAX_SESSIONS: usize = 4096;

/// Built-in accounting/metering poll cadence (openNDS-proven 15s, §7.6).
pub const DEFAULT_ACCOUNTING_INTERVAL: Duration = Duration::from_secs(15);

/// Built-in walled-garden reconcile cadence (§7.3).
pub const DEFAULT_GARDEN_TICK: Duration = Duration::from_secs(30);

/// Built-in session-expiry sweep cadence (§7.8 dual-path expiry).
pub const DEFAULT_EXPIRY_TICK: Duration = Duration::from_secs(1);

/// Fleet-wide per-[`Tier`] grant defaults (TDD §7.4/§7.5). The control plane
/// pushes these via `SetTierPolicies`; the engine fills any 0-valued grant field
/// from the matching tier's policy before applying the grant. A field of `0`
/// here means *unset*: it resolves to the built-in default ([`DEFAULT_TTL`] for
/// `ttl`) or to *unlimited* (`quota_bytes` / `rate_bps`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TierPolicy {
    pub tier: Tier,
    pub ttl: Duration,
    pub quota_bytes: u64,
    pub rate_bps: u64,
}

/// Full snapshot of the runtime-adjustable engine parameters
/// (`SetEngineParameters`). Every push replaces the whole set; a `0` on the
/// wire resolves to the matching `DEFAULT_*` const before this struct is built,
/// so the values here are always concrete. **RAM-only** — the control plane
/// re-pushes on reconnect (§5.4 no-NAND).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineParams {
    pub accounting_interval: Duration,
    pub garden_tick: Duration,
    pub expiry_tick: Duration,
    pub max_sessions: usize,
    /// Disconnect a session after this long with no metered traffic (the
    /// RADIUS Idle-Timeout equivalent, checked in the expiry sweep). Unlike the
    /// other fields, [`Duration::ZERO`] means **disabled**, not "use a default"
    /// — mirroring `quota_bytes == 0` == unlimited. Bounds when non-zero:
    /// 30 s ..= 24 h (see [`validate`](EngineParams::validate)).
    pub idle_timeout: Duration,
}

impl Default for EngineParams {
    fn default() -> Self {
        EngineParams {
            accounting_interval: DEFAULT_ACCOUNTING_INTERVAL,
            garden_tick: DEFAULT_GARDEN_TICK,
            expiry_tick: DEFAULT_EXPIRY_TICK,
            max_sessions: DEFAULT_MAX_SESSIONS,
            // Idle disconnect is opt-in: off unless configured / pushed.
            idle_timeout: Duration::ZERO,
        }
    }
}

impl EngineParams {
    /// Bounds (validated post zero-substitution, mirrored by the control
    /// plane): accounting 1..=3600 s, expiry 1..=60 s, garden 5..=3600 s,
    /// max_sessions 1..=16384. The session cap's upper bound protects the
    /// <30 MB RSS budget (§14); the lower interval bounds keep
    /// `tokio::time::interval` from panicking on a zero period.
    pub fn validate(&self) -> Result<()> {
        let secs = |d: Duration| d.as_secs();
        if !(1..=3600).contains(&secs(self.accounting_interval)) {
            return Err(Error::BadRequest(format!(
                "accounting_interval {}s out of bounds [1, 3600]",
                secs(self.accounting_interval)
            )));
        }
        if !(1..=60).contains(&secs(self.expiry_tick)) {
            return Err(Error::BadRequest(format!(
                "expiry_tick {}s out of bounds [1, 60]",
                secs(self.expiry_tick)
            )));
        }
        if !(5..=3600).contains(&secs(self.garden_tick)) {
            return Err(Error::BadRequest(format!(
                "garden_tick {}s out of bounds [5, 3600]",
                secs(self.garden_tick)
            )));
        }
        if !(1..=16384).contains(&self.max_sessions) {
            return Err(Error::BadRequest(format!(
                "max_sessions {} out of bounds [1, 16384]",
                self.max_sessions
            )));
        }
        // 0 = disabled; any non-zero value must be a sane 30 s ..= 24 h window
        // (short enough to matter, long enough not to churn live clients).
        let idle = secs(self.idle_timeout);
        if idle != 0 && !(30..=86400).contains(&idle) {
            return Err(Error::BadRequest(format!(
                "idle_timeout {idle}s out of bounds (0=disabled, else [30, 86400])"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Runtime metrics (GetMetrics gRPC — fleet monitoring). Lock-free counters the
// hot paths bump with Relaxed atomics; the gRPC handler reads a snapshot.
// ---------------------------------------------------------------------------

/// A monotonic `u64` counter that works on **every** target. 32-bit MIPS (the
/// RUTM11, `mipsel-unknown-linux-musl`) has no native `AtomicU64`, so a tiny
/// `Mutex` is used instead of pulling in `portable-atomic`. Every increment is
/// on a cold / low-frequency path (grants, revokes, expiries, event eviction,
/// rate-limit rejections — all human-paced or already the slow path), so lock
/// contention is a non-issue.
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

    /// Current value.
    pub fn get(&self) -> u64 {
        *self.0.lock().expect("counter mutex poisoned")
    }
}

/// Process-wide runtime counters, shared (via `Arc`) between the session
/// layer, the redirect responder, and the gRPC `GetMetrics` handler. Counters
/// count since boot (they reset with the engine's `boot_id`); RAM-only, like
/// everything else (§5.4).
///
/// Deliberately NOT here: `events_emitted/evicted` (owned by the control
/// crate's `EventLog`), `sessions_active` (a gauge the [`Enforcer`] reports),
/// and `rss_bytes` (read from the kernel at scrape time via [`rss_bytes`]).
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    grants: Counter,
    grant_failures: Counter,
    revokes: Counter,
    expires: Counter,
    quota_kills: Counter,
    idle_kills: Counter,
    shaper_failures: Counter,
    redirect_rejections: Counter,
    started: Option<std::time::Instant>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        MetricsRegistry { started: Some(std::time::Instant::now()), ..Default::default() }
    }

    /// A grant was applied successfully.
    pub fn inc_grants(&self) {
        self.grants.inc();
    }

    /// A grant failed (session cap reached, writer/kernel error).
    pub fn inc_grant_failures(&self) {
        self.grant_failures.inc();
    }

    /// A session was revoked (admin/quota/MAC-change teardown).
    pub fn inc_revokes(&self) {
        self.revokes.inc();
    }

    /// A session hit its daemon-side expiry.
    pub fn inc_expires(&self) {
        self.expires.inc();
    }

    /// A session was revoked for exceeding its byte quota.
    pub fn inc_quota_kills(&self) {
        self.quota_kills.inc();
    }

    /// A session was torn down by the idle-timeout sweep.
    pub fn inc_idle_kills(&self) {
        self.idle_kills.inc();
    }

    /// A best-effort shaper apply/clear failed (QoS only).
    pub fn inc_shaper_failures(&self) {
        self.shaper_failures.inc();
    }

    /// The redirect responder rate-limited a request.
    pub fn inc_redirect_rejections(&self) {
        self.redirect_rejections.inc();
    }

    /// A point-in-time copy of every counter plus the uptime.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            grants: self.grants.get(),
            grant_failures: self.grant_failures.get(),
            revokes: self.revokes.get(),
            expires: self.expires.get(),
            quota_kills: self.quota_kills.get(),
            idle_kills: self.idle_kills.get(),
            shaper_failures: self.shaper_failures.get(),
            redirect_rejections: self.redirect_rejections.get(),
            // `Default` (used by tests) has no start instant → 0 uptime.
            uptime_secs: self.started.map(|s| s.elapsed().as_secs()).unwrap_or(0),
        }
    }
}

/// Plain-data view of a [`MetricsRegistry`] (see [`MetricsRegistry::snapshot`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub grants: u64,
    pub grant_failures: u64,
    pub revokes: u64,
    pub expires: u64,
    pub quota_kills: u64,
    pub idle_kills: u64,
    pub shaper_failures: u64,
    pub redirect_rejections: u64,
    pub uptime_secs: u64,
}

/// Resident-set size of this process in bytes, from `/proc/self/status`
/// (`VmRSS:`). Returns `0` when it cannot be read — notably on non-Linux dev
/// hosts (macOS), where `/proc` does not exist. The one deliberate exception
/// to this crate's "no I/O" rule: it reads only our own procfs entry, so it
/// stays kernel-agnostic and mock-free for every consumer.
pub fn rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| parse_vmrss_kb(&s))
            .map_or(0, |kb| kb.saturating_mul(1024))
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Extract the `VmRSS` value (kB) from a `/proc/self/status` document.
/// Kept separate (and compiled on every platform) so the parsing is
/// unit-testable on non-Linux dev hosts — where only the tests call it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_vmrss_kb(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok())
}

/// FNV-1a 64-bit over UTF-8 bytes. Deterministic across platforms/languages —
/// the control plane (Go) implements the same function over the same canonical
/// strings so config-state hashes compare equal (see `ConfigState`). Kept in
/// `types` so every crate hashes one way; covered by shared test vectors.
pub fn fnv1a64(s: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Snapshot of the control-plane-managed engine state, reduced to canonical
/// hashes (16 lowercase hex chars each, [`fnv1a64`]) so the control plane can
/// detect drift with one `GetEngineInfo` call instead of re-pushing on a
/// timer. Canonical forms are pinned in `proto/enforcement.proto` (EngineInfo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigState {
    pub tier_policies_hash: String,
    pub engine_params_hash: String,
    pub garden_hash: String,
    pub enforcement_enabled: bool,
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
    /// No metered traffic within `idle_timeout` (daemon expiry sweep).
    Idle,
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
    /// Idle-timeout teardown (RADIUS Acct-Terminate-Cause = Idle-Timeout).
    IdleTimeout,
}

impl From<RevokeReason> for EventKind {
    fn from(r: RevokeReason) -> Self {
        match r {
            RevokeReason::Quota => EventKind::QuotaExceeded,
            RevokeReason::Idle => EventKind::IdleTimeout,
            RevokeReason::Admin | RevokeReason::MacChange => EventKind::Revoked,
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
    /// Global enforcement gate: `true` = the engine is blocking unauthorized
    /// traffic (FORWARD/PREROUTING jumps installed); `false` = gate lifted, all
    /// traffic flows. Toggled via [`Enforcer::set_enforcement`].
    pub enforcement_enabled: bool,
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

    /// Toggle the global enforcement gate. `true` installs the FORWARD/PREROUTING
    /// jump rules (block unauthorized traffic); `false` removes them so all
    /// traffic flows. MUST leave the `auth` set and chains intact (idempotent).
    async fn set_enforcement(&self, enabled: bool) -> Result<()>;

    /// Replace the walled-garden IP sets atomically with the given resolved
    /// addresses (engine-resolver garden for routers without dnsmasq ipset
    /// support). Full-replace; MUST be atomic (no fail-open window).
    async fn replace_garden(
        &self,
        v4: Vec<std::net::Ipv4Addr>,
        v6: Vec<std::net::Ipv6Addr>,
    ) -> Result<()>;
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

    /// Number of sessions currently tracked (the `sessions_active` gauge in
    /// `GetMetrics`). Read-only and cheap — no kernel round-trip.
    async fn active_sessions(&self) -> usize;

    /// Set the global enforcement gate (admin toggle via control plane). On
    /// success the reported [`HealthStatus::enforcement_enabled`] reflects the
    /// new state. Fails closed: on backend error the prior state is kept.
    async fn set_enforcement(&self, enabled: bool) -> Result<()>;

    /// Current global enforcement gate state.
    async fn enforcement_enabled(&self) -> bool;

    /// Replace the pre-auth walled-garden FQDN list (control-plane managed).
    /// Full set, not a delta. Returns Err if no garden controller is wired.
    async fn set_garden(&self, fqdns: Vec<String>) -> Result<()>;

    /// Replace the fleet-wide per-tier grant defaults (control-plane managed).
    /// Full replacement, not a delta: any tier absent from `policies` is reset
    /// to its built-in default. Applied to subsequent grants (fills 0-valued
    /// grant fields, see [`TierPolicy`]). **RAM-only** — the control plane
    /// re-pushes on reconnect, so implementations MUST NOT persist this to flash
    /// (§5.4 no-NAND).
    async fn set_tier_policies(&self, policies: Vec<TierPolicy>) -> Result<()>;

    /// Apply a full snapshot of the runtime engine parameters (control-plane
    /// managed, see [`EngineParams`]). Implementations re-validate (defence in
    /// depth) and MUST NOT evict existing sessions when `max_sessions` drops
    /// below the current count — the lowered cap only blocks new grants (G2).
    /// **RAM-only**, like the tier policies.
    async fn set_engine_parameters(&self, params: EngineParams) -> Result<()>;

    /// Canonical hashes of the control-plane-managed state currently applied
    /// (drift detection, see [`ConfigState`]). Read-only and cheap.
    async fn config_state(&self) -> ConfigState;
}

/// Apply / clear a per-client bandwidth cap (TDD §7.7 — `tc`/HTB, download
/// direction). `rate_bps == 0` means unlimited. Shaping is **best-effort QoS**,
/// not enforcement: callers log-and-continue on error (quota/revoke remain the
/// hard gates). Implemented by `portcullis-accounting` (`TcShaper`/`NoopShaper`)
/// and wired into the `SessionManager` at composition time.
#[async_trait]
pub trait Shaper: Send + Sync {
    /// Cap `mac` to `rate_bps` bits/sec (download). `rate_bps == 0` clears any
    /// existing cap instead.
    async fn apply(&self, mac: MacAddr, rate_bps: u64) -> Result<()>;

    /// Remove any cap for `mac` (idempotent — clearing an unshaped MAC is Ok).
    async fn clear(&self, mac: MacAddr) -> Result<()>;
}

/// Control-plane-managed walled garden, implemented by `portcullis-garden`'s
/// manager and injected into the SessionManager. Replacing the FQDN list
/// reconciles the dnsmasq garden config (guarded by dnsmasq ipset support).
#[async_trait]
pub trait GardenControl: Send + Sync {
    async fn set_fqdns(&self, fqdns: Vec<String>) -> Result<()>;
}

/// Accounting-facing sink, implemented by the SessionManager and called by the
/// `portcullis-accounting` loop. Pushing a counter snapshot updates per-session
/// byte totals, emits `INTERIM` events, and triggers a quota revoke when
/// `bytes_in + bytes_out > quota_bytes` (TDD §7.6/§7.7).
#[async_trait]
pub trait MeteringSink: Send + Sync {
    async fn apply_counters(&self, snapshot: Vec<(MacAddr, Counters)>) -> Result<()>;
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
        // Conventional names parse and print verbatim.
        assert_eq!("retail".parse::<Tier>().unwrap().as_str(), "retail");
        assert_eq!("home".parse::<Tier>().unwrap().to_string(), "home");
        // Empty => the conventional default.
        assert_eq!("".parse::<Tier>().unwrap(), Tier::public());
        assert_eq!(Tier::default(), Tier::public());
        // Data-driven: any well-formed name is accepted.
        assert_eq!("gold".parse::<Tier>().unwrap().as_str(), "gold");
        assert_eq!("vip_2-a".parse::<Tier>().unwrap().as_str(), "vip_2-a");
    }

    #[test]
    fn tier_normalizes_trim_and_case() {
        assert_eq!("  Retail  ".parse::<Tier>().unwrap().as_str(), "retail");
        assert_eq!("GOLD".parse::<Tier>().unwrap(), "gold".parse::<Tier>().unwrap());
        assert_eq!("   ".parse::<Tier>().unwrap(), Tier::public());
    }

    #[test]
    fn tier_rejects_bad_charset_and_length() {
        assert!(matches!("plat!num".parse::<Tier>(), Err(Error::InvalidTier(_))));
        assert!(matches!("tier with spaces".parse::<Tier>(), Err(Error::InvalidTier(_))));
        assert!(matches!("tiếng".parse::<Tier>(), Err(Error::InvalidTier(_))));
        // 32 chars is the edge; 33 is out.
        assert!("a".repeat(32).parse::<Tier>().is_ok());
        assert!(matches!("a".repeat(33).parse::<Tier>(), Err(Error::InvalidTier(_))));
    }

    #[test]
    fn tier_serde_is_string() {
        let t: Tier = "gold".parse().unwrap();
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(j, "\"gold\"");
        let back: Tier = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
        // Deserialization normalizes/validates via FromStr.
        let up: Tier = serde_json::from_str("\"GOLD\"").unwrap();
        assert_eq!(up, t);
        assert!(serde_json::from_str::<Tier>("\"bad tier!\"").is_err());
    }

    #[test]
    fn fnv1a64_matches_shared_vectors() {
        // Golden vectors shared with the Go control plane (hash.go tests) —
        // any change here breaks cross-language drift detection.
        for (s, want) in [
            ("", "cbf29ce484222325"),
            ("a", "af63dc4c8601ec8c"),
            ("hello", "a430d84680aabd0b"),
            ("15:30:1:4096", "3dadbdd27d764902"),
            // Legacy v1 tiers canonical form — kept as a pure string→hash
            // vector (the live v2 tiers vectors are pinned in
            // portcullis-session's config_state tests).
            ("home:86400:0:0|public:7200:0:0|retail:28800:0:0", "f91fea58d22e1509"),
            ("cdn.wifihub.vn|portal.wifihub.vn", "c34e4b6bbbbe11ee"),
        ] {
            assert_eq!(format!("{:016x}", fnv1a64(s)), want, "vector {s:?}");
        }
    }

    #[test]
    fn tier_policy_default_is_public_and_zeroed() {
        let p = TierPolicy::default();
        assert_eq!(p.tier, Tier::public());
        assert_eq!(p.ttl, Duration::ZERO);
        assert_eq!(p.quota_bytes, 0);
        assert_eq!(p.rate_bps, 0);
        // Built-in TTL fallback matches the §9 config default.
        assert_eq!(DEFAULT_TTL, Duration::from_secs(1800));
        assert_eq!(DEFAULT_MAX_SESSIONS, 4096);
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
    fn metrics_registry_counts_and_snapshots() {
        let m = MetricsRegistry::new();
        assert_eq!(m.snapshot(), MetricsSnapshot { ..Default::default() });

        m.inc_grants();
        m.inc_grants();
        m.inc_grant_failures();
        m.inc_revokes();
        m.inc_expires();
        m.inc_quota_kills();
        m.inc_shaper_failures();
        m.inc_redirect_rejections();

        let s = m.snapshot();
        assert_eq!(s.grants, 2);
        assert_eq!(s.grant_failures, 1);
        assert_eq!(s.revokes, 1);
        assert_eq!(s.expires, 1);
        assert_eq!(s.quota_kills, 1);
        assert_eq!(s.shaper_failures, 1);
        assert_eq!(s.redirect_rejections, 1);
    }

    #[test]
    fn parse_vmrss_extracts_kb() {
        let status = "Name:\tportcullis\nVmPeak:\t  20000 kB\nVmRSS:\t   12345 kB\nThreads:\t1\n";
        assert_eq!(parse_vmrss_kb(status), Some(12345));
        assert_eq!(parse_vmrss_kb("Name:\tx\n"), None);
        assert_eq!(parse_vmrss_kb("VmRSS:\tnot-a-number kB\n"), None);
    }

    #[test]
    fn rss_bytes_is_platform_gated() {
        // Linux: our own procfs entry always has a VmRSS; elsewhere: 0.
        #[cfg(target_os = "linux")]
        assert!(rss_bytes() > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(rss_bytes(), 0);
    }
}
