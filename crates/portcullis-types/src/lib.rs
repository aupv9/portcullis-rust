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
}

impl From<RevokeReason> for EventKind {
    fn from(r: RevokeReason) -> Self {
        match r {
            RevokeReason::Quota => EventKind::QuotaExceeded,
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

    /// Set the global enforcement gate (admin toggle via control plane). On
    /// success the reported [`HealthStatus::enforcement_enabled`] reflects the
    /// new state. Fails closed: on backend error the prior state is kept.
    async fn set_enforcement(&self, enabled: bool) -> Result<()>;

    /// Current global enforcement gate state.
    async fn enforcement_enabled(&self) -> bool;

    /// Replace the pre-auth walled-garden FQDN list (control-plane managed).
    /// Full set, not a delta. Returns Err if no garden controller is wired.
    async fn set_garden(&self, fqdns: Vec<String>) -> Result<()>;
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
}
