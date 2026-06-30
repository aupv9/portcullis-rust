//! PURE proto <-> `portcullis_types` conversions (TDD §7.5).
//!
//! No I/O, no async, no kernel. Every mapping here is unit-tested for
//! round-trip / rejection behaviour. Validation failures are surfaced as
//! `portcullis_types::Error` (never silently defaulted) so that the gRPC
//! layer can reject a bad grant instead of failing open (§11, §13).

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use portcullis_types::{
    Error, GrantParams, HealthStatus, MacAddr, Result, RevokeReason, SessionEvent, SessionId,
    SessionInfo, Tier,
};

use crate::pb;

// ---------------------------------------------------------------------------
// GrantRequest -> GrantParams
// ---------------------------------------------------------------------------

/// Parse and validate a wire [`pb::GrantRequest`] into a domain [`GrantParams`].
///
/// Validation rules (§7.5):
/// - `client_mac` is parsed via [`MacAddr::from_str`]; an invalid MAC is
///   **rejected** (no fail-open default).
/// - `tier` is parsed via [`Tier::from_str`] (empty string => `public`); an
///   unknown tier is rejected.
/// - `client_ip` is optional/informational: empty => `None`; a non-empty but
///   unparseable IP is rejected (it would otherwise be silently dropped).
/// - `ttl_seconds` -> [`Duration`] (the nft set-element timeout).
/// - `quota_bytes == 0` and `rate_bps == 0` both mean *unlimited* and are
///   carried through verbatim (the domain layer interprets `0`).
pub fn grant_request_to_params(req: pb::GrantRequest) -> Result<GrantParams> {
    let mac = MacAddr::from_str(&req.client_mac)?;
    let tier = Tier::from_str(&req.tier)?;

    let ip = parse_optional_ip(&req.client_ip)?;

    Ok(GrantParams {
        store_id: req.store_id,
        mac,
        ip,
        ttl: Duration::from_secs(u64::from(req.ttl_seconds)),
        quota_bytes: req.quota_bytes,
        rate_bps: req.rate_bps,
        tier,
        session_id: SessionId::from(req.session_id),
    })
}

/// Parse a wire MAC string into a [`MacAddr`], rejecting anything malformed.
/// Shared by the request paths that key on a raw `client_mac` (Revoke / Get).
pub fn parse_mac(s: &str) -> Result<MacAddr> {
    MacAddr::from_str(s)
}

/// Empty string => informational IP absent; otherwise must parse.
fn parse_optional_ip(s: &str) -> Result<Option<IpAddr>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<IpAddr>()
        .map(Some)
        .map_err(|_| Error::BadRequest(format!("invalid client_ip: {s}")))
}

// ---------------------------------------------------------------------------
// SessionInfo (domain) -> pb::SessionInfo
// ---------------------------------------------------------------------------

/// `expires_in` is rendered to whole seconds (the proto field is `uint32`);
/// values are saturated rather than wrapped so a long TTL never reports a
/// nonsensically small remaining time.
pub fn session_info_to_pb(info: &SessionInfo) -> pb::SessionInfo {
    pb::SessionInfo {
        session_id: info.session_id.as_str().to_owned(),
        client_mac: info.mac.to_canonical(),
        client_ip: info.ip.map(|ip| ip.to_string()).unwrap_or_default(),
        tier: info.tier.to_string(),
        granted_at_unix: info.granted_at_unix,
        expires_in_secs: u32::try_from(info.expires_in.as_secs()).unwrap_or(u32::MAX),
        quota_bytes: info.quota_bytes,
        rate_bps: info.rate_bps,
        bytes_in: info.bytes_in,
        bytes_out: info.bytes_out,
    }
}

// ---------------------------------------------------------------------------
// RevokeReason <-> pb::RevokeReason
// ---------------------------------------------------------------------------

/// Map a wire revoke reason to the domain enum. Tonic decodes an unknown enum
/// value to `0` (proto3 open-enum semantics), so anything we don't recognise
/// is treated as `Admin` — the safest (most restrictive) interpretation.
pub fn revoke_reason_from_pb(r: pb::RevokeReason) -> RevokeReason {
    match r {
        pb::RevokeReason::RevokeAdmin => RevokeReason::Admin,
        pb::RevokeReason::RevokeQuota => RevokeReason::Quota,
        pb::RevokeReason::RevokeMacChange => RevokeReason::MacChange,
    }
}

pub fn revoke_reason_to_pb(r: RevokeReason) -> pb::RevokeReason {
    match r {
        RevokeReason::Admin => pb::RevokeReason::RevokeAdmin,
        RevokeReason::Quota => pb::RevokeReason::RevokeQuota,
        RevokeReason::MacChange => pb::RevokeReason::RevokeMacChange,
    }
}

// ---------------------------------------------------------------------------
// SessionEvent (domain) -> pb::SessionEvent
// ---------------------------------------------------------------------------

pub fn event_kind_to_pb(k: portcullis_types::EventKind) -> pb::EventKind {
    use portcullis_types::EventKind as E;
    match k {
        E::Granted => pb::EventKind::Granted,
        E::Interim => pb::EventKind::Interim,
        E::Expired => pb::EventKind::Expired,
        E::Revoked => pb::EventKind::Revoked,
        E::QuotaExceeded => pb::EventKind::QuotaExceeded,
    }
}

pub fn event_kind_from_pb(k: pb::EventKind) -> portcullis_types::EventKind {
    use portcullis_types::EventKind as E;
    match k {
        pb::EventKind::Granted => E::Granted,
        pb::EventKind::Interim => E::Interim,
        pb::EventKind::Expired => E::Expired,
        pb::EventKind::Revoked => E::Revoked,
        pb::EventKind::QuotaExceeded => E::QuotaExceeded,
    }
}

pub fn session_event_to_pb(ev: &SessionEvent) -> pb::SessionEvent {
    pb::SessionEvent {
        session_id: ev.session_id.as_str().to_owned(),
        client_mac: ev.mac.to_canonical(),
        kind: event_kind_to_pb(ev.kind) as i32,
        bytes_in: ev.bytes_in,
        bytes_out: ev.bytes_out,
        ts_unix: ev.ts_unix,
    }
}

// ---------------------------------------------------------------------------
// HealthStatus (domain) -> pb::HealthReply
// ---------------------------------------------------------------------------

pub fn health_to_pb(h: HealthStatus) -> pb::HealthReply {
    pb::HealthReply {
        backend_ok: h.backend_ok,
        kernel_table_present: h.kernel_table_present,
        cp_connected: h.cp_connected,
        last_reconcile_ok: h.last_reconcile_ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_grant() -> pb::GrantRequest {
        pb::GrantRequest {
            store_id: "store-7".into(),
            client_mac: "aa:bb:cc:dd:ee:ff".into(),
            client_ip: "10.1.2.3".into(),
            ttl_seconds: 3600,
            quota_bytes: 0,
            rate_bps: 0,
            tier: "retail".into(),
            session_id: "sess-123".into(),
        }
    }

    #[test]
    fn grant_request_parses_fully() {
        let p = grant_request_to_params(sample_grant()).unwrap();
        assert_eq!(p.store_id, "store-7");
        assert_eq!(p.mac.to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(p.ip, Some("10.1.2.3".parse().unwrap()));
        assert_eq!(p.ttl, Duration::from_secs(3600));
        assert_eq!(p.quota_bytes, 0); // unlimited
        assert_eq!(p.rate_bps, 0); // unlimited
        assert_eq!(p.tier, Tier::Retail);
        assert_eq!(p.session_id, SessionId("sess-123".into()));
    }

    #[test]
    fn grant_request_invalid_mac_rejected() {
        let mut g = sample_grant();
        g.client_mac = "not-a-mac".into();
        let err = grant_request_to_params(g).unwrap_err();
        assert!(matches!(err, Error::InvalidMac(_)));
    }

    #[test]
    fn grant_request_invalid_tier_rejected() {
        let mut g = sample_grant();
        g.tier = "platinum".into();
        let err = grant_request_to_params(g).unwrap_err();
        assert!(matches!(err, Error::InvalidTier(_)));
    }

    #[test]
    fn grant_request_empty_tier_is_public() {
        let mut g = sample_grant();
        g.tier = "".into();
        assert_eq!(grant_request_to_params(g).unwrap().tier, Tier::Public);
    }

    #[test]
    fn grant_request_empty_ip_is_none() {
        let mut g = sample_grant();
        g.client_ip = "".into();
        assert_eq!(grant_request_to_params(g).unwrap().ip, None);
    }

    #[test]
    fn grant_request_garbage_ip_rejected() {
        let mut g = sample_grant();
        g.client_ip = "999.999.999.999".into();
        let err = grant_request_to_params(g).unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn session_info_roundtrips_fields() {
        let info = SessionInfo {
            session_id: SessionId("s1".into()),
            mac: "01:02:03:04:05:06".parse().unwrap(),
            ip: Some("192.168.0.9".parse().unwrap()),
            tier: Tier::Home,
            granted_at_unix: 1_700_000_000,
            expires_in: Duration::from_secs(120),
            quota_bytes: 1_000_000,
            rate_bps: 2_000_000,
            bytes_in: 10,
            bytes_out: 20,
        };
        let pb = session_info_to_pb(&info);
        assert_eq!(pb.session_id, "s1");
        assert_eq!(pb.client_mac, "01:02:03:04:05:06");
        assert_eq!(pb.client_ip, "192.168.0.9");
        assert_eq!(pb.tier, "home");
        assert_eq!(pb.granted_at_unix, 1_700_000_000);
        assert_eq!(pb.expires_in_secs, 120);
        assert_eq!(pb.quota_bytes, 1_000_000);
        assert_eq!(pb.rate_bps, 2_000_000);
        assert_eq!(pb.bytes_in, 10);
        assert_eq!(pb.bytes_out, 20);
    }

    #[test]
    fn session_info_no_ip_is_empty_string() {
        let info = SessionInfo {
            session_id: SessionId("s1".into()),
            mac: "01:02:03:04:05:06".parse().unwrap(),
            ip: None,
            tier: Tier::Public,
            granted_at_unix: 0,
            expires_in: Duration::ZERO,
            quota_bytes: 0,
            rate_bps: 0,
            bytes_in: 0,
            bytes_out: 0,
        };
        assert_eq!(session_info_to_pb(&info).client_ip, "");
    }

    #[test]
    fn session_info_expiry_saturates() {
        let info = SessionInfo {
            session_id: SessionId("s1".into()),
            mac: "01:02:03:04:05:06".parse().unwrap(),
            ip: None,
            tier: Tier::Public,
            granted_at_unix: 0,
            expires_in: Duration::from_secs(u64::from(u32::MAX) + 100),
            quota_bytes: 0,
            rate_bps: 0,
            bytes_in: 0,
            bytes_out: 0,
        };
        assert_eq!(session_info_to_pb(&info).expires_in_secs, u32::MAX);
    }

    #[test]
    fn revoke_reason_roundtrips() {
        for r in [RevokeReason::Admin, RevokeReason::Quota, RevokeReason::MacChange] {
            assert_eq!(revoke_reason_from_pb(revoke_reason_to_pb(r)), r);
        }
    }

    #[test]
    fn event_kind_roundtrips() {
        use portcullis_types::EventKind as E;
        for k in [E::Granted, E::Interim, E::Expired, E::Revoked, E::QuotaExceeded] {
            assert_eq!(event_kind_from_pb(event_kind_to_pb(k)), k);
        }
    }

    #[test]
    fn session_event_to_pb_maps_fields() {
        let ev = SessionEvent {
            session_id: SessionId("s1".into()),
            mac: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            kind: portcullis_types::EventKind::QuotaExceeded,
            bytes_in: 100,
            bytes_out: 200,
            ts_unix: 1_700_000_123,
        };
        let pb = session_event_to_pb(&ev);
        assert_eq!(pb.session_id, "s1");
        assert_eq!(pb.client_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(pb.kind, pb::EventKind::QuotaExceeded as i32);
        assert_eq!(pb.bytes_in, 100);
        assert_eq!(pb.bytes_out, 200);
        assert_eq!(pb.ts_unix, 1_700_000_123);
    }

    #[test]
    fn health_maps_all_flags() {
        let h = HealthStatus {
            backend_ok: true,
            kernel_table_present: false,
            cp_connected: true,
            last_reconcile_ok: false,
        };
        let pb = health_to_pb(h);
        assert!(pb.backend_ok);
        assert!(!pb.kernel_table_present);
        assert!(pb.cp_connected);
        assert!(!pb.last_reconcile_ok);
    }
}
