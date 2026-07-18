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
    EngineInfoSnapshot, EngineParameters, Error, GrantParams, HealthStatus, MacAddr,
    MetricsSnapshot, PeerAllow, ProvisionState, Result, RevokeReason, SessionEvent, SessionId,
    SessionInfo, SsidSpec, Tier, TierPolicy, WirelessDesiredState, WirelessLiveness, WirelessStatus,
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
/// - `quota_bytes == 0` means *unlimited* and is carried through verbatim.
/// - `rate_bps == 0` means *unlimited* (no cap). A non-zero value is carried
///   through and enforced by the tc/HTB `Shaper` on grant (G5) — the engine
///   advertises the `shaper` capability (via `GetEngineInfo`) only when shaping
///   is actually enabled, so the control plane won't send a cap the engine can't
///   apply.
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

/// Fill a grant's unset (`0`) `ttl` / `quota` / `rate` from the named tier's
/// policy (G3a/G5) — a grant that names a user-group tier but omits limits
/// inherits that group's CP-pushed defaults.
pub fn apply_tier_defaults(req: &mut pb::GrantRequest, pol: &TierPolicy) {
    if req.ttl_seconds == 0 {
        req.ttl_seconds = pol.ttl_secs;
    }
    if req.quota_bytes == 0 {
        req.quota_bytes = pol.quota_bytes;
    }
    if req.rate_bps == 0 {
        req.rate_bps = pol.rate_bps;
    }
}

/// Wire [`pb::SetTierPoliciesRequest`] -> domain tier policies (G3a). Validation
/// (name shape, duplicates) is done by the [`EngineControl`] impl on apply.
///
/// [`EngineControl`]: portcullis_types::EngineControl
pub fn tier_policies_from_pb(req: pb::SetTierPoliciesRequest) -> Vec<TierPolicy> {
    req.policies
        .into_iter()
        .map(|p| TierPolicy {
            tier: p.tier,
            ttl_secs: p.ttl_seconds,
            quota_bytes: p.quota_bytes,
            rate_bps: p.rate_bps,
        })
        .collect()
}

/// Wire [`pb::SetEngineParametersRequest`] -> domain [`EngineParameters`] (G3a).
/// Per the proto, `0` means "use the engine built-in default" for every field
/// EXCEPT `idle_timeout_secs`, where `0` means "disabled". Bounds are enforced by
/// [`EngineParameters::validate`] on apply.
pub fn engine_params_from_pb(req: pb::SetEngineParametersRequest) -> EngineParameters {
    let d = EngineParameters::default();
    let or_default = |v: u32, dflt: u32| if v == 0 { dflt } else { v };
    EngineParameters {
        accounting_interval_secs: or_default(req.accounting_interval_secs, d.accounting_interval_secs),
        garden_tick_secs: or_default(req.garden_tick_secs, d.garden_tick_secs),
        expiry_tick_secs: or_default(req.expiry_tick_secs, d.expiry_tick_secs),
        max_sessions: or_default(req.max_sessions, d.max_sessions),
        idle_timeout_secs: req.idle_timeout_secs, // 0 = disabled (kept verbatim)
    }
}

/// Domain [`EngineInfoSnapshot`] -> wire [`pb::EngineInfo`] (G4). Fields this
/// snapshot doesn't own (event seqs, wireless hash) default to 0/empty.
pub fn engine_info_to_pb(info: EngineInfoSnapshot) -> pb::EngineInfo {
    pb::EngineInfo {
        version: info.version,
        boot_id: info.boot_id,
        capabilities: info.capabilities,
        enforcement_enabled: info.enforcement_enabled,
        tier_policies_hash: info.tier_policies_hash,
        engine_params_hash: info.engine_params_hash,
        garden_hash: info.garden_hash,
        ..Default::default()
    }
}

/// Domain [`MetricsSnapshot`] -> wire [`pb::MetricsReply`] (G4). Counters the
/// snapshot doesn't carry (grant_failures, event buffer, shaper, rss) default to 0.
pub fn metrics_to_pb(m: MetricsSnapshot) -> pb::MetricsReply {
    pb::MetricsReply {
        sessions_active: m.sessions_active,
        grants_total: m.grants_total,
        revokes_total: m.revokes_total,
        expires_total: m.expires_total,
        quota_kills_total: m.quota_kills_total,
        shaper_failures_total: m.shaper_failures_total,
        idle_kills_total: m.idle_kills_total,
        ..Default::default()
    }
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
        // Idle-timeout is engine-initiated and surfaced to the CP as an
        // `IDLE_TIMEOUT` *event* (EventKind), not a wire Revoke *reason* (the CP
        // never issues an idle revoke). This direction is only used in tests; map
        // to the generic Admin reason for totality.
        RevokeReason::IdleTimeout => pb::RevokeReason::RevokeAdmin,
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
        E::IdleTimeout => pb::EventKind::IdleTimeout,
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
        pb::EventKind::IdleTimeout => E::IdleTimeout,
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
        // Per-boot monotonic sequence (superset proto). Event replay/resume is
        // not wired yet; emit 0 (= pre-replay engine, per the proto comment).
        seq: 0,
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
        // Global enforcement gate (superset proto). The on/off toggle is not
        // wired into HealthStatus yet; report enabled (the fail-closed default —
        // the engine enforces unless explicitly told otherwise).
        enforcement_enabled: true,
    }
}

// ---------------------------------------------------------------------------
// Provisioning lifecycle state -> wire (shared by the wireless status mapping).
// ---------------------------------------------------------------------------

fn provision_state_to_pb(s: ProvisionState) -> pb::ProvisionState {
    match s {
        ProvisionState::AppliedPending => pb::ProvisionState::ProvisionAppliedPending,
        ProvisionState::Committed => pb::ProvisionState::ProvisionCommitted,
        ProvisionState::RolledBack => pb::ProvisionState::ProvisionRolledBack,
        ProvisionState::Failed => pb::ProvisionState::ProvisionFailed,
    }
}

// ---------------------------------------------------------------------------
// CP-managed wireless (P-W1): pb::SetWirelessConfigRequest -> domain
// WirelessDesiredState, and domain WirelessStatus / WirelessDesiredState -> pb.
// Keys (PSKs) are REDACTED on the way out (the engine never echoes secrets).
// ---------------------------------------------------------------------------

/// Translate one wire [`pb::WirelessSsid`] into the domain [`SsidSpec`]
/// (flattening the nested network/firewall submessages). Field-level validation
/// lives in `portcullis-provision::validate_wireless`; this is a total copy.
pub fn wireless_ssid_from_pb(s: pb::WirelessSsid) -> SsidSpec {
    let net = s.network.unwrap_or_default();
    let fw = s.firewall.unwrap_or_default();
    SsidSpec {
        slug: s.slug,
        ssid: s.ssid,
        radios: s.radios,
        encryption: s.encryption,
        key: s.key,
        hidden: s.hidden,
        isolate: s.isolate,
        gated: s.gated,
        bridge_name: net.bridge_name,
        ipaddr: net.ipaddr,
        netmask: net.netmask,
        dhcp_start: net.dhcp_start,
        dhcp_limit: net.dhcp_limit,
        dhcp_leasetime: net.dhcp_leasetime,
        dhcp_disabled: net.dhcp_disabled,
        egress_zone: fw.egress_zone,
        max_clients: s.max_clients,
        mac_policy: s.mac_policy,
        mac_list: s.mac_list,
        rate_down_kbps: s.rate_down_kbps,
        rate_up_kbps: s.rate_up_kbps,
        mode: s.mode,
        ieee80211r: s.ieee80211r,
        ieee80211w: s.ieee80211w,
    }
}

/// Translate a wire [`pb::SetWirelessConfigRequest`] into the domain desired-state
/// the provision subsystem consumes.
pub fn wireless_config_from_pb(req: pb::SetWirelessConfigRequest) -> WirelessDesiredState {
    WirelessDesiredState {
        config_version: req.config_version,
        ssids: req.ssids.into_iter().map(wireless_ssid_from_pb).collect(),
        confirm_timeout_secs: req.confirm_timeout_secs,
        peer_allows: req
            .peer_allows
            .into_iter()
            .map(|p| PeerAllow { from_slug: p.from_slug, to_slug: p.to_slug })
            .collect(),
    }
}

/// Map a domain [`WirelessStatus`] to the wire `EngineFrame.wireless_status`.
/// (Status carries no secrets — only slugs/ifaces/verdicts.)
pub fn wireless_status_to_pb(s: &WirelessStatus) -> pb::WirelessStatus {
    pb::WirelessStatus {
        config_version: s.config_version.clone(),
        state: provision_state_to_pb(s.state) as i32,
        per_ssid: s
            .per_ssid
            .iter()
            .map(|r| pb::SsidResult {
                slug: r.slug.clone(),
                ok: r.ok,
                message: r.message.clone(),
                iface: r.iface.clone(),
            })
            .collect(),
        message: s.message.clone(),
    }
}

/// Map a domain [`WirelessLiveness`] snapshot to the wire
/// `EngineFrame.wireless_liveness` (P5). Purely observational — no secrets.
pub fn wireless_liveness_to_pb(lv: &WirelessLiveness) -> pb::WirelessLiveness {
    pb::WirelessLiveness {
        config_version: lv.config_version.clone(),
        per_ssid: lv
            .per_ssid
            .iter()
            .map(|s| pb::SsidLiveness {
                slug: s.slug.clone(),
                iface: s.iface.clone(),
                broadcasting: s.broadcasting,
                stations: s.stations,
                signal_dbm: s.signal_dbm,
            })
            .collect(),
        ts_unix: lv.ts_unix,
    }
}

/// Map the committed domain [`WirelessDesiredState`] to the `get_wireless_config`
/// reply. PSK keys are **REDACTED** (emptied): the engine never echoes a secret
/// back over the wire, even to the control plane that set it.
pub fn wireless_config_to_pb(state: &WirelessDesiredState) -> pb::WirelessConfig {
    pb::WirelessConfig {
        config_version: state.config_version.clone(),
        ssids: state.ssids.iter().map(ssid_spec_to_pb_redacted).collect(),
    }
}

fn ssid_spec_to_pb_redacted(s: &SsidSpec) -> pb::WirelessSsid {
    pb::WirelessSsid {
        slug: s.slug.clone(),
        ssid: s.ssid.clone(),
        radios: s.radios.clone(),
        encryption: s.encryption.clone(),
        key: String::new(), // REDACTED — never echo the PSK
        hidden: s.hidden,
        isolate: s.isolate,
        gated: s.gated,
        network: Some(pb::WirelessNetwork {
            bridge_name: s.bridge_name.clone(),
            ipaddr: s.ipaddr.clone(),
            netmask: s.netmask.clone(),
            dhcp_start: s.dhcp_start.clone(),
            dhcp_limit: s.dhcp_limit.clone(),
            dhcp_leasetime: s.dhcp_leasetime.clone(),
            dhcp_disabled: s.dhcp_disabled,
        }),
        firewall: Some(pb::WirelessFirewall { egress_zone: s.egress_zone.clone() }),
        max_clients: s.max_clients,
        mac_policy: s.mac_policy.clone(),
        mac_list: s.mac_list.clone(),
        rate_down_kbps: s.rate_down_kbps,
        rate_up_kbps: s.rate_up_kbps,
        mode: s.mode.clone(),
        ieee80211r: s.ieee80211r,
        ieee80211w: s.ieee80211w.clone(),
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
    fn grant_request_rate_bps_carried_through() {
        // G5: a non-zero rate is now accepted and carried through to be enforced
        // by the tc/HTB shaper (was rejected in Phase 1).
        let mut g = sample_grant();
        g.rate_bps = 2_000_000;
        assert_eq!(grant_request_to_params(g).unwrap().rate_bps, 2_000_000);
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
    fn wireless_status_maps_provision_states() {
        // provision_state_to_pb is exercised via the wireless status mapping.
        let cases = [
            (ProvisionState::AppliedPending, pb::ProvisionState::ProvisionAppliedPending),
            (ProvisionState::Committed, pb::ProvisionState::ProvisionCommitted),
            (ProvisionState::RolledBack, pb::ProvisionState::ProvisionRolledBack),
            (ProvisionState::Failed, pb::ProvisionState::ProvisionFailed),
        ];
        for (domain, wire) in cases {
            let s = WirelessStatus {
                config_version: "cfg".into(),
                state: domain,
                per_ssid: Vec::new(),
                message: "m".into(),
            };
            assert_eq!(wireless_status_to_pb(&s).state, wire as i32);
        }
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

    // --- CP-managed wireless (P-W1) ----------------------------------------

    fn pb_ssid(slug: &str, gated: bool, key: &str) -> pb::WirelessSsid {
        pb::WirelessSsid {
            slug: slug.into(),
            ssid: format!("WifiHub {slug}"),
            radios: vec!["radio0".into()],
            encryption: if gated { "none".into() } else { "psk2".into() },
            key: key.into(),
            hidden: false,
            isolate: true,
            gated,
            network: Some(pb::WirelessNetwork {
                bridge_name: format!("br-{slug}"),
                ipaddr: "10.0.0.1".into(),
                netmask: "255.255.255.0".into(),
                dhcp_start: "10".into(),
                dhcp_limit: "200".into(),
                dhcp_leasetime: "2h".into(),
                dhcp_disabled: false,
            }),
            firewall: Some(pb::WirelessFirewall { egress_zone: "wan".into() }),
            max_clients: 0,
            mac_policy: String::new(),
            mac_list: Vec::new(),
            rate_down_kbps: 0,
            rate_up_kbps: 0,
            mode: String::new(),
            ieee80211r: false,
            ieee80211w: String::new(),
        }
    }

    #[test]
    fn wireless_config_from_pb_flattens_ssids() {
        let req = pb::SetWirelessConfigRequest {
            config_version: "cfg-1".into(),
            ssids: vec![pb_ssid("public", true, ""), pb_ssid("home", false, "supersecret")],
            confirm_timeout_secs: 90,
            peer_allows: Vec::new(),
        };
        let st = wireless_config_from_pb(req);
        assert_eq!(st.config_version, "cfg-1");
        assert_eq!(st.confirm_timeout_secs, 90);
        assert_eq!(st.ssids.len(), 2);
        let home = st.ssids.iter().find(|s| s.slug == "home").unwrap();
        assert_eq!(home.bridge_name, "br-home");
        assert_eq!(home.egress_zone, "wan");
        assert_eq!(home.key, "supersecret");
        assert!(!home.gated);
        // Default: no peer allows => full isolation (unchanged behaviour).
        assert!(st.peer_allows.is_empty());
    }

    #[test]
    fn wireless_config_from_pb_maps_peer_allows() {
        let req = pb::SetWirelessConfigRequest {
            config_version: "cfg-1".into(),
            ssids: vec![pb_ssid("public", true, ""), pb_ssid("staff", false, "supersecret")],
            confirm_timeout_secs: 0,
            peer_allows: vec![pb::WirelessPeerAllow {
                from_slug: "public".into(),
                to_slug: "staff".into(),
            }],
        };
        let st = wireless_config_from_pb(req);
        assert_eq!(st.peer_allows.len(), 1);
        assert_eq!(st.peer_allows[0].from_slug, "public");
        assert_eq!(st.peer_allows[0].to_slug, "staff");
    }

    #[test]
    fn wireless_config_to_pb_redacts_keys() {
        // The get_wireless reply must NEVER echo a PSK back over the wire.
        let state = WirelessDesiredState {
            config_version: "cfg-2".into(),
            confirm_timeout_secs: 0,
            peer_allows: Vec::new(),
            ssids: vec![SsidSpec {
                slug: "home".into(),
                ssid: "Staff".into(),
                radios: vec!["radio0".into()],
                encryption: "psk2".into(),
                key: "supersecret".into(),
                hidden: false,
                isolate: true,
                gated: false,
                bridge_name: "br-home".into(),
                ipaddr: "10.1.0.1".into(),
                netmask: "255.255.255.0".into(),
                dhcp_start: "10".into(),
                dhcp_limit: "200".into(),
                dhcp_leasetime: "2h".into(),
                dhcp_disabled: false,
                egress_zone: String::new(),
                max_clients: 0,
                mac_policy: String::new(),
                mac_list: Vec::new(),
                rate_down_kbps: 0,
                rate_up_kbps: 0,
                mode: String::new(),
                ieee80211r: false,
                ieee80211w: String::new(),
            }],
        };
        let pb = wireless_config_to_pb(&state);
        assert_eq!(pb.config_version, "cfg-2");
        assert_eq!(pb.ssids.len(), 1);
        assert_eq!(pb.ssids[0].key, "", "PSK must be redacted in the reply");
        // Non-secret fields are preserved.
        assert_eq!(pb.ssids[0].encryption, "psk2");
        assert_eq!(pb.ssids[0].network.as_ref().unwrap().bridge_name, "br-home");
    }

    #[test]
    fn wireless_status_maps_states_and_per_ssid() {
        let s = WirelessStatus {
            config_version: "cfg-3".into(),
            state: ProvisionState::Committed,
            per_ssid: vec![portcullis_types::SsidResult {
                slug: "public".into(),
                ok: true,
                message: String::new(),
                iface: "br-public".into(),
            }],
            message: "confirmed".into(),
        };
        let pb = wireless_status_to_pb(&s);
        assert_eq!(pb.config_version, "cfg-3");
        assert_eq!(pb.state, pb::ProvisionState::ProvisionCommitted as i32);
        assert_eq!(pb.per_ssid.len(), 1);
        assert_eq!(pb.per_ssid[0].iface, "br-public");
    }

    // ---- config-push conversions (G3a) ----

    #[test]
    fn apply_tier_defaults_fills_unset_ttl_quota_and_rate() {
        let pol = TierPolicy { tier: "vip".into(), ttl_secs: 7200, quota_bytes: 5_000, rate_bps: 999 };
        // All three unset (0) -> filled from the tier (G3a ttl/quota, G5 rate).
        let mut a = pb::GrantRequest { ttl_seconds: 0, quota_bytes: 0, rate_bps: 0, ..Default::default() };
        apply_tier_defaults(&mut a, &pol);
        assert_eq!(a.ttl_seconds, 7200);
        assert_eq!(a.quota_bytes, 5_000);
        assert_eq!(a.rate_bps, 999);
        // explicit non-zero values are preserved (not overwritten by the tier).
        let mut b =
            pb::GrantRequest { ttl_seconds: 60, quota_bytes: 100, rate_bps: 42, ..Default::default() };
        apply_tier_defaults(&mut b, &pol);
        assert_eq!(b.ttl_seconds, 60);
        assert_eq!(b.quota_bytes, 100);
        assert_eq!(b.rate_bps, 42);
    }

    #[test]
    fn engine_params_from_pb_maps_zero_to_default_except_idle() {
        let d = EngineParameters::default();
        let req = pb::SetEngineParametersRequest {
            accounting_interval_secs: 0, // -> default
            garden_tick_secs: 45,        // -> kept
            expiry_tick_secs: 0,         // -> default
            max_sessions: 0,             // -> default
            idle_timeout_secs: 0,        // -> stays 0 (disabled), NOT default
        };
        let p = engine_params_from_pb(req);
        assert_eq!(p.accounting_interval_secs, d.accounting_interval_secs);
        assert_eq!(p.garden_tick_secs, 45);
        assert_eq!(p.expiry_tick_secs, d.expiry_tick_secs);
        assert_eq!(p.max_sessions, d.max_sessions);
        assert_eq!(p.idle_timeout_secs, 0, "idle 0 = disabled, must not become a default");
    }

    #[test]
    fn tier_policies_from_pb_maps_fields() {
        let req = pb::SetTierPoliciesRequest {
            policies: vec![pb::TierPolicy {
                tier: "home".into(),
                ttl_seconds: 3600,
                quota_bytes: 1_000,
                rate_bps: 2_000,
            }],
        };
        let out = tier_policies_from_pb(req);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tier, "home");
        assert_eq!(out[0].ttl_secs, 3600);
        assert_eq!(out[0].rate_bps, 2_000);
    }
}
