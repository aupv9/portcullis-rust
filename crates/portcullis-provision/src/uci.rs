//! Pure, testable UCI rendering + validation for the hotspot provision
//! subsystem (P0.5). No I/O, no async — every function here is a unit test away
//! from the reference desired-state UCI in `docs/design/hotspot-service-plan.md`.
//!
//! ## The hard allowlist (load-bearing)
//!
//! The subsystem may read/write ONLY these NINE fixed section keys:
//!
//! | key                       | UCI config | type        | purpose                       |
//! |---------------------------|------------|-------------|-------------------------------|
//! | `network.br_hotspot`      | `network`  | `device`    | the bridge                    |
//! | `network.hotspot`         | `network`  | `interface` | subnet on the bridge          |
//! | `wireless.wifi_hotspot`   | `wireless` | `wifi-iface`| the public AP                 |
//! | `dhcp.hotspot`            | `dhcp`     | `dhcp`      | guest DHCP pool               |
//! | `firewall.hotspot`        | `firewall` | `zone`      | the hotspot zone (secure)     |
//! | `firewall.hotspot_fwd`    | `firewall` | `forwarding`| hotspot → wan (NAT breakout)  |
//! | `firewall.hotspot_dhcp`   | `firewall` | `rule`      | allow guest DHCP (udp/67)     |
//! | `firewall.hotspot_dns`    | `firewall` | `rule`      | allow guest DNS (tcp+udp/53)  |
//! | `firewall.hotspot_portal` | `firewall` | `rule`      | allow the redirect responder  |
//!
//! It NEVER touches `network.lan` / br-lan, admin config, the existing
//! `firewall.lan` / `firewall.wan` / anonymous fw zones, or the enforcement
//! `inet wifihub` table. [`validate`] rejects any spec that would; [`OWNED`] is
//! the single source of truth for what "owned" means (used by the snapshot
//! filter too, so a snapshot can never capture a non-owned section).

use portcullis_types::{ProvisionError, ProvisionSpec};

/// The nine owned UCI sections — the entire config surface this subsystem may
/// touch, as `<config>.<section>` keys. The snapshot filter and the apply batch
/// are both derived from this list so they can never diverge. All are NAMED
/// sections (not anonymous), so every `uci set` is idempotent.
pub const OWNED: [&str; 9] = [
    "network.br_hotspot",
    "network.hotspot",
    "wireless.wifi_hotspot",
    "dhcp.hotspot",
    "firewall.hotspot",
    "firewall.hotspot_fwd",
    "firewall.hotspot_dhcp",
    "firewall.hotspot_dns",
    "firewall.hotspot_portal",
];

/// The UCI `config`s (top-level files) the reload touches. Commit order:
/// `uci commit network wireless dhcp firewall` (firewall last — its zone
/// references the `hotspot` interface, so the interface must be committed first).
pub const OWNED_CONFIGS: [&str; 4] = ["network", "wireless", "dhcp", "firewall"];

/// The WAN firewall zone the hotspot forwards out through. On RUTOS (RUT200/
/// RUTM11) the default WAN zone is named `wan` and already carries `masq '1'`
/// (network `wan wan6 mob1s1a1`), so `hotspot → wan` forwarding is masqueraded
/// by the EXISTING wan zone — we deliberately do NOT set masq on the hotspot
/// zone. NOTE: adjust this const if deploying on a non-RUTOS OpenWrt whose WAN
/// zone is named differently.
pub const WAN_ZONE: &str = "wan";

/// Default local commit-confirm watchdog window (seconds) when the spec leaves
/// `confirm_timeout_secs == 0`.
pub const DEFAULT_CONFIRM_TIMEOUT_SECS: u32 = 90;
/// Lower bound on the confirm window (design doc: `[15, 600]`).
pub const MIN_CONFIRM_TIMEOUT_SECS: u32 = 15;
/// Upper bound on the confirm window.
pub const MAX_CONFIRM_TIMEOUT_SECS: u32 = 600;

/// A single `uci` mutation in the apply/teardown batch. Rendered to explicit
/// argv (never a shell string) by the [`crate::runner::CommandRunner`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UciCmd {
    /// `uci set <key>=<value>`   (`<key>` is `config.section` or `config.section.option`).
    Set { key: String, value: String },
    /// `uci delete <key>`  (best-effort; a missing section is not an error on teardown).
    Delete { key: String },
}

impl UciCmd {
    fn set(key: impl Into<String>, value: impl Into<String>) -> Self {
        UciCmd::Set { key: key.into(), value: value.into() }
    }
    fn delete(key: impl Into<String>) -> Self {
        UciCmd::Delete { key: key.into() }
    }

    /// The explicit argv (excluding the `uci` program itself) for this command.
    /// A `set` is `["set", "key=value"]`; a `delete` is `["delete", "key"]`.
    pub fn argv(&self) -> Vec<String> {
        match self {
            UciCmd::Set { key, value } => vec!["set".to_string(), format!("{key}={value}")],
            UciCmd::Delete { key } => vec!["delete".to_string(), key.clone()],
        }
    }
}

/// The engine's default wifi-device when a spec leaves `radio` empty.
pub const DEFAULT_RADIO: &str = "radio0";

/// The effective wifi-device for a spec: `spec.radio`, or [`DEFAULT_RADIO`] when
/// empty. This is the SINGLE source of truth for the radio: [`render_uci`] uses
/// it for `wireless.wifi_hotspot.device`, and the reload path uses it to reload
/// ONLY the hotspot's radio (`wifi reload <radio>`) — never `wifi reload` (all
/// radios), which would bounce the admin/control-plane radio on a dual-band
/// router and sever the engine↔CP link mid-commit-confirm.
pub fn effective_radio(spec: &ProvisionSpec) -> &str {
    if spec.radio.is_empty() {
        DEFAULT_RADIO
    } else {
        spec.radio.as_str()
    }
}

/// The effective confirm-timeout window for a spec: its value, or the default
/// when `0`. Assumes [`validate`] already bounded it.
pub fn effective_confirm_timeout(spec: &ProvisionSpec) -> u32 {
    if spec.confirm_timeout_secs == 0 {
        DEFAULT_CONFIRM_TIMEOUT_SECS
    } else {
        spec.confirm_timeout_secs
    }
}

/// Validate a [`ProvisionSpec`] before ANY apply (fail-OPEN: reject up front so
/// nothing is ever written for a bad spec).
///
/// Checks:
/// - `provision_id` non-empty (it keys the watchdog + confirm).
/// - `confirm_timeout_secs` is `0` (=> default) or within `[15, 600]`.
/// - the resulting names are the *fixed* allowlist names — a caller cannot
///   redirect us at `network.lan` etc.: `bridge_name` must be `br-hotspot`.
/// - `ssid` present + sane length; a non-`none` encryption requires a key.
/// - `ipaddr` / `netmask` parse as dotted-quad IPv4 (gateway must not be the
///   network/broadcast address); `dhcp_start` / `dhcp_limit` are numeric and in
///   range; `dhcp_leasetime` looks like `<n>[smhd]` or `infinite`.
///
/// Enable vs teardown: a teardown (`enabled == false`) only needs a
/// `provision_id` + a valid timeout + the fixed bridge name; the network
/// parameters are irrelevant (the sections are being deleted).
pub fn validate(spec: &ProvisionSpec) -> Result<(), ProvisionError> {
    let bad = |m: String| Err(ProvisionError::Invalid(m));

    if spec.provision_id.trim().is_empty() {
        return bad("provision_id must not be empty".into());
    }
    if spec.confirm_timeout_secs != 0
        && !(MIN_CONFIRM_TIMEOUT_SECS..=MAX_CONFIRM_TIMEOUT_SECS).contains(&spec.confirm_timeout_secs)
    {
        return bad(format!(
            "confirm_timeout_secs must be 0 (default) or in [{MIN_CONFIRM_TIMEOUT_SECS}, {MAX_CONFIRM_TIMEOUT_SECS}], got {}",
            spec.confirm_timeout_secs
        ));
    }

    // Allowlist guard: the resulting bridge is the ONE fixed name. Anything else
    // would point the interface's `device`/`network` at a non-owned section.
    if spec.bridge_name != "br-hotspot" {
        return bad(format!(
            "bridge_name is a fixed owned name; must be 'br-hotspot', got '{}'",
            spec.bridge_name
        ));
    }

    // Teardown needs nothing more than identity + the fixed bridge.
    if !spec.enabled {
        return Ok(());
    }

    // --- enable path: validate the network parameters ---
    let ssid = spec.ssid.trim();
    if ssid.is_empty() || ssid.len() > 32 {
        return bad(format!("ssid must be 1..=32 chars, got {} chars", ssid.len()));
    }

    // radio: empty => engine default; otherwise a plain wifi-device token.
    if !spec.radio.is_empty() && !is_uci_ident(&spec.radio) {
        return bad(format!("radio must be a UCI identifier, got '{}'", spec.radio));
    }

    let enc = if spec.encryption.is_empty() { "none" } else { spec.encryption.as_str() };
    if enc != "none" {
        // WPA-family: require a key of a sane length (WPA2 PSK is 8..=63 chars).
        let key_len = spec.key.chars().count();
        if !(8..=63).contains(&key_len) {
            return bad(format!(
                "encryption '{enc}' requires a key of 8..=63 chars, got {key_len}"
            ));
        }
    }

    let gw = parse_ipv4(&spec.ipaddr)
        .ok_or_else(|| ProvisionError::Invalid(format!("ipaddr not a dotted-quad IPv4: '{}'", spec.ipaddr)))?;
    let mask = parse_ipv4(&spec.netmask)
        .ok_or_else(|| ProvisionError::Invalid(format!("netmask not a dotted-quad IPv4: '{}'", spec.netmask)))?;
    if !is_contiguous_mask(mask) {
        return bad(format!("netmask '{}' is not a contiguous subnet mask", spec.netmask));
    }
    // Gateway must be a host address (not the network or broadcast address) so a
    // client can actually route through it.
    let net = mask_and(gw, mask);
    let bcast = or_inv(net, mask);
    if gw == net || gw == bcast {
        return bad(format!(
            "ipaddr '{}' is the network/broadcast address of {}/{}",
            spec.ipaddr, spec.ipaddr, spec.netmask
        ));
    }

    let start: u32 = spec
        .dhcp_start
        .trim()
        .parse()
        .map_err(|_| ProvisionError::Invalid(format!("dhcp_start not a number: '{}'", spec.dhcp_start)))?;
    let limit: u32 = spec
        .dhcp_limit
        .trim()
        .parse()
        .map_err(|_| ProvisionError::Invalid(format!("dhcp_limit not a number: '{}'", spec.dhcp_limit)))?;
    if start == 0 || start > 65535 {
        return bad(format!("dhcp_start out of range (1..=65535): {start}"));
    }
    if limit == 0 || limit > 65535 {
        return bad(format!("dhcp_limit out of range (1..=65535): {limit}"));
    }

    if !is_leasetime(&spec.dhcp_leasetime) {
        return bad(format!(
            "dhcp_leasetime must be '<n>[smhd]' or 'infinite', got '{}'",
            spec.dhcp_leasetime
        ));
    }

    Ok(())
}

/// Render the `uci set` batch for the ENABLE path — the exact owned sections in
/// the design doc's reference UCI. Pure: assumes [`validate`] passed.
///
/// Renders (in order): the bridge device → the interface (static, ipaddr/netmask)
/// → the wifi-iface (ssid/encryption/isolate) → the dhcp pool → the firewall
/// zone + forwarding + three allow-rules. Each owned section is stamped with
/// `option owner 'portcullis-hotspot'` so the ownership is visible on-device and
/// a future audit can confirm the subsystem's footprint.
///
/// `responder_port` is the portcullis :8080 redirect responder port
/// ([`portcullis_config::Config::responder_port`]) — it is a LOCAL engine
/// setting, not carried on the wire, so it is injected here rather than read from
/// the spec. The `hotspot_portal` rule opens exactly that port so a pre-auth
/// guest can reach the captive redirect.
pub fn render_uci(spec: &ProvisionSpec, responder_port: u16) -> Vec<UciCmd> {
    let radio = effective_radio(spec);
    let enc = if spec.encryption.is_empty() { "none" } else { spec.encryption.as_str() };

    let mut cmds = Vec::with_capacity(40);

    // network.br_hotspot = device  (the bridge)
    cmds.push(UciCmd::set("network.br_hotspot", "device"));
    cmds.push(UciCmd::set("network.br_hotspot.name", &spec.bridge_name));
    cmds.push(UciCmd::set("network.br_hotspot.type", "bridge"));
    cmds.push(UciCmd::set("network.br_hotspot.owner", "portcullis-hotspot"));

    // network.hotspot = interface  (static subnet on the bridge)
    cmds.push(UciCmd::set("network.hotspot", "interface"));
    cmds.push(UciCmd::set("network.hotspot.device", &spec.bridge_name));
    cmds.push(UciCmd::set("network.hotspot.proto", "static"));
    cmds.push(UciCmd::set("network.hotspot.ipaddr", &spec.ipaddr));
    cmds.push(UciCmd::set("network.hotspot.netmask", &spec.netmask));
    cmds.push(UciCmd::set("network.hotspot.owner", "portcullis-hotspot"));

    // wireless.wifi_hotspot = wifi-iface  (the public AP, attached to `hotspot`)
    cmds.push(UciCmd::set("wireless.wifi_hotspot", "wifi-iface"));
    cmds.push(UciCmd::set("wireless.wifi_hotspot.device", radio));
    cmds.push(UciCmd::set("wireless.wifi_hotspot.mode", "ap"));
    cmds.push(UciCmd::set("wireless.wifi_hotspot.network", "hotspot"));
    cmds.push(UciCmd::set("wireless.wifi_hotspot.ssid", &spec.ssid));
    cmds.push(UciCmd::set("wireless.wifi_hotspot.encryption", enc));
    if enc != "none" {
        cmds.push(UciCmd::set("wireless.wifi_hotspot.key", &spec.key));
    }
    cmds.push(UciCmd::set(
        "wireless.wifi_hotspot.isolate",
        if spec.isolate { "1" } else { "0" },
    ));
    cmds.push(UciCmd::set("wireless.wifi_hotspot.owner", "portcullis-hotspot"));

    // dhcp.hotspot = dhcp  (guest pool)
    cmds.push(UciCmd::set("dhcp.hotspot", "dhcp"));
    cmds.push(UciCmd::set("dhcp.hotspot.interface", "hotspot"));
    cmds.push(UciCmd::set("dhcp.hotspot.start", &spec.dhcp_start));
    cmds.push(UciCmd::set("dhcp.hotspot.limit", &spec.dhcp_limit));
    cmds.push(UciCmd::set("dhcp.hotspot.leasetime", &spec.dhcp_leasetime));
    cmds.push(UciCmd::set("dhcp.hotspot.dhcpv6", "disabled"));
    cmds.push(UciCmd::set("dhcp.hotspot.owner", "portcullis-hotspot"));

    // firewall.hotspot = zone  (SECURE captive posture: guests cannot reach the
    // router (input REJECT) nor forward anywhere by default (forward REJECT); the
    // three rules below open only DHCP, DNS, and the portal responder, and the
    // forwarding below opens hotspot → wan. No masq here — the existing `wan`
    // zone already masquerades (RUTOS default), so NAT breakout is inherited.
    cmds.push(UciCmd::set("firewall.hotspot", "zone"));
    cmds.push(UciCmd::set("firewall.hotspot.name", "hotspot"));
    cmds.push(UciCmd::set("firewall.hotspot.network", "hotspot"));
    cmds.push(UciCmd::set("firewall.hotspot.input", "REJECT"));
    cmds.push(UciCmd::set("firewall.hotspot.output", "ACCEPT"));
    cmds.push(UciCmd::set("firewall.hotspot.forward", "REJECT"));
    cmds.push(UciCmd::set("firewall.hotspot.owner", "portcullis-hotspot"));

    // firewall.hotspot_fwd = forwarding  (hotspot → wan: the NAT breakout path)
    cmds.push(UciCmd::set("firewall.hotspot_fwd", "forwarding"));
    cmds.push(UciCmd::set("firewall.hotspot_fwd.src", "hotspot"));
    cmds.push(UciCmd::set("firewall.hotspot_fwd.dest", WAN_ZONE));
    cmds.push(UciCmd::set("firewall.hotspot_fwd.owner", "portcullis-hotspot"));

    // firewall.hotspot_dhcp = rule  (allow guest DHCP requests to the router)
    cmds.push(UciCmd::set("firewall.hotspot_dhcp", "rule"));
    cmds.push(UciCmd::set("firewall.hotspot_dhcp.name", "Allow-hotspot-DHCP"));
    cmds.push(UciCmd::set("firewall.hotspot_dhcp.src", "hotspot"));
    cmds.push(UciCmd::set("firewall.hotspot_dhcp.proto", "udp"));
    cmds.push(UciCmd::set("firewall.hotspot_dhcp.dest_port", "67"));
    cmds.push(UciCmd::set("firewall.hotspot_dhcp.target", "ACCEPT"));
    cmds.push(UciCmd::set("firewall.hotspot_dhcp.owner", "portcullis-hotspot"));

    // firewall.hotspot_dns = rule  (allow guest DNS to the router's dnsmasq)
    cmds.push(UciCmd::set("firewall.hotspot_dns", "rule"));
    cmds.push(UciCmd::set("firewall.hotspot_dns.name", "Allow-hotspot-DNS"));
    cmds.push(UciCmd::set("firewall.hotspot_dns.src", "hotspot"));
    cmds.push(UciCmd::set("firewall.hotspot_dns.proto", "tcp udp"));
    cmds.push(UciCmd::set("firewall.hotspot_dns.dest_port", "53"));
    cmds.push(UciCmd::set("firewall.hotspot_dns.target", "ACCEPT"));
    cmds.push(UciCmd::set("firewall.hotspot_dns.owner", "portcullis-hotspot"));

    // firewall.hotspot_portal = rule  (allow the captive redirect responder —
    // the local :8080 port, injected from Config.responder_port, NOT the wire).
    cmds.push(UciCmd::set("firewall.hotspot_portal", "rule"));
    cmds.push(UciCmd::set("firewall.hotspot_portal.name", "Allow-hotspot-portal"));
    cmds.push(UciCmd::set("firewall.hotspot_portal.src", "hotspot"));
    cmds.push(UciCmd::set("firewall.hotspot_portal.proto", "tcp"));
    cmds.push(UciCmd::set("firewall.hotspot_portal.dest_port", responder_port.to_string()));
    cmds.push(UciCmd::set("firewall.hotspot_portal.target", "ACCEPT"));
    cmds.push(UciCmd::set("firewall.hotspot_portal.owner", "portcullis-hotspot"));

    cmds
}

/// Render the teardown batch: delete exactly the nine owned sections (and
/// nothing else). Deletes are best-effort at apply time (a missing section is
/// fine), so ordering is not load-bearing here — but we delete the firewall
/// sections first, then dhcp → wifi → interface → bridge (reverse of create) for
/// tidiness (a zone's forwarding/rules reference it, so drop those before it).
pub fn render_teardown() -> Vec<UciCmd> {
    vec![
        UciCmd::delete("firewall.hotspot_portal"),
        UciCmd::delete("firewall.hotspot_dns"),
        UciCmd::delete("firewall.hotspot_dhcp"),
        UciCmd::delete("firewall.hotspot_fwd"),
        UciCmd::delete("firewall.hotspot"),
        UciCmd::delete("dhcp.hotspot"),
        UciCmd::delete("wireless.wifi_hotspot"),
        UciCmd::delete("network.hotspot"),
        UciCmd::delete("network.br_hotspot"),
    ]
}

// --- validation helpers ----------------------------------------------------

/// A UCI section/device identifier: `[A-Za-z0-9_-]+`, non-empty.
fn is_uci_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Parse a strict dotted-quad IPv4 into a `u32` (host order). Rejects anything
/// that is not exactly four decimal octets `0..=255`.
fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out: u32 = 0;
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let octet: u32 = p.parse().ok()?;
        if octet > 255 {
            return None;
        }
        out = (out << 8) | octet;
    }
    Some(out)
}

/// A valid subnet mask is a run of 1-bits followed by a run of 0-bits, and must
/// not be all-zero (a `/0` "mask" gives a degenerate hotspot subnet). All-ones
/// (`/32`) is also rejected — it leaves no host range.
fn is_contiguous_mask(mask: u32) -> bool {
    if mask == 0 || mask == u32::MAX {
        return false;
    }
    // A contiguous mask negated + 1 is a power of two (the low zero-run + 1).
    let inv = !mask;
    inv & inv.wrapping_add(1) == 0
}

fn mask_and(ip: u32, mask: u32) -> u32 {
    ip & mask
}
fn or_inv(net: u32, mask: u32) -> u32 {
    net | !mask
}

/// dnsmasq lease time: `infinite`, or `<n>` optionally suffixed with `s`/`m`/
/// `h`/`d` (e.g. `2h`, `720m`, `43200`).
fn is_leasetime(s: &str) -> bool {
    let s = s.trim();
    if s.eq_ignore_ascii_case("infinite") {
        return true;
    }
    if s.is_empty() {
        return false;
    }
    let (num, _suffix) = match s.chars().last() {
        Some(c @ ('s' | 'm' | 'h' | 'd')) => (&s[..s.len() - c.len_utf8()], Some(c)),
        _ => (s, None),
    };
    !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) && num.parse::<u64>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> ProvisionSpec {
        ProvisionSpec {
            provision_id: "prov-1".into(),
            enabled: true,
            ssid: "WifiHub Guest".into(),
            radio: "radio0".into(),
            encryption: "none".into(),
            key: String::new(),
            isolate: true,
            bridge_name: "br-hotspot".into(),
            ipaddr: "10.0.0.1".into(),
            netmask: "255.255.255.0".into(),
            dhcp_start: "10".into(),
            dhcp_limit: "200".into(),
            dhcp_leasetime: "2h".into(),
            confirm_timeout_secs: 0,
        }
    }

    #[test]
    fn render_uci_matches_reference_design_doc() {
        // The reference desired-state UCI (RUT200, design doc P0.5): an open
        // captive SSID on radio0 + br-hotspot 10.0.0.1/24 + a DHCP pool + the
        // firewall zone/forwarding/rules (portal rule on the 8080 responder).
        let cmds = render_uci(&valid_spec(), 8080);
        let flat: Vec<(String, String)> = cmds
            .iter()
            .map(|c| match c {
                UciCmd::Set { key, value } => (key.clone(), value.clone()),
                UciCmd::Delete { key } => (format!("DELETE {key}"), String::new()),
            })
            .collect();

        let expect = vec![
            ("network.br_hotspot", "device"),
            ("network.br_hotspot.name", "br-hotspot"),
            ("network.br_hotspot.type", "bridge"),
            ("network.br_hotspot.owner", "portcullis-hotspot"),
            ("network.hotspot", "interface"),
            ("network.hotspot.device", "br-hotspot"),
            ("network.hotspot.proto", "static"),
            ("network.hotspot.ipaddr", "10.0.0.1"),
            ("network.hotspot.netmask", "255.255.255.0"),
            ("network.hotspot.owner", "portcullis-hotspot"),
            ("wireless.wifi_hotspot", "wifi-iface"),
            ("wireless.wifi_hotspot.device", "radio0"),
            ("wireless.wifi_hotspot.mode", "ap"),
            ("wireless.wifi_hotspot.network", "hotspot"),
            ("wireless.wifi_hotspot.ssid", "WifiHub Guest"),
            ("wireless.wifi_hotspot.encryption", "none"),
            ("wireless.wifi_hotspot.isolate", "1"),
            ("wireless.wifi_hotspot.owner", "portcullis-hotspot"),
            ("dhcp.hotspot", "dhcp"),
            ("dhcp.hotspot.interface", "hotspot"),
            ("dhcp.hotspot.start", "10"),
            ("dhcp.hotspot.limit", "200"),
            ("dhcp.hotspot.leasetime", "2h"),
            ("dhcp.hotspot.dhcpv6", "disabled"),
            ("dhcp.hotspot.owner", "portcullis-hotspot"),
            ("firewall.hotspot", "zone"),
            ("firewall.hotspot.name", "hotspot"),
            ("firewall.hotspot.network", "hotspot"),
            ("firewall.hotspot.input", "REJECT"),
            ("firewall.hotspot.output", "ACCEPT"),
            ("firewall.hotspot.forward", "REJECT"),
            ("firewall.hotspot.owner", "portcullis-hotspot"),
            ("firewall.hotspot_fwd", "forwarding"),
            ("firewall.hotspot_fwd.src", "hotspot"),
            ("firewall.hotspot_fwd.dest", "wan"),
            ("firewall.hotspot_fwd.owner", "portcullis-hotspot"),
            ("firewall.hotspot_dhcp", "rule"),
            ("firewall.hotspot_dhcp.name", "Allow-hotspot-DHCP"),
            ("firewall.hotspot_dhcp.src", "hotspot"),
            ("firewall.hotspot_dhcp.proto", "udp"),
            ("firewall.hotspot_dhcp.dest_port", "67"),
            ("firewall.hotspot_dhcp.target", "ACCEPT"),
            ("firewall.hotspot_dhcp.owner", "portcullis-hotspot"),
            ("firewall.hotspot_dns", "rule"),
            ("firewall.hotspot_dns.name", "Allow-hotspot-DNS"),
            ("firewall.hotspot_dns.src", "hotspot"),
            ("firewall.hotspot_dns.proto", "tcp udp"),
            ("firewall.hotspot_dns.dest_port", "53"),
            ("firewall.hotspot_dns.target", "ACCEPT"),
            ("firewall.hotspot_dns.owner", "portcullis-hotspot"),
            ("firewall.hotspot_portal", "rule"),
            ("firewall.hotspot_portal.name", "Allow-hotspot-portal"),
            ("firewall.hotspot_portal.src", "hotspot"),
            ("firewall.hotspot_portal.proto", "tcp"),
            ("firewall.hotspot_portal.dest_port", "8080"),
            ("firewall.hotspot_portal.target", "ACCEPT"),
            ("firewall.hotspot_portal.owner", "portcullis-hotspot"),
        ];
        let expect: Vec<(String, String)> =
            expect.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert_eq!(flat, expect);
    }

    #[test]
    fn render_uci_portal_rule_uses_injected_responder_port() {
        // Default 8080.
        let cmds = render_uci(&valid_spec(), 8080);
        assert!(cmds.contains(&UciCmd::set("firewall.hotspot_portal.dest_port", "8080")));
        // A custom port flows through verbatim (not a wire field).
        let cmds = render_uci(&valid_spec(), 9443);
        assert!(cmds.contains(&UciCmd::set("firewall.hotspot_portal.dest_port", "9443")));
        assert!(!cmds.contains(&UciCmd::set("firewall.hotspot_portal.dest_port", "8080")));
    }

    #[test]
    fn render_uci_forwarding_targets_wan_and_no_masq_on_hotspot() {
        let cmds = render_uci(&valid_spec(), 8080);
        // hotspot -> wan forwarding (NAT breakout inherited from the wan zone).
        assert!(cmds.contains(&UciCmd::set("firewall.hotspot_fwd.dest", "wan")));
        // No masq is ever set on the hotspot zone (the wan zone already masqs).
        assert!(!cmds.iter().any(|c| matches!(c, UciCmd::Set { key, .. } if key.starts_with("firewall.hotspot.masq"))));
    }

    #[test]
    fn render_uci_only_touches_owned_sections() {
        // Every `set` key must be prefixed by one of the nine owned section keys
        // — the allowlist guarantee, asserted structurally.
        for c in render_uci(&valid_spec(), 8080) {
            let key = match &c {
                UciCmd::Set { key, .. } => key,
                UciCmd::Delete { key } => key,
            };
            assert!(
                OWNED.iter().any(|owned| key == owned || key.starts_with(&format!("{owned}."))),
                "key '{key}' escapes the owned allowlist"
            );
        }
    }

    #[test]
    fn render_uci_with_psk_emits_key() {
        let mut s = valid_spec();
        s.encryption = "psk2".into();
        s.key = "supersecret".into();
        let cmds = render_uci(&s, 8080);
        assert!(cmds.contains(&UciCmd::set("wireless.wifi_hotspot.encryption", "psk2")));
        assert!(cmds.contains(&UciCmd::set("wireless.wifi_hotspot.key", "supersecret")));
    }

    #[test]
    fn render_uci_open_has_no_key() {
        let cmds = render_uci(&valid_spec(), 8080);
        assert!(!cmds.iter().any(|c| matches!(c, UciCmd::Set { key, .. } if key.ends_with(".key"))));
    }

    #[test]
    fn render_teardown_deletes_only_owned() {
        let cmds = render_teardown();
        assert_eq!(cmds.len(), 9);
        for c in &cmds {
            match c {
                UciCmd::Delete { key } => assert!(OWNED.contains(&key.as_str())),
                other => panic!("teardown must be deletes only, got {other:?}"),
            }
        }
        // Every owned section is torn down (no stragglers left on-device).
        let deleted: Vec<&str> = cmds
            .iter()
            .map(|c| match c {
                UciCmd::Delete { key } => key.as_str(),
                _ => unreachable!(),
            })
            .collect();
        for owned in OWNED {
            assert!(deleted.contains(&owned), "teardown missed owned section {owned}");
        }
    }

    #[test]
    fn argv_is_explicit_no_shell() {
        assert_eq!(
            UciCmd::set("network.hotspot.ipaddr", "10.0.0.1").argv(),
            vec!["set".to_string(), "network.hotspot.ipaddr=10.0.0.1".to_string()]
        );
        assert_eq!(
            UciCmd::delete("dhcp.hotspot").argv(),
            vec!["delete".to_string(), "dhcp.hotspot".to_string()]
        );
    }

    #[test]
    fn validate_accepts_reference_spec() {
        validate(&valid_spec()).unwrap();
    }

    #[test]
    fn validate_rejects_non_owned_bridge_name() {
        let mut s = valid_spec();
        s.bridge_name = "br-lan".into();
        assert!(matches!(validate(&s), Err(ProvisionError::Invalid(_))));
    }

    #[test]
    fn validate_rejects_empty_provision_id() {
        let mut s = valid_spec();
        s.provision_id = "".into();
        assert!(validate(&s).is_err());
    }

    #[test]
    fn validate_rejects_bad_timeout() {
        let mut s = valid_spec();
        s.confirm_timeout_secs = 5; // below 15
        assert!(validate(&s).is_err());
        s.confirm_timeout_secs = 601; // above 600
        assert!(validate(&s).is_err());
        s.confirm_timeout_secs = 0; // 0 = default, allowed
        assert!(validate(&s).is_ok());
        s.confirm_timeout_secs = 90;
        assert!(validate(&s).is_ok());
    }

    #[test]
    fn validate_rejects_bad_subnet() {
        let mut s = valid_spec();
        s.ipaddr = "999.1.1.1".into();
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.netmask = "255.0.255.0".into(); // non-contiguous
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.ipaddr = "10.0.0.0".into(); // network address, not a host
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.ipaddr = "10.0.0.255".into(); // broadcast address for /24
        assert!(validate(&s).is_err());
    }

    #[test]
    fn validate_rejects_bad_dhcp_and_lease() {
        let mut s = valid_spec();
        s.dhcp_start = "x".into();
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.dhcp_limit = "0".into();
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.dhcp_leasetime = "2 hours".into();
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.dhcp_leasetime = "infinite".into();
        assert!(validate(&s).is_ok());
    }

    #[test]
    fn validate_rejects_bad_ssid_and_missing_psk() {
        let mut s = valid_spec();
        s.ssid = "".into();
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.ssid = "x".repeat(33);
        assert!(validate(&s).is_err());

        let mut s = valid_spec();
        s.encryption = "psk2".into();
        s.key = "short".into(); // < 8 chars
        assert!(validate(&s).is_err());
    }

    #[test]
    fn validate_teardown_ignores_network_params() {
        // A teardown only needs id + fixed bridge + valid timeout; garbage
        // network fields are irrelevant because the sections are being deleted.
        let mut s = valid_spec();
        s.enabled = false;
        s.ssid = "".into();
        s.ipaddr = "not-an-ip".into();
        s.dhcp_start = "junk".into();
        validate(&s).unwrap();
    }

    #[test]
    fn effective_timeout_defaults_when_zero() {
        let mut s = valid_spec();
        s.confirm_timeout_secs = 0;
        assert_eq!(effective_confirm_timeout(&s), DEFAULT_CONFIRM_TIMEOUT_SECS);
        s.confirm_timeout_secs = 120;
        assert_eq!(effective_confirm_timeout(&s), 120);
    }
}
