//! Pure, testable UCI rendering + validation for the CP-managed wireless
//! provision subsystem (P-W1). No I/O, no async — every function here is a unit
//! test away from the reference desired-state UCI.
//!
//! ## Ownership namespace (load-bearing)
//!
//! The subsystem may read/write ONLY sections it owns: every section is named
//! `pc_<slug>_*` and stamped `option owner 'portcullis-wireless'`. It NEVER
//! touches `network.lan` / br-lan, admin config, the existing `firewall.lan` /
//! `firewall.wan` zones, or the enforcement `inet wifihub` table — enforced by
//! [`validate_wireless`]'s reserved denylist ([`RESERVED_SLUGS`] /
//! [`RESERVED_BRIDGES`] / [`RESERVED_EGRESS`]) plus the `pc_` name prefix.
//! [`is_owned_wireless_section`] is the single source of truth for "owned" (used
//! by the snapshot filter too, so a snapshot can never capture a non-owned
//! section).

use portcullis_types::{ProvisionError, SsidSpec, WirelessDesiredState};

/// The UCI `config`s (top-level files) the reload touches. Commit order:
/// `uci commit network wireless dhcp firewall sqm` (firewall before sqm; sqm
/// references the SSID's bridge interface). `sqm` is OPTIONAL — a device without
/// sqm-scripts has no /etc/config/sqm, so its show/commit are tolerated as no-ops
/// (see snapshot_wireless / commit_and_reload_multi).
pub const OWNED_CONFIGS: [&str; 5] = ["network", "wireless", "dhcp", "firewall", "sqm"];

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
    /// `uci add_list <key>=<value>` — append one element to a UCI list option
    /// (e.g. `wireless.<iface>.maclist`). The section is always freshly recreated
    /// each apply (delete-then-set), so appends never accumulate stale entries.
    AddList { key: String, value: String },
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
    fn add_list(key: impl Into<String>, value: impl Into<String>) -> Self {
        UciCmd::AddList { key: key.into(), value: value.into() }
    }

    /// The explicit argv (excluding the `uci` program itself) for this command.
    /// A `set` is `["set", "key=value"]`; a `delete` is `["delete", "key"]`.
    pub fn argv(&self) -> Vec<String> {
        match self {
            UciCmd::Set { key, value } => vec!["set".to_string(), format!("{key}={value}")],
            UciCmd::AddList { key, value } => vec!["add_list".to_string(), format!("{key}={value}")],
            UciCmd::Delete { key } => vec!["delete".to_string(), key.clone()],
        }
    }
}

/// The engine's default wifi-device when an SSID leaves `radios` empty.
pub const DEFAULT_RADIO: &str = "radio0";


// ===========================================================================
// CP-managed wireless (P-W1): arbitrary owned SSIDs.
//
// Ownership boundary moves from a FIXED name allowlist (hotspot) to an
// ownership NAMESPACE: every section this path writes is named `pc_<slug>_*` and
// stamped `option owner 'portcullis-wireless'`. The engine may modify/delete
// ONLY these; a reserved denylist ([`RESERVED_SLUGS`]/[`RESERVED_BRIDGES`]/
// [`RESERVED_EGRESS`]) keeps a spec from ever aliasing lan / br-lan / admin /
// wan / the `inet wifihub` table. Both [`render_wireless`] and the snapshot
// filter derive names from the same helpers so they cannot diverge.
// ===========================================================================

/// The owner tag stamped on every CP-managed wireless section. Distinct from the
/// hotspot subsystem's `portcullis-hotspot` so the two never alias during
/// migration; sections are ALSO name-namespaced with [`WIRELESS_SECTION_PREFIX`].
pub const WIRELESS_OWNER: &str = "portcullis-wireless";
/// Name prefix on every owned wireless section (the ownership marker in the name).
pub const WIRELESS_SECTION_PREFIX: &str = "pc_";
/// Max CP-managed SSID `wifi-iface`s the engine will place on one radio (the
/// admin/management SSID already consumes one VIF on top of this).
///
/// Conservative on purpose (RC2): a structurally-valid push that asks for more
/// BSSIDs than the mt76 chip can actually instantiate makes `wifi reload` bring
/// the radio up with ZERO interfaces — darkening every SSID on it, admin
/// included. Validation can't probe the driver, so the cap is the guard. Kept at
/// a value comfortably within the mt76 parts on the RUTM11/RUT200 rather than the
/// theoretical maximum. Exceeding it is a clean fail-open REJECT (nothing is
/// applied — no outage), so if a deployment's hardware provably supports more,
/// raising this constant is safe. Validate the real per-band limit on-device
/// (`iwinfo <phy> info`) before doing so.
pub const MAX_SSIDS_PER_RADIO: usize = 4;
/// Max radios one SSID may span (teardown deletes `pc_<slug>_ap0..apN`).
pub const MAX_RADIOS_PER_SSID: usize = 4;
/// Slugs the CP may not use (would confuse with core networks / the hotspot path).
pub const RESERVED_SLUGS: [&str; 6] = ["lan", "wan", "wan6", "admin", "loopback", "hotspot"];
/// Egress zones an SSID may not forward into (forwarding to lan bypasses the gate).
pub const RESERVED_EGRESS: [&str; 1] = ["lan"];
/// Bridge ifaces the CP may not claim.
pub const RESERVED_BRIDGES: [&str; 1] = ["br-lan"];

/// The effective radios for an SSID: its list, or `[DEFAULT_RADIO]` when empty.
pub fn effective_radios(spec: &SsidSpec) -> Vec<&str> {
    if spec.radios.is_empty() {
        vec![DEFAULT_RADIO]
    } else {
        spec.radios.iter().map(String::as_str).collect()
    }
}

/// The effective confirm window for a raw `secs`: its value, or the default at 0.
pub fn effective_confirm_timeout_secs(secs: u32) -> u32 {
    if secs == 0 {
        DEFAULT_CONFIRM_TIMEOUT_SECS
    } else {
        secs
    }
}

/// Whether a `config.section` key names an owned wireless section. Used by the
/// snapshot filter so it can only ever capture our own sections.
pub fn is_owned_wireless_section(key: &str) -> bool {
    key.split_once('.')
        .map(|(_, sec)| sec.starts_with(WIRELESS_SECTION_PREFIX))
        .unwrap_or(false)
}

/// Render the `uci set` batch for ONE validated SSID: the owned `pc_<slug>_*`
/// sections — bridge, interface, one wifi-iface per radio, dhcp, firewall zone,
/// forwarding, dhcp/dns allow-rules, and (only when `gated`) a portal rule. Each
/// section is stamped `owner = portcullis-wireless`. Pure; assumes
/// [`validate_wireless`] passed. `responder_port` is the LOCAL :8080 redirect port.
pub fn render_ssid(spec: &SsidSpec, responder_port: u16) -> Vec<UciCmd> {
    let s = spec.slug.as_str();
    let enc = if spec.encryption.is_empty() { "none" } else { spec.encryption.as_str() };
    let egress = if spec.egress_zone.is_empty() { WAN_ZONE } else { spec.egress_zone.as_str() };
    let iface = format!("pc_{s}_if");

    let mut c = Vec::with_capacity(48);

    // network.pc_<s>_dev = device  (the bridge)
    let dev = format!("network.pc_{s}_dev");
    c.push(UciCmd::set(&dev, "device"));
    c.push(UciCmd::set(format!("{dev}.name"), &spec.bridge_name));
    c.push(UciCmd::set(format!("{dev}.type"), "bridge"));
    c.push(UciCmd::set(format!("{dev}.owner"), WIRELESS_OWNER));

    // network.pc_<s>_if = interface  (static subnet on the bridge)
    let ifk = format!("network.{iface}");
    c.push(UciCmd::set(&ifk, "interface"));
    c.push(UciCmd::set(format!("{ifk}.device"), &spec.bridge_name));
    c.push(UciCmd::set(format!("{ifk}.proto"), "static"));
    c.push(UciCmd::set(format!("{ifk}.ipaddr"), &spec.ipaddr));
    c.push(UciCmd::set(format!("{ifk}.netmask"), &spec.netmask));
    c.push(UciCmd::set(format!("{ifk}.owner"), WIRELESS_OWNER));

    // wireless.pc_<s>_ap{i} = wifi-iface  (one per radio)
    for (i, radio) in effective_radios(spec).iter().enumerate() {
        let ap = format!("wireless.pc_{s}_ap{i}");
        c.push(UciCmd::set(&ap, "wifi-iface"));
        c.push(UciCmd::set(format!("{ap}.device"), *radio));
        c.push(UciCmd::set(format!("{ap}.mode"), "ap"));
        c.push(UciCmd::set(format!("{ap}.network"), &iface));
        c.push(UciCmd::set(format!("{ap}.ssid"), &spec.ssid));
        c.push(UciCmd::set(format!("{ap}.encryption"), enc));
        if enc != "none" {
            c.push(UciCmd::set(format!("{ap}.key"), &spec.key));
        }
        c.push(UciCmd::set(format!("{ap}.isolate"), if spec.isolate { "1" } else { "0" }));
        if spec.hidden {
            c.push(UciCmd::set(format!("{ap}.hidden"), "1"));
        }
        // PMF (ieee80211w): WPA3-SAE mandates it (2 = required); sae-mixed makes it
        // optional (1) so legacy WPA2 clients still associate. psk2/open leave it
        // unset (hostapd default off). Correctness fix — SAE without PMF is invalid.
        match enc {
            "sae" => c.push(UciCmd::set(format!("{ap}.ieee80211w"), "2")),
            "sae-mixed" => c.push(UciCmd::set(format!("{ap}.ieee80211w"), "1")),
            _ => {}
        }
        // maxassoc: cap associated stations per AP (0 = unlimited => unset).
        if spec.max_clients > 0 {
            c.push(UciCmd::set(format!("{ap}.maxassoc"), spec.max_clients.to_string()));
        }
        // MAC access-control (hostapd macfilter): "allow" = only listed MACs may
        // associate; "deny" = listed MACs are blocked. maclist is a UCI *list* —
        // one add_list per MAC. The whole section is recreated each apply (delete-
        // then-set), so appends never accumulate; rollback restores prior lists via
        // Snapshot::prior_lists. Empty policy / empty list => no filter.
        if !spec.mac_list.is_empty() {
            let filter = match spec.mac_policy.as_str() {
                "allow" => Some("allow"),
                "deny" => Some("deny"),
                _ => None,
            };
            if let Some(filter) = filter {
                c.push(UciCmd::set(format!("{ap}.macfilter"), filter));
                for m in &spec.mac_list {
                    c.push(UciCmd::add_list(format!("{ap}.maclist"), m.to_lowercase()));
                }
            }
        }
        c.push(UciCmd::set(format!("{ap}.owner"), WIRELESS_OWNER));
    }

    // dhcp.pc_<s> = dhcp  (guest pool), unless bridged-no-dhcp
    if !spec.dhcp_disabled {
        let d = format!("dhcp.pc_{s}");
        c.push(UciCmd::set(&d, "dhcp"));
        c.push(UciCmd::set(format!("{d}.interface"), &iface));
        c.push(UciCmd::set(format!("{d}.start"), &spec.dhcp_start));
        c.push(UciCmd::set(format!("{d}.limit"), &spec.dhcp_limit));
        c.push(UciCmd::set(format!("{d}.leasetime"), &spec.dhcp_leasetime));
        c.push(UciCmd::set(format!("{d}.dhcpv6"), "disabled"));
        c.push(UciCmd::set(format!("{d}.owner"), WIRELESS_OWNER));
    }

    // firewall.pc_<s>_zone = zone  (SECURE posture; zone name = slug)
    let z = format!("firewall.pc_{s}_zone");
    c.push(UciCmd::set(&z, "zone"));
    c.push(UciCmd::set(format!("{z}.name"), s));
    c.push(UciCmd::set(format!("{z}.network"), &iface));
    c.push(UciCmd::set(format!("{z}.input"), "REJECT"));
    c.push(UciCmd::set(format!("{z}.output"), "ACCEPT"));
    c.push(UciCmd::set(format!("{z}.forward"), "REJECT"));
    c.push(UciCmd::set(format!("{z}.owner"), WIRELESS_OWNER));

    // firewall.pc_<s>_fwd = forwarding  (zone -> egress; NAT inherited from egress)
    let f = format!("firewall.pc_{s}_fwd");
    c.push(UciCmd::set(&f, "forwarding"));
    c.push(UciCmd::set(format!("{f}.src"), s));
    c.push(UciCmd::set(format!("{f}.dest"), egress));
    c.push(UciCmd::set(format!("{f}.owner"), WIRELESS_OWNER));

    // firewall.pc_<s>_dhcp = rule  (allow guest DHCP)
    let rd = format!("firewall.pc_{s}_dhcp");
    c.push(UciCmd::set(&rd, "rule"));
    c.push(UciCmd::set(format!("{rd}.name"), format!("Allow-{s}-DHCP")));
    c.push(UciCmd::set(format!("{rd}.src"), s));
    c.push(UciCmd::set(format!("{rd}.proto"), "udp"));
    c.push(UciCmd::set(format!("{rd}.dest_port"), "67"));
    c.push(UciCmd::set(format!("{rd}.target"), "ACCEPT"));
    c.push(UciCmd::set(format!("{rd}.owner"), WIRELESS_OWNER));

    // firewall.pc_<s>_dns = rule  (allow guest DNS)
    let rn = format!("firewall.pc_{s}_dns");
    c.push(UciCmd::set(&rn, "rule"));
    c.push(UciCmd::set(format!("{rn}.name"), format!("Allow-{s}-DNS")));
    c.push(UciCmd::set(format!("{rn}.src"), s));
    c.push(UciCmd::set(format!("{rn}.proto"), "tcp udp"));
    c.push(UciCmd::set(format!("{rn}.dest_port"), "53"));
    c.push(UciCmd::set(format!("{rn}.target"), "ACCEPT"));
    c.push(UciCmd::set(format!("{rn}.owner"), WIRELESS_OWNER));

    // firewall.pc_<s>_portal = rule  (GATED only: open the captive redirect port)
    if spec.gated {
        let rp = format!("firewall.pc_{s}_portal");
        c.push(UciCmd::set(&rp, "rule"));
        c.push(UciCmd::set(format!("{rp}.name"), format!("Allow-{s}-portal")));
        c.push(UciCmd::set(format!("{rp}.src"), s));
        c.push(UciCmd::set(format!("{rp}.proto"), "tcp"));
        c.push(UciCmd::set(format!("{rp}.dest_port"), responder_port.to_string()));
        c.push(UciCmd::set(format!("{rp}.target"), "ACCEPT"));
        c.push(UciCmd::set(format!("{rp}.owner"), WIRELESS_OWNER));
    }

    // sqm.pc_<s> = queue  (F9: per-SSID bandwidth cap on this SSID's bridge). Only
    // when a cap is set; 0 in a direction = unlimited (SQM treats 0 as "no shaping"
    // for that leg). `cake` + piece_of_cake.qos is a simple single-tier shaper.
    // Needs sqm-scripts + a cake/fq_codel qdisc on the device (golden-image dep).
    if spec.rate_down_kbps > 0 || spec.rate_up_kbps > 0 {
        let q = format!("sqm.pc_{s}");
        c.push(UciCmd::set(&q, "queue"));
        c.push(UciCmd::set(format!("{q}.interface"), &spec.bridge_name));
        c.push(UciCmd::set(format!("{q}.enabled"), "1"));
        c.push(UciCmd::set(format!("{q}.download"), spec.rate_down_kbps.to_string())); // to client (ingress)
        c.push(UciCmd::set(format!("{q}.upload"), spec.rate_up_kbps.to_string())); // from client (egress)
        c.push(UciCmd::set(format!("{q}.qdisc"), "cake"));
        c.push(UciCmd::set(format!("{q}.script"), "piece_of_cake.qos"));
        c.push(UciCmd::set(format!("{q}.owner"), WIRELESS_OWNER));
    }

    c
}

/// Render the full desired-state `uci set` batch (every SSID). Pure; assumes
/// [`validate_wireless`] passed. The set/delete DIFF against on-device owned
/// state is computed in `sm.rs` — this renders the desired half.
pub fn render_wireless(state: &WirelessDesiredState, responder_port: u16) -> Vec<UciCmd> {
    let mut c = Vec::new();
    for ssid in &state.ssids {
        c.extend(render_ssid(ssid, responder_port));
    }
    c
}

/// Render a `uci delete` for each given `config.section` key (deletes are
/// best-effort at apply time). Used by the reconcile diff to drop pre-existing
/// owned sections before re-setting the desired state.
pub fn render_deletes(section_keys: &[String]) -> Vec<UciCmd> {
    section_keys.iter().map(UciCmd::delete).collect()
}

/// Extract the section-decl keys (`config.section`, i.e. exactly one `.`) from a
/// rendered `set` batch — the sections the batch creates. Single source of truth
/// for "which sections does this desired-state own" (fed to the rollback /
/// marker as `current_sections`), derived from the renderer so they can't drift.
pub fn section_decls(cmds: &[UciCmd]) -> Vec<String> {
    cmds.iter()
        .filter_map(|c| match c {
            UciCmd::Set { key, .. } if key.matches('.').count() == 1 => Some(key.clone()),
            _ => None,
        })
        .collect()
}

/// Delete every owned section of one SSID (firewall first — rules/forwarding
/// reference the zone — then dhcp → wifi → interface → bridge). Deletes are
/// best-effort, so over-deleting unused `ap{i}` indices is harmless.
pub fn render_ssid_teardown(slug: &str) -> Vec<UciCmd> {
    let s = slug;
    let mut c = Vec::with_capacity(6 + MAX_RADIOS_PER_SSID + 2);
    c.push(UciCmd::delete(format!("firewall.pc_{s}_portal")));
    c.push(UciCmd::delete(format!("firewall.pc_{s}_dns")));
    c.push(UciCmd::delete(format!("firewall.pc_{s}_dhcp")));
    c.push(UciCmd::delete(format!("firewall.pc_{s}_fwd")));
    c.push(UciCmd::delete(format!("firewall.pc_{s}_zone")));
    c.push(UciCmd::delete(format!("dhcp.pc_{s}")));
    c.push(UciCmd::delete(format!("sqm.pc_{s}")));
    for i in 0..MAX_RADIOS_PER_SSID {
        c.push(UciCmd::delete(format!("wireless.pc_{s}_ap{i}")));
    }
    c.push(UciCmd::delete(format!("network.pc_{s}_if")));
    c.push(UciCmd::delete(format!("network.pc_{s}_dev")));
    c
}

/// A MAC address in `aa:bb:cc:dd:ee:ff` form (case-insensitive): six colon-
/// separated pairs of hex digits.
fn is_mac_addr(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A slug: `[a-z0-9_]` (lowercase only), 1..=16 chars.
fn is_slug(s: &str) -> bool {
    let n = s.chars().count();
    (1..=16).contains(&n) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Validate a whole [`WirelessDesiredState`] before ANY apply (fail-OPEN: reject
/// up front so a bad push writes nothing). Per-SSID: slug (namespaced, not
/// reserved), ssid length, radios, encryption/key, bridge (not reserved),
/// egress_zone (not `lan`), static subnet (host gateway, contiguous mask), DHCP.
/// Cross-SSID: unique slugs + bridges, non-overlapping subnets, per-radio VIF cap.
/// An empty `ssids` (tear down everything) is valid.
pub fn validate_wireless(state: &WirelessDesiredState) -> Result<(), ProvisionError> {
    let bad = |m: String| Err(ProvisionError::Invalid(m));

    if state.confirm_timeout_secs != 0
        && !(MIN_CONFIRM_TIMEOUT_SECS..=MAX_CONFIRM_TIMEOUT_SECS).contains(&state.confirm_timeout_secs)
    {
        return bad(format!(
            "confirm_timeout_secs must be 0 (default) or in [{MIN_CONFIRM_TIMEOUT_SECS}, {MAX_CONFIRM_TIMEOUT_SECS}], got {}",
            state.confirm_timeout_secs
        ));
    }
    if state.ssids.is_empty() {
        return Ok(()); // teardown-all
    }

    let mut seen_slugs: Vec<&str> = Vec::new();
    let mut seen_bridges: Vec<&str> = Vec::new();
    let mut subnets: Vec<(u32, u32, &str)> = Vec::new(); // (net, bcast, slug)
    let mut radio_vifs: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();

    for ssid in &state.ssids {
        let s = ssid.slug.as_str();
        if !is_slug(s) {
            return bad(format!("slug must match [a-z0-9_]{{1,16}}, got '{s}'"));
        }
        if RESERVED_SLUGS.contains(&s) {
            return bad(format!("slug '{s}' is reserved"));
        }
        if seen_slugs.contains(&s) {
            return bad(format!("duplicate slug '{s}'"));
        }
        seen_slugs.push(s);

        // Validate the RAW ssid (what render_ssid emits verbatim) so validation
        // and rendering agree. Reject control chars: an SSID with `\n`/`\r` would
        // otherwise be written to UCI and could corrupt the tmpfs marker's
        // line-based (key=value) round-trip that rollback replays.
        let name = ssid.ssid.as_str();
        if name.trim().is_empty() || name.chars().count() > 32 {
            return bad(format!("ssid for '{s}' must be 1..=32 chars"));
        }
        if name.chars().any(|c| c.is_control()) {
            return bad(format!("ssid for '{s}' must not contain control characters"));
        }

        let radios = effective_radios(ssid);
        if radios.len() > MAX_RADIOS_PER_SSID {
            return bad(format!("slug '{s}' spans {} radios (max {MAX_RADIOS_PER_SSID})", radios.len()));
        }
        for r in &radios {
            if !is_uci_ident(r) {
                return bad(format!("radio '{r}' for slug '{s}' is not a UCI identifier"));
            }
            *radio_vifs.entry(*r).or_insert(0) += 1;
        }

        let enc = if ssid.encryption.is_empty() { "none" } else { ssid.encryption.as_str() };
        if !matches!(enc, "none" | "psk2" | "psk2+ccmp" | "sae" | "sae-mixed") {
            return bad(format!("encryption '{enc}' for slug '{s}' unsupported"));
        }
        if enc != "none" {
            let kl = ssid.key.chars().count();
            if !(8..=63).contains(&kl) {
                return bad(format!("encryption '{enc}' for slug '{s}' requires key 8..=63 chars, got {kl}"));
            }
            // A WPA passphrase is printable ASCII (0x20..=0x7e). Rejecting
            // control chars / non-ASCII keeps a key from corrupting the rendered
            // config or the tmpfs marker's line-based round-trip (rollback safety).
            if ssid.key.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
                return bad(format!("key for slug '{s}' must be printable ASCII (32..=126)"));
            }
        }

        // MAC access-control (F7). Policy must be a known value; allow/deny needs a
        // non-empty list of well-formed MACs (each element becomes a maclist entry
        // via add_list). Reject up front so a bad ACL writes nothing.
        match ssid.mac_policy.as_str() {
            "" | "disable" => {}
            "allow" | "deny" => {
                if ssid.mac_list.is_empty() {
                    return bad(format!("mac_policy '{}' for slug '{s}' requires a non-empty mac_list", ssid.mac_policy));
                }
                for m in &ssid.mac_list {
                    if !is_mac_addr(m) {
                        return bad(format!("mac_list entry '{m}' for slug '{s}' is not a MAC (aa:bb:cc:dd:ee:ff)"));
                    }
                }
            }
            other => return bad(format!("mac_policy '{other}' for slug '{s}' unsupported (allow|deny|disable)")),
        }

        // Validate the RAW bridge_name (is_uci_ident already rejects whitespace)
        // so validation matches what render_ssid / rescope emit verbatim.
        let br = ssid.bridge_name.as_str();
        if !is_uci_ident(br) {
            return bad(format!("bridge_name '{br}' for slug '{s}' is not a valid iface name"));
        }
        if RESERVED_BRIDGES.contains(&br) {
            return bad(format!("bridge_name '{br}' is reserved"));
        }
        if seen_bridges.contains(&br) {
            return bad(format!("duplicate bridge_name '{br}'"));
        }
        seen_bridges.push(br);

        let egress = if ssid.egress_zone.is_empty() { WAN_ZONE } else { ssid.egress_zone.as_str() };
        if !is_uci_ident(egress) {
            return bad(format!("egress_zone '{egress}' for slug '{s}' is not a valid zone name"));
        }
        if RESERVED_EGRESS.contains(&egress) {
            return bad(format!("egress_zone '{egress}' for slug '{s}' is not allowed (would bypass the gate)"));
        }

        let gw = parse_ipv4(&ssid.ipaddr).ok_or_else(|| {
            ProvisionError::Invalid(format!("ipaddr '{}' for slug '{s}' not a dotted-quad IPv4", ssid.ipaddr))
        })?;
        let mask = parse_ipv4(&ssid.netmask).ok_or_else(|| {
            ProvisionError::Invalid(format!("netmask '{}' for slug '{s}' not a dotted-quad IPv4", ssid.netmask))
        })?;
        if !is_contiguous_mask(mask) {
            return bad(format!("netmask '{}' for slug '{s}' is not a contiguous subnet mask", ssid.netmask));
        }
        let net = mask_and(gw, mask);
        let bcast = or_inv(net, mask);
        if gw == net || gw == bcast {
            return bad(format!("ipaddr '{}' for slug '{s}' is the network/broadcast address", ssid.ipaddr));
        }
        for (onet, obcast, oslug) in &subnets {
            if net <= *obcast && *onet <= bcast {
                return bad(format!("subnet of slug '{s}' overlaps slug '{oslug}'"));
            }
        }
        subnets.push((net, bcast, s));

        if !ssid.dhcp_disabled {
            let start: u32 = ssid.dhcp_start.trim().parse().map_err(|_| {
                ProvisionError::Invalid(format!("dhcp_start '{}' for slug '{s}' not a number", ssid.dhcp_start))
            })?;
            let limit: u32 = ssid.dhcp_limit.trim().parse().map_err(|_| {
                ProvisionError::Invalid(format!("dhcp_limit '{}' for slug '{s}' not a number", ssid.dhcp_limit))
            })?;
            if start == 0 || start > 65535 {
                return bad(format!("dhcp_start out of range (1..=65535) for slug '{s}': {start}"));
            }
            if limit == 0 || limit > 65535 {
                return bad(format!("dhcp_limit out of range (1..=65535) for slug '{s}': {limit}"));
            }
            if !is_leasetime(&ssid.dhcp_leasetime) {
                return bad(format!("dhcp_leasetime '{}' for slug '{s}' is invalid", ssid.dhcp_leasetime));
            }
        }
    }

    for (r, n) in &radio_vifs {
        if *n > MAX_SSIDS_PER_RADIO {
            return bad(format!("radio '{r}' would carry {n} SSIDs (max {MAX_SSIDS_PER_RADIO})"));
        }
    }

    Ok(())
}

/// Reject a desired-state that places any owned SSID on a PROTECTED radio (the
/// admin/management radio an operator marked off-limits via config). `wifi reload
/// <radio>` rebuilds the WHOLE radio, so an owned SSID sharing the admin radio
/// makes every apply/rollback bounce the admin SSID; forbidding the overlap keeps
/// the protected radio untouched. An SSID with no explicit `radios` defaults to
/// [`DEFAULT_RADIO`], so if that is protected the operator must name another radio
/// explicitly. Fail-open REJECT (nothing applied). Empty `protected` = no-op
/// (default), preserving the current behaviour on single-radio routers.
pub fn validate_protected_radios(
    state: &WirelessDesiredState,
    protected: &[String],
) -> Result<(), ProvisionError> {
    if protected.is_empty() {
        return Ok(());
    }
    for ssid in &state.ssids {
        for r in effective_radios(ssid) {
            if protected.iter().any(|p| p.as_str() == r) {
                return Err(ProvisionError::Invalid(format!(
                    "slug '{}' targets protected radio '{r}' (admin/management radio); assign it to a non-protected radio",
                    ssid.slug
                )));
            }
        }
    }
    Ok(())
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

    // --- CP-managed wireless (P-W1) ----------------------------------------

    fn valid_ssid(slug: &str, gated: bool) -> SsidSpec {
        SsidSpec {
            slug: slug.into(),
            ssid: format!("WifiHub {slug}"),
            radios: vec!["radio0".into()],
            encryption: if gated { "none".into() } else { "psk2".into() },
            key: if gated { String::new() } else { "supersecret".into() },
            hidden: false,
            isolate: true,
            gated,
            bridge_name: format!("br-{slug}"),
            ipaddr: "10.0.0.1".into(),
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
        }
    }

    /// `valid_ssid` on a distinct `/24` (third octet = `subnet3`) so multi-SSID
    /// states don't trip the overlap check.
    fn ssid_on(slug: &str, gated: bool, subnet3: u8) -> SsidSpec {
        let mut s = valid_ssid(slug, gated);
        s.ipaddr = format!("10.0.{subnet3}.1");
        s
    }

    fn wstate(ssids: Vec<SsidSpec>) -> WirelessDesiredState {
        WirelessDesiredState { config_version: "cfg-1".into(), ssids, confirm_timeout_secs: 0 }
    }

    fn has_set(cmds: &[UciCmd], key: &str, value: &str) -> bool {
        cmds.iter().any(|c| *c == UciCmd::set(key, value))
    }
    fn has_key(cmds: &[UciCmd], key: &str) -> bool {
        cmds.iter().any(|c| matches!(c, UciCmd::Set { key: k, .. } if k == key))
    }
    fn has_delete(cmds: &[UciCmd], key: &str) -> bool {
        cmds.iter().any(|c| *c == UciCmd::delete(key))
    }

    #[test]
    fn render_ssid_gated_open_has_expected_sections() {
        let cmds = render_ssid(&valid_ssid("public", true), 8080);
        // bridge + interface
        assert!(has_set(&cmds, "network.pc_public_dev", "device"));
        assert!(has_set(&cmds, "network.pc_public_dev.name", "br-public"));
        assert!(has_set(&cmds, "network.pc_public_if", "interface"));
        assert!(has_set(&cmds, "network.pc_public_if.ipaddr", "10.0.0.1"));
        // wifi-iface (open captive → no key)
        assert!(has_set(&cmds, "wireless.pc_public_ap0", "wifi-iface"));
        assert!(has_set(&cmds, "wireless.pc_public_ap0.device", "radio0"));
        assert!(has_set(&cmds, "wireless.pc_public_ap0.encryption", "none"));
        assert!(!has_key(&cmds, "wireless.pc_public_ap0.key"));
        // dhcp + firewall zone/forwarding
        assert!(has_set(&cmds, "dhcp.pc_public", "dhcp"));
        assert!(has_set(&cmds, "firewall.pc_public_zone", "zone"));
        assert!(has_set(&cmds, "firewall.pc_public_zone.name", "public"));
        assert!(has_set(&cmds, "firewall.pc_public_fwd.dest", "wan"));
        assert!(has_set(&cmds, "firewall.pc_public_dhcp.dest_port", "67"));
        assert!(has_set(&cmds, "firewall.pc_public_dns.dest_port", "53"));
        // gated → portal rule opens the responder port
        assert!(has_set(&cmds, "firewall.pc_public_portal.dest_port", "8080"));
        // every section stamped with the owner
        assert!(has_set(&cmds, "firewall.pc_public_zone.owner", WIRELESS_OWNER));
    }

    #[test]
    fn render_ssid_trusted_psk_has_key_and_no_portal() {
        let cmds = render_ssid(&valid_ssid("home", false), 8080);
        assert!(has_set(&cmds, "wireless.pc_home_ap0.encryption", "psk2"));
        assert!(has_set(&cmds, "wireless.pc_home_ap0.key", "supersecret"));
        // NOT gated → no portal rule
        assert!(!has_key(&cmds, "firewall.pc_home_portal"));
    }

    #[test]
    fn render_ssid_multi_radio_makes_one_ap_per_radio() {
        let mut s = valid_ssid("public", true);
        s.radios = vec!["radio0".into(), "radio1".into()];
        let cmds = render_ssid(&s, 8080);
        assert!(has_set(&cmds, "wireless.pc_public_ap0.device", "radio0"));
        assert!(has_set(&cmds, "wireless.pc_public_ap1.device", "radio1"));
    }

    // Phase 2 (F5): PMF is derived from encryption — SAE required, mixed optional,
    // psk2/open unset.
    #[test]
    fn render_ssid_pmf_ieee80211w_by_encryption() {
        let mut sae = valid_ssid("s3", false);
        sae.encryption = "sae".into();
        assert!(has_set(&render_ssid(&sae, 8080), "wireless.pc_s3_ap0.ieee80211w", "2"));

        let mut mixed = valid_ssid("mx", false);
        mixed.encryption = "sae-mixed".into();
        assert!(has_set(&render_ssid(&mixed, 8080), "wireless.pc_mx_ap0.ieee80211w", "1"));

        // psk2 and open never set PMF.
        assert!(!has_key(&render_ssid(&valid_ssid("home", false), 8080), "wireless.pc_home_ap0.ieee80211w"));
        assert!(!has_key(&render_ssid(&valid_ssid("public", true), 8080), "wireless.pc_public_ap0.ieee80211w"));
    }

    // Phase 2 (F6): maxassoc set only when max_clients > 0.
    #[test]
    fn render_ssid_maxassoc_when_capped() {
        let mut capped = valid_ssid("home", false);
        capped.max_clients = 32;
        assert!(has_set(&render_ssid(&capped, 8080), "wireless.pc_home_ap0.maxassoc", "32"));
        // unlimited (0) => unset
        assert!(!has_key(&render_ssid(&valid_ssid("home", false), 8080), "wireless.pc_home_ap0.maxassoc"));
    }

    fn has_add_list(cmds: &[UciCmd], key: &str, value: &str) -> bool {
        cmds.iter().any(|c| *c == UciCmd::add_list(key, value))
    }

    // Phase 2 (F7): MAC ACL renders macfilter + one lowercased add_list per MAC.
    #[test]
    fn render_ssid_mac_deny_list() {
        let mut s = valid_ssid("home", false);
        s.mac_policy = "deny".into();
        s.mac_list = vec!["AA:BB:CC:DD:EE:FF".into(), "11:22:33:44:55:66".into()];
        let cmds = render_ssid(&s, 8080);
        assert!(has_set(&cmds, "wireless.pc_home_ap0.macfilter", "deny"));
        assert!(has_add_list(&cmds, "wireless.pc_home_ap0.maclist", "aa:bb:cc:dd:ee:ff")); // lowercased
        assert!(has_add_list(&cmds, "wireless.pc_home_ap0.maclist", "11:22:33:44:55:66"));
    }

    #[test]
    fn render_ssid_no_mac_filter_when_policy_off() {
        // empty policy => neither macfilter nor maclist
        let cmds = render_ssid(&valid_ssid("home", false), 8080);
        assert!(!has_key(&cmds, "wireless.pc_home_ap0.macfilter"));
        assert!(!has_key(&cmds, "wireless.pc_home_ap0.maclist"));
    }

    fn wstate1(s: SsidSpec) -> WirelessDesiredState {
        WirelessDesiredState { config_version: "cfg".into(), ssids: vec![s], confirm_timeout_secs: 0 }
    }

    // Phase 3 (F9): a rate cap renders an sqm `queue` section on the SSID's bridge.
    #[test]
    fn render_ssid_sqm_when_rate_capped() {
        let mut s = valid_ssid("home", false);
        s.rate_down_kbps = 20000;
        s.rate_up_kbps = 5000;
        let cmds = render_ssid(&s, 8080);
        assert!(has_set(&cmds, "sqm.pc_home", "queue"));
        assert!(has_set(&cmds, "sqm.pc_home.interface", "br-home"));
        assert!(has_set(&cmds, "sqm.pc_home.enabled", "1"));
        assert!(has_set(&cmds, "sqm.pc_home.download", "20000"));
        assert!(has_set(&cmds, "sqm.pc_home.upload", "5000"));
        assert!(has_set(&cmds, "sqm.pc_home.owner", WIRELESS_OWNER));
    }

    #[test]
    fn render_ssid_no_sqm_when_uncapped() {
        assert!(!has_key(&render_ssid(&valid_ssid("home", false), 8080), "sqm.pc_home"));
    }

    #[test]
    fn teardown_removes_sqm_section() {
        assert!(render_ssid_teardown("home").iter().any(|c| *c == UciCmd::delete("sqm.pc_home")));
    }

    #[test]
    fn validate_wireless_rejects_bad_mac_and_empty_list() {
        // allow/deny with an empty list is rejected
        let mut empty = valid_ssid("home", false);
        empty.mac_policy = "allow".into();
        assert!(validate_wireless(&wstate1(empty)).is_err());
        // malformed MAC is rejected
        let mut bad = valid_ssid("home", false);
        bad.mac_policy = "deny".into();
        bad.mac_list = vec!["not-a-mac".into()];
        assert!(validate_wireless(&wstate1(bad)).is_err());
        // unknown policy rejected
        let mut unknown = valid_ssid("home", false);
        unknown.mac_policy = "whitelist".into();
        assert!(validate_wireless(&wstate1(unknown)).is_err());
        // valid deny-list passes
        let mut ok = valid_ssid("home", false);
        ok.mac_policy = "deny".into();
        ok.mac_list = vec!["aa:bb:cc:dd:ee:ff".into()];
        assert!(validate_wireless(&wstate1(ok)).is_ok());
    }

    #[test]
    fn render_ssid_egress_zone_overrides_wan() {
        let mut s = valid_ssid("public", true);
        s.egress_zone = "wan_4g".into();
        let cmds = render_ssid(&s, 8080);
        assert!(has_set(&cmds, "firewall.pc_public_fwd.dest", "wan_4g"));
    }

    #[test]
    fn render_wireless_covers_all_ssids() {
        let st = wstate(vec![ssid_on("public", true, 0), ssid_on("staff", false, 1)]);
        let cmds = render_wireless(&st, 8080);
        assert!(has_set(&cmds, "wireless.pc_public_ap0", "wifi-iface"));
        assert!(has_set(&cmds, "wireless.pc_staff_ap0", "wifi-iface"));
    }

    #[test]
    fn validate_wireless_accepts_valid_multi() {
        let st = wstate(vec![ssid_on("public", true, 0), ssid_on("staff", false, 1)]);
        validate_wireless(&st).unwrap();
    }

    #[test]
    fn validate_wireless_empty_is_teardown_ok() {
        validate_wireless(&wstate(vec![])).unwrap();
    }

    #[test]
    fn validate_protected_radios_empty_is_noop() {
        // Default (no protected radios) never rejects — preserves current behaviour.
        let st = wstate(vec![ssid_on("public", true, 0)]); // defaults to radio0
        validate_protected_radios(&st, &[]).unwrap();
    }

    #[test]
    fn validate_protected_radios_rejects_ssid_on_admin_radio() {
        // An SSID with no explicit radios defaults to radio0; protecting radio0
        // rejects it (operator must move it to another radio explicitly).
        let st = wstate(vec![ssid_on("public", true, 0)]);
        let err = validate_protected_radios(&st, &["radio0".to_string()]).unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));

        // Explicitly targeting the protected radio is also rejected.
        let mut s = ssid_on("staff", false, 1);
        s.radios = vec!["radio0".into()];
        let err = validate_protected_radios(&wstate(vec![s]), &["radio0".to_string()]).unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));
    }

    #[test]
    fn validate_protected_radios_allows_ssid_on_free_radio() {
        // Guest on radio1 while radio0 is protected → accepted.
        let mut s = ssid_on("public", true, 0);
        s.radios = vec!["radio1".into()];
        validate_protected_radios(&wstate(vec![s]), &["radio0".to_string()]).unwrap();
    }

    #[test]
    fn validate_wireless_rejects_reserved_slug() {
        assert!(validate_wireless(&wstate(vec![ssid_on("lan", false, 0)])).is_err());
        assert!(validate_wireless(&wstate(vec![ssid_on("wan", false, 0)])).is_err());
    }

    #[test]
    fn validate_wireless_rejects_duplicate_slug() {
        let st = wstate(vec![ssid_on("dup", true, 0), ssid_on("dup", false, 1)]);
        assert!(validate_wireless(&st).is_err());
    }

    #[test]
    fn validate_wireless_rejects_duplicate_bridge() {
        let mut a = ssid_on("public", true, 0);
        let mut b = ssid_on("staff", false, 1);
        a.bridge_name = "br-shared".into();
        b.bridge_name = "br-shared".into();
        assert!(validate_wireless(&wstate(vec![a, b])).is_err());
    }

    #[test]
    fn validate_wireless_rejects_br_lan() {
        let mut s = ssid_on("public", true, 0);
        s.bridge_name = "br-lan".into();
        assert!(validate_wireless(&wstate(vec![s])).is_err());
    }

    #[test]
    fn validate_wireless_rejects_egress_lan() {
        let mut s = ssid_on("public", true, 0);
        s.egress_zone = "lan".into();
        assert!(validate_wireless(&wstate(vec![s])).is_err());
    }

    #[test]
    fn validate_wireless_rejects_overlapping_subnets() {
        let a = ssid_on("public", true, 0);
        let b = ssid_on("staff", false, 0); // same /24 as a
        assert!(validate_wireless(&wstate(vec![a, b])).is_err());
    }

    #[test]
    fn validate_wireless_rejects_bad_key_len() {
        let mut s = ssid_on("home", false, 0);
        s.key = "short".into(); // < 8
        assert!(validate_wireless(&wstate(vec![s])).is_err());
    }

    #[test]
    fn validate_wireless_rejects_radio_vif_overflow() {
        let ssids: Vec<SsidSpec> = (0..=(MAX_SSIDS_PER_RADIO as u8))
            .map(|i| ssid_on(&format!("s{i}"), false, i)) // all default radio0
            .collect();
        assert!(validate_wireless(&wstate(ssids)).is_err());
    }

    #[test]
    fn validate_wireless_rejects_bad_timeout() {
        let mut st = wstate(vec![ssid_on("public", true, 0)]);
        st.confirm_timeout_secs = 5; // below MIN 15
        assert!(validate_wireless(&st).is_err());
    }

    #[test]
    fn render_ssid_teardown_deletes_owned() {
        let cmds = render_ssid_teardown("public");
        assert!(has_delete(&cmds, "firewall.pc_public_zone"));
        assert!(has_delete(&cmds, "firewall.pc_public_portal"));
        assert!(has_delete(&cmds, "dhcp.pc_public"));
        assert!(has_delete(&cmds, "wireless.pc_public_ap0"));
        assert!(has_delete(&cmds, "network.pc_public_if"));
        assert!(has_delete(&cmds, "network.pc_public_dev"));
    }

    #[test]
    fn is_owned_wireless_section_only_for_pc_prefix() {
        assert!(is_owned_wireless_section("network.pc_public_dev"));
        assert!(is_owned_wireless_section("firewall.pc_staff_zone"));
        assert!(!is_owned_wireless_section("network.lan"));
        assert!(!is_owned_wireless_section("wireless.wifi_hotspot"));
        assert!(!is_owned_wireless_section("firewall.wan"));
    }

    #[test]
    fn validate_wireless_rejects_control_chars_in_ssid_and_key() {
        // Security MED-1: a `\n` in the SSID/PSK would corrupt the rendered config
        // and the tmpfs marker's line-based round-trip used by rollback.
        let mut a = ssid_on("public", true, 0);
        a.ssid = "Bad\nSSID".into();
        assert!(validate_wireless(&wstate(vec![a])).is_err());

        let mut b = ssid_on("home", false, 1);
        b.key = "sup\nersecret".into(); // control char in key
        assert!(validate_wireless(&wstate(vec![b])).is_err());
    }

    #[test]
    fn validate_wireless_rejects_whitespace_in_bridge_name() {
        // F3: validation is on the RAW bridge_name (matching what render emits),
        // so a trailing space fails the ident check.
        let mut s = ssid_on("public", true, 0);
        s.bridge_name = "br-public ".into();
        assert!(validate_wireless(&wstate(vec![s])).is_err());
    }

    #[test]
    fn ssid_spec_debug_redacts_key() {
        // LOW-1: the PSK must never appear in Debug output.
        let mut s = valid_ssid("home", false); // key = "supersecret"
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("supersecret"), "Debug leaked the PSK: {dbg}");
        assert!(dbg.contains("<redacted>"));
        s.key = String::new();
        assert!(format!("{s:?}").contains("<none>"));
    }
}
