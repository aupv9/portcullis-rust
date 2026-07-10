//! Configuration types, load, and hot-reload classification for `portcullis`
//! (TDD §9).
//!
//! Configuration is sourced from UCI (`/etc/config/portcullis`) on the router,
//! bootstrapped at first boot and reconciled by the fleet pipeline. For host
//! tests and tooling a TOML representation is also supported (the field set is
//! identical). This crate is pure parsing/validation plus `std::fs` load — it
//! performs no kernel I/O and pulls in no Linux-only dependencies.
//!
//! Note (§13): the HMAC key itself lives *outside* this config. We only carry
//! the `hmac_key_file` path here; the key bytes are read by the redirect
//! responder from that file, never embedded in config.

#![forbid(unsafe_code)]

use std::path::Path;

use serde::{Deserialize, Serialize};

use portcullis_types::{Error, Result};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// The full `portcullis` engine configuration, mirroring the UCI `config
/// portcullis 'main'` section from TDD §9.
///
/// Defaults match the §9 example so a freshly bootstrapped device with a
/// minimal config behaves predictably.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Stable store identity, e.g. `SITE-0042`. Signed into the redirect HMAC.
    pub store_id: String,

    /// gRPC control-plane endpoint the engine **dials outbound** (the router sits
    /// behind CGNAT, so it is the client — see `docs/design/cgnat-bidi-control-channel.md`).
    pub control_endpoint: String,

    /// Path to the CA that signs the control plane's **server** certificate; the
    /// engine verifies the CP against it when dialing. Defaulted for
    /// backward-compatible configs.
    #[serde(default = "default_cp_server_ca_file")]
    pub cp_server_ca_file: String,

    /// Expected server name (SNI / cert CN·SAN) of the control plane, verified
    /// during the TLS handshake. Empty => derive from `control_endpoint`.
    #[serde(default)]
    pub cp_server_name: String,

    /// Cap (seconds) on the reconnect exponential backoff to the control plane.
    #[serde(default = "default_reconnect_max_secs")]
    pub control_reconnect_max_secs: u64,

    /// HTTP/2 keepalive interval (seconds) on the control channel, kept below the
    /// carrier CGNAT idle timeout so the outbound mapping stays fresh.
    #[serde(default = "default_keepalive_secs")]
    pub control_keepalive_secs: u64,

    /// Radios the CP-managed wireless subsystem must NOT place owned SSIDs on
    /// (typically the admin/management radio). A push naming any of these is
    /// rejected up front, so `wifi reload <radio>` — which rebuilds the WHOLE radio
    /// — can never bounce or dark the admin SSID sharing it. Empty (default) = no
    /// protection, current behaviour. Opt-in per deployment: on a dual-band router
    /// set e.g. `radio0` here and give guest SSIDs `radios=radio1`. Leave empty on
    /// single-radio routers (no spare radio to move guests onto).
    #[serde(default)]
    pub wireless_protected_radios: Vec<String>,

    /// Path to the HMAC key file (§13 — the key lives outside this config).
    pub hmac_key_file: String,

    /// TCP port the :8080 redirect responder listens on.
    pub responder_port: u16,

    /// Seconds between conntrack accounting snapshots.
    pub accounting_interval: u64,

    /// Default session TTL in seconds when a grant omits one.
    pub default_ttl: u64,

    /// Default per-session byte quota in megabytes (`0` == unlimited).
    pub default_quota_mb: u64,

    /// Default per-session rate limit in kbps (`0` == unlimited).
    pub default_rate_kbps: u64,

    /// TCP port for the Prometheus `/metrics` endpoint, bound on loopback
    /// (TDD §12). `0` disables the endpoint. `#[serde(default)]` so existing
    /// configs (which predate this field) still parse under `deny_unknown_fields`.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Seconds between drift-reconciliation passes against the kernel `auth`
    /// set (TDD §7.8). Defaulted for backward-compatible configs.
    #[serde(default = "default_reconcile_interval")]
    pub reconcile_interval: u64,

    /// Walled-garden FQDNs always reachable pre-auth (portal, CDN, OTP, pay).
    #[serde(default)]
    pub garden_fqdn: Vec<String>,

    /// Firewall backend selection (TDD §17 option A vs B): `"auto"` (default —
    /// probe for kernel nft NAT support, fall back to ipset), `"nft"` (force
    /// [`portcullis_types`]-agnostic `NftJsonBackend`), or `"ipset"` (force the
    /// stock-RutOS `IpsetIptablesBackend`). `#[serde(default)]` so pre-existing
    /// configs (which predate this field) still parse under `deny_unknown_fields`.
    #[serde(default = "default_firewall_backend")]
    pub firewall_backend: String,

    /// The hotspot interface enforcement scopes to (P0) — the bridge the
    /// `portcullis-provision` subsystem creates (P0.5), e.g. `br-hotspot`. Empty
    /// (the default) means "not scoped": enforcement binds fleet-wide as before,
    /// which is the pre-P0 behaviour and the root of the whole-LAN-block incident.
    /// Once provisioning lands, the control plane fills this with the resulting
    /// bridge so the FORWARD/redirect jumps gate ONLY the public SSID.
    /// `#[serde(default)]` so pre-existing configs still parse under
    /// `deny_unknown_fields`.
    #[serde(default)]
    pub hotspot_iface: String,

    /// Reap established conntrack flows on de-auth (revoke/expiry/quota/idle) and
    /// via a periodic reconcile sweep — invariant #9, conntrack ⊆ auth. On (the
    /// default) closes the "established flow leaks past de-auth" bug; requires the
    /// `conntrack` binary (already a metering dependency). Set `false` to disable
    /// (e.g. a device without `conntrack`). `#[serde(default)]` for back-compat.
    #[serde(default = "default_reap_conntrack")]
    pub reap_conntrack: bool,

    /// Enable per-session bandwidth shaping (tc/HTB, G5). Off by default (Phase-2,
    /// device-validated). When on, `shape_iface` must name the LAN egress
    /// interface the HTB qdisc lives on; the engine advertises the `shaper`
    /// capability so the control plane may send `rate_bps` caps. `#[serde(default)]`.
    #[serde(default)]
    pub shape_bandwidth: bool,

    /// LAN egress interface for the tc/HTB qdisc (e.g. `br-lan`). Only used when
    /// `shape_bandwidth` is on; empty disables shaping even if the flag is set.
    #[serde(default)]
    pub shape_iface: String,

    /// Local seed for the idle-timeout threshold in seconds (G6); `0` = disabled.
    /// The control plane can override at runtime via `SetEngineParameters`.
    /// `#[serde(default)]` (0) for back-compat.
    #[serde(default)]
    pub idle_timeout: u64,
}

fn default_reap_conntrack() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_firewall_backend() -> String {
    "auto".to_string()
}

fn default_reconcile_interval() -> u64 {
    60
}

fn default_cp_server_ca_file() -> String {
    "/etc/portcullis/tls/cp-ca.crt".to_string()
}

fn default_reconnect_max_secs() -> u64 {
    60
}

fn default_keepalive_secs() -> u64 {
    20
}

impl Default for Config {
    fn default() -> Self {
        // Mirrors the §9 example.
        Config {
            store_id: String::new(),
            control_endpoint: "https://cp.wifihub.internal:8443".to_string(),
            cp_server_ca_file: default_cp_server_ca_file(),
            cp_server_name: String::new(),
            control_reconnect_max_secs: default_reconnect_max_secs(),
            control_keepalive_secs: default_keepalive_secs(),
            wireless_protected_radios: Vec::new(),
            hmac_key_file: "/etc/portcullis/hmac.key".to_string(),
            responder_port: 8080,
            accounting_interval: 15,
            default_ttl: 1800,
            default_quota_mb: 0,
            default_rate_kbps: 2048,
            metrics_port: default_metrics_port(),
            reconcile_interval: default_reconcile_interval(),
            garden_fqdn: Vec::new(),
            firewall_backend: default_firewall_backend(),
            hotspot_iface: String::new(),
            reap_conntrack: default_reap_conntrack(),
            shape_bandwidth: false,
            shape_iface: String::new(),
            idle_timeout: 0,
        }
    }
}

impl Config {
    /// Parse a TOML document into a [`Config`].
    pub fn from_toml_str(s: &str) -> Result<Config> {
        toml::from_str(s).map_err(|e| Error::Config(format!("invalid TOML config: {e}")))
    }

    /// Serialize this config to a TOML document.
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| Error::Config(format!("failed to serialize config: {e}")))
    }

    /// Load and parse a TOML config file from disk.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Config> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read config {}: {e}", path.display())))?;
        Self::from_toml_str(&text)
    }

    /// Parse the UCI format shown in TDD §9.
    ///
    /// Accepts the `config portcullis 'main'` section followed by `option <key>
    /// '<value>'` lines and repeated `list garden_fqdn '<value>'` lines.
    /// Tolerant of arbitrary leading/trailing whitespace; `#` introduces a
    /// comment that runs to end of line. Values may be single-quoted,
    /// double-quoted, or bare.
    pub fn from_uci_str(s: &str) -> Result<Config> {
        let mut cfg = Config::default();
        let mut saw_section = false;

        for (lineno, raw) in s.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }

            let mut tokens = tokenize(line)
                .map_err(|e| Error::Config(format!("UCI line {}: {e}", lineno + 1)))?;
            if tokens.is_empty() {
                continue;
            }

            let kw = tokens.remove(0);
            match kw.as_str() {
                "config" => {
                    // e.g. `config portcullis 'main'`
                    match tokens.first().map(String::as_str) {
                        Some("portcullis") => saw_section = true,
                        Some(other) => {
                            return Err(Error::Config(format!(
                                "UCI line {}: unexpected config section type '{other}'",
                                lineno + 1
                            )));
                        }
                        None => {
                            return Err(Error::Config(format!(
                                "UCI line {}: 'config' without a section type",
                                lineno + 1
                            )));
                        }
                    }
                }
                "option" => {
                    if tokens.len() != 2 {
                        return Err(Error::Config(format!(
                            "UCI line {}: 'option' expects <key> <value>",
                            lineno + 1
                        )));
                    }
                    let key = &tokens[0];
                    let val = &tokens[1];
                    apply_option(&mut cfg, key, val, lineno + 1)?;
                }
                "list" => {
                    if tokens.len() != 2 {
                        return Err(Error::Config(format!(
                            "UCI line {}: 'list' expects <key> <value>",
                            lineno + 1
                        )));
                    }
                    let key = &tokens[0];
                    let val = &tokens[1];
                    match key.as_str() {
                        "garden_fqdn" => cfg.garden_fqdn.push(val.clone()),
                        "wireless_protected_radio" => cfg.wireless_protected_radios.push(val.clone()),
                        other => {
                            return Err(Error::Config(format!(
                                "UCI line {}: unknown list key '{other}'",
                                lineno + 1
                            )));
                        }
                    }
                }
                other => {
                    return Err(Error::Config(format!(
                        "UCI line {}: unexpected keyword '{other}'",
                        lineno + 1
                    )));
                }
            }
        }

        if !saw_section {
            return Err(Error::Config(
                "UCI config missing 'config portcullis' section".to_string(),
            ));
        }

        Ok(cfg)
    }

    /// Validate the config for internal consistency (§9). Returns
    /// [`Error::Config`] with a clear message on the first failure.
    pub fn validate(&self) -> Result<()> {
        if self.store_id.trim().is_empty() {
            return Err(Error::Config("store_id must not be empty".to_string()));
        }
        if self.control_endpoint.trim().is_empty() {
            return Err(Error::Config(
                "control_endpoint must not be empty".to_string(),
            ));
        }
        if self.hmac_key_file.trim().is_empty() {
            return Err(Error::Config("hmac_key_file must not be empty".to_string()));
        }
        if self.responder_port == 0 {
            return Err(Error::Config("responder_port must not be 0".to_string()));
        }
        if self.accounting_interval < 1 {
            return Err(Error::Config(
                "accounting_interval must be >= 1 second".to_string(),
            ));
        }
        if self.default_ttl < 1 {
            return Err(Error::Config("default_ttl must be >= 1 second".to_string()));
        }
        if !matches!(self.firewall_backend.as_str(), "auto" | "ipset" | "nft") {
            return Err(Error::Config(format!(
                "firewall_backend must be one of auto|ipset|nft, got '{}'",
                self.firewall_backend
            )));
        }
        // Each garden FQDN is written verbatim into a dnsmasq `ipset=`/`nftset=`
        // directive; a newline/space/`#`/`/` would inject a directive or produce a
        // malformed line dnsmasq treats as FATAL (whole-LAN DNS loss). Reject
        // anything that isn't a plain hostname at config load, so a UCI typo is
        // caught loudly (the engine's garden renderer also drops invalid entries as
        // a defence-in-depth sink guard).
        for fqdn in &self.garden_fqdn {
            if !is_valid_garden_fqdn(fqdn) {
                return Err(Error::Config(format!(
                    "garden_fqdn '{fqdn}' is not a valid hostname (dot-separated [A-Za-z0-9-] labels)"
                )));
            }
        }
        Ok(())
    }
}

/// A plain DNS hostname safe to embed in a dnsmasq set directive (see
/// `portcullis_garden::is_valid_fqdn`; duplicated here to keep config dependency-
/// free): 1..=253 chars, dot-separated 1..=63-char labels of `[A-Za-z0-9-]`, no
/// label edge `-`, no empty labels.
fn is_valid_garden_fqdn(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Apply a single `option <key> <value>` to the config, parsing typed fields.
fn apply_option(cfg: &mut Config, key: &str, val: &str, lineno: usize) -> Result<()> {
    let parse_u16 = |v: &str| -> Result<u16> {
        v.parse::<u16>().map_err(|_| {
            Error::Config(format!("UCI line {lineno}: '{key}' expects a u16, got '{v}'"))
        })
    };
    let parse_u64 = |v: &str| -> Result<u64> {
        v.parse::<u64>().map_err(|_| {
            Error::Config(format!("UCI line {lineno}: '{key}' expects a u64, got '{v}'"))
        })
    };
    let parse_bool = |v: &str| -> Result<bool> {
        match v {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(Error::Config(format!(
                "UCI line {lineno}: '{key}' expects a bool (0/1/true/false), got '{v}'"
            ))),
        }
    };

    match key {
        "store_id" => cfg.store_id = val.to_string(),
        "control_endpoint" => cfg.control_endpoint = val.to_string(),
        "cp_server_ca_file" => cfg.cp_server_ca_file = val.to_string(),
        "cp_server_name" => cfg.cp_server_name = val.to_string(),
        "control_reconnect_max_secs" => cfg.control_reconnect_max_secs = parse_u64(val)?,
        "control_keepalive_secs" => cfg.control_keepalive_secs = parse_u64(val)?,
        "hmac_key_file" => cfg.hmac_key_file = val.to_string(),
        "responder_port" => cfg.responder_port = parse_u16(val)?,
        "accounting_interval" => cfg.accounting_interval = parse_u64(val)?,
        "default_ttl" => cfg.default_ttl = parse_u64(val)?,
        "default_quota_mb" => cfg.default_quota_mb = parse_u64(val)?,
        "default_rate_kbps" => cfg.default_rate_kbps = parse_u64(val)?,
        "metrics_port" => cfg.metrics_port = parse_u16(val)?,
        "reconcile_interval" => cfg.reconcile_interval = parse_u64(val)?,
        "firewall_backend" => cfg.firewall_backend = val.to_string(),
        "hotspot_iface" => cfg.hotspot_iface = val.to_string(),
        "reap_conntrack" => cfg.reap_conntrack = parse_bool(val)?,
        "shape_bandwidth" => cfg.shape_bandwidth = parse_bool(val)?,
        "shape_iface" => cfg.shape_iface = val.to_string(),
        "idle_timeout" => cfg.idle_timeout = parse_u64(val)?,
        other => {
            return Err(Error::Config(format!(
                "UCI line {lineno}: unknown option '{other}'"
            )));
        }
    }
    Ok(())
}

/// Strip an unquoted `#` comment from a UCI line, respecting quoted spans so a
/// `#` inside a quoted value is preserved.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '#' => return &line[..i],
                _ => {}
            },
        }
    }
    line
}

/// Split a UCI line into whitespace-separated tokens, honouring single and
/// double quotes (quotes are stripped from the resulting token).
fn tokenize(line: &str) -> std::result::Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;

    for c in line.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_token = true;
                }
                c if c.is_whitespace() => {
                    if in_token {
                        tokens.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                }
                _ => {
                    cur.push(c);
                    in_token = true;
                }
            },
        }
    }

    if quote.is_some() {
        return Err("unterminated quote".to_string());
    }
    if in_token {
        tokens.push(cur);
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Hot-reload classification (§9)
// ---------------------------------------------------------------------------

/// Whether a config change can be applied live or needs a daemon restart (§9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloadImpact {
    /// Apply in place without dropping sessions (garden FQDNs, tier defaults,
    /// accounting interval).
    HotReloadable,
    /// Touches a foundational binding (control endpoint, control-channel TLS,
    /// HMAC key file, responder port) — the daemon must restart.
    RequiresRestart,
}

/// Classify the change between `old` and `new` (§9).
///
/// Any change to a restart-only field yields [`ReloadImpact::RequiresRestart`];
/// otherwise (including the no-op case) the change is
/// [`ReloadImpact::HotReloadable`].
pub fn diff(old: &Config, new: &Config) -> ReloadImpact {
    let requires_restart = old.control_endpoint != new.control_endpoint
        || old.cp_server_ca_file != new.cp_server_ca_file
        || old.cp_server_name != new.cp_server_name
        || old.hmac_key_file != new.hmac_key_file
        || old.responder_port != new.responder_port
        || old.store_id != new.store_id
        // The backend is selected once at composition (before the writer actor
        // spawns); switching it means rebuilding the kernel ruleset.
        || old.firewall_backend != new.firewall_backend;

    if requires_restart {
        ReloadImpact::RequiresRestart
    } else {
        ReloadImpact::HotReloadable
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact §9 UCI example.
    const UCI_EXAMPLE: &str = r#"
config portcullis 'main'
    option store_id           'SITE-0042'
    option control_endpoint   'https://cp.wifihub.internal:8443'   # engine dials outbound
    option cp_server_ca_file  '/etc/portcullis/tls/cp-ca.crt'
    option hmac_key_file      '/etc/portcullis/hmac.key'
    option responder_port     '8080'
    option accounting_interval '15'
    option default_ttl        '1800'
    option default_quota_mb   '0'
    option default_rate_kbps  '2048'
    list   garden_fqdn        'portal.wifihub.vn'
    list   garden_fqdn        'cdn.wifihub.vn'
    list   garden_fqdn        'otp.gateway'
    list   garden_fqdn        'pay.example'
"#;

    #[test]
    fn parses_exact_uci_example() {
        let cfg = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        assert_eq!(cfg.store_id, "SITE-0042");
        assert_eq!(cfg.control_endpoint, "https://cp.wifihub.internal:8443");
        assert_eq!(cfg.cp_server_ca_file, "/etc/portcullis/tls/cp-ca.crt");
        assert_eq!(cfg.hmac_key_file, "/etc/portcullis/hmac.key");
        assert_eq!(cfg.responder_port, 8080);
        assert_eq!(cfg.accounting_interval, 15);
        assert_eq!(cfg.default_ttl, 1800);
        assert_eq!(cfg.default_quota_mb, 0);
        assert_eq!(cfg.default_rate_kbps, 2048);
        assert_eq!(
            cfg.garden_fqdn,
            vec![
                "portal.wifihub.vn".to_string(),
                "cdn.wifihub.vn".to_string(),
                "otp.gateway".to_string(),
                "pay.example".to_string(),
            ]
        );
        // The parsed example is valid.
        cfg.validate().unwrap();
    }

    #[test]
    fn uci_comment_inside_quotes_is_preserved() {
        let uci = "config portcullis 'main'\n    option store_id 'a#b'\n";
        let cfg = Config::from_uci_str(uci).unwrap();
        assert_eq!(cfg.store_id, "a#b");
    }

    #[test]
    fn uci_full_line_comment_and_blank_lines_ignored() {
        let uci = "# header comment\nconfig portcullis 'main'\n\n  # mid comment\n  option store_id 'X'\n";
        let cfg = Config::from_uci_str(uci).unwrap();
        assert_eq!(cfg.store_id, "X");
    }

    #[test]
    fn uci_missing_section_is_error() {
        let uci = "option store_id 'X'\n";
        assert!(Config::from_uci_str(uci).is_err());
    }

    #[test]
    fn uci_bad_u16_is_error() {
        let uci = "config portcullis 'main'\n    option responder_port 'notaport'\n";
        assert!(Config::from_uci_str(uci).is_err());
    }

    #[test]
    fn uci_unknown_option_is_error() {
        let uci = "config portcullis 'main'\n    option bogus 'x'\n";
        assert!(Config::from_uci_str(uci).is_err());
    }

    #[test]
    fn uci_parses_cp_client_options() {
        let uci = "config portcullis 'main'\n\
            option store_id 'X'\n\
            option cp_server_ca_file '/etc/portcullis/tls/cp-ca.crt'\n\
            option cp_server_name 'cp.wifihub.internal'\n\
            option control_reconnect_max_secs '30'\n\
            option control_keepalive_secs '10'\n";
        let cfg = Config::from_uci_str(uci).unwrap();
        assert_eq!(cfg.cp_server_ca_file, "/etc/portcullis/tls/cp-ca.crt");
        assert_eq!(cfg.cp_server_name, "cp.wifihub.internal");
        assert_eq!(cfg.control_reconnect_max_secs, 30);
        assert_eq!(cfg.control_keepalive_secs, 10);
    }

    #[test]
    fn diff_cp_server_ca_requires_restart() {
        let old = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        let mut new = old.clone();
        new.cp_server_ca_file = "/etc/portcullis/tls/other-ca.crt".to_string();
        assert_eq!(diff(&old, &new), ReloadImpact::RequiresRestart);
    }

    #[test]
    fn toml_roundtrip_equals_original() {
        let original = Config {
            store_id: "SITE-0042".to_string(),
            control_endpoint: "https://cp.wifihub.internal:8443".to_string(),
            cp_server_ca_file: "/etc/portcullis/tls/cp-ca.crt".to_string(),
            cp_server_name: String::new(),
            control_reconnect_max_secs: 60,
            control_keepalive_secs: 20,
            // non-default so the roundtrip actually exercises the field.
            wireless_protected_radios: vec!["radio0".to_string()],
            hmac_key_file: "/etc/portcullis/hmac.key".to_string(),
            responder_port: 8080,
            accounting_interval: 15,
            default_ttl: 1800,
            default_quota_mb: 0,
            default_rate_kbps: 2048,
            metrics_port: 9090,
            reconcile_interval: 60,
            garden_fqdn: vec![
                "portal.wifihub.vn".to_string(),
                "cdn.wifihub.vn".to_string(),
                "otp.gateway".to_string(),
                "pay.example".to_string(),
            ],
            firewall_backend: "auto".to_string(),
            hotspot_iface: "br-hotspot".to_string(),
            // non-default so the roundtrip actually exercises the field.
            reap_conntrack: false,
            shape_bandwidth: true,
            shape_iface: "br-lan".to_string(),
            idle_timeout: 300,
        };
        let toml = original.to_toml_string().unwrap();
        let parsed = Config::from_toml_str(&toml).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn default_matches_section_9_defaults() {
        let d = Config::default();
        assert_eq!(d.control_endpoint, "https://cp.wifihub.internal:8443");
        assert_eq!(d.cp_server_ca_file, "/etc/portcullis/tls/cp-ca.crt");
        assert_eq!(d.hmac_key_file, "/etc/portcullis/hmac.key");
        assert_eq!(d.responder_port, 8080);
        assert_eq!(d.accounting_interval, 15);
        assert_eq!(d.default_ttl, 1800);
        assert_eq!(d.default_quota_mb, 0);
        assert_eq!(d.default_rate_kbps, 2048);
        assert!(d.garden_fqdn.is_empty());
    }

    #[test]
    fn validate_rejects_injection_garden_fqdn() {
        // P0 #1 (config path): a garden_fqdn with a newline/space/`#` is rejected
        // at load, so it can never reach the dnsmasq conf.
        let bad = Config {
            store_id: "S".into(),
            garden_fqdn: vec!["ok.example".into(), "evil\nserver=/./6.6.6.6".into()],
            ..Config::default()
        };
        assert!(bad.validate().is_err());
        // Clean list validates.
        let good = Config {
            store_id: "S".into(),
            garden_fqdn: vec!["portal.wifihub.vn".into(), "cdn.wifihub.vn".into()],
            ..Config::default()
        };
        assert!(good.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_port() {
        let mut cfg = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        cfg.responder_port = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_interval() {
        let mut cfg = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        cfg.accounting_interval = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_control_endpoint() {
        let mut cfg = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        cfg.control_endpoint = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn diff_control_endpoint_requires_restart() {
        let old = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        let mut new = old.clone();
        new.control_endpoint = "https://other:8443".to_string();
        assert_eq!(diff(&old, &new), ReloadImpact::RequiresRestart);
    }

    #[test]
    fn diff_garden_fqdn_is_hot_reloadable() {
        let old = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        let mut new = old.clone();
        new.garden_fqdn.push("new.example".to_string());
        assert_eq!(diff(&old, &new), ReloadImpact::HotReloadable);
    }

    #[test]
    fn diff_idle_timeout_is_hot_reloadable() {
        // G6/G7: idle_timeout is pushed through the runtime controller on SIGHUP,
        // no restart needed.
        let old = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        let mut new = old.clone();
        new.idle_timeout = 600;
        assert_eq!(diff(&old, &new), ReloadImpact::HotReloadable);
    }

    #[test]
    fn diff_tier_defaults_and_interval_are_hot_reloadable() {
        let old = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        let mut new = old.clone();
        new.default_ttl = 3600;
        new.default_quota_mb = 100;
        new.default_rate_kbps = 4096;
        new.accounting_interval = 30;
        assert_eq!(diff(&old, &new), ReloadImpact::HotReloadable);
    }

    #[test]
    fn diff_responder_port_requires_restart() {
        let old = Config::from_uci_str(UCI_EXAMPLE).unwrap();
        let mut new = old.clone();
        new.responder_port = 9090;
        assert_eq!(diff(&old, &new), ReloadImpact::RequiresRestart);
    }

    #[test]
    fn firewall_backend_parses_defaults_and_validates() {
        // Absent (pre-existing config files, UCI and TOML): defaults to "auto".
        let old =
            Config::from_uci_str("config portcullis 'main'\n    option store_id 'S'\n").unwrap();
        assert_eq!(old.firewall_backend, "auto");
        assert_eq!(Config::default().firewall_backend, "auto");

        // Explicit UCI option parses.
        let uci =
            "config portcullis 'main'\n    option store_id 'S'\n    option firewall_backend 'nft'\n";
        let cfg = Config::from_uci_str(uci).unwrap();
        assert_eq!(cfg.firewall_backend, "nft");
        cfg.validate().unwrap();

        // Every allowed value validates; anything else is rejected.
        for ok in ["auto", "ipset", "nft"] {
            let cfg = Config {
                store_id: "S".into(),
                firewall_backend: ok.into(),
                ..Config::default()
            };
            cfg.validate().unwrap();
        }
        let bad = Config {
            store_id: "S".into(),
            firewall_backend: "iptables".into(),
            ..Config::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn hotspot_iface_parses_and_defaults_empty() {
        // Absent (pre-existing configs): defaults to empty (not scoped).
        let old =
            Config::from_uci_str("config portcullis 'main'\n    option store_id 'S'\n").unwrap();
        assert_eq!(old.hotspot_iface, "");
        assert_eq!(Config::default().hotspot_iface, "");

        // Explicit UCI option parses (the P0.5 bridge feeding P0 scoping).
        let uci = "config portcullis 'main'\n    option store_id 'S'\n    option hotspot_iface 'br-hotspot'\n";
        let cfg = Config::from_uci_str(uci).unwrap();
        assert_eq!(cfg.hotspot_iface, "br-hotspot");
        cfg.validate().unwrap();
    }

    #[test]
    fn diff_firewall_backend_requires_restart() {
        let old = Config {
            store_id: "S".into(),
            ..Config::default()
        };
        let mut new = old.clone();
        new.firewall_backend = "nft".to_string();
        assert_eq!(diff(&old, &new), ReloadImpact::RequiresRestart);
    }

    #[test]
    fn load_reads_toml_from_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("portcullis-config-test-{}.toml", std::process::id()));
        let cfg = Config {
            store_id: "SITE-0042".to_string(),
            ..Config::default()
        };
        std::fs::write(&path, cfg.to_toml_string().unwrap()).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded, cfg);
        let _ = std::fs::remove_file(&path);
    }
}
