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

    /// gRPC control-plane endpoint, reached over the WireGuard overlay.
    pub control_endpoint: String,

    /// WireGuard interface carrying control + accounting traffic.
    pub wg_interface: String,

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

    /// Walled-garden FQDNs always reachable pre-auth (portal, CDN, OTP, pay).
    #[serde(default)]
    pub garden_fqdn: Vec<String>,

    /// Initial global enforcement gate state applied at boot, before the control
    /// plane pushes the persisted admin choice. Defaults to `true` (fail-closed,
    /// §11/G5): the engine always boots blocking unauthorized traffic.
    #[serde(default = "default_enforcement")]
    pub enforcement_default: bool,

    /// Redirect responder rate limit: token-bucket burst capacity per source IP
    /// (integer — `Config` is `Eq`; converted to f64 at the wiring point).
    #[serde(default = "default_rl_capacity")]
    pub redirect_rl_capacity: u32,

    /// Redirect responder rate limit: sustained requests/second per source IP.
    #[serde(default = "default_rl_refill")]
    pub redirect_rl_refill_per_sec: u32,

    /// Redirect responder rate limit: max distinct source IPs tracked
    /// (anti-exhaustion cap on the limiter's memory).
    #[serde(default = "default_rl_max_keys")]
    pub redirect_rl_max_keys: u32,

    /// Bound of the in-RAM event fan-out channel (gRPC StreamEvents). Slow or
    /// disconnected consumers drop oldest past this; enforcement never blocks.
    #[serde(default = "default_event_buffer")]
    pub event_buffer_size: u32,
}

/// Serde default for [`Config::enforcement_default`]: boot fail-closed.
fn default_enforcement() -> bool {
    true
}

/// Serde defaults for the redirect rate limiter / event buffer — mirror the
/// previously hardcoded values so pre-0.3 config files parse unchanged.
fn default_rl_capacity() -> u32 {
    5
}
fn default_rl_refill() -> u32 {
    1
}
fn default_rl_max_keys() -> u32 {
    10_000
}
fn default_event_buffer() -> u32 {
    512
}

impl Default for Config {
    fn default() -> Self {
        // Mirrors the §9 example.
        Config {
            store_id: String::new(),
            control_endpoint: "https://cp.wifihub.internal:8443".to_string(),
            wg_interface: "wg-hub".to_string(),
            hmac_key_file: "/etc/portcullis/hmac.key".to_string(),
            responder_port: 8080,
            accounting_interval: 15,
            default_ttl: 1800,
            default_quota_mb: 0,
            default_rate_kbps: 2048,
            garden_fqdn: Vec::new(),
            enforcement_default: true,
            redirect_rl_capacity: 5,
            redirect_rl_refill_per_sec: 1,
            redirect_rl_max_keys: 10_000,
            event_buffer_size: 512,
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
        if self.wg_interface.trim().is_empty() {
            return Err(Error::Config("wg_interface must not be empty".to_string()));
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
        if self.redirect_rl_capacity == 0 {
            return Err(Error::Config(
                "redirect_rl_capacity must be >= 1".to_string(),
            ));
        }
        if self.redirect_rl_refill_per_sec == 0 {
            return Err(Error::Config(
                "redirect_rl_refill_per_sec must be >= 1".to_string(),
            ));
        }
        if self.redirect_rl_max_keys == 0 {
            return Err(Error::Config(
                "redirect_rl_max_keys must be >= 1".to_string(),
            ));
        }
        if self.event_buffer_size == 0 {
            return Err(Error::Config(
                "event_buffer_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
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
    let parse_u32 = |v: &str| -> Result<u32> {
        v.parse::<u32>().map_err(|_| {
            Error::Config(format!("UCI line {lineno}: '{key}' expects a u32, got '{v}'"))
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
        "wg_interface" => cfg.wg_interface = val.to_string(),
        "hmac_key_file" => cfg.hmac_key_file = val.to_string(),
        "responder_port" => cfg.responder_port = parse_u16(val)?,
        "accounting_interval" => cfg.accounting_interval = parse_u64(val)?,
        "default_ttl" => cfg.default_ttl = parse_u64(val)?,
        "default_quota_mb" => cfg.default_quota_mb = parse_u64(val)?,
        "default_rate_kbps" => cfg.default_rate_kbps = parse_u64(val)?,
        "enforcement_default" => cfg.enforcement_default = parse_bool(val)?,
        "redirect_rl_capacity" => cfg.redirect_rl_capacity = parse_u32(val)?,
        "redirect_rl_refill_per_sec" => cfg.redirect_rl_refill_per_sec = parse_u32(val)?,
        "redirect_rl_max_keys" => cfg.redirect_rl_max_keys = parse_u32(val)?,
        "event_buffer_size" => cfg.event_buffer_size = parse_u32(val)?,
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
    /// Touches a foundational binding (control endpoint, WG interface, HMAC
    /// key file, responder port) — the daemon must restart.
    RequiresRestart,
}

/// Classify the change between `old` and `new` (§9).
///
/// Any change to a restart-only field yields [`ReloadImpact::RequiresRestart`];
/// otherwise (including the no-op case) the change is
/// [`ReloadImpact::HotReloadable`].
pub fn diff(old: &Config, new: &Config) -> ReloadImpact {
    let requires_restart = old.control_endpoint != new.control_endpoint
        || old.wg_interface != new.wg_interface
        || old.hmac_key_file != new.hmac_key_file
        || old.responder_port != new.responder_port
        || old.store_id != new.store_id
        // The rate limiter and event channel are built once at composition;
        // resizing either requires a restart (the CP-tunable knobs live in
        // SetEngineParameters instead).
        || old.redirect_rl_capacity != new.redirect_rl_capacity
        || old.redirect_rl_refill_per_sec != new.redirect_rl_refill_per_sec
        || old.redirect_rl_max_keys != new.redirect_rl_max_keys
        || old.event_buffer_size != new.event_buffer_size;

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
    option control_endpoint   'https://cp.wifihub.internal:8443'   # over WG overlay
    option wg_interface       'wg-hub'
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
        assert_eq!(cfg.wg_interface, "wg-hub");
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
    fn new_boot_options_parse_from_uci_and_default_when_absent() {
        let uci = r#"
config portcullis 'main'
    option store_id 'SITE-1'
    option redirect_rl_capacity '20'
    option redirect_rl_refill_per_sec '4'
    option redirect_rl_max_keys '5000'
    option event_buffer_size '1024'
"#;
        let cfg = Config::from_uci_str(uci).unwrap();
        assert_eq!(cfg.redirect_rl_capacity, 20);
        assert_eq!(cfg.redirect_rl_refill_per_sec, 4);
        assert_eq!(cfg.redirect_rl_max_keys, 5000);
        assert_eq!(cfg.event_buffer_size, 1024);

        // Absent options (pre-0.3 config files) keep the built-in values.
        let old = Config::from_uci_str("config portcullis 'main'\n    option store_id 'S'\n").unwrap();
        assert_eq!(old.redirect_rl_capacity, 5);
        assert_eq!(old.redirect_rl_refill_per_sec, 1);
        assert_eq!(old.redirect_rl_max_keys, 10_000);
        assert_eq!(old.event_buffer_size, 512);
        // Same for TOML documents that predate the fields.
        let toml = Config::from_toml_str(
            r#"
store_id = "S"
control_endpoint = "https://cp:8443"
wg_interface = "wg-hub"
hmac_key_file = "/etc/portcullis/hmac.key"
responder_port = 8080
accounting_interval = 15
default_ttl = 1800
default_quota_mb = 0
default_rate_kbps = 2048
"#,
        )
        .unwrap();
        assert_eq!(toml.event_buffer_size, 512);
    }

    #[test]
    fn new_boot_options_reject_zero() {
        let mut cfg = Config { store_id: "S".into(), ..Config::default() };
        cfg.redirect_rl_capacity = 0;
        assert!(cfg.validate().is_err());
        cfg = Config { store_id: "S".into(), ..Config::default() };
        cfg.redirect_rl_refill_per_sec = 0;
        assert!(cfg.validate().is_err());
        cfg = Config { store_id: "S".into(), ..Config::default() };
        cfg.redirect_rl_max_keys = 0;
        assert!(cfg.validate().is_err());
        cfg = Config { store_id: "S".into(), ..Config::default() };
        cfg.event_buffer_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn new_boot_options_require_restart() {
        let old = Config::default();
        for change in [
            |c: &mut Config| c.redirect_rl_capacity = 9,
            |c: &mut Config| c.redirect_rl_refill_per_sec = 9,
            |c: &mut Config| c.redirect_rl_max_keys = 9,
            |c: &mut Config| c.event_buffer_size = 9,
        ] {
            let mut new = old.clone();
            change(&mut new);
            assert_eq!(diff(&old, &new), ReloadImpact::RequiresRestart);
        }
    }

    #[test]
    fn toml_roundtrip_equals_original() {
        let original = Config {
            store_id: "SITE-0042".to_string(),
            control_endpoint: "https://cp.wifihub.internal:8443".to_string(),
            wg_interface: "wg-hub".to_string(),
            hmac_key_file: "/etc/portcullis/hmac.key".to_string(),
            responder_port: 8080,
            accounting_interval: 15,
            default_ttl: 1800,
            default_quota_mb: 0,
            default_rate_kbps: 2048,
            garden_fqdn: vec![
                "portal.wifihub.vn".to_string(),
                "cdn.wifihub.vn".to_string(),
                "otp.gateway".to_string(),
                "pay.example".to_string(),
            ],
            enforcement_default: true,
            redirect_rl_capacity: 5,
            redirect_rl_refill_per_sec: 1,
            redirect_rl_max_keys: 10_000,
            event_buffer_size: 512,
        };
        let toml = original.to_toml_string().unwrap();
        let parsed = Config::from_toml_str(&toml).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn default_matches_section_9_defaults() {
        let d = Config::default();
        assert_eq!(d.control_endpoint, "https://cp.wifihub.internal:8443");
        assert_eq!(d.wg_interface, "wg-hub");
        assert_eq!(d.hmac_key_file, "/etc/portcullis/hmac.key");
        assert_eq!(d.responder_port, 8080);
        assert_eq!(d.accounting_interval, 15);
        assert_eq!(d.default_ttl, 1800);
        assert_eq!(d.default_quota_mb, 0);
        assert_eq!(d.default_rate_kbps, 2048);
        assert!(d.garden_fqdn.is_empty());
        assert!(d.enforcement_default, "boots fail-closed by default");
    }

    #[test]
    fn toml_without_enforcement_default_falls_back_to_enabled() {
        // A config file predating the field must still parse, defaulting to true.
        let cfg = Config::from_toml_str(
            "store_id = \"S\"\ncontrol_endpoint = \"https://x:8443\"\n\
             wg_interface = \"wg-hub\"\nhmac_key_file = \"/k\"\nresponder_port = 8080\n\
             accounting_interval = 15\ndefault_ttl = 1800\ndefault_quota_mb = 0\n\
             default_rate_kbps = 2048\n",
        )
        .unwrap();
        assert!(cfg.enforcement_default);
    }

    #[test]
    fn uci_parses_enforcement_default_off() {
        let uci = "config portcullis 'main'\n\toption enforcement_default '0'\n";
        let cfg = Config::from_uci_str(uci).unwrap();
        assert!(!cfg.enforcement_default);
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
