//! Production [`FirewallBackend`] for stock RutOS/OpenWrt via `ipset` +
//! `iptables`/`ip6tables` (TDD §17 "option B").
//!
//! **Why not the nft backend on-device:** the RUTM11 kernel (6.6.126) ships
//! `nf_tables` but **no NAT chain support** — `nft_nat`/`nft_chain_nat`/
//! `nft_masq` are absent (`CONFIG_NFT_NAT` unset), so creating the
//! `type nat hook prerouting` redirect chain fails ENOENT and the whole atomic
//! base ruleset rolls back → the daemon fail-closes and never starts.
//! `iptables` + `ipset` ARE fully supported on stock firmware (the same
//! mechanism fw3/openNDS use), so this backend needs **no custom kernel or
//! firmware** and deploys fleet-wide as a plain `.ipk`.
//!
//! Enforcement shape mirrors [`crate::ruleset`] exactly:
//! ```text
//! ipset wifihub_auth  hash:mac  (per-element timeout)         authorized MACs
//! ipset wifihub_g4 hash:net inet / wifihub_g6 hash:net inet6  walled garden (dnsmasq ipset=)
//! nat  wifihub_pre  (PREROUTING): RETURN authed/garden ; else tcp dport 80 REDIRECT -> :8080
//! filter wifihub_fwd (FORWARD)  : RETURN established/authed/garden ; else DROP
//! ```
//! The allow branches **RETURN** (not `ACCEPT`): in iptables a user-chain
//! `ACCEPT` is globally terminal, whereas the design wants a *pre-filter* that
//! only DROPs unauthenticated non-garden traffic and lets everything else fall
//! through to fw3 (the mirror of §7.1 subtlety 1/4).
//!
//! State is kernel-held: the `wifihub_auth` ipset carries per-element timeouts,
//! so a daemon restart adopts it via [`FirewallBackend::list_auth`] and never
//! drops clients (§7.4, §7.8). `ensure_base` uses `ipset create -exist` and
//! never flushes the auth/garden sets.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use portcullis_types::{AuthElement, Error, MacAddr, Result};
use tokio::process::Command;

use crate::backend::FirewallBackend;
use crate::ruleset::REDIRECT_PORT;

/// ipset holding authorized client MACs (per-element timeout = the kernel-side
/// expiry backstop, §7.4). `hash:mac` is family-agnostic (matched by src MAC in
/// both iptables and ip6tables).
pub const IPSET_AUTH: &str = "wifihub_auth";
/// IPv4 walled-garden set (`hash:net`), populated by dnsmasq `ipset=`.
pub const IPSET_G4: &str = "wifihub_g4";
/// IPv6 walled-garden set (`hash:net family inet6`).
pub const IPSET_G6: &str = "wifihub_g6";
/// Our nat prerouting chain (jumped from `PREROUTING`, ahead of fw3).
pub const CHAIN_NAT: &str = "wifihub_pre";
/// Our filter forward chain (jumped from `FORWARD`, ahead of fw3).
pub const CHAIN_FWD: &str = "wifihub_fwd";

/// [`FirewallBackend`] driving `ipset` + `iptables`/`ip6tables` binaries.
pub struct IpsetIptablesBackend {
    ipset_bin: String,
    /// (binary, garden set) for each address family we program.
    tables: Vec<(String, String)>,
    /// Port the tcp:80 REDIRECT sends to — MUST equal the responder's listen
    /// port so the hijacked request reaches the portcullis responder.
    redirect_port: u16,
}

impl Default for IpsetIptablesBackend {
    fn default() -> Self {
        Self {
            ipset_bin: "ipset".to_string(),
            tables: vec![
                ("iptables".to_string(), IPSET_G4.to_string()),
                ("ip6tables".to_string(), IPSET_G6.to_string()),
            ],
            redirect_port: REDIRECT_PORT,
        }
    }
}

impl IpsetIptablesBackend {
    /// Set the tcp:80 REDIRECT target port. Pass the daemon's configured
    /// `responder_port` so the REDIRECT and the responder always agree.
    pub fn with_redirect_port(mut self, port: u16) -> Self {
        self.redirect_port = port;
        self
    }

    /// Override binary paths (tests / non-standard installs). `iptables` and
    /// `ip6tables` are paired with their family's garden set.
    pub fn with_bins(
        ipset_bin: impl Into<String>,
        iptables_bin: impl Into<String>,
        ip6tables_bin: impl Into<String>,
    ) -> Self {
        Self {
            ipset_bin: ipset_bin.into(),
            tables: vec![
                (iptables_bin.into(), IPSET_G4.to_string()),
                (ip6tables_bin.into(), IPSET_G6.to_string()),
            ],
            redirect_port: REDIRECT_PORT,
        }
    }

    /// Run a command to completion; map a non-zero exit to `Error::Backend`
    /// (never fail open — a firewall mutation that didn't apply is an error).
    async fn run(bin: &str, args: &[&str]) -> Result<()> {
        let out = Command::new(bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Backend(format!("spawn {bin}: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::Backend(format!(
                "{bin} {} exited {:?}: {}",
                args.join(" "),
                out.status.code(),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Run a command, returning `true` on success and `false` on any non-zero
    /// exit (for idempotent probes like `iptables -C` / `-N`). Never errors.
    async fn run_ok(bin: &str, args: &[&str]) -> bool {
        Command::new(bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Run a command and capture stdout (for `ipset list`).
    async fn run_stdout(bin: &str, args: &[&str]) -> Result<String> {
        let out = Command::new(bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Backend(format!("spawn {bin}: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::Backend(format!(
                "{bin} {} exited {:?}: {}",
                args.join(" "),
                out.status.code(),
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Ensure a user chain exists and is populated with exactly `rules`, then
    /// ensure a single jump into it from `hook` at position 1. `table` is
    /// `"nat"` or `"filter"`. Idempotent; safe to re-run.
    async fn ensure_chain(
        ipt: &str,
        table: &str,
        chain: &str,
        hook: &str,
        rules: &[Vec<&str>],
    ) -> Result<()> {
        // Create the chain if missing (ignore "already exists"), then flush so
        // the rule set below is authoritative. Flushing touches only our own
        // static rules — never the auth ipset — so no client state is lost.
        let _ = Self::run_ok(ipt, &["-t", table, "-N", chain]).await;
        Self::run(ipt, &["-t", table, "-F", chain]).await?;

        for rule in rules {
            let mut args = vec!["-t", table, "-A", chain];
            args.extend(rule.iter().copied());
            Self::run(ipt, &args).await?;
        }

        // Ensure exactly one jump hook -> chain, inserted ahead of fw3 (pos 1).
        // The chain is fully populated (drop-terminated) before the jump is
        // added, so first-boot never has a fail-open window.
        Self::set_hook(ipt, table, chain, hook, true).await
    }

    /// Add or remove the jump `hook -> chain` in `table` (`"nat"`/`"filter"`).
    ///
    /// This is the single global enforcement gate: the gating chains and the
    /// `auth` set are never touched here — only whether traffic is routed
    /// *through* them. Idempotent in both directions:
    /// - `enabled = true`: ensure exactly one jump exists, inserted at position 1
    ///   (ahead of fw3). Because the chain is already drop-terminated, enabling
    ///   never opens a fail-open window.
    /// - `enabled = false`: delete every copy of the jump so unauthorized traffic
    ///   falls straight through to fw3 (i.e. flows). The chain remains populated
    ///   but unreferenced, so re-enabling is a single `-I`.
    async fn set_hook(ipt: &str, table: &str, chain: &str, hook: &str, enabled: bool) -> Result<()> {
        let check = ["-t", table, "-C", hook, "-j", chain];
        if enabled {
            if !Self::run_ok(ipt, &check).await {
                Self::run(ipt, &["-t", table, "-I", hook, "1", "-j", chain]).await?;
            }
        } else {
            // Remove all copies (defensive: a re-inserted duplicate must not
            // survive a disable). Bounded by the number of live jumps.
            while Self::run_ok(ipt, &check).await {
                Self::run(ipt, &["-t", table, "-D", hook, "-j", chain]).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl FirewallBackend for IpsetIptablesBackend {
    async fn ensure_base(&self) -> Result<()> {
        // 1. Sets. `-exist` = create-if-missing and DON'T flush an existing set,
        //    so restart adoption keeps the live auth membership (§7.8).
        Self::run(
            &self.ipset_bin,
            &["create", "-exist", IPSET_AUTH, "hash:mac", "timeout", "0"],
        )
        .await?;
        Self::run(
            &self.ipset_bin,
            &["create", "-exist", IPSET_G4, "hash:net", "family", "inet"],
        )
        .await?;
        Self::run(
            &self.ipset_bin,
            &["create", "-exist", IPSET_G6, "hash:net", "family", "inet6"],
        )
        .await?;

        // 2. Per-family iptables chains. Same shape for v4/v6, only the garden
        //    set differs.
        let port = self.redirect_port.to_string();
        for (ipt, gset) in &self.tables {
            // nat prerouting: exempt authed + garden, else redirect :80 -> :8080.
            let nat_rules: Vec<Vec<&str>> = vec![
                vec!["-m", "set", "--match-set", IPSET_AUTH, "src", "-j", "RETURN"],
                vec!["-m", "set", "--match-set", gset, "dst", "-j", "RETURN"],
                vec![
                    "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", &port,
                ],
            ];
            Self::ensure_chain(ipt, "nat", CHAIN_NAT, "PREROUTING", &nat_rules).await?;

            // filter forward: pre-filter that only DROPs unauth non-garden new
            // traffic; everything else RETURNs and falls through to fw3.
            let fwd_rules: Vec<Vec<&str>> = vec![
                vec![
                    "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN",
                ],
                vec!["-m", "set", "--match-set", IPSET_AUTH, "src", "-j", "RETURN"],
                vec!["-m", "set", "--match-set", gset, "dst", "-j", "RETURN"],
                vec!["-j", "DROP"],
            ];
            Self::ensure_chain(ipt, "filter", CHAIN_FWD, "FORWARD", &fwd_rules).await?;
        }
        Ok(())
    }

    async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()> {
        let mac = mac.to_canonical();
        let secs = ttl.as_secs().to_string();
        // `-exist` refreshes the timeout if the MAC is already present.
        Self::run(
            &self.ipset_bin,
            &["add", "-exist", IPSET_AUTH, &mac, "timeout", &secs],
        )
        .await
    }

    async fn del_auth(&self, mac: MacAddr) -> Result<()> {
        let mac = mac.to_canonical();
        // `-exist` makes deleting an already-absent element a no-op (not an
        // error) — a revoke racing kernel timeout expiry must not fail.
        Self::run(&self.ipset_bin, &["del", "-exist", IPSET_AUTH, &mac]).await
    }

    async fn list_auth(&self) -> Result<Vec<AuthElement>> {
        let out = Self::run_stdout(&self.ipset_bin, &["list", IPSET_AUTH]).await?;
        Ok(parse_ipset_list(&out))
    }

    async fn set_enforcement(&self, enabled: bool) -> Result<()> {
        // Toggle the jump into both gating chains for every family (v4 + v6).
        // The chains + `auth` set are left intact; only the base-hook jump moves.
        for (ipt, _gset) in &self.tables {
            Self::set_hook(ipt, "nat", CHAIN_NAT, "PREROUTING", enabled).await?;
            Self::set_hook(ipt, "filter", CHAIN_FWD, "FORWARD", enabled).await?;
        }
        Ok(())
    }

    async fn replace_garden(
        &self,
        v4: Vec<std::net::Ipv4Addr>,
        v6: Vec<std::net::Ipv6Addr>,
    ) -> Result<()> {
        let v4s: Vec<String> = v4.iter().map(|a| a.to_string()).collect();
        let v6s: Vec<String> = v6.iter().map(|a| a.to_string()).collect();
        self.replace_set(IPSET_G4, "inet", &v4s).await?;
        self.replace_set(IPSET_G6, "inet6", &v6s).await?;
        Ok(())
    }
}

impl IpsetIptablesBackend {
    /// Atomically replace a garden hash:net set with `addrs`: populate a tmp set
    /// then `ipset swap` it in (no window where the set is empty), and destroy
    /// the tmp. Used by the engine-resolver garden path.
    async fn replace_set(&self, set: &str, family: &str, addrs: &[String]) -> Result<()> {
        let tmp = format!("{set}_tmp");
        Self::run(&self.ipset_bin, &["create", "-exist", &tmp, "hash:net", "family", family]).await?;
        Self::run(&self.ipset_bin, &["flush", &tmp]).await?;
        for a in addrs {
            // /32|/128 host entries; best-effort per address (skip a bad one).
            let _ = Self::run(&self.ipset_bin, &["add", "-exist", &tmp, a]).await;
        }
        Self::run(&self.ipset_bin, &["swap", &tmp, set]).await?;
        let _ = Self::run_ok(&self.ipset_bin, &["destroy", &tmp]).await;
        Ok(())
    }
}

/// Parse `ipset list wifihub_auth` output into [`AuthElement`]s.
///
/// The relevant tail is:
/// ```text
/// Members:
/// 00:11:22:33:44:55 timeout 59
/// aa:bb:cc:dd:ee:ff timeout 1720
/// ```
/// Strict and bounded: only lines after `Members:` with a parseable MAC are
/// kept; malformed entries are skipped (logged), never panicked on. A member
/// without a `timeout` token reports `remaining = 0`.
pub fn parse_ipset_list(stdout: &str) -> Vec<AuthElement> {
    let mut out = Vec::new();
    let mut in_members = false;
    for line in stdout.lines() {
        let line = line.trim();
        if !in_members {
            if line == "Members:" {
                in_members = true;
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let mut toks = line.split_whitespace();
        let Some(mac_tok) = toks.next() else { continue };
        let mac = match mac_tok.parse::<MacAddr>() {
            Ok(m) => m,
            Err(_) => {
                tracing::warn!(target: "portcullis_nft", elem = %mac_tok, "skipping malformed ipset member");
                continue;
            }
        };
        // Find "timeout <secs>" if present.
        let mut remaining = Duration::ZERO;
        let toks: Vec<&str> = toks.collect();
        if let Some(pos) = toks.iter().position(|&t| t == "timeout") {
            if let Some(secs) = toks.get(pos + 1).and_then(|s| s.parse::<u64>().ok()) {
                remaining = Duration::from_secs(secs);
            }
        }
        out.push(AuthElement { mac, remaining });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_members_with_timeout() {
        let sample = "\
Name: wifihub_auth
Type: hash:mac
Revision: 0
Header: hashsize 1024 maxelem 65536 timeout 0
Size in memory: 456
References: 2
Number of entries: 2
Members:
00:11:22:33:44:55 timeout 59
aa:bb:cc:dd:ee:ff timeout 1720
";
        let mut got = parse_ipset_list(sample);
        got.sort_by_key(|e| e.mac.octets());
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].mac, "00:11:22:33:44:55".parse().unwrap());
        assert_eq!(got[0].remaining, Duration::from_secs(59));
        assert_eq!(got[1].mac, "aa:bb:cc:dd:ee:ff".parse().unwrap());
        assert_eq!(got[1].remaining, Duration::from_secs(1720));
    }

    #[test]
    fn parse_empty_members() {
        let sample = "Name: wifihub_auth\nType: hash:mac\nMembers:\n";
        assert!(parse_ipset_list(sample).is_empty());
    }

    #[test]
    fn parse_member_without_timeout_is_zero() {
        let sample = "Members:\n00:11:22:33:44:55\n";
        let got = parse_ipset_list(sample);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].remaining, Duration::ZERO);
    }

    #[test]
    fn skips_malformed_and_ignores_preamble() {
        let sample = "\
Name: wifihub_auth
notamac timeout 5
Members:
zz:zz:zz:zz:zz:zz timeout 5
00:11:22:33:44:55 timeout 10
";
        let got = parse_ipset_list(sample);
        // The pre-`Members:` line is ignored; the bad MAC after is skipped.
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].mac, "00:11:22:33:44:55".parse().unwrap());
    }
}
