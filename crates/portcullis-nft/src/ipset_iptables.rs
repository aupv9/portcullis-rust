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
//! firmware** and deploys fleet-wide as a plain `.ipk`. It implements the same
//! [`FirewallBackend`] seam as [`crate::nftables_json::NftJsonBackend`], so the
//! writer actor (§7.9) and SessionManager are unchanged; the backend is picked
//! at composition (`firewall_backend=auto|nft|ipset`, see the engine daemon).
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
    /// The hotspot interface enforcement is scoped to (P0). `Some("br-hotspot")`
    /// → the FORWARD/PREROUTING jumps carry `-i <iface>` so ONLY that ingress is
    /// gated (br-lan untouched). `None`/empty → the jumps are NOT installed at
    /// all (fail-OPEN — nothing to gate; NEVER blanket-block the whole router).
    /// The `wifihub_fwd`/`wifihub_pre` chains + auth/garden sets are still
    /// created either way (kernel-as-truth adoption keeps working).
    hotspot_iface: Option<String>,
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
            hotspot_iface: None,
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

    /// Scope enforcement to the hotspot interface (P0). An empty string means
    /// "not scoped" → the interface-scoped FORWARD/PREROUTING jumps are omitted
    /// (fail-OPEN). Pass the daemon's configured `hotspot_iface`.
    pub fn with_hotspot_iface(mut self, iface: impl Into<String>) -> Self {
        let iface = iface.into();
        self.hotspot_iface = if iface.trim().is_empty() {
            None
        } else {
            Some(iface)
        };
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
            hotspot_iface: None,
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
    ///
    /// P0 interface scoping: when `iface` is `Some(name)` the jump carries
    /// `-i <name>` so ONLY ingress from the hotspot SSID is gated (br-lan and
    /// every other interface fall straight through to fw3). When `iface` is
    /// `None` the jump is **not installed at all** (fail-OPEN — nothing to gate;
    /// NEVER blanket-block the whole router). The chain itself is always created
    /// and populated so kernel-as-truth adoption keeps working.
    async fn ensure_chain(
        ipt: &str,
        table: &str,
        chain: &str,
        hook: &str,
        rules: &[Vec<&str>],
        iface: Option<&str>,
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

        // Ensure exactly one interface-scoped jump hook -> chain, inserted ahead
        // of fw3 (pos 1). The chain is fully populated (drop-terminated) before
        // the jump is added, so first-boot never has a fail-open window.
        //
        // With no hotspot_iface configured we deliberately install NO jump: the
        // gating chain exists (adoption works) but nothing reaches it, so the
        // whole router — including br-lan — is untouched (the P0 fail-OPEN case).
        let Some(iface) = iface else {
            return Ok(());
        };
        let check = ["-t", table, "-C", hook, "-i", iface, "-j", chain];
        if !Self::run_ok(ipt, &check).await {
            Self::run(ipt, &["-t", table, "-I", hook, "1", "-i", iface, "-j", chain]).await?;
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
        //    set differs. The FORWARD/PREROUTING jumps into these chains are
        //    scoped to `hotspot_iface` (P0); with no iface configured they are
        //    not installed at all (fail-OPEN — see below).
        let iface = self.hotspot_iface.as_deref();
        if iface.is_none() {
            tracing::warn!(
                target: "portcullis_nft",
                "no hotspot_iface configured: enforcement is INERT — the wifihub_fwd/wifihub_pre \
                 chains + sets are created but NOT jumped from FORWARD/PREROUTING (nothing gated; \
                 br-lan and the whole router are untouched). Set hotspot_iface to gate the SSID."
            );
        }
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
            Self::ensure_chain(ipt, "nat", CHAIN_NAT, "PREROUTING", &nat_rules, iface).await?;

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
            Self::ensure_chain(ipt, "filter", CHAIN_FWD, "FORWARD", &fwd_rules, iface).await?;
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

    #[test]
    fn default_backend_uses_wifihub_sets_and_default_redirect_port() {
        // Guards the on-device contract: the sets/chains dnsmasq (`ipset=`) and
        // the redirect responder agree on. Constants, not behaviour, but a
        // rename here would silently break enforcement on the router.
        let _b = IpsetIptablesBackend::default();
        assert_eq!(IPSET_AUTH, "wifihub_auth");
        assert_eq!(IPSET_G4, "wifihub_g4");
        assert_eq!(IPSET_G6, "wifihub_g6");
        assert_eq!(CHAIN_NAT, "wifihub_pre");
        assert_eq!(CHAIN_FWD, "wifihub_fwd");
    }

    #[tokio::test]
    async fn ensure_base_scopes_jumps_to_hotspot_iface() {
        // P0: with hotspot_iface set, the FORWARD + PREROUTING jumps into
        // wifihub_fwd/wifihub_pre must carry `-i br-hotspot` so ONLY the hotspot
        // SSID is gated; br-lan is never touched.
        let (ipset, _id) = fake_ipset("scope-set");
        let (ipt, ilog, _iid) = fake_iptables("scope-set");
        let backend = IpsetIptablesBackend::with_bins(&ipset, &ipt, &ipt)
            .with_hotspot_iface("br-hotspot");
        backend.ensure_base().await.unwrap();

        let jumps = jump_inserts(&ilog);
        // One jump per hook per family (v4 + v6): 2 FORWARD + 2 PREROUTING = 4.
        let fwd: Vec<&String> = jumps.iter().filter(|l| l.contains(CHAIN_FWD)).collect();
        let pre: Vec<&String> = jumps.iter().filter(|l| l.contains(CHAIN_NAT)).collect();
        assert_eq!(fwd.len(), 2, "one FORWARD jump per family: {jumps:?}");
        assert_eq!(pre.len(), 2, "one PREROUTING jump per family: {jumps:?}");

        // The EXACT scoped argv forms.
        assert!(
            fwd.iter().all(|l| l
                .contains("-t filter -I FORWARD 1 -i br-hotspot -j wifihub_fwd")),
            "FORWARD jump must be `-i br-hotspot`: {fwd:?}"
        );
        assert!(
            pre.iter().all(|l| l
                .contains("-t nat -I PREROUTING 1 -i br-hotspot -j wifihub_pre")),
            "PREROUTING jump must be `-i br-hotspot`: {pre:?}"
        );
    }

    #[tokio::test]
    async fn ensure_base_omits_jumps_when_iface_unset_but_builds_chains() {
        // P0 fail-OPEN: with NO hotspot_iface, install NO FORWARD/PREROUTING
        // jump (never blanket-block the whole router) — but the chains + their
        // rules ARE still created so kernel-as-truth adoption keeps working.
        let (ipset, _id) = fake_ipset("scope-unset");
        let (ipt, ilog, _iid) = fake_iptables("scope-unset");
        // Default backend has no iface; be explicit that empty == unset too.
        let backend =
            IpsetIptablesBackend::with_bins(&ipset, &ipt, &ipt).with_hotspot_iface("");
        backend.ensure_base().await.unwrap();

        // No jump was inserted at all.
        assert!(
            jump_inserts(&ilog).is_empty(),
            "no jump must be inserted when hotspot_iface is unset"
        );

        // The chains were still created and populated (adoption keeps working):
        // the wifihub_fwd DROP rule and the wifihub_pre REDIRECT rule are appended.
        let all = lines(&ilog);
        assert!(
            all.iter().any(|l| l.contains("-A wifihub_fwd") && l.contains("DROP")),
            "wifihub_fwd chain must still be populated with its DROP: {all:?}"
        );
        assert!(
            all.iter()
                .any(|l| l.contains("-A wifihub_pre") && l.contains("REDIRECT")),
            "wifihub_pre chain must still be populated with its REDIRECT: {all:?}"
        );
    }

    #[tokio::test]
    async fn add_del_list_roundtrip_against_fake_ipset() {
        // Drive the backend through a fake `ipset` shell script that records
        // `add`/`del` into a members file and answers `list` from it — exercising
        // add_auth/del_auth/list_auth end-to-end without a kernel.
        let (ipset, _dir) = fake_ipset("roundtrip");
        let backend = IpsetIptablesBackend::with_bins(&ipset, "/bin/true", "/bin/true");

        let m1: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        let m2: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        backend.add_auth(m1, Duration::from_secs(1800)).await.unwrap();
        backend.add_auth(m2, Duration::from_secs(600)).await.unwrap();

        let mut listed = backend.list_auth().await.unwrap();
        listed.sort_by_key(|e| e.mac.octets());
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].mac, m1);
        assert_eq!(listed[0].remaining, Duration::from_secs(1800));
        assert_eq!(listed[1].mac, m2);

        backend.del_auth(m1).await.unwrap();
        let listed = backend.list_auth().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].mac, m2);
    }

    #[tokio::test]
    async fn run_maps_nonzero_exit_to_backend_error_never_fails_open() {
        // `/bin/false` exits 1 → the backend must surface an Error, not succeed.
        let backend = IpsetIptablesBackend::with_bins("/bin/false", "/bin/true", "/bin/true");
        let m: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        let err = backend.add_auth(m, Duration::from_secs(60)).await.unwrap_err();
        assert!(matches!(err, Error::Backend(_)), "got {err:?}");
    }

    /// A fake `ipset` binary: `add -exist <set> <mac> timeout <n>` appends a
    /// member line, `del -exist <set> <mac>` removes it, `list <set>` prints a
    /// realistic `Members:`-tailed dump. Members are stored in a sibling file so
    /// state survives across invocations. Same temp-dir script pattern the
    /// engine's `fake_nft`/shaper `fake_tc` tests use.
    fn fake_ipset(tag: &str) -> (String, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("portcullis-ipset-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let members = dir.join("members");
        std::fs::write(&members, "").unwrap();
        let script = dir.join("ipset");
        let body = format!(
            r#"#!/bin/sh
M="{members}"
cmd="$1"; shift
# strip a leading -exist flag
[ "$1" = "-exist" ] && shift
set="$1"; shift
case "$cmd" in
  add)
    mac="$1"; shift
    to=0
    [ "$1" = "timeout" ] && to="$2"
    grep -v "^$mac " "$M" > "$M.tmp" 2>/dev/null || true
    mv "$M.tmp" "$M"
    echo "$mac timeout $to" >> "$M"
    ;;
  del)
    mac="$1"
    grep -v "^$mac " "$M" > "$M.tmp" 2>/dev/null || true
    mv "$M.tmp" "$M"
    ;;
  list)
    echo "Name: $set"
    echo "Type: hash:mac"
    echo "Members:"
    cat "$M"
    ;;
  *) : ;;
esac
exit 0
"#,
            members = members.display()
        );
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (script.display().to_string(), dir)
    }

    /// A fake `iptables`/`ip6tables` binary that records every invocation's argv
    /// (one line per call) into a log file. `-N` (create chain) and `-C` (check)
    /// exit non-zero so `ensure_chain` treats the chain as absent and the jump as
    /// missing — forcing the real `-F`/`-A`/`-I` mutation path to run and be
    /// logged. Every other command exits 0. Returns `(bin, log, dir)`.
    fn fake_iptables(tag: &str) -> (String, std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("portcullis-ipt-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("ipt.log");
        std::fs::write(&log, "").unwrap();
        let script = dir.join("iptables");
        // `-C` (jump-exists probe) must fail so the `-I` insert runs; `-N` is
        // ignored idempotently by the caller via run_ok either way.
        let body = format!(
            r#"#!/bin/sh
echo "$@" >> "{log}"
for a in "$@"; do
  case "$a" in
    -C) exit 1;;
    -N) exit 1;;
  esac
done
exit 0
"#,
            log = log.display()
        );
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (script.display().to_string(), log, dir)
    }

    /// All logged iptables invocations, one argv per line.
    fn lines(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Just the jump-insert invocations (`-I <hook> 1 ... -j <chain>`).
    fn jump_inserts(log: &std::path::Path) -> Vec<String> {
        lines(log)
            .into_iter()
            .filter(|l| l.contains("-I ") && l.contains("-j "))
            .collect()
    }
}
