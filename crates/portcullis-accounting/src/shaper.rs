//! Bandwidth shaping (TDD §7.7) — **optional Phase-2 module**.
//!
//! IMPORTANT: bandwidth shaping uses **`tc` (HTB)**, NOT nftables `limit`.
//! `nft ... limit rate` rate-limits *packets per second*, not *bytes per
//! second*, and is the classic wrong tool for `rate_bps`. A per-session HTB
//! class is attached on grant and torn down on expiry/revoke.
//!
//! Phase 1 may ship without shaping if the uplink is otherwise capped
//! (`rate_bps == 0` means unlimited — callers should skip shaping entirely).
//! The [`NoopShaper`] is the Phase-1 default.

use std::collections::HashMap;

use async_trait::async_trait;
use portcullis_types::{Error, MacAddr, Result};
use tokio::process::Command;

// The trait lives in `portcullis-types` (like `GardenControl`) so the session
// layer can hold a `dyn Shaper` without depending on this crate; re-exported
// here for the existing import paths.
pub use portcullis_types::Shaper;

/// Phase-1 default: does nothing. Used when the uplink is otherwise capped or
/// shaping is disabled. Every method is a successful no-op.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopShaper;

#[async_trait]
impl Shaper for NoopShaper {
    async fn apply(&self, mac: MacAddr, rate_bps: u64) -> Result<()> {
        tracing::trace!(%mac, rate_bps, "NoopShaper: ignoring apply (shaping disabled)");
        Ok(())
    }

    async fn clear(&self, mac: MacAddr) -> Result<()> {
        tracing::trace!(%mac, "NoopShaper: ignoring clear");
        Ok(())
    }
}

/// `tc`/HTB download shaper: one HTB class + dst-MAC filter per shaped client
/// on the LAN egress interface (traffic *to* the client). Upload shaping
/// (ingress/IFB) is out of scope for v1.
///
/// Kernel objects per client (minor `M`, allocated from an in-RAM map):
/// - class  `1:M`  — `htb rate <bps> ceil <bps>`
/// - filter prio `M` — `u32` matching the client's **dst MAC** via the classic
///   negative-offset recipe (`-14`/`-12` reach back into the ether header from
///   the network header), one filter each for `ip` and `ipv6`.
///
/// The root qdisc (`1: htb default 0`) is (re)installed by [`ensure_root`] at
/// composition time; `replace` is idempotent but wipes existing classes, so
/// adopted sessions restart unshaped (consistent with adoption dropping
/// quota — the CP re-grants with policy on the next session).
///
/// State is RAM-only (§5.4): the MAC→minor map lives here; kernel classes are
/// rebuilt as grants arrive. The negative-offset match is the §18-class
/// on-device risk — validated by the netns suite and flagged for RUTM11
/// verification (fallback: `flower dst_mac`).
///
/// [`ensure_root`]: TcShaper::ensure_root
#[derive(Debug)]
pub struct TcShaper {
    /// Egress interface the HTB qdisc lives on (e.g. the LAN bridge `br-lan`).
    iface: String,
    /// `tc` binary (overridable for odd install paths / tests).
    program: String,
    /// MAC -> HTB class minor. Minors are 2..=0xFFFE (1: is the root handle).
    classes: tokio::sync::Mutex<HashMap<MacAddr, u16>>,
}

impl TcShaper {
    pub fn new(iface: impl Into<String>) -> Self {
        Self::with_program(iface, "tc")
    }

    pub fn with_program(iface: impl Into<String>, program: impl Into<String>) -> Self {
        TcShaper {
            iface: iface.into(),
            program: program.into(),
            classes: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Install (or replace) the root HTB qdisc. `default 0` sends unclassified
    /// traffic straight through, so clients without a cap are untouched. Also
    /// serves as the runtime probe: failure means `tc`/HTB is unavailable and
    /// the caller falls back to [`NoopShaper`] instead of taking a hard .ipk
    /// dependency.
    pub async fn ensure_root(&self) -> Result<()> {
        self.run(&["qdisc", "replace", "dev", &self.iface, "root", "handle", "1:", "htb", "default", "0"])
            .await
    }

    /// Reserve (or look up) the class minor for `mac`.
    async fn minor_for(&self, mac: MacAddr) -> Result<u16> {
        let mut map = self.classes.lock().await;
        if let Some(&m) = map.get(&mac) {
            return Ok(m);
        }
        // Smallest free minor >= 2. Linear scan is fine at <= MAX_SESSIONS.
        let used: std::collections::HashSet<u16> = map.values().copied().collect();
        let minor = (2..=0xFFFEu16)
            .find(|m| !used.contains(m))
            .ok_or_else(|| Error::Backend("tc class minors exhausted".into()))?;
        map.insert(mac, minor);
        Ok(minor)
    }

    /// The classic u32 dst-MAC match, reaching back into the ether header:
    /// bytes 0-1 of the dst MAC at offset -14, bytes 2-5 at -12.
    fn mac_match(mac: MacAddr) -> (String, String) {
        let o = mac.octets();
        (
            format!("0x{:02x}{:02x}", o[0], o[1]),
            format!("0x{:02x}{:02x}{:02x}{:02x}", o[2], o[3], o[4], o[5]),
        )
    }

    async fn del_filters_and_class(&self, minor: u16) {
        let prio = minor.to_string();
        let classid = format!("1:{minor:x}");
        // Best-effort teardown: parts may not exist (never applied / already
        // cleared) — errors here are expected and ignored.
        for proto in ["ip", "ipv6"] {
            let _ = self
                .run(&["filter", "del", "dev", &self.iface, "parent", "1:", "protocol", proto, "prio", &prio])
                .await;
        }
        let _ = self.run(&["class", "del", "dev", &self.iface, "classid", &classid]).await;
    }

    async fn run(&self, args: &[&str]) -> Result<()> {
        let output = Command::new(&self.program)
            .args(args)
            .output()
            .await
            .map_err(|e| Error::Backend(format!("spawn {}: {e}", self.program)))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Backend(format!(
                "{} {} -> {}: {}",
                self.program,
                args.join(" "),
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl Shaper for TcShaper {
    async fn apply(&self, mac: MacAddr, rate_bps: u64) -> Result<()> {
        if rate_bps == 0 {
            // Unlimited: ensure no leftover class remains.
            return self.clear(mac).await;
        }
        let minor = self.minor_for(mac).await?;
        let classid = format!("1:{minor:x}");
        let rate = format!("{rate_bps}bit");
        let prio = minor.to_string();
        let flowid = classid.clone();

        // Class first (replace = idempotent refresh on re-grant)...
        self.run(&[
            "class", "replace", "dev", &self.iface, "parent", "1:", "classid", &classid,
            "htb", "rate", &rate, "ceil", &rate, "burst", "32k",
        ])
        .await?;

        // ...then the dst-MAC filters. `filter replace` is unreliable for u32,
        // so del-then-add; the sub-ms window where the class exists unfiltered
        // just means the client is briefly unshaped (QoS, not enforcement).
        let (hi, lo) = Self::mac_match(mac);
        for proto in ["ip", "ipv6"] {
            let _ = self
                .run(&["filter", "del", "dev", &self.iface, "parent", "1:", "protocol", proto, "prio", &prio])
                .await;
            self.run(&[
                "filter", "add", "dev", &self.iface, "parent", "1:", "protocol", proto,
                "prio", &prio, "u32",
                "match", "u16", &hi, "0xffff", "at", "-14",
                "match", "u32", &lo, "0xffffffff", "at", "-12",
                "flowid", &flowid,
            ])
            .await?;
        }
        tracing::info!(%mac, iface = %self.iface, rate_bps, classid = %classid, "tc shaper cap applied");
        Ok(())
    }

    async fn clear(&self, mac: MacAddr) -> Result<()> {
        let minor = { self.classes.lock().await.remove(&mac) };
        if let Some(minor) = minor {
            self.del_filters_and_class(minor).await;
            tracing::debug!(%mac, iface = %self.iface, minor, "tc shaper cap cleared");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_shaper_is_a_noop() {
        let s = NoopShaper;
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        // Both directions succeed and do nothing observable.
        assert!(s.apply(mac, 1_000_000).await.is_ok());
        assert!(s.apply(mac, 0).await.is_ok());
        assert!(s.clear(mac).await.is_ok());
    }

    /// Fake `tc`: appends each invocation's args to a log file and exits 0, so
    /// the tests assert the exact command shapes without a kernel. Files live
    /// under a unique std temp-dir path (same pattern as the garden tests —
    /// no tempfile dependency).
    fn fake_tc(tag: &str) -> (String, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("portcullis-tc-test-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("tc.log");
        let script = dir.join("tc");
        std::fs::write(&script, format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display())).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (script.display().to_string(), log)
    }

    fn lines(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn tc_shaper_renders_class_and_dst_mac_filters() {
        let (program, log) = fake_tc("render");
        let s = TcShaper::with_program("br-lan", program);
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();

        s.ensure_root().await.unwrap();
        s.apply(mac, 2_000_000).await.unwrap();

        let cmds = lines(&log);
        assert_eq!(cmds[0], "qdisc replace dev br-lan root handle 1: htb default 0");
        // First free minor is 2 -> classid 1:2, filter prio 2.
        assert_eq!(
            cmds[1],
            "class replace dev br-lan parent 1: classid 1:2 htb rate 2000000bit ceil 2000000bit burst 32k"
        );
        // del-then-add per protocol; the u32 negative-offset dst-MAC match.
        assert!(cmds[3].contains("filter add dev br-lan parent 1: protocol ip prio 2 u32"));
        assert!(cmds[3].contains("match u16 0xaabb 0xffff at -14"));
        assert!(cmds[3].contains("match u32 0xccddeeff 0xffffffff at -12"));
        assert!(cmds[3].ends_with("flowid 1:2"));
        assert!(cmds[5].contains("protocol ipv6 prio 2 u32"));

        // Re-apply reuses the same minor (stable classid per MAC).
        s.apply(mac, 1_000_000).await.unwrap();
        assert!(lines(&log).iter().any(|c| c.contains("classid 1:2 htb rate 1000000bit")));

        // Clear tears down filters + class and frees the minor for the next MAC.
        s.clear(mac).await.unwrap();
        let cmds = lines(&log);
        assert!(cmds.iter().any(|c| c == "filter del dev br-lan parent 1: protocol ip prio 2"));
        assert!(cmds.iter().any(|c| c == "class del dev br-lan classid 1:2"));

        let mac2: MacAddr = "aa:bb:cc:dd:ee:01".parse().unwrap();
        s.apply(mac2, 500_000).await.unwrap();
        assert!(lines(&log).iter().any(|c| c.contains("classid 1:2 htb rate 500000bit")));
    }

    #[tokio::test]
    async fn tc_shaper_rate_zero_clears_and_unknown_mac_is_ok() {
        let (program, log) = fake_tc("zero");
        let s = TcShaper::with_program("br-lan", program);
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();

        // Clearing a never-shaped MAC is a silent no-op (no tc calls).
        s.clear(mac).await.unwrap();
        assert!(lines(&log).is_empty());

        // rate 0 on a shaped MAC routes through clear.
        s.apply(mac, 9_000).await.unwrap();
        s.apply(mac, 0).await.unwrap();
        assert!(lines(&log).iter().any(|c| c == "class del dev br-lan classid 1:2"));
    }
}
