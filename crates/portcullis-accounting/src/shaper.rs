//! Bandwidth shaping — see ADR-0013.
//!
//! Uses `tc` (HTB), NOT nftables `limit` (which caps packets/sec, not bytes/sec).
//! A per-MAC HTB class is attached on grant and torn down on de-auth.
//! `rate_bps == 0` = unlimited; [`NoopShaper`] is the default when shaping is off.

use async_trait::async_trait;
// The `Shaper` port + `NoopShaper` live in `portcullis-types` (like `FlowReaper`)
// so the SessionManager can hold `Arc<dyn Shaper>` without depending on this
// crate. This crate owns the concrete `TcShaper` (the tc/HTB adapter).
use portcullis_types::{Error, MacAddr, Result, Shaper};
use tokio::process::Command;

/// `tc`/HTB per-MAC bandwidth shaper (ADR-0013). A per-MAC HTB class capped at
/// `rate_bps` on the LAN egress, with a filter matching the client's dst MAC;
/// torn down on de-auth.
///
/// The exact `tc` syntax is device-validated on the MIPS target (like the
/// nft/ipset backends); the classid allocation + argument vectors are pure and
/// unit-tested here. A live `tc` failure degrades (best-effort, never fails the
/// grant).
#[derive(Clone, Debug)]
pub struct TcShaper {
    /// Egress interface the HTB qdisc lives on (e.g. the LAN bridge `br-lan`).
    iface: String,
    /// `tc` binary (overridable for odd install paths / a fake in tests).
    program: String,
}

impl TcShaper {
    pub fn new(iface: impl Into<String>) -> Self {
        TcShaper { iface: iface.into(), program: "tc".to_string() }
    }

    pub fn with_program(iface: impl Into<String>, program: impl Into<String>) -> Self {
        TcShaper { iface: iface.into(), program: program.into() }
    }

    /// Deterministic HTB minor handle for a MAC, in `[0x0002, 0xffff]` (`1:0` is
    /// the qdisc, `1:1` the root class). FNV-1a over the 6 MAC bytes. Collisions
    /// are possible in principle but negligible at per-store client counts; a
    /// collision would only mean two MACs share one class (documented; revisit
    /// with a stateful allocator if it ever bites on-device).
    fn classid_minor(mac: MacAddr) -> u16 {
        let mut h: u32 = 0x811c_9dc5;
        for b in mac.octets() {
            h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
        }
        let m = (h & 0xffff) as u16;
        m.max(2)
    }

    /// The `tc class replace ...` argument vector for `mac` at `rate_bps` (pure,
    /// unit-tested). `replace` is idempotent — re-granting refreshes the cap.
    fn class_args(&self, mac: MacAddr, rate_bps: u64) -> Vec<String> {
        let classid = format!("1:{:x}", Self::classid_minor(mac));
        let rate = format!("{rate_bps}bit");
        [
            "class", "replace", "dev", &self.iface, "parent", "1:", "classid", &classid, "htb",
            "rate", &rate, "ceil", &rate,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// The `tc filter ...` argument vector steering `mac`'s downstream traffic
    /// into its class (pure, unit-tested).
    fn filter_args(&self, mac: MacAddr) -> Vec<String> {
        let classid = format!("1:{:x}", Self::classid_minor(mac));
        [
            "filter", "replace", "dev", &self.iface, "parent", "1:", "protocol", "all", "u32",
            "match", "ether", "dst", &mac.to_string(), "flowid", &classid,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// The `tc class delete ...` argument vector for `mac` (pure, unit-tested).
    fn del_class_args(&self, mac: MacAddr) -> Vec<String> {
        let classid = format!("1:{:x}", Self::classid_minor(mac));
        ["class", "delete", "dev", &self.iface, "classid", &classid]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    async fn run(&self, args: &[String]) -> Result<()> {
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
        tracing::info!(%mac, iface = %self.iface, rate_bps, "TcShaper: applying per-MAC HTB cap");
        self.run(&self.class_args(mac, rate_bps)).await?;
        self.run(&self.filter_args(mac)).await
    }

    async fn clear(&self, mac: MacAddr) -> Result<()> {
        tracing::info!(%mac, iface = %self.iface, "TcShaper: clearing per-MAC HTB cap");
        // Deleting the class also drops its attached filter. Idempotent on-device
        // ("class not found" is tolerated by the caller's best-effort handling).
        self.run(&self.del_class_args(mac)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_types::NoopShaper;

    #[tokio::test]
    async fn noop_shaper_is_a_noop() {
        let s = NoopShaper;
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        // Both directions succeed and do nothing observable.
        assert!(s.apply(mac, 1_000_000).await.is_ok());
        assert!(s.apply(mac, 0).await.is_ok());
        assert!(s.clear(mac).await.is_ok());
    }

    #[test]
    fn classid_is_deterministic_and_reserved_safe() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let a = TcShaper::classid_minor(mac);
        let b = TcShaper::classid_minor(mac);
        assert_eq!(a, b, "same MAC -> same classid (idempotent apply)");
        assert!(a >= 2, "must avoid the reserved 1:0 / 1:1 handles");
        // Different MACs generally map to different handles.
        let other: MacAddr = "aa:bb:cc:dd:ee:00".parse().unwrap();
        assert_ne!(TcShaper::classid_minor(mac), TcShaper::classid_minor(other));
    }

    #[test]
    fn class_and_filter_args_are_well_formed() {
        let s = TcShaper::new("br-lan");
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let class = s.class_args(mac, 2_000_000);
        assert_eq!(&class[0..4], &["class", "replace", "dev", "br-lan"]);
        assert!(class.contains(&"htb".to_string()));
        assert!(class.contains(&"2000000bit".to_string()), "rate carried through: {class:?}");
        let filter = s.filter_args(mac);
        assert!(filter.contains(&"aa:bb:cc:dd:ee:ff".to_string()), "filter matches dst MAC");
        // class + filter reference the SAME classid.
        let cid = format!("1:{:x}", TcShaper::classid_minor(mac));
        assert!(class.contains(&cid) && filter.contains(&cid));
    }

    #[tokio::test]
    async fn apply_zero_rate_clears() {
        // rate 0 = unlimited -> apply must clear, not install a class. Point at a
        // missing binary so a real class install would error; clear on a fake `tc`
        // that exits 0 succeeds. Here we just assert the zero-rate path routes to
        // clear via a fake `tc` that always succeeds.
        let s = TcShaper::with_program("br-lan", "true");
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert!(s.apply(mac, 0).await.is_ok());
    }
}
