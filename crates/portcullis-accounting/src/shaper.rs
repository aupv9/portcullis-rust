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

use async_trait::async_trait;
use portcullis_types::{Error, MacAddr, Result};
use tokio::process::Command;

/// Apply / clear a per-client bandwidth cap. `rate_bps == 0` means unlimited.
#[async_trait]
pub trait Shaper: Send + Sync {
    /// Apply an HTB class capping `mac` to `rate_bps` bits/sec. `rate_bps == 0`
    /// is treated as "no cap" and should clear any existing shaping for `mac`.
    async fn apply(&self, mac: MacAddr, rate_bps: u64) -> Result<()>;

    /// Remove any shaping applied to `mac` (idempotent — clearing an unshaped
    /// MAC is not an error).
    async fn clear(&self, mac: MacAddr) -> Result<()>;
}

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

/// Phase-2 `tc`/HTB shaper. Shells out to `tc` to attach a per-MAC HTB class on
/// the LAN egress interface. This is a skeleton: the real class-id allocation
/// and filter wiring are device-specific and validated on-hardware (§16/§18);
/// it is documented and trait-shaped here so Phase 1 can ship with [`NoopShaper`]
/// and swap this in without touching call sites.
#[derive(Clone, Debug)]
pub struct TcShaper {
    /// Egress interface the HTB qdisc lives on (e.g. the LAN bridge `br-lan`).
    iface: String,
    /// `tc` binary (overridable for odd install paths).
    program: String,
}

impl TcShaper {
    pub fn new(iface: impl Into<String>) -> Self {
        TcShaper { iface: iface.into(), program: "tc".to_string() }
    }

    pub fn with_program(iface: impl Into<String>, program: impl Into<String>) -> Self {
        TcShaper { iface: iface.into(), program: program.into() }
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
        // Phase-2 skeleton: a real impl allocates a stable classid per MAC,
        // creates the HTB class with `rate`/`ceil`, and installs a filter that
        // matches the client's dst MAC. Left as a documented shell-out shape.
        let rate = format!("{rate_bps}bit");
        tracing::info!(%mac, iface = %self.iface, rate = %rate, "TcShaper: applying HTB class (Phase-2)");
        self.run(&["qdisc", "show", "dev", &self.iface]).await
    }

    async fn clear(&self, mac: MacAddr) -> Result<()> {
        tracing::info!(%mac, iface = %self.iface, "TcShaper: clearing HTB class (Phase-2)");
        // Real impl deletes the per-MAC class/filter; show is a safe placeholder.
        self.run(&["qdisc", "show", "dev", &self.iface]).await
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
}
