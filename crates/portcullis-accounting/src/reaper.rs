//! conntrack flow reaping on de-auth (invariant #9, conntrack ⊆ auth).
//!
//! Removing a MAC from the `@auth` set only gates *new* connections. An
//! already-established flow keeps sailing through the `ct established,related
//! accept` fast path indefinitely — so a revoked / expired / quota-capped client
//! whose browser or VPN holds a long-lived socket stays online. Reaping the
//! client's conntrack flows on de-auth closes that leak.
//!
//! Two paths use this:
//! - the **de-auth fast path** (SessionManager) reaps the session's recorded IP
//!   the moment it removes the MAC;
//! - the **reconcile sweep** ([`reap_orphan_flows`]) reaps any neighbour IP whose
//!   MAC is no longer in `@auth` — the backstop for IPs the session never
//!   recorded (dual-stack, DHCP churn) and for cold start after a restart.
//!
//! Fail-closed: a reap error is a *degradation* (the leaked flow persists until
//! the next sweep), never a fail-open. It must not abort a revoke or unblock the
//! gate. The real invocation is thin; the exit-code interpretation is the pure,
//! directly-tested seam ([`interpret_delete_output`]).

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use portcullis_types::{Error, FlowReaper, MacAddr, NeighResolver, Result, RulesetWriter};
use tokio::process::Command;
use tokio::time::{interval_at, Instant, MissedTickBehavior};

/// Production [`FlowReaper`]: shells `conntrack -D -s <ip>`.
///
/// `conntrack -D` prints `N flow entries have been deleted` to stderr and exits
/// nonzero when nothing matched (benign). We parse the count out of stderr and
/// treat "nothing matched" as `Ok(0)` — only a genuine spawn/tool failure is an
/// error (which the caller degrades, never fails open).
#[derive(Clone)]
pub struct ConntrackReaper {
    program: String,
}

impl Default for ConntrackReaper {
    fn default() -> Self {
        ConntrackReaper { program: "conntrack".to_string() }
    }
}

impl ConntrackReaper {
    pub fn new(program: impl Into<String>) -> Self {
        ConntrackReaper { program: program.into() }
    }
}

#[async_trait]
impl FlowReaper for ConntrackReaper {
    async fn reap_by_ip(&self, ip: std::net::IpAddr) -> Result<usize> {
        // Args are engine-constructed (`ip.to_string()` on a validated IpAddr),
        // never raw client text, and Command runs no shell — no injection surface.
        let out = Command::new(&self.program)
            .arg("-D")
            .arg("-s")
            .arg(ip.to_string())
            .output()
            .await
            .map_err(|e| Error::Counter(format!("spawn {}: {e}", self.program)))?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        interpret_delete_output(out.status.success(), &stderr)
            .map_err(|msg| Error::Counter(format!("conntrack -D -s {ip}: {msg}")))
    }
}

/// Pure interpretation of a `conntrack -D` invocation (the unit-test seam).
///
/// - a parseable `N flow entries have been deleted` → `Ok(N)` (whatever the exit
///   code — nonzero just means "nothing matched", which parses as 0);
/// - exit success with no count → `Ok(0)`;
/// - exit failure with no count → `Err(stderr)` (a real tool failure).
fn interpret_delete_output(success: bool, stderr: &str) -> std::result::Result<usize, String> {
    if let Some(n) = parse_deleted_count(stderr) {
        return Ok(n);
    }
    if success {
        Ok(0)
    } else {
        Err(stderr.trim().to_string())
    }
}

/// Extract the leading integer from `... N flow entries have been deleted`.
fn parse_deleted_count(stderr: &str) -> Option<usize> {
    let idx = stderr.find("flow entries have been deleted")?;
    stderr[..idx]
        .split_whitespace()
        .next_back()
        .and_then(|tok| tok.parse::<usize>().ok())
}

/// Reap the conntrack flows of every neighbour whose MAC is **not** in `@auth`
/// (invariant #9). Reads the authoritative auth set from the kernel via the
/// writer, dumps the neighbour table for the reverse (MAC → IP) lookup, and
/// reaps each orphan IP. Only LAN neighbours are candidates, so the router's own
/// IPs and the outbound control-plane flow are structurally never reaped.
///
/// Per-IP reap failures are logged and skipped; a whole-set/table read failure
/// returns `Err` so the caller skips the sweep (never fail open). Returns the
/// number of flows removed.
pub async fn reap_orphan_flows(
    writer: &dyn RulesetWriter,
    resolver: &dyn NeighResolver,
    reaper: &dyn FlowReaper,
) -> Result<usize> {
    let authed: HashSet<MacAddr> =
        writer.list_auth().await?.into_iter().map(|e| e.mac).collect();
    let table = resolver.table().await?;
    let mut reaped = 0usize;
    for (ip, mac) in table {
        if authed.contains(&mac) {
            continue;
        }
        match reaper.reap_by_ip(ip).await {
            Ok(n) => reaped += n,
            Err(e) => {
                tracing::warn!(%ip, error = %e, "orphan conntrack reap failed; gate still holds");
            }
        }
    }
    if reaped > 0 {
        tracing::info!(reaped, "reconcile sweep reaped orphan conntrack flows");
    }
    Ok(reaped)
}

/// Periodic reconcile sweep: run [`reap_orphan_flows`] every `interval` until
/// `shutdown` resolves. The first sweep fires immediately (cold-start reap: sever
/// any flow left over from before this daemon adopted the kernel state). A sweep
/// error is logged and the loop continues — the kernel set-element timeout is the
/// backstop, so a blind sweep never strands a client (§11).
pub async fn run_reap_loop<F>(
    writer: Arc<dyn RulesetWriter>,
    resolver: Arc<dyn NeighResolver>,
    reaper: Arc<dyn FlowReaper>,
    interval: Duration,
    shutdown: F,
) where
    F: Future<Output = ()>,
{
    let mut ticker = interval_at(Instant::now(), interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::debug!("reap loop shutting down");
                return;
            }
            _ = ticker.tick() => {
                if let Err(e) = reap_orphan_flows(writer.as_ref(), resolver.as_ref(), reaper.as_ref()).await {
                    tracing::warn!(error = %e, "conntrack reconcile sweep failed; skipping tick");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Mutex;
    use portcullis_types::AuthElement;

    #[test]
    fn interpret_parses_deleted_count() {
        // conntrack prints the count to stderr even on the benign nonzero exit.
        assert_eq!(
            interpret_delete_output(true, "conntrack v1.4.6: 3 flow entries have been deleted.\n"),
            Ok(3)
        );
        assert_eq!(
            interpret_delete_output(false, "0 flow entries have been deleted.\n"),
            Ok(0)
        );
    }

    #[test]
    fn interpret_success_without_count_is_zero() {
        assert_eq!(interpret_delete_output(true, ""), Ok(0));
    }

    #[test]
    fn interpret_failure_without_count_is_error() {
        let r = interpret_delete_output(false, "conntrack: command not found");
        assert!(r.is_err(), "a real tool failure must not be swallowed as Ok(0)");
    }

    // ---- reap_orphan_flows over mock ports ----

    struct FixedWriter {
        authed: Vec<MacAddr>,
    }
    #[async_trait]
    impl RulesetWriter for FixedWriter {
        async fn ensure_base(&self) -> Result<()> {
            Ok(())
        }
        async fn add_auth(&self, _mac: MacAddr, _ttl: Duration) -> Result<()> {
            Ok(())
        }
        async fn del_auth(&self, _mac: MacAddr) -> Result<()> {
            Ok(())
        }
        async fn list_auth(&self) -> Result<Vec<AuthElement>> {
            Ok(self
                .authed
                .iter()
                .map(|m| AuthElement { mac: *m, remaining: Duration::from_secs(60) })
                .collect())
        }
        async fn set_gated_ifaces(&self, _ifaces: Vec<String>) -> Result<()> {
            Ok(())
        }
    }

    struct FixedResolver {
        table: Vec<(IpAddr, MacAddr)>,
    }
    #[async_trait]
    impl NeighResolver for FixedResolver {
        async fn resolve(&self, ip: IpAddr) -> Result<Option<MacAddr>> {
            Ok(self.table.iter().find(|(i, _)| *i == ip).map(|(_, m)| *m))
        }
        async fn table(&self) -> Result<Vec<(IpAddr, MacAddr)>> {
            Ok(self.table.clone())
        }
    }

    #[derive(Default)]
    struct RecordingReaper {
        reaped: Mutex<Vec<IpAddr>>,
    }
    #[async_trait]
    impl FlowReaper for RecordingReaper {
        async fn reap_by_ip(&self, ip: IpAddr) -> Result<usize> {
            self.reaped.lock().unwrap().push(ip);
            Ok(1)
        }
    }

    #[tokio::test]
    async fn sweep_reaps_only_unauthed_neighbours() {
        let auth_mac: MacAddr = "aa:aa:aa:aa:aa:aa".parse().unwrap();
        let orphan_mac: MacAddr = "bb:bb:bb:bb:bb:bb".parse().unwrap();
        let auth_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let orphan_ip: IpAddr = "10.0.0.3".parse().unwrap();

        let writer = FixedWriter { authed: vec![auth_mac] };
        let resolver = FixedResolver {
            table: vec![(auth_ip, auth_mac), (orphan_ip, orphan_mac)],
        };
        let reaper = RecordingReaper::default();

        let n = reap_orphan_flows(&writer, &resolver, &reaper).await.unwrap();
        assert_eq!(n, 1, "one orphan flow reaped");
        let reaped = reaper.reaped.lock().unwrap();
        assert_eq!(&*reaped, &[orphan_ip], "authed neighbour must not be reaped");
    }
}
