//! `conntrack`-backed [`CounterSource`] (TDD §7.6).
//!
//! On RutOS the native firewall is fw3, which masquerades the WAN. A conntrack
//! entry therefore carries two tuples: the **ORIGINAL** tuple (client -> server,
//! as seen *before* NAT) and the **REPLY** tuple (server -> router's WAN IP,
//! *after* NAT). We MUST aggregate on the ORIGINAL source IP — that is the real
//! client address; the reply tuple's `dst` is the post-NAT WAN address and would
//! collapse every client onto one IP.
//!
//! Byte direction, from the client's point of view:
//! - ORIGINAL `bytes=` = traffic the client sent  => `bytes_out`
//! - REPLY    `bytes=` = traffic the client got    => `bytes_in`
//!
//! Real reads shell out to `conntrack -L` behind the [`ConntrackReader`] trait so
//! the loop is unit-testable without a kernel; [`parse_conntrack`] is the pure
//! text parser exercised directly in tests.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use portcullis_types::{Counters, Error, MacAddr, NeighResolver, Result};
use tokio::process::Command;

use crate::CounterSource;

/// Abstraction over "produce the raw `conntrack -L` text". Real impl forks
/// `conntrack`; tests inject canned output. Kept separate from parsing so the
/// kernel-touching part is the only thing that needs mocking.
#[async_trait]
pub trait ConntrackReader: Send + Sync {
    /// Return the full multi-line dump of the current conntrack table.
    async fn dump(&self) -> Result<String>;
}

/// Production [`ConntrackReader`]: shells out to `conntrack -L`.
///
/// Requires `net.netfilter.nf_conntrack_acct=1` to be set so that the `bytes=`
/// fields are populated; without it conntrack omits the byte counters and we
/// simply see zeros (logged + degraded, never fabricated — TDD §11).
#[derive(Clone)]
pub struct ConntrackCli {
    /// Binary to invoke (default `conntrack`; overridable for odd install paths).
    program: String,
}

impl Default for ConntrackCli {
    fn default() -> Self {
        ConntrackCli { program: "conntrack".to_string() }
    }
}

impl ConntrackCli {
    pub fn new(program: impl Into<String>) -> Self {
        ConntrackCli { program: program.into() }
    }
}

#[async_trait]
impl ConntrackReader for ConntrackCli {
    async fn dump(&self) -> Result<String> {
        // `-L` list, `-o extended` keeps the stable `src=/bytes=` text format we
        // parse. We do not pass `-f` so both ipv4 and ipv6 entries are emitted.
        let output = Command::new(&self.program)
            .arg("-L")
            .arg("-o")
            .arg("extended")
            .output()
            .await
            .map_err(|e| Error::Counter(format!("spawn {}: {e}", self.program)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Counter(format!(
                "{} -L exited with {}: {}",
                self.program,
                output.status,
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Pure parser for `conntrack -L` text. Aggregates byte counters per **original
/// source IP** across all flows. Unknown / malformed lines are skipped (never
/// panics, never fabricates). This is the unit-test seam (TDD §7.6).
///
/// A representative line looks like:
/// ```text
/// tcp 6 431999 ESTABLISHED src=192.168.1.10 dst=93.184.216.34 sport=5 dport=443 \
///     packets=120 bytes=15000 src=93.184.216.34 dst=203.0.113.5 sport=443 \
///     dport=5 packets=98 bytes=210000 [ASSURED] mark=0 use=1
/// ```
/// The first `src=`/`bytes=` pair is the ORIGINAL tuple; the second is the REPLY.
pub fn parse_conntrack(output: &str) -> Vec<(IpAddr, Counters)> {
    let mut by_ip: HashMap<IpAddr, Counters> = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Walk tokens, collecting (src, bytes) pairs in flow order. The first
        // `src=` belongs to the ORIGINAL tuple, the second to the REPLY tuple.
        // We track the *most recent* `src=` so each `bytes=` is attributed to the
        // tuple it belongs to.
        let mut original_src: Option<IpAddr> = None;
        let mut seen_src = 0u8;
        let mut orig_bytes: u64 = 0;
        let mut reply_bytes: u64 = 0;

        for tok in line.split_whitespace() {
            if let Some(val) = tok.strip_prefix("src=") {
                if let Ok(ip) = val.parse::<IpAddr>() {
                    seen_src += 1;
                    if seen_src == 1 {
                        original_src = Some(ip);
                    }
                }
            } else if let Some(val) = tok.strip_prefix("bytes=") {
                if let Ok(n) = val.parse::<u64>() {
                    // Attribute to whichever tuple we are currently inside.
                    match seen_src {
                        0 => {} // bytes before any valid src= — ignore.
                        1 => orig_bytes = orig_bytes.saturating_add(n),
                        _ => reply_bytes = reply_bytes.saturating_add(n),
                    }
                }
            }
        }

        let Some(client_ip) = original_src else { continue };

        // ORIGINAL bytes = client -> server = bytes_out (from the client's view).
        // REPLY    bytes = server -> client = bytes_in.
        let entry = by_ip.entry(client_ip).or_default();
        entry.bytes_out = entry.bytes_out.saturating_add(orig_bytes);
        entry.bytes_in = entry.bytes_in.saturating_add(reply_bytes);
    }

    by_ip.into_iter().collect()
}

/// [`CounterSource`] backed by conntrack + a [`NeighResolver`] for IP -> MAC.
///
/// `snapshot()` dumps conntrack, aggregates per original source IP, resolves each
/// IP to its MAC via the neighbour table, and folds counters per MAC (multiple
/// IPs could, in principle, resolve to one MAC). IPs with **no** neighbour entry
/// are dropped — we never invent a MAC and never fail open (TDD §7.2, §11).
pub struct ConntrackSource<N: NeighResolver> {
    reader: Arc<dyn ConntrackReader>,
    neigh: N,
}

impl<N: NeighResolver> ConntrackSource<N> {
    /// Construct with the production `conntrack -L` reader.
    pub fn new(neigh: N) -> Self {
        ConntrackSource { reader: Arc::new(ConntrackCli::default()), neigh }
    }

    /// Construct with a custom [`ConntrackReader`] (tests, alternate binary).
    pub fn with_reader(reader: Arc<dyn ConntrackReader>, neigh: N) -> Self {
        ConntrackSource { reader, neigh }
    }
}

#[async_trait]
impl<N: NeighResolver> CounterSource for ConntrackSource<N> {
    async fn snapshot(&self) -> Result<Vec<(MacAddr, Counters)>> {
        let raw = self.reader.dump().await?;
        let per_ip = parse_conntrack(&raw);

        // At most one MAC per source IP, so size to the flow count up front to
        // avoid rehash churn on the 15 s tick.
        let mut by_mac: HashMap<MacAddr, Counters> = HashMap::with_capacity(per_ip.len());
        for (ip, counters) in per_ip {
            match self.neigh.resolve(ip).await {
                Ok(Some(mac)) => {
                    let e = by_mac.entry(mac).or_default();
                    e.bytes_in = e.bytes_in.saturating_add(counters.bytes_in);
                    e.bytes_out = e.bytes_out.saturating_add(counters.bytes_out);
                }
                Ok(None) => {
                    // No neighbour entry: client gone / not L2-local. Drop it —
                    // do not fabricate a MAC.
                    tracing::debug!(%ip, "conntrack flow has no neighbour entry; dropping");
                }
                Err(e) => {
                    // A single resolve failure must not sink the whole tick.
                    tracing::warn!(%ip, error = %e, "neighbour resolve failed; dropping flow");
                }
            }
        }

        Ok(by_mac.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    const SAMPLE: &str = "\
tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=93.184.216.34 sport=54321 dport=443 packets=120 bytes=15000 src=93.184.216.34 dst=203.0.113.5 sport=443 dport=54321 packets=98 bytes=210000 [ASSURED] mark=0 use=1
udp      17 29 src=192.168.1.10 dst=8.8.8.8 sport=5353 dport=53 packets=2 bytes=140 src=8.8.8.8 dst=203.0.113.5 sport=53 dport=5353 packets=2 bytes=300 mark=0 use=1
tcp      6 117 TIME_WAIT src=192.168.1.20 dst=140.82.121.4 sport=44002 dport=443 packets=10 bytes=1200 src=140.82.121.4 dst=203.0.113.5 sport=443 dport=44002 packets=8 bytes=9000 [ASSURED] mark=0 use=1

garbage line with no tuples
tcp 6 0 src=not-an-ip dst=1.2.3.4 bytes=999 src=1.2.3.4 bytes=888";

    fn map(v: Vec<(IpAddr, Counters)>) -> Map<IpAddr, Counters> {
        v.into_iter().collect()
    }

    #[test]
    fn parses_original_source_and_directions() {
        let m = map(parse_conntrack(SAMPLE));

        let c10: IpAddr = "192.168.1.10".parse().unwrap();
        let c20: IpAddr = "192.168.1.20".parse().unwrap();

        // 192.168.1.10 has two flows: tcp (out 15000 / in 210000) + udp (out 140 / in 300)
        let a = m.get(&c10).copied().unwrap();
        assert_eq!(a.bytes_out, 15000 + 140);
        assert_eq!(a.bytes_in, 210000 + 300);

        // 192.168.1.20 single flow.
        let b = m.get(&c20).copied().unwrap();
        assert_eq!(b.bytes_out, 1200);
        assert_eq!(b.bytes_in, 9000);

        // The WAN/post-NAT reply addresses must NOT appear as client keys.
        let wan: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(!m.contains_key(&wan), "must aggregate on original source, not reply");
        let server: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(!m.contains_key(&server));

        // On the malformed line the unparseable `src=not-an-ip` is ignored, so
        // the first *valid* src (1.2.3.4) becomes the original tuple and its
        // `bytes=888` is attributed there; the earlier `bytes=999` (which had no
        // preceding valid src) is dropped. Either way: no panic, no WAN/server
        // address ever becomes a client key.
        let recovered: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(m.get(&recovered).copied().unwrap().bytes_out, 888);
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(parse_conntrack("").is_empty());
        assert!(parse_conntrack("\n\n   \n").is_empty());
    }

    // --- ConntrackSource IP->MAC mapping ---

    struct StaticReader(String);
    #[async_trait]
    impl ConntrackReader for StaticReader {
        async fn dump(&self) -> Result<String> {
            Ok(self.0.clone())
        }
    }

    struct MockNeighResolver {
        table: Map<IpAddr, MacAddr>,
    }
    #[async_trait]
    impl NeighResolver for MockNeighResolver {
        async fn resolve(&self, ip: IpAddr) -> Result<Option<MacAddr>> {
            Ok(self.table.get(&ip).copied())
        }
    }

    #[tokio::test]
    async fn maps_ip_to_mac_and_drops_unknown() {
        let mac10: MacAddr = "aa:bb:cc:00:00:10".parse().unwrap();
        // 192.168.1.20 is intentionally absent from the neighbour table.
        let mut table = Map::new();
        table.insert("192.168.1.10".parse::<IpAddr>().unwrap(), mac10);

        let src = ConntrackSource::with_reader(
            Arc::new(StaticReader(SAMPLE.to_string())),
            MockNeighResolver { table },
        );

        let snap: Map<MacAddr, Counters> = src.snapshot().await.unwrap().into_iter().collect();

        // Only the resolvable MAC survives.
        assert_eq!(snap.len(), 1);
        let c = snap.get(&mac10).copied().unwrap();
        assert_eq!(c.bytes_out, 15000 + 140);
        assert_eq!(c.bytes_in, 210000 + 300);

        // 192.168.1.20 had no neighbour entry -> dropped, no fabricated MAC.
        let mac20: MacAddr = "aa:bb:cc:00:00:20".parse().unwrap();
        assert!(!snap.contains_key(&mac20));
    }

    #[tokio::test]
    async fn folds_multiple_ips_onto_one_mac() {
        // Two original-source IPs both resolving to the same MAC must sum.
        let txt = "\
tcp 6 1 ESTABLISHED src=10.0.0.1 dst=1.1.1.1 sport=1 dport=2 packets=1 bytes=100 src=1.1.1.1 dst=9.9.9.9 sport=2 dport=1 packets=1 bytes=200 mark=0 use=1
tcp 6 1 ESTABLISHED src=10.0.0.2 dst=1.1.1.1 sport=3 dport=4 packets=1 bytes=10 src=1.1.1.1 dst=9.9.9.9 sport=4 dport=3 packets=1 bytes=20 mark=0 use=1";
        let mac: MacAddr = "de:ad:be:ef:00:01".parse().unwrap();
        let mut table = Map::new();
        table.insert("10.0.0.1".parse::<IpAddr>().unwrap(), mac);
        table.insert("10.0.0.2".parse::<IpAddr>().unwrap(), mac);

        let src = ConntrackSource::with_reader(
            Arc::new(StaticReader(txt.to_string())),
            MockNeighResolver { table },
        );
        let snap: Map<MacAddr, Counters> = src.snapshot().await.unwrap().into_iter().collect();
        let c = snap.get(&mac).copied().unwrap();
        assert_eq!(c.bytes_out, 110);
        assert_eq!(c.bytes_in, 220);
    }

    #[tokio::test]
    async fn reader_error_propagates() {
        struct FailReader;
        #[async_trait]
        impl ConntrackReader for FailReader {
            async fn dump(&self) -> Result<String> {
                Err(Error::Counter("boom".into()))
            }
        }
        let src = ConntrackSource::with_reader(
            Arc::new(FailReader),
            MockNeighResolver { table: Map::new() },
        );
        assert!(src.snapshot().await.is_err());
    }
}
