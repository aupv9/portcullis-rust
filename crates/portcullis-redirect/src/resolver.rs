//! [`NeighResolver`] adapters: resolve a client source IP -> L2 MAC.
//!
//! The redirect responder learns the connecting client's source IP from the
//! socket, then maps it to the stable session key (the MAC) via the kernel
//! neighbour table (TDD §7.2). Two impls:
//!
//! * [`IpNeighResolver`] — production: shells out to `ip neigh show <ip>` via
//!   `tokio::process` and parses the one matching line. (On the RUTM11 the
//!   neighbour table is the same one nft/conntrack see.)
//! * [`MockNeighResolver`] — a `HashMap` for unit tests, so [`crate::respond`]
//!   is testable without a live kernel or socket.
//!
//! Kernel-sourced data is **untrusted input** (security-auditor): the parser is
//! total and validates the MAC via `MacAddr::from_str` before returning it.

use std::collections::HashMap;
use std::net::IpAddr;

use async_trait::async_trait;
use portcullis_types::{Error, MacAddr, NeighResolver, Result};
use tokio::process::Command;

/// Production resolver backed by the `ip neigh` command.
///
/// Note: the binary does not exist on the macOS host build target; this type
/// compiles and is unit-testable for its *parser*, while the live `resolve`
/// path is exercised on-device / in the Linux netns harness (TDD §15).
#[derive(Clone, Debug)]
pub struct IpNeighResolver {
    /// Path to the `ip` binary; overridable for tests/odd layouts.
    ip_bin: String,
}

impl Default for IpNeighResolver {
    fn default() -> Self {
        Self { ip_bin: "ip".to_string() }
    }
}

impl IpNeighResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the `ip` binary path (e.g. an absolute `/sbin/ip`).
    pub fn with_ip_bin(ip_bin: impl Into<String>) -> Self {
        Self { ip_bin: ip_bin.into() }
    }

    /// Parse a single `ip neigh` line into its `(ip, lladdr-mac)` pair, if the
    /// entry is usable.
    ///
    /// Format of a line (fields after the IP are order-stable in iproute2):
    /// `192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE`
    /// Entries with no `lladdr` (e.g. `FAILED`, `INCOMPLETE`) or a garbage MAC
    /// yield `None`.
    ///
    /// Total: tolerates empty lines, extra whitespace, missing fields, and
    /// garbage `lladdr` values (rejected by MAC parsing) without panicking.
    fn parse_neigh_line(line: &str) -> Option<(IpAddr, MacAddr)> {
        let mut tokens = line.split_whitespace();
        // First token is the neighbour IP.
        let line_ip: IpAddr = tokens.next()?.parse().ok()?;
        // Scan remaining tokens for `lladdr <mac>`.
        while let Some(tok) = tokens.next() {
            if tok == "lladdr" {
                // Validate via the frozen MacAddr parser; reject junk.
                return tokens.next()?.parse::<MacAddr>().ok().map(|mac| (line_ip, mac));
            }
        }
        None
    }

    /// Parse the output of `ip neigh show <ip>` and extract the `lladdr` MAC for
    /// the given IP, if present and usable.
    fn parse_neigh_output(output: &str, want_ip: IpAddr) -> Option<MacAddr> {
        output
            .lines()
            .filter_map(Self::parse_neigh_line)
            .find(|(ip, _)| *ip == want_ip)
            .map(|(_, mac)| mac)
    }

    /// Parse the output of a full `ip neigh show` (no IP filter) into every
    /// usable `(ip, mac)` mapping. This is the batch path (see
    /// [`resolve_many`](NeighResolver::resolve_many)) — a single kernel dump
    /// serves all of a tick's lookups instead of one fork/exec per client.
    fn parse_neigh_table(output: &str) -> Vec<(IpAddr, MacAddr)> {
        output.lines().filter_map(Self::parse_neigh_line).collect()
    }
}

#[async_trait]
impl NeighResolver for IpNeighResolver {
    async fn resolve(&self, ip: IpAddr) -> Result<Option<MacAddr>> {
        // Args are engine-constructed; `ip.to_string()` is a validated IpAddr,
        // never raw client text, and Command does not invoke a shell — so no
        // argument-injection surface (security-auditor).
        let out = Command::new(&self.ip_bin)
            .arg("neigh")
            .arg("show")
            .arg(ip.to_string())
            .output()
            .await
            .map_err(|e| Error::NeighLookup(ip, e.to_string()))?;

        if !out.status.success() {
            return Err(Error::NeighLookup(
                ip,
                format!("ip neigh exited with status {}", out.status),
            ));
        }

        let text = String::from_utf8_lossy(&out.stdout);
        Ok(Self::parse_neigh_output(&text, ip))
    }

    /// Batch resolve via a **single** full-table `ip neigh show` (no IP arg),
    /// then filter to the requested IPs. This collapses the accounting loop's
    /// per-client fork/exec into one process spawn per tick (embedded-perf, TDD
    /// §14). An empty request needs no dump. A failed dump returns an error so
    /// the caller skips the tick (the kernel timeout is the backstop, §11).
    async fn resolve_many(&self, ips: &[IpAddr]) -> Result<Vec<(IpAddr, MacAddr)>> {
        use std::collections::HashSet;
        if ips.is_empty() {
            return Ok(Vec::new());
        }

        let out = Command::new(&self.ip_bin)
            .arg("neigh")
            .arg("show")
            .output()
            .await
            .map_err(|e| Error::NeighLookup(ips[0], e.to_string()))?;

        if !out.status.success() {
            return Err(Error::NeighLookup(
                ips[0],
                format!("ip neigh show exited with status {}", out.status),
            ));
        }

        let text = String::from_utf8_lossy(&out.stdout);
        let want: HashSet<IpAddr> = ips.iter().copied().collect();
        Ok(Self::parse_neigh_table(&text)
            .into_iter()
            .filter(|(ip, _)| want.contains(ip))
            .collect())
    }

    /// Full neighbour-table dump for the conntrack reconcile sweep's reverse
    /// (MAC → IP) lookup (invariant #9). Same `ip neigh show` as `resolve_many`,
    /// but returns every `(ip, mac)` instead of filtering to a request set.
    async fn table(&self) -> Result<Vec<(IpAddr, MacAddr)>> {
        let out = Command::new(&self.ip_bin)
            .arg("neigh")
            .arg("show")
            .output()
            .await
            .map_err(|e| Error::Other(format!("ip neigh show (table dump): {e}")))?;
        if !out.status.success() {
            return Err(Error::Other(format!(
                "ip neigh show (table dump) exited with status {}",
                out.status
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(Self::parse_neigh_table(&text))
    }
}

/// In-memory resolver for unit tests: a fixed IP -> MAC map.
#[derive(Clone, Debug, Default)]
pub struct MockNeighResolver {
    table: HashMap<IpAddr, MacAddr>,
}

impl MockNeighResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a mapping. Builder-style for ergonomic test setup.
    pub fn with(mut self, ip: IpAddr, mac: MacAddr) -> Self {
        self.table.insert(ip, mac);
        self
    }

    pub fn insert(&mut self, ip: IpAddr, mac: MacAddr) {
        self.table.insert(ip, mac);
    }
}

#[async_trait]
impl NeighResolver for MockNeighResolver {
    async fn resolve(&self, ip: IpAddr) -> Result<Option<MacAddr>> {
        Ok(self.table.get(&ip).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_reachable_line() {
        let out = "192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE\n";
        let mac = IpNeighResolver::parse_neigh_output(out, ip("192.168.1.10"));
        assert_eq!(mac, Some("aa:bb:cc:dd:ee:ff".parse().unwrap()));
    }

    #[test]
    fn parses_among_multiple_lines() {
        let out = "\
10.0.0.1 dev eth0 lladdr 00:11:22:33:44:55 STALE
192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff DELAY
192.168.1.11 dev br-lan FAILED
";
        assert_eq!(
            IpNeighResolver::parse_neigh_output(out, ip("192.168.1.10")),
            Some("aa:bb:cc:dd:ee:ff".parse().unwrap())
        );
        assert_eq!(
            IpNeighResolver::parse_neigh_output(out, ip("10.0.0.1")),
            Some("00:11:22:33:44:55".parse().unwrap())
        );
    }

    #[test]
    fn failed_entry_without_lladdr_is_none() {
        let out = "192.168.1.11 dev br-lan FAILED\n";
        assert_eq!(IpNeighResolver::parse_neigh_output(out, ip("192.168.1.11")), None);
    }

    #[test]
    fn unknown_ip_is_none() {
        let out = "192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE\n";
        assert_eq!(IpNeighResolver::parse_neigh_output(out, ip("8.8.8.8")), None);
    }

    #[test]
    fn parser_is_total_on_garbage() {
        // Empty, junk, partial, and malformed lladdr must all yield None, never
        // panic — kernel output is untrusted input.
        let want = ip("1.2.3.4");
        for junk in [
            "",
            "\n\n\n",
            "garbage with no structure",
            "1.2.3.4",                       // IP only, no fields
            "1.2.3.4 dev",                   // truncated
            "1.2.3.4 dev x lladdr",          // lladdr with no value
            "1.2.3.4 dev x lladdr not-a-mac",// bad mac
            "1.2.3.4 dev x lladdr zz:zz:zz:zz:zz:zz REACHABLE",
            "   1.2.3.4   dev  x   lladdr   ", // odd whitespace, dangling
            "not-an-ip dev x lladdr aa:bb:cc:dd:ee:ff",
        ] {
            assert_eq!(IpNeighResolver::parse_neigh_output(junk, want), None, "junk: {junk:?}");
        }
    }

    #[test]
    fn ipv6_neighbour_parses() {
        let out = "fe80::1 dev br-lan lladdr 00:11:22:33:44:55 REACHABLE\n";
        assert_eq!(
            IpNeighResolver::parse_neigh_output(out, ip("fe80::1")),
            Some("00:11:22:33:44:55".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn mock_resolver_roundtrips() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let r = MockNeighResolver::new().with(ip("192.168.1.10"), mac);
        assert_eq!(r.resolve(ip("192.168.1.10")).await.unwrap(), Some(mac));
        assert_eq!(r.resolve(ip("192.168.1.99")).await.unwrap(), None);
    }

    #[test]
    fn parse_neigh_table_collects_all_usable_entries() {
        let out = "\
10.0.0.1 dev eth0 lladdr 00:11:22:33:44:55 STALE
192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff DELAY
192.168.1.11 dev br-lan FAILED
192.168.1.12 dev br-lan lladdr zz:zz:zz:zz:zz:zz REACHABLE
fe80::1 dev br-lan lladdr 66:77:88:99:aa:bb REACHABLE
";
        let table: HashMap<IpAddr, MacAddr> = IpNeighResolver::parse_neigh_table(out).into_iter().collect();
        // Two IPv4 + one IPv6 usable entry; FAILED (no lladdr) and the garbage
        // MAC line are dropped.
        assert_eq!(table.len(), 3);
        assert_eq!(table.get(&ip("10.0.0.1")), Some(&"00:11:22:33:44:55".parse().unwrap()));
        assert_eq!(table.get(&ip("192.168.1.10")), Some(&"aa:bb:cc:dd:ee:ff".parse().unwrap()));
        assert_eq!(table.get(&ip("fe80::1")), Some(&"66:77:88:99:aa:bb".parse().unwrap()));
        assert!(!table.contains_key(&ip("192.168.1.11")));
        assert!(!table.contains_key(&ip("192.168.1.12")));
    }

    #[test]
    fn parse_neigh_table_agrees_with_single_lookup() {
        // The batch parser and the single-IP parser must never disagree on a MAC.
        let out = "192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE\n";
        let table: HashMap<IpAddr, MacAddr> = IpNeighResolver::parse_neigh_table(out).into_iter().collect();
        assert_eq!(
            table.get(&ip("192.168.1.10")).copied(),
            IpNeighResolver::parse_neigh_output(out, ip("192.168.1.10")),
        );
    }

    #[tokio::test]
    async fn default_resolve_many_batches_over_resolve_and_omits_misses() {
        // MockNeighResolver only implements `resolve`; the default `resolve_many`
        // should fan out over it, returning only the resolvable IPs (misses are
        // omitted, never fabricated).
        let mac10: MacAddr = "aa:bb:cc:00:00:10".parse().unwrap();
        let mac20: MacAddr = "aa:bb:cc:00:00:20".parse().unwrap();
        let r = MockNeighResolver::new()
            .with(ip("192.168.1.10"), mac10)
            .with(ip("192.168.1.20"), mac20);

        let got: HashMap<IpAddr, MacAddr> = r
            .resolve_many(&[ip("192.168.1.10"), ip("192.168.1.20"), ip("10.9.9.9")])
            .await
            .unwrap()
            .into_iter()
            .collect();

        assert_eq!(got.len(), 2, "the unknown IP must be omitted, not fabricated");
        assert_eq!(got.get(&ip("192.168.1.10")), Some(&mac10));
        assert_eq!(got.get(&ip("192.168.1.20")), Some(&mac20));
    }
}
