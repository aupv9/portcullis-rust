//! Production [`FirewallBackend`] driving `nft -j` (JSON) via `tokio::process`.
//!
//! Per TDD §5.5 the backend is `nft -j`: pure userspace, easiest MIPS
//! cross-compile, fork/exec per batch is fine at per-store churn. This module
//! compiles on any host (it only spawns a child process); it will only *run*
//! on a box that has the `nft` binary (i.e. Linux with nftables). On this
//! aarch64-apple-darwin CI host the binary is absent, so the runtime calls are
//! not exercised by unit tests — those use [`crate::backend::MockBackend`].
//!
//! No fail-open: every non-zero exit / parse failure becomes an `Err`.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use portcullis_types::{AuthElement, Error, MacAddr, Result};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::backend::FirewallBackend;
use crate::ruleset::{build_base_ruleset, SET_AUTH, TABLE_FAMILY, TABLE_NAME};

/// Backend that builds `nft -j` JSON and invokes the `nft` binary.
pub struct NftJsonBackend {
    /// Path to the `nft` binary (default `"nft"`, resolved via `PATH`).
    nft_bin: String,
}

impl Default for NftJsonBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NftJsonBackend {
    pub fn new() -> Self {
        Self {
            nft_bin: "nft".to_string(),
        }
    }

    /// Override the `nft` binary path (tests / non-standard installs).
    pub fn with_binary(nft_bin: impl Into<String>) -> Self {
        Self {
            nft_bin: nft_bin.into(),
        }
    }

    /// Feed a `nft -j` JSON command document to `nft -j -f -` on stdin and
    /// apply it as one atomic batch. Maps any failure to `Error::NftTransaction`.
    async fn apply_json(&self, doc: &Value) -> Result<()> {
        let payload = serde_json::to_vec(doc)
            .map_err(|e| Error::NftTransaction(format!("serialize: {e}")))?;

        tracing::debug!(
            target: "portcullis_nft",
            doc = %doc,
            "applying nft -j batch"
        );

        let mut child = Command::new(&self.nft_bin)
            .arg("-j")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::NftTransaction(format!("spawn {}: {e}", self.nft_bin)))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::NftTransaction("child stdin unavailable".into()))?;
            stdin
                .write_all(&payload)
                .await
                .map_err(|e| Error::NftTransaction(format!("write stdin: {e}")))?;
            stdin
                .shutdown()
                .await
                .map_err(|e| Error::NftTransaction(format!("close stdin: {e}")))?;
        }

        let out = child
            .wait_with_output()
            .await
            .map_err(|e| Error::NftTransaction(format!("wait: {e}")))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::NftTransaction(format!(
                "nft exited {:?}: {}",
                out.status.code(),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Run `nft -j list set inet wifihub auth` and return parsed stdout JSON.
    async fn list_set_json(&self, set: &str) -> Result<Value> {
        let out = Command::new(&self.nft_bin)
            .arg("-j")
            .arg("list")
            .arg("set")
            .arg(TABLE_FAMILY)
            .arg(TABLE_NAME)
            .arg(set)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::NftTransaction(format!("spawn {}: {e}", self.nft_bin)))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::NftTransaction(format!(
                "nft list set exited {:?}: {}",
                out.status.code(),
                stderr.trim()
            )));
        }

        serde_json::from_slice(&out.stdout)
            .map_err(|e| Error::NftTransaction(format!("parse list output: {e}")))
    }

    /// Build the `add element` JSON for a single MAC with a timeout (seconds).
    fn add_element_doc(mac: MacAddr, ttl: Duration) -> Value {
        serde_json::json!({
            "nftables": [
                {
                    "add": {
                        "element": {
                            "family": TABLE_FAMILY,
                            "table": TABLE_NAME,
                            "name": SET_AUTH,
                            "elem": [
                                {
                                    "elem": {
                                        "val": mac.to_canonical(),
                                        "timeout": ttl.as_secs()
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        })
    }

    /// Build the `delete element` JSON for a single MAC.
    fn del_element_doc(mac: MacAddr) -> Value {
        serde_json::json!({
            "nftables": [
                {
                    "delete": {
                        "element": {
                            "family": TABLE_FAMILY,
                            "table": TABLE_NAME,
                            "name": SET_AUTH,
                            "elem": [ mac.to_canonical() ]
                        }
                    }
                }
            ]
        })
    }
}

#[async_trait]
impl FirewallBackend for NftJsonBackend {
    async fn ensure_base(&self) -> Result<()> {
        self.apply_json(&build_base_ruleset()).await
    }

    async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()> {
        self.apply_json(&Self::add_element_doc(mac, ttl)).await
    }

    async fn del_auth(&self, mac: MacAddr) -> Result<()> {
        self.apply_json(&Self::del_element_doc(mac)).await
    }

    async fn list_auth(&self) -> Result<Vec<AuthElement>> {
        let doc = self.list_set_json(SET_AUTH).await?;
        parse_auth_set(&doc)
    }
}

/// Parse the JSON produced by `nft -j list set inet wifihub auth` into
/// [`AuthElement`]s. Strict and bounded: only well-formed elements with a
/// parseable MAC are returned; malformed entries are skipped (logged), never
/// panicked on.
///
/// The relevant shape is:
/// ```json
/// { "nftables": [ { "metainfo": ... },
///   { "set": { "name": "auth", "elem": [
///       { "elem": { "val": "aa:bb:cc:dd:ee:ff", "expires": 1700, "timeout": 1800 } },
///       "aa:bb:cc:dd:ee:00"
///   ] } } ] }
/// ```
/// `expires` is the remaining seconds (kernel countdown); when absent we fall
/// back to `timeout`; absent both -> zero remaining.
pub fn parse_auth_set(doc: &Value) -> Result<Vec<AuthElement>> {
    let arr = doc
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::NftTransaction("list output missing nftables array".into()))?;

    let mut out = Vec::new();

    for item in arr {
        let Some(set) = item.get("set") else { continue };
        // Only the auth set (defensive — we asked for it specifically).
        if set.get("name").and_then(Value::as_str) != Some(SET_AUTH) {
            continue;
        }
        let Some(elems) = set.get("elem").and_then(Value::as_array) else {
            continue;
        };
        // Bound: a per-store set is tiny; refuse absurd lists rather than OOM.
        if elems.len() > 100_000 {
            return Err(Error::NftTransaction(format!(
                "auth set too large to parse: {} elements",
                elems.len()
            )));
        }
        for e in elems {
            if let Some(parsed) = parse_one_elem(e) {
                out.push(parsed);
            } else {
                tracing::warn!(target: "portcullis_nft", elem = %e, "skipping malformed auth element");
            }
        }
    }

    Ok(out)
}

/// Parse a single `elem` entry, which is either a bare string (the value) or an
/// object `{ "elem": { "val": ..., "expires"/"timeout": ... } }`.
fn parse_one_elem(e: &Value) -> Option<AuthElement> {
    // Bare string form: a value with no timeout info -> zero remaining.
    if let Some(s) = e.as_str() {
        let mac = s.parse::<MacAddr>().ok()?;
        return Some(AuthElement {
            mac,
            remaining: Duration::ZERO,
        });
    }

    let inner = e.get("elem")?;
    let val = inner.get("val").and_then(Value::as_str)?;
    let mac = val.parse::<MacAddr>().ok()?;

    // Prefer `expires` (remaining countdown); fall back to `timeout`.
    let remaining_secs = inner
        .get("expires")
        .and_then(Value::as_u64)
        .or_else(|| inner.get("timeout").and_then(Value::as_u64))
        .unwrap_or(0);

    Some(AuthElement {
        mac,
        remaining: Duration::from_secs(remaining_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_element_doc_has_mac_and_timeout_seconds() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let doc = NftJsonBackend::add_element_doc(mac, Duration::from_secs(1800));
        let elem = &doc["nftables"][0]["add"]["element"];
        assert_eq!(elem["family"], "inet");
        assert_eq!(elem["table"], "wifihub");
        assert_eq!(elem["name"], "auth");
        let inner = &elem["elem"][0]["elem"];
        assert_eq!(inner["val"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(inner["timeout"], 1800);
    }

    #[test]
    fn del_element_doc_targets_auth_by_mac() {
        let mac: MacAddr = "01:02:03:04:05:06".parse().unwrap();
        let doc = NftJsonBackend::del_element_doc(mac);
        let elem = &doc["nftables"][0]["delete"]["element"];
        assert_eq!(elem["name"], "auth");
        assert_eq!(elem["elem"][0], "01:02:03:04:05:06");
    }

    #[test]
    fn parse_auth_set_reads_expires_then_timeout() {
        let doc = serde_json::json!({
            "nftables": [
                { "metainfo": { "version": "1.0" } },
                {
                    "set": {
                        "family": "inet",
                        "table": "wifihub",
                        "name": "auth",
                        "type": "ether_addr",
                        "elem": [
                            { "elem": { "val": "aa:bb:cc:dd:ee:ff", "expires": 1700, "timeout": 1800 } },
                            { "elem": { "val": "11:22:33:44:55:66", "timeout": 900 } }
                        ]
                    }
                }
            ]
        });
        let mut got = parse_auth_set(&doc).unwrap();
        got.sort_by_key(|e| e.mac.octets());
        assert_eq!(got.len(), 2);

        let first: MacAddr = "11:22:33:44:55:66".parse().unwrap();
        let second: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(got[0].mac, first);
        assert_eq!(got[0].remaining, Duration::from_secs(900)); // timeout fallback
        assert_eq!(got[1].mac, second);
        assert_eq!(got[1].remaining, Duration::from_secs(1700)); // expires preferred
    }

    #[test]
    fn parse_auth_set_handles_bare_string_and_skips_garbage() {
        let doc = serde_json::json!({
            "nftables": [
                {
                    "set": {
                        "name": "auth",
                        "elem": [
                            "de:ad:be:ef:00:01",
                            { "elem": { "val": "not-a-mac", "expires": 5 } },
                            { "elem": { "expires": 5 } }
                        ]
                    }
                }
            ]
        });
        let got = parse_auth_set(&doc).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].remaining, Duration::ZERO);
    }

    #[test]
    fn parse_auth_set_errors_on_missing_root() {
        let doc = serde_json::json!({ "something_else": [] });
        assert!(parse_auth_set(&doc).is_err());
    }

    #[test]
    fn parse_auth_set_empty_when_no_auth_set_present() {
        let doc = serde_json::json!({ "nftables": [ { "set": { "name": "garden4", "elem": [] } } ] });
        let got = parse_auth_set(&doc).unwrap();
        assert!(got.is_empty());
    }
}
