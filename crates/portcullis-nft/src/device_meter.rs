//! Per-device byte metering via **nft named counters** (P3 device telemetry).
//!
//! ## Why nft named counters (not conntrack)
//! Device SSIDs pin each appliance to a **static IP** via a DHCP reservation
//! (vending / smart-POS / camera / NVR). That static IP is the perfect meter key:
//! two named counters per device IP — one matching `ip saddr <ip>` (bytes FROM
//! the device = upload) and one matching `ip daddr <ip>` (bytes TO the device =
//! download) — give a cheap, cumulative, per-device byte total that survives
//! association flaps (the counter lives in the kernel, not tied to a flow).
//!
//! conntrack is deliberately NOT used here: `conntrack-tools` is absent on the
//! RUT906 target, and the static-IP reservation makes per-IP nft counters both
//! sufficient and lighter than walking the conntrack table.
//!
//! ## Where the counters live
//! In the engine-owned `inet wifihub` table (the ONLY table the engine touches),
//! in a dedicated **device-metering chain** [`CHAIN_DEVICE_METER`]. The chain is
//! a `type filter hook forward` chain at a priority just AFTER the gating
//! `forward` chain, so it observes the same forwarded traffic. Its policy is
//! `accept` and every rule is a pure `counter` with NO verdict — it only meters,
//! it never drops or accepts terminally, so it can never affect enforcement (the
//! §7.1 invariant: only `drop` in a base chain is globally terminal; a bare
//! `counter` rule falls through).
//!
//! ## Deterministic, safe counter names
//! A counter name is derived from the IP by [`counter_name`]: dots → underscores,
//! prefixed `pc_dev_ul_` / `pc_dev_dl_`. So `10.40.0.11` →
//! `pc_dev_ul_10_40_0_11` / `pc_dev_dl_10_40_0_11`. Deterministic (so a re-poll
//! finds the same counters) and character-safe for nft identifiers.
//!
//! ## Lifecycle (reconcile, not event-plumb)
//! [`build_reconcile_doc`] renders an idempotent `nft -j` document that, for the
//! given set of device IPs, (re)creates the chain, **FLUSHES the chain's rules**,
//! then re-adds exactly one counter+rule pair per current IP. Callers apply it
//! every poll from the CURRENT reservation set, so the chain always holds exactly
//! two rules per current reservation — no duplicates, no unbounded growth.
//!
//! ### Why flush-then-readd (the idempotency crux)
//! `add rule` in nft is an APPEND, not create-if-missing (unlike `add counter` /
//! `add chain`). Re-applying the reconcile doc every ~30 s poll without flushing
//! therefore appended two more rules per IP each tick — an unbounded rule leak in
//! the `device_meter` chain, deadly on the RUT906's tight RAM. The fix flushes the
//! chain's rules first, in the SAME atomic `nft -j -f -` document, then re-adds
//! them; `nft` applies the doc as one transaction so there is no window with the
//! chain empty (and a failure rolls the whole doc back).
//!
//! ### Why byte totals survive the flush (named counter OBJECTS)
//! The bytes are held in named **counter objects** (`add counter <name>` creates a
//! standalone object; each rule merely REFERENCES it by name via
//! `counter { name: … }`). Flushing a chain removes its RULES, never the counter
//! objects — so the cumulative `packets`/`bytes` on each `pc_dev_ul_*`/`pc_dev_dl_*`
//! counter persist untouched across every reconcile. (Had the counters been inline
//! per-rule instead of named objects, a chain flush would zero them; that is
//! exactly why this design uses named objects, and why [`build_reconcile_doc`]
//! re-adds the counter objects with `add counter` — create-if-missing, so the
//! existing object with its accumulated total is kept, not reset.)
//!
//! Removal of a stale IP's counters is handled by [`build_prune_doc`] (delete the
//! counter objects no longer backed by a reservation).
//!
//! ## Reading
//! [`parse_counters`] parses `nft -j list counters table inet wifihub` output into
//! a `name -> bytes` map; [`bytes_for_ip`] pulls the up/down totals for one IP.
//! All parsers are pure + fail-soft (unparseable ⇒ empty / zero), unit-tested on
//! the host; the shell-out that produces the JSON only runs on-device.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::ruleset::{TABLE_FAMILY, TABLE_NAME};

/// The dedicated device-metering chain (owned, inside `inet wifihub`).
pub const CHAIN_DEVICE_METER: &str = "device_meter";

/// Hook-priority offset for the metering chain: `filter - 45`, i.e. just AFTER
/// the gating `forward` chain (`filter - 50`) so it sees the same forwarded
/// packets but never precedes the gate. It only counts (no verdict), so ordering
/// is not load-bearing — this keeps it adjacent to the forward chain for clarity.
const PRIO_METER_OFFSET: i64 = -45;

/// Counter-name prefixes (upload = from device, download = to device).
const UL_PREFIX: &str = "pc_dev_ul_";
const DL_PREFIX: &str = "pc_dev_dl_";

/// Sanitize an IP into an nft-identifier-safe token: dots and colons → `_`.
/// (IPv4 `10.40.0.11` → `10_40_0_11`; an IPv6 literal's colons map the same
/// way.) Any other non-alphanumeric char is also mapped to `_` defensively.
fn sanitize_ip(ip: &str) -> String {
    ip.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Deterministic upload/download counter names for a device IP. Returns
/// `(upload_name, download_name)`.
pub fn counter_name(ip: &str) -> (String, String) {
    let t = sanitize_ip(ip);
    (format!("{UL_PREFIX}{t}"), format!("{DL_PREFIX}{t}"))
}

/// `add counter` command object for a named counter in the owned table.
fn add_counter(name: &str) -> Value {
    json!({ "add": { "counter": {
        "family": TABLE_FAMILY,
        "table": TABLE_NAME,
        "name": name,
    }}})
}

/// `add chain` for the device-metering chain (create-if-missing, policy accept).
fn add_meter_chain() -> Value {
    json!({ "add": { "chain": {
        "family": TABLE_FAMILY,
        "table": TABLE_NAME,
        "name": CHAIN_DEVICE_METER,
        "type": "filter",
        "hook": "forward",
        "prio": { "base": "filter", "offset": PRIO_METER_OFFSET },
        "policy": "accept",
    }}})
}

/// `flush chain` for the device-metering chain: removes all RULES in the chain,
/// leaving the chain itself and every named counter OBJECT intact. Applied right
/// after [`add_meter_chain`] (which guarantees the chain exists so the flush can
/// never target a missing chain) and before the per-IP rules are re-added, so a
/// re-applied reconcile doc yields exactly the current rule set — no accumulation.
/// Counter byte totals persist because they live in the objects, not the rules.
fn flush_meter_chain() -> Value {
    json!({ "flush": { "chain": {
        "family": TABLE_FAMILY,
        "table": TABLE_NAME,
        "name": CHAIN_DEVICE_METER,
    }}})
}

/// A rule `ip <dir> <ip> counter name "<name>"` (a pure meter — no verdict).
fn meter_rule(field: &str, ip: &str, counter: &str) -> Value {
    json!({ "add": { "rule": {
        "family": TABLE_FAMILY,
        "table": TABLE_NAME,
        "chain": CHAIN_DEVICE_METER,
        "expr": [
            { "match": {
                "op": "==",
                "left": { "payload": { "protocol": "ip", "field": field } },
                "right": ip,
            }},
            { "counter": { "name": counter } },
        ],
    }}})
}

/// Build the idempotent `nft -j` reconcile document for a set of device IPs.
///
/// Emits, as ONE atomic transaction:
///   1. `add chain` — create the metering chain if missing (create-if-missing).
///   2. `flush chain` — clear the chain's RULES (the counter objects survive).
///   3. per IP: `add counter` (×2, create-if-missing — keeps the existing object
///      and its accumulated total) + `add rule` (×2, `saddr→upload`,
///      `daddr→download`).
///
/// Because `add rule` APPENDS (it is not create-if-missing), the step-2 flush is
/// what makes re-applying every poll idempotent: the chain always ends up holding
/// exactly two rules per current IP, never a tick's worth more. Byte totals are
/// unaffected — they live in the named counter OBJECTS, and flushing a chain
/// removes rules, not objects (see the module docs). Returns `{"nftables":[…]}` —
/// the exact shape `nft -j -f -` consumes. An empty IP set still (re)asserts +
/// flushes the chain so the table shape is stable and any stale rules are cleared.
pub fn build_reconcile_doc(device_ips: &[String]) -> Value {
    // Order matters within the atomic doc: `add chain` first so `flush chain`
    // always has a target (idempotent on a fresh boot AND on every re-poll), then
    // flush the rules, then re-add exactly the current IP set's counters + rules.
    let mut cmds: Vec<Value> = vec![add_meter_chain(), flush_meter_chain()];
    for ip in device_ips {
        let ip = ip.trim();
        if ip.is_empty() {
            continue;
        }
        let (ul, dl) = counter_name(ip);
        cmds.push(add_counter(&ul));
        cmds.push(add_counter(&dl));
        cmds.push(meter_rule("saddr", ip, &ul));
        cmds.push(meter_rule("daddr", ip, &dl));
    }
    json!({ "nftables": cmds })
}

/// Build a `nft -j` document that DELETES the named counters for IPs no longer
/// backed by a reservation. `stale_ips` is the set to remove; each yields a
/// `delete counter` for both its upload and download names. Returns `None` when
/// there is nothing to prune (so the caller can skip the shell-out entirely).
///
/// Deleting a counter also detaches it from any rule referencing it on the next
/// chain flush; for the observe path we simply stop reading a pruned name.
pub fn build_prune_doc(stale_ips: &[String]) -> Option<Value> {
    let mut cmds: Vec<Value> = Vec::new();
    for ip in stale_ips {
        let ip = ip.trim();
        if ip.is_empty() {
            continue;
        }
        let (ul, dl) = counter_name(ip);
        cmds.push(del_counter(&ul));
        cmds.push(del_counter(&dl));
    }
    if cmds.is_empty() {
        None
    } else {
        Some(json!({ "nftables": cmds }))
    }
}

fn del_counter(name: &str) -> Value {
    json!({ "delete": { "counter": {
        "family": TABLE_FAMILY,
        "table": TABLE_NAME,
        "name": name,
    }}})
}

/// Parse `nft -j list counters table inet wifihub` into a `name -> bytes` map.
///
/// The `nft -j` schema is `{ "nftables": [ { "counter": { "family":"inet",
/// "table":"wifihub", "name":"pc_dev_ul_10_40_0_11", "packets":N, "bytes":M } },
/// … ] }`. Only counters in the owned `inet wifihub` table are kept. Fail-soft:
/// an unparseable / unexpected payload yields an empty map.
pub fn parse_counters(json_str: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let v: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return out,
    };
    let Some(items) = v.get("nftables").and_then(Value::as_array) else {
        return out;
    };
    for item in items {
        let Some(c) = item.get("counter") else { continue };
        // Only our owned table's counters.
        if c.get("family").and_then(Value::as_str) != Some(TABLE_FAMILY)
            || c.get("table").and_then(Value::as_str) != Some(TABLE_NAME)
        {
            continue;
        }
        let Some(name) = c.get("name").and_then(Value::as_str) else { continue };
        let bytes = c.get("bytes").and_then(Value::as_u64).unwrap_or(0);
        out.insert(name.to_string(), bytes);
    }
    out
}

/// Pull `(rx_bytes, tx_bytes)` for one device IP from a parsed counter map.
/// `rx` = upload (bytes FROM the device, `ip saddr`), `tx` = download (bytes TO
/// the device, `ip daddr`) — matching the [`crate`]-level and proto semantics. A
/// missing counter reads as `0` (device seen but no traffic yet, or counters not
/// yet created).
pub fn bytes_for_ip(counters: &BTreeMap<String, u64>, ip: &str) -> (u64, u64) {
    let (ul, dl) = counter_name(ip);
    let rx = counters.get(&ul).copied().unwrap_or(0);
    let tx = counters.get(&dl).copied().unwrap_or(0);
    (rx, tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_name_is_deterministic_and_sanitized() {
        let (ul, dl) = counter_name("10.40.0.11");
        assert_eq!(ul, "pc_dev_ul_10_40_0_11");
        assert_eq!(dl, "pc_dev_dl_10_40_0_11");
        // Deterministic: same IP -> same names.
        assert_eq!(counter_name("10.40.0.11"), (ul, dl));
        // No dots survive (nft-identifier-safe).
        assert!(!counter_name("192.168.1.50").0.contains('.'));
    }

    #[test]
    fn counter_name_sanitizes_ipv6_colons() {
        let (ul, _dl) = counter_name("fd00::5");
        assert!(!ul.contains(':'));
        assert_eq!(ul, "pc_dev_ul_fd00__5");
    }

    fn cmds(v: &Value) -> &Vec<Value> {
        v.get("nftables").unwrap().as_array().unwrap()
    }

    /// Count the `flush chain` commands targeting the metering chain.
    fn flush_chain_count(doc: &Value) -> usize {
        cmds(doc)
            .iter()
            .filter(|c| {
                c.get("flush")
                    .and_then(|f| f.get("chain"))
                    .and_then(|ch| ch.get("name"))
                    .and_then(Value::as_str)
                    == Some(CHAIN_DEVICE_METER)
            })
            .count()
    }

    #[test]
    fn reconcile_doc_creates_chain_and_counter_pair_per_ip() {
        let doc = build_reconcile_doc(&["10.40.0.11".into(), "10.40.0.12".into()]);
        let s = serde_json::to_string(&doc).unwrap();
        // Chain created inside the OWNED table only.
        assert!(s.contains("device_meter"));
        assert!(s.contains("\"table\":\"wifihub\""));
        // Two counters + two rules per IP, plus the chain.
        let counters = cmds(&doc)
            .iter()
            .filter(|c| c.get("add").and_then(|a| a.get("counter")).is_some())
            .count();
        assert_eq!(counters, 4, "2 counters per IP");
        let rules = cmds(&doc)
            .iter()
            .filter(|c| c.get("add").and_then(|a| a.get("rule")).is_some())
            .count();
        assert_eq!(rules, 4, "2 rules per IP");
        // Both directions present for the first IP.
        assert!(s.contains("pc_dev_ul_10_40_0_11"));
        assert!(s.contains("pc_dev_dl_10_40_0_11"));
        // The rules match saddr (upload) and daddr (download), and NEVER carry a
        // drop/accept verdict — pure meters (§7.1: a bare counter falls through).
        assert!(s.contains("\"field\":\"saddr\""));
        assert!(s.contains("\"field\":\"daddr\""));
        assert!(!s.contains("\"drop\""));
    }

    #[test]
    fn reconcile_doc_flushes_chain_before_readding_rules() {
        // The idempotency crux: the doc must FLUSH the chain's rules before
        // re-adding them, so a re-poll cannot accumulate rules. The flush must
        // come AFTER the `add chain` (so it always has a target) and BEFORE any
        // `add rule` (so nothing already-added is thrown away).
        let doc = build_reconcile_doc(&["10.40.0.11".into()]);
        let list = cmds(&doc);
        assert_eq!(flush_chain_count(&doc), 1, "exactly one flush chain");

        let add_chain_idx = list
            .iter()
            .position(|c| c.get("add").and_then(|a| a.get("chain")).is_some())
            .expect("add chain present");
        let flush_idx = list
            .iter()
            .position(|c| c.get("flush").and_then(|f| f.get("chain")).is_some())
            .expect("flush chain present");
        let first_rule_idx = list
            .iter()
            .position(|c| c.get("add").and_then(|a| a.get("rule")).is_some())
            .expect("at least one rule");
        assert!(add_chain_idx < flush_idx, "flush must follow add-chain (target exists)");
        assert!(flush_idx < first_rule_idx, "flush must precede the re-added rules");
    }

    #[test]
    fn reconcile_doc_is_idempotent_no_rule_growth_when_applied_twice() {
        // Re-deriving the doc for the SAME reservation set yields the SAME command
        // count — the flush means a second (third, …) poll never grows the doc, so
        // the chain never accumulates duplicate rules. (The doc IS the transaction
        // applied each poll; identical docs ⇒ identical resulting chain.)
        let ips = vec!["10.40.0.11".to_string(), "10.40.0.12".to_string()];
        let doc1 = build_reconcile_doc(&ips);
        let doc2 = build_reconcile_doc(&ips);
        assert_eq!(doc1, doc2, "same reservation set ⇒ byte-identical reconcile doc");

        let rules = |d: &Value| {
            cmds(d)
                .iter()
                .filter(|c| c.get("add").and_then(|a| a.get("rule")).is_some())
                .count()
        };
        assert_eq!(rules(&doc1), 4);
        assert_eq!(rules(&doc2), 4, "second apply carries the SAME 4 rules, not 8");
        // And every apply flushes exactly once before re-adding.
        assert_eq!(flush_chain_count(&doc1), 1);
        assert_eq!(flush_chain_count(&doc2), 1);
    }

    #[test]
    fn reconcile_doc_re_adds_named_counters_so_totals_survive_flush() {
        // Byte totals persist across a reconcile because they live in named
        // counter OBJECTS, which the chain flush does NOT remove. Two guarantees:
        //  (a) the doc flushes the chain's RULES (not the counters) — asserted by
        //      the flush targeting a CHAIN, never a counter; and
        //  (b) the counters are re-asserted with `add counter` (create-if-missing:
        //      keeps the existing object + its accumulated total, never resets it).
        let doc = build_reconcile_doc(&["10.40.0.11".into()]);
        // (a) The only flush is a chain flush — no counter is ever flushed/reset.
        assert_eq!(flush_chain_count(&doc), 1);
        assert!(
            !cmds(&doc).iter().any(|c| c.get("flush").and_then(|f| f.get("counter")).is_some()),
            "must NOT flush any counter object (would zero its total)"
        );
        // (b) Counters are re-asserted by NAME via `add counter` (idempotent).
        let counter_adds: Vec<&str> = cmds(&doc)
            .iter()
            .filter_map(|c| {
                c.get("add")
                    .and_then(|a| a.get("counter"))
                    .and_then(|ct| ct.get("name"))
                    .and_then(Value::as_str)
            })
            .collect();
        assert_eq!(counter_adds, vec!["pc_dev_ul_10_40_0_11", "pc_dev_dl_10_40_0_11"]);
        // The rules reference the counters BY NAME (not an inline per-rule counter
        // that a flush would zero) — so `parse_counters` reads persistent totals.
        let s = serde_json::to_string(&doc).unwrap();
        assert!(s.contains("\"counter\":{\"name\":\"pc_dev_ul_10_40_0_11\"}"));
    }

    #[test]
    fn reconcile_doc_skips_blank_ips_but_keeps_chain_and_flush() {
        let doc = build_reconcile_doc(&["".into(), "   ".into()]);
        // Only the chain + its flush, no counters/rules — the empty set still
        // clears any rules a previous non-empty set left behind.
        assert_eq!(cmds(&doc).len(), 2);
        assert!(cmds(&doc)[0].get("add").and_then(|a| a.get("chain")).is_some());
        assert!(cmds(&doc)[1].get("flush").and_then(|f| f.get("chain")).is_some());
    }

    #[test]
    fn prune_doc_deletes_both_counters_or_none() {
        let doc = build_prune_doc(&["10.40.0.11".into()]).expect("something to prune");
        let s = serde_json::to_string(&doc).unwrap();
        let dels = cmds(&doc)
            .iter()
            .filter(|c| c.get("delete").and_then(|d| d.get("counter")).is_some())
            .count();
        assert_eq!(dels, 2, "delete both upload and download counters");
        assert!(s.contains("pc_dev_ul_10_40_0_11"));
        assert!(s.contains("pc_dev_dl_10_40_0_11"));
        // Nothing to prune -> None (caller skips the shell-out).
        assert!(build_prune_doc(&[]).is_none());
        assert!(build_prune_doc(&["".into()]).is_none());
    }

    #[test]
    fn parse_counters_reads_owned_table_only() {
        let json = r#"{ "nftables": [
            { "counter": { "family":"inet", "table":"wifihub", "name":"pc_dev_ul_10_40_0_11", "packets":10, "bytes":1500 } },
            { "counter": { "family":"inet", "table":"wifihub", "name":"pc_dev_dl_10_40_0_11", "packets":20, "bytes":9000 } },
            { "counter": { "family":"inet", "table":"other",   "name":"foreign", "bytes":999 } },
            { "rule": { "family":"inet", "table":"wifihub", "chain":"device_meter" } }
        ] }"#;
        let m = parse_counters(json);
        assert_eq!(m.len(), 2, "foreign-table counter + non-counter items ignored");
        assert_eq!(m.get("pc_dev_ul_10_40_0_11"), Some(&1500));
        assert_eq!(m.get("pc_dev_dl_10_40_0_11"), Some(&9000));
    }

    #[test]
    fn parse_counters_fail_soft() {
        assert!(parse_counters("not json").is_empty());
        assert!(parse_counters("{}").is_empty());
        assert!(parse_counters(r#"{"nftables":[]}"#).is_empty());
    }

    #[test]
    fn bytes_for_ip_maps_rx_upload_tx_download() {
        let mut m = BTreeMap::new();
        m.insert("pc_dev_ul_10_40_0_11".to_string(), 1500u64);
        m.insert("pc_dev_dl_10_40_0_11".to_string(), 9000u64);
        // rx = upload (saddr), tx = download (daddr).
        assert_eq!(bytes_for_ip(&m, "10.40.0.11"), (1500, 9000));
        // Missing IP -> zeros (device seen, no traffic yet).
        assert_eq!(bytes_for_ip(&m, "10.40.0.99"), (0, 0));
    }
}
