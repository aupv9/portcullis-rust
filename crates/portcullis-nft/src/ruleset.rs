//! Builder for the base `table inet wifihub` ruleset (TDD §7.1).
//!
//! Produces the `nft -j` JSON command array (a `serde_json::Value` whose
//! `nftables` key holds the ordered list of `add`/`table`/`chain`/`set`/`rule`
//! commands) plus an equivalent human-readable nft script for logging.
//!
//! Invariants baked in here (see nft-ruleset SKILL):
//! - exactly one table, `inet wifihub`; we never flush or touch other tables;
//! - sets `garden4`(ipv4_addr,interval), `garden6`(ipv6_addr,interval),
//!   `auth`(ether_addr,timeout);
//! - `prerouting` is `type nat hook prerouting priority dstnat - 50` and ends
//!   with `tcp dport 80 redirect to :8080`;
//! - `forward` is `type filter hook forward priority filter - 50` and ends with
//!   a terminal `drop` (the only globally-terminal verdict, §7.1 subtlety 1);
//! - NO postrouting / masquerade — fw3 already NATs the WAN.

use serde_json::{json, Value};

/// The single table family the engine owns.
pub const TABLE_FAMILY: &str = "inet";
/// The single table the engine owns.
pub const TABLE_NAME: &str = "wifihub";

/// Set names.
pub const SET_GARDEN4: &str = "garden4";
pub const SET_GARDEN6: &str = "garden6";
pub const SET_AUTH: &str = "auth";

/// Chain names.
pub const CHAIN_PREROUTING: &str = "prerouting";
pub const CHAIN_FORWARD: &str = "forward";

/// The local redirect responder port (§7.2).
pub const REDIRECT_PORT: u16 = 8080;

/// Hook-priority offset placing our chains *before* fw3's equivalent hooks
/// (§7.1 subtlety 2). These are starting points; verified on-device (§18).
const PRIO_DSTNAT_OFFSET: i64 = -50;
const PRIO_FILTER_OFFSET: i64 = -50;

fn add(obj: Value) -> Value {
    json!({ "add": obj })
}

fn set_obj(name: &str, set_type: &str, flag: &str) -> Value {
    json!({
        "set": {
            "family": TABLE_FAMILY,
            "table": TABLE_NAME,
            "name": name,
            "type": set_type,
            "flags": [flag],
        }
    })
}

fn chain_obj(name: &str, hook: &str, prio: Value, chain_type: &str) -> Value {
    json!({
        "chain": {
            "family": TABLE_FAMILY,
            "table": TABLE_NAME,
            "name": name,
            "type": chain_type,
            "hook": hook,
            "prio": prio,
            "policy": "accept",
        }
    })
}

/// A rule object for the given chain carrying `expr` (an array of statements).
fn rule_obj(chain: &str, expr: Value) -> Value {
    json!({
        "rule": {
            "family": TABLE_FAMILY,
            "table": TABLE_NAME,
            "chain": chain,
            "expr": expr,
        }
    })
}

/// `<l3field> <dir> @<set> accept` (e.g. `ip daddr @garden4 accept`).
fn match_set_accept(proto: &str, field: &str, set_name: &str) -> Value {
    json!([
        {
            "match": {
                "op": "==",
                "left": { "payload": { "protocol": proto, "field": field } },
                "right": format!("@{set_name}")
            }
        },
        { "accept": null }
    ])
}

/// `ct state established,related accept`.
fn ct_established_accept() -> Value {
    json!([
        {
            "match": {
                "op": "in",
                "left": { "ct": { "key": "state" } },
                "right": ["established", "related"]
            }
        },
        { "accept": null }
    ])
}

/// A single terminal verdict statement, e.g. `drop`.
fn verdict_only(verdict: &str) -> Value {
    json!([ { verdict: null } ])
}

/// Build the full base ruleset as the `nft -j` command array.
///
/// The returned value is `{"nftables": [ ... ]}` — the exact shape `nft -j -f -`
/// consumes on stdin. Order matters: table, then sets, then chains, then the
/// rules within each chain in evaluation order.
pub fn build_base_ruleset() -> Value {
    let prio_dstnat = json!({ "base": "dstnat", "offset": PRIO_DSTNAT_OFFSET });
    let prio_filter = json!({ "base": "filter", "offset": PRIO_FILTER_OFFSET });

    let mut cmds: Vec<Value> = Vec::new();

    // The table itself (create-if-missing; nft `add` is idempotent on table).
    cmds.push(add(json!({ "table": { "family": TABLE_FAMILY, "name": TABLE_NAME } })));

    // Sets.
    cmds.push(add(set_obj(SET_GARDEN4, "ipv4_addr", "interval")));
    cmds.push(add(set_obj(SET_GARDEN6, "ipv6_addr", "interval")));
    cmds.push(add(set_obj(SET_AUTH, "ether_addr", "timeout")));

    // Chains.
    cmds.push(add(chain_obj(CHAIN_PREROUTING, "prerouting", prio_dstnat, "nat")));
    cmds.push(add(chain_obj(CHAIN_FORWARD, "forward", prio_filter, "filter")));

    // prerouting rules, in order.
    cmds.push(add(rule_obj(
        CHAIN_PREROUTING,
        match_set_accept("ether", "saddr", SET_AUTH),
    )));
    cmds.push(add(rule_obj(
        CHAIN_PREROUTING,
        match_set_accept("ip", "daddr", SET_GARDEN4),
    )));
    cmds.push(add(rule_obj(
        CHAIN_PREROUTING,
        match_set_accept("ip6", "daddr", SET_GARDEN6),
    )));
    // tcp dport 80 redirect to :8080
    cmds.push(add(rule_obj(
        CHAIN_PREROUTING,
        json!([
            {
                "match": {
                    "op": "==",
                    "left": { "payload": { "protocol": "tcp", "field": "dport" } },
                    "right": 80
                }
            },
            { "redirect": { "port": REDIRECT_PORT } }
        ]),
    )));

    // forward rules, in order; terminal drop last.
    cmds.push(add(rule_obj(CHAIN_FORWARD, ct_established_accept())));
    cmds.push(add(rule_obj(
        CHAIN_FORWARD,
        match_set_accept("ether", "saddr", SET_AUTH),
    )));
    cmds.push(add(rule_obj(
        CHAIN_FORWARD,
        match_set_accept("ip", "daddr", SET_GARDEN4),
    )));
    cmds.push(add(rule_obj(
        CHAIN_FORWARD,
        match_set_accept("ip6", "daddr", SET_GARDEN6),
    )));
    cmds.push(add(rule_obj(CHAIN_FORWARD, verdict_only("drop"))));

    json!({ "nftables": cmds })
}

/// Build the equivalent human-readable nft script (for DEBUG logging only;
/// the JSON form is what is actually applied).
pub fn build_base_script() -> String {
    format!(
        "table {fam} {tbl} {{\n\
         \tset {g4} {{ type ipv4_addr; flags interval; }}\n\
         \tset {g6} {{ type ipv6_addr; flags interval; }}\n\
         \tset {auth} {{ type ether_addr; flags timeout; }}\n\
         \tchain {pre} {{\n\
         \t\ttype nat hook prerouting priority dstnat - 50; policy accept;\n\
         \t\tether saddr @{auth} accept\n\
         \t\tip daddr @{g4} accept\n\
         \t\tip6 daddr @{g6} accept\n\
         \t\ttcp dport 80 redirect to :{port}\n\
         \t}}\n\
         \tchain {fwd} {{\n\
         \t\ttype filter hook forward priority filter - 50; policy accept;\n\
         \t\tct state established,related accept\n\
         \t\tether saddr @{auth} accept\n\
         \t\tip daddr @{g4} accept\n\
         \t\tip6 daddr @{g6} accept\n\
         \t\tdrop\n\
         \t}}\n\
         }}\n",
        fam = TABLE_FAMILY,
        tbl = TABLE_NAME,
        g4 = SET_GARDEN4,
        g6 = SET_GARDEN6,
        auth = SET_AUTH,
        pre = CHAIN_PREROUTING,
        fwd = CHAIN_FORWARD,
        port = REDIRECT_PORT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(v: &Value) -> &Vec<Value> {
        v.get("nftables").unwrap().as_array().unwrap()
    }

    #[test]
    fn ruleset_has_single_inet_wifihub_table() {
        let rs = build_base_ruleset();
        let tables: Vec<&Value> = cmds(&rs)
            .iter()
            .filter_map(|c| c.get("add").and_then(|a| a.get("table")))
            .collect();
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0]["family"], "inet");
        assert_eq!(tables[0]["name"], "wifihub");
    }

    #[test]
    fn ruleset_has_all_three_sets_with_correct_types_and_flags() {
        let rs = build_base_ruleset();
        let sets: Vec<&Value> = cmds(&rs)
            .iter()
            .filter_map(|c| c.get("add").and_then(|a| a.get("set")))
            .collect();
        assert_eq!(sets.len(), 3);

        let find = |name: &str| sets.iter().find(|s| s["name"] == name).unwrap();
        let g4 = find("garden4");
        assert_eq!(g4["type"], "ipv4_addr");
        assert_eq!(g4["flags"], json!(["interval"]));
        let g6 = find("garden6");
        assert_eq!(g6["type"], "ipv6_addr");
        assert_eq!(g6["flags"], json!(["interval"]));
        let auth = find("auth");
        assert_eq!(auth["type"], "ether_addr");
        assert_eq!(auth["flags"], json!(["timeout"]));
    }

    #[test]
    fn ruleset_has_both_chains_with_right_hooks_and_priorities() {
        let rs = build_base_ruleset();
        let chains: Vec<&Value> = cmds(&rs)
            .iter()
            .filter_map(|c| c.get("add").and_then(|a| a.get("chain")))
            .collect();
        assert_eq!(chains.len(), 2);

        let pre = chains.iter().find(|c| c["name"] == "prerouting").unwrap();
        assert_eq!(pre["type"], "nat");
        assert_eq!(pre["hook"], "prerouting");
        assert_eq!(pre["prio"], json!({ "base": "dstnat", "offset": -50 }));
        assert_eq!(pre["policy"], "accept");

        let fwd = chains.iter().find(|c| c["name"] == "forward").unwrap();
        assert_eq!(fwd["type"], "filter");
        assert_eq!(fwd["hook"], "forward");
        assert_eq!(fwd["prio"], json!({ "base": "filter", "offset": -50 }));
        assert_eq!(fwd["policy"], "accept");
    }

    #[test]
    fn prerouting_redirects_tcp_80_to_8080() {
        let rs = build_base_ruleset();
        let redirect = cmds(&rs).iter().any(|c| {
            let Some(rule) = c.get("add").and_then(|a| a.get("rule")) else {
                return false;
            };
            if rule["chain"] != "prerouting" {
                return false;
            }
            let expr = rule["expr"].as_array().unwrap();
            let has_dport_80 = expr.iter().any(|e| {
                e.get("match")
                    .map(|m| {
                        m["left"]["payload"]["protocol"] == "tcp"
                            && m["left"]["payload"]["field"] == "dport"
                            && m["right"] == 80
                    })
                    .unwrap_or(false)
            });
            let has_redirect_8080 = expr
                .iter()
                .any(|e| e.get("redirect").map(|r| r["port"] == 8080).unwrap_or(false));
            has_dport_80 && has_redirect_8080
        });
        assert!(redirect, "prerouting must redirect tcp dport 80 to :8080");
    }

    #[test]
    fn forward_chain_ends_with_terminal_drop() {
        let rs = build_base_ruleset();
        // The last rule in the forward chain must be a bare drop.
        let forward_rules: Vec<&Value> = cmds(&rs)
            .iter()
            .filter_map(|c| c.get("add").and_then(|a| a.get("rule")))
            .filter(|r| r["chain"] == "forward")
            .collect();
        let last = forward_rules.last().unwrap();
        let expr = last["expr"].as_array().unwrap();
        assert_eq!(expr.len(), 1);
        assert!(expr[0].get("drop").is_some(), "last forward rule must be drop");
    }

    #[test]
    fn no_postrouting_or_masquerade() {
        // We must not duplicate fw3's NAT.
        let rs = build_base_ruleset();
        let s = serde_json::to_string(&rs).unwrap();
        assert!(!s.contains("postrouting"), "must not define postrouting");
        assert!(!s.contains("masquerade"), "must not masquerade");
        assert!(!s.contains("snat"), "must not snat");
    }

    #[test]
    fn forward_accepts_established_and_auth() {
        let rs = build_base_ruleset();
        let s = serde_json::to_string(&rs).unwrap();
        assert!(s.contains("established"));
        assert!(s.contains("@auth"));
        assert!(s.contains("@garden4"));
        assert!(s.contains("@garden6"));
    }

    #[test]
    fn script_form_matches_invariants() {
        let script = build_base_script();
        assert!(script.contains("table inet wifihub"));
        assert!(script.contains("priority dstnat - 50"));
        assert!(script.contains("priority filter - 50"));
        assert!(script.contains("redirect to :8080"));
        assert!(script.trim_end().ends_with("}"));
        assert!(script.contains("drop"));
        assert!(!script.contains("masquerade"));
    }
}
