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

/// Default local redirect responder port (§7.2). 8082, not 8080: RutOS's own
/// `uhttpd` already binds :8080. Overridable per-store via `responder_port`.
pub const REDIRECT_PORT: u16 = 8082;

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

/// `flush chain inet wifihub <name>` — empties a chain without deleting it.
fn flush_chain(name: &str) -> Value {
    json!({
        "flush": {
            "chain": { "family": TABLE_FAMILY, "table": TABLE_NAME, "name": name }
        }
    })
}

/// The ordered gating rules for the `prerouting` chain: exempt authed + garden,
/// else redirect tcp:80 to the responder on `redirect_port`. Shared by
/// [`build_base_ruleset`] and [`build_set_enforcement`] so the two never drift.
fn prerouting_gate_rules(redirect_port: u16) -> Vec<Value> {
    vec![
        add(rule_obj(CHAIN_PREROUTING, match_set_accept("ether", "saddr", SET_AUTH))),
        add(rule_obj(CHAIN_PREROUTING, match_set_accept("ip", "daddr", SET_GARDEN4))),
        add(rule_obj(CHAIN_PREROUTING, match_set_accept("ip6", "daddr", SET_GARDEN6))),
        add(rule_obj(
            CHAIN_PREROUTING,
            json!([
                {
                    "match": {
                        "op": "==",
                        "left": { "payload": { "protocol": "tcp", "field": "dport" } },
                        "right": 80
                    }
                },
                { "redirect": { "port": redirect_port } }
            ]),
        )),
    ]
}

/// The ordered gating rules for the `forward` chain: accept established + authed
/// + garden, terminal `drop` last (the only globally-terminal verdict, §7.1).
fn forward_gate_rules() -> Vec<Value> {
    vec![
        add(rule_obj(CHAIN_FORWARD, ct_established_accept())),
        add(rule_obj(CHAIN_FORWARD, match_set_accept("ether", "saddr", SET_AUTH))),
        add(rule_obj(CHAIN_FORWARD, match_set_accept("ip", "daddr", SET_GARDEN4))),
        add(rule_obj(CHAIN_FORWARD, match_set_accept("ip6", "daddr", SET_GARDEN6))),
        add(rule_obj(CHAIN_FORWARD, verdict_only("drop"))),
    ]
}

/// Build the full base ruleset as the `nft -j` command array. `redirect_port`
/// is the responder port the tcp:80 REDIRECT targets (the daemon passes its
/// configured `responder_port`; [`REDIRECT_PORT`] is the default).
///
/// The returned value is `{"nftables": [ ... ]}` — the exact shape `nft -j -f -`
/// consumes on stdin. Order matters: table, then sets, then chains, then the
/// rules within each chain in evaluation order.
pub fn build_base_ruleset(redirect_port: u16) -> Value {
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

    // Rules, in evaluation order.
    cmds.extend(prerouting_gate_rules(redirect_port));
    cmds.extend(forward_gate_rules());

    json!({ "nftables": cmds })
}

/// Build the atomic `nft -j` batch that toggles the global enforcement gate.
///
/// Unlike the ipset/iptables backend (which adds/removes a base-hook jump), the
/// nft base chains are hooked intrinsically, so the gate is toggled by flushing
/// their rules. Applied as one atomic batch so `enabled = true` never exposes a
/// fail-open window:
/// - `enabled = false`: flush `prerouting` + `forward` → both keep `policy
///   accept` with no rules, so all traffic flows and nothing is redirected.
/// - `enabled = true`: flush then re-add the gate rules → exactly one copy each,
///   idempotent regardless of the prior state.
///
/// The `auth`/`garden` sets are never touched, so session state survives a
/// toggle. Assumes the base table/chains exist (created by [`build_base_ruleset`]
/// at boot).
pub fn build_set_enforcement(enabled: bool, redirect_port: u16) -> Value {
    let mut cmds: Vec<Value> = vec![flush_chain(CHAIN_PREROUTING), flush_chain(CHAIN_FORWARD)];
    if enabled {
        cmds.extend(prerouting_gate_rules(redirect_port));
        cmds.extend(forward_gate_rules());
    }
    json!({ "nftables": cmds })
}

/// Build the equivalent human-readable nft script (for DEBUG logging only;
/// the JSON form is what is actually applied).
pub fn build_base_script(redirect_port: u16) -> String {
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
        port = redirect_port,
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
        let rs = build_base_ruleset(REDIRECT_PORT);
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
        let rs = build_base_ruleset(REDIRECT_PORT);
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
        let rs = build_base_ruleset(REDIRECT_PORT);
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
        let rs = build_base_ruleset(REDIRECT_PORT);
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
            let has_redirect = expr
                .iter()
                .any(|e| e.get("redirect").map(|r| r["port"] == REDIRECT_PORT).unwrap_or(false));
            has_dport_80 && has_redirect
        });
        assert!(redirect, "prerouting must redirect tcp dport 80 to :{REDIRECT_PORT}");
    }

    #[test]
    fn redirect_port_is_parameterized() {
        // The responder port from config must land in every form of the
        // ruleset — base, enforcement re-add, and the debug script.
        let s = serde_json::to_string(&build_base_ruleset(9999)).unwrap();
        assert!(s.contains("\"port\":9999"));
        assert!(!s.contains(&format!("\"port\":{REDIRECT_PORT}")));

        let toggle = serde_json::to_string(&build_set_enforcement(true, 9999)).unwrap();
        assert!(toggle.contains("\"port\":9999"));

        assert!(build_base_script(9999).contains("redirect to :9999"));
    }

    #[test]
    fn forward_chain_ends_with_terminal_drop() {
        let rs = build_base_ruleset(REDIRECT_PORT);
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
        let rs = build_base_ruleset(REDIRECT_PORT);
        let s = serde_json::to_string(&rs).unwrap();
        assert!(!s.contains("postrouting"), "must not define postrouting");
        assert!(!s.contains("masquerade"), "must not masquerade");
        assert!(!s.contains("snat"), "must not snat");
    }

    #[test]
    fn forward_accepts_established_and_auth() {
        let rs = build_base_ruleset(REDIRECT_PORT);
        let s = serde_json::to_string(&rs).unwrap();
        assert!(s.contains("established"));
        assert!(s.contains("@auth"));
        assert!(s.contains("@garden4"));
        assert!(s.contains("@garden6"));
    }

    #[test]
    fn set_enforcement_disabled_only_flushes_no_rules() {
        let rs = build_set_enforcement(false, REDIRECT_PORT);
        let c = cmds(&rs);
        // Exactly two flushes (prerouting + forward), no rules.
        let flushes: Vec<&Value> = c.iter().filter_map(|v| v.get("flush")).collect();
        assert_eq!(flushes.len(), 2);
        assert!(c.iter().all(|v| v.get("add").and_then(|a| a.get("rule")).is_none()));
        // Must not touch the auth set.
        let s = serde_json::to_string(&rs).unwrap();
        assert!(!s.contains("\"set\""), "toggle must not touch sets");
    }

    #[test]
    fn set_enforcement_enabled_flushes_then_readds_gate_with_terminal_drop() {
        let rs = build_set_enforcement(true, REDIRECT_PORT);
        let c = cmds(&rs);
        assert_eq!(c.iter().filter_map(|v| v.get("flush")).count(), 2);
        // Re-adds the forward chain ending in a terminal drop.
        let forward_rules: Vec<&Value> = c
            .iter()
            .filter_map(|v| v.get("add").and_then(|a| a.get("rule")))
            .filter(|r| r["chain"] == "forward")
            .collect();
        let last = forward_rules.last().unwrap();
        assert!(last["expr"].as_array().unwrap()[0].get("drop").is_some());
        // Flushes come before the re-added rules (atomic ordering).
        let first_flush = c.iter().position(|v| v.get("flush").is_some()).unwrap();
        let first_rule = c
            .iter()
            .position(|v| v.get("add").and_then(|a| a.get("rule")).is_some())
            .unwrap();
        assert!(first_flush < first_rule, "flush must precede re-add");
    }

    #[test]
    fn script_form_matches_invariants() {
        let script = build_base_script(REDIRECT_PORT);
        assert!(script.contains("table inet wifihub"));
        assert!(script.contains("priority dstnat - 50"));
        assert!(script.contains("priority filter - 50"));
        assert!(script.contains(&format!("redirect to :{REDIRECT_PORT}")));
        assert!(script.trim_end().ends_with("}"));
        assert!(script.contains("drop"));
        assert!(!script.contains("masquerade"));
    }
}
