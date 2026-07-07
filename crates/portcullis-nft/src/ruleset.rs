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

/// An `iifname == "<iface>"` match statement (P0 interface scoping). Prepended
/// to the gating rules (the forward `drop` and the prerouting `redirect`) so
/// they fire ONLY for ingress from the hotspot SSID; everything else (br-lan…)
/// falls through untouched.
fn iifname_match(iface: &str) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": { "meta": { "key": "iifname" } },
            "right": iface
        }
    })
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

/// Build the full base ruleset as the `nft -j` command array.
///
/// The returned value is `{"nftables": [ ... ]}` — the exact shape `nft -j -f -`
/// consumes on stdin. Order matters: table, then sets, then chains, then the
/// rules within each chain in evaluation order.
///
/// P0 interface scoping (`hotspot_iface`):
/// - `Some("br-hotspot")` → the two **gating** rules (the prerouting
///   `tcp dport 80 redirect` and the forward terminal `drop`) are prefixed with
///   `iifname "br-hotspot"`, so ONLY ingress from the hotspot SSID is
///   redirected/dropped. br-lan and every other interface fall through untouched.
/// - `None` (or empty) → those two gating rules are **omitted entirely**
///   (fail-OPEN): the table, sets, chains and the auth/garden `accept` rules are
///   still created (so kernel-as-truth adoption keeps working), but nothing is
///   redirected or dropped — the whole router, including br-lan, is untouched.
///   This is the ONE deliberate fail-open, gated on an unset interface.
pub fn build_base_ruleset(hotspot_iface: Option<&str>) -> Value {
    let iface = hotspot_iface.filter(|s| !s.trim().is_empty());
    if iface.is_none() {
        tracing::warn!(
            target: "portcullis_nft",
            "no hotspot_iface configured: enforcement is INERT — the wifihub table/sets/chains \
             are created but the prerouting redirect and forward drop are omitted (nothing gated; \
             br-lan and the whole router are untouched). Set hotspot_iface to gate the SSID."
        );
    }

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
    // [iifname "<iface>"] tcp dport 80 redirect to :8080 — the captive gate.
    // Only emitted when scoped to a hotspot iface (fail-OPEN otherwise).
    if let Some(iface) = iface {
        let mut expr: Vec<Value> = Vec::new();
        expr.push(iifname_match(iface));
        expr.push(json!({
            "match": {
                "op": "==",
                "left": { "payload": { "protocol": "tcp", "field": "dport" } },
                "right": 80
            }
        }));
        expr.push(json!({ "redirect": { "port": REDIRECT_PORT } }));
        cmds.push(add(rule_obj(CHAIN_PREROUTING, Value::Array(expr))));
    }

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
    // [iifname "<iface>"] drop — the only globally-terminal verdict (§7.1).
    // Only emitted when scoped to a hotspot iface (fail-OPEN otherwise).
    if let Some(iface) = iface {
        cmds.push(add(rule_obj(
            CHAIN_FORWARD,
            json!([iifname_match(iface), { "drop": null }]),
        )));
    }

    json!({ "nftables": cmds })
}

/// Build the equivalent human-readable nft script (for DEBUG logging only;
/// the JSON form is what is actually applied). Mirrors [`build_base_ruleset`]'s
/// P0 interface scoping: with a hotspot iface the gate rules carry `iifname`;
/// with none they are omitted (fail-OPEN).
pub fn build_base_script(hotspot_iface: Option<&str>) -> String {
    let iface = hotspot_iface.filter(|s| !s.trim().is_empty());
    // The two gating lines, scoped to the hotspot iface or omitted entirely.
    let (redirect_line, drop_line) = match iface {
        Some(i) => (
            format!("\t\tiifname \"{i}\" tcp dport 80 redirect to :{REDIRECT_PORT}\n"),
            format!("\t\tiifname \"{i}\" drop\n"),
        ),
        None => (String::new(), String::new()),
    };
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
         {redirect_line}\
         \t}}\n\
         \tchain {fwd} {{\n\
         \t\ttype filter hook forward priority filter - 50; policy accept;\n\
         \t\tct state established,related accept\n\
         \t\tether saddr @{auth} accept\n\
         \t\tip daddr @{g4} accept\n\
         \t\tip6 daddr @{g6} accept\n\
         {drop_line}\
         \t}}\n\
         }}\n",
        fam = TABLE_FAMILY,
        tbl = TABLE_NAME,
        g4 = SET_GARDEN4,
        g6 = SET_GARDEN6,
        auth = SET_AUTH,
        pre = CHAIN_PREROUTING,
        fwd = CHAIN_FORWARD,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scoped iface used by the "gate present" assertions.
    const IFACE: &str = "br-hotspot";

    fn cmds(v: &Value) -> &Vec<Value> {
        v.get("nftables").unwrap().as_array().unwrap()
    }

    /// Collect the `expr` arrays of every rule in `chain`.
    fn rule_exprs<'a>(rs: &'a Value, chain: &str) -> Vec<&'a Vec<Value>> {
        cmds(rs)
            .iter()
            .filter_map(|c| c.get("add").and_then(|a| a.get("rule")))
            .filter(|r| r["chain"] == chain)
            .map(|r| r["expr"].as_array().unwrap())
            .collect()
    }

    /// Does this rule expr redirect tcp dport 80 to :8080?
    fn is_redirect_80(expr: &[Value]) -> bool {
        let dport80 = expr.iter().any(|e| {
            e.get("match")
                .map(|m| {
                    m["left"]["payload"]["protocol"] == "tcp"
                        && m["left"]["payload"]["field"] == "dport"
                        && m["right"] == 80
                })
                .unwrap_or(false)
        });
        let redirect = expr
            .iter()
            .any(|e| e.get("redirect").map(|r| r["port"] == 8080).unwrap_or(false));
        dport80 && redirect
    }

    /// The `iifname == "<iface>"` guard, if this rule carries one.
    fn iifname_of(expr: &[Value]) -> Option<&str> {
        expr.iter().find_map(|e| {
            let m = e.get("match")?;
            if m["left"]["meta"]["key"] == "iifname" {
                m["right"].as_str()
            } else {
                None
            }
        })
    }

    #[test]
    fn ruleset_has_single_inet_wifihub_table() {
        let rs = build_base_ruleset(Some(IFACE));
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
        let rs = build_base_ruleset(Some(IFACE));
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
        let rs = build_base_ruleset(Some(IFACE));
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
        let rs = build_base_ruleset(Some(IFACE));
        let redirect = rule_exprs(&rs, "prerouting")
            .iter()
            .any(|expr| is_redirect_80(expr));
        assert!(redirect, "prerouting must redirect tcp dport 80 to :8080");
    }

    #[test]
    fn forward_chain_ends_with_iface_scoped_drop() {
        let rs = build_base_ruleset(Some(IFACE));
        // P0: the terminal forward rule is `iifname "<iface>" drop`.
        let forward = rule_exprs(&rs, "forward");
        let last = forward.last().unwrap();
        // Two statements now: the iifname guard, then the drop.
        assert_eq!(last.len(), 2);
        assert_eq!(iifname_of(last), Some(IFACE), "drop must be iface-scoped");
        assert!(
            last.iter().any(|e| e.get("drop").is_some()),
            "last forward rule must drop"
        );
    }

    #[test]
    fn scoped_gate_carries_iifname_on_both_backends_rules() {
        // P0 (nft): with a hotspot iface, BOTH gating rules carry
        // `iifname "<iface>"` — the prerouting redirect and the forward drop.
        let rs = build_base_ruleset(Some(IFACE));

        let redirect = rule_exprs(&rs, "prerouting")
            .into_iter()
            .find(|expr| is_redirect_80(expr))
            .expect("redirect rule present");
        assert_eq!(
            iifname_of(redirect),
            Some(IFACE),
            "prerouting redirect must be scoped to the hotspot iface"
        );

        let drop = rule_exprs(&rs, "forward")
            .into_iter()
            .find(|expr| expr.iter().any(|e| e.get("drop").is_some()))
            .expect("forward drop present");
        assert_eq!(
            iifname_of(drop),
            Some(IFACE),
            "forward drop must be scoped to the hotspot iface"
        );
    }

    #[test]
    fn unset_iface_omits_gate_but_keeps_base_fail_open() {
        // P0 fail-OPEN: with no hotspot iface the table/sets/chains + auth/garden
        // accept rules are STILL created (kernel-as-truth adoption keeps working),
        // but NO prerouting redirect and NO forward drop are emitted — nothing is
        // gated, so br-lan and the whole router are untouched.
        for none in [None, Some(""), Some("   ")] {
            let rs = build_base_ruleset(none);

            // Base still present.
            let tables = cmds(&rs)
                .iter()
                .filter(|c| c.get("add").and_then(|a| a.get("table")).is_some())
                .count();
            assert_eq!(tables, 1, "table still created ({none:?})");
            let sets = cmds(&rs)
                .iter()
                .filter(|c| c.get("add").and_then(|a| a.get("set")).is_some())
                .count();
            assert_eq!(sets, 3, "all sets still created ({none:?})");
            let chains = cmds(&rs)
                .iter()
                .filter(|c| c.get("add").and_then(|a| a.get("chain")).is_some())
                .count();
            assert_eq!(chains, 2, "both chains still created ({none:?})");

            // The auth/garden RETURN(accept) exemptions are still present.
            let s = serde_json::to_string(&rs).unwrap();
            assert!(s.contains("@auth"), "auth exemption kept ({none:?})");
            assert!(s.contains("@garden4"), "garden exemption kept ({none:?})");

            // But NO gate: no redirect, no drop.
            let has_redirect = rule_exprs(&rs, "prerouting")
                .iter()
                .any(|expr| is_redirect_80(expr));
            assert!(!has_redirect, "no redirect when unset ({none:?})");
            let has_drop = rule_exprs(&rs, "forward")
                .iter()
                .any(|expr| expr.iter().any(|e| e.get("drop").is_some()));
            assert!(!has_drop, "no forward drop when unset ({none:?})");
            // And never an iifname match (nothing to scope).
            assert!(!s.contains("iifname"), "no iifname when unset ({none:?})");
        }
    }

    #[test]
    fn no_postrouting_or_masquerade() {
        // We must not duplicate fw3's NAT.
        for iface in [Some(IFACE), None] {
            let rs = build_base_ruleset(iface);
            let s = serde_json::to_string(&rs).unwrap();
            assert!(!s.contains("postrouting"), "must not define postrouting");
            assert!(!s.contains("masquerade"), "must not masquerade");
            assert!(!s.contains("snat"), "must not snat");
        }
    }

    #[test]
    fn forward_accepts_established_and_auth() {
        let rs = build_base_ruleset(Some(IFACE));
        let s = serde_json::to_string(&rs).unwrap();
        assert!(s.contains("established"));
        assert!(s.contains("@auth"));
        assert!(s.contains("@garden4"));
        assert!(s.contains("@garden6"));
    }

    #[test]
    fn script_form_matches_invariants() {
        let script = build_base_script(Some(IFACE));
        assert!(script.contains("table inet wifihub"));
        assert!(script.contains("priority dstnat - 50"));
        assert!(script.contains("priority filter - 50"));
        // Both gating lines are iface-scoped.
        assert!(script.contains("iifname \"br-hotspot\" tcp dport 80 redirect to :8080"));
        assert!(script.contains("iifname \"br-hotspot\" drop"));
        assert!(script.trim_end().ends_with("}"));
        assert!(!script.contains("masquerade"));
    }

    #[test]
    fn script_form_omits_gate_when_unset() {
        let script = build_base_script(None);
        assert!(script.contains("table inet wifihub"));
        // Base structure intact, but no gate + no iifname.
        assert!(!script.contains("redirect to"));
        assert!(!script.contains("drop"));
        assert!(!script.contains("iifname"));
    }
}
