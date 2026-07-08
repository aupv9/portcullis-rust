# ADR-0008: `FirewallBackend` trait + two backends (nft-json, ipset/iptables)

- Status: Accepted
- Recorded: 2026-07-08

## Context

The documented plan is a from-scratch `nf_tables` engine (nft-json). But stock
RutOS is **fw3 (iptables/xtables)** on OpenWrt 21.02 and may ship no `kmod-nft-*` /
`CONFIG_NFT_NAT`. Committing to nft-only would strand those devices; the from-scratch
nft path is also the single biggest platform risk (§18).

## Decision

Abstract the netfilter layer behind a `FirewallBackend` trait with **two** concrete
adapters: `NftJsonBackend` (drives `nft -j` JSON) and `IpsetIptablesBackend`
(ipset + iptables/ip6tables, uses fw3's existing tooling). The composition root
**auto-probes** the kernel for nft NAT-chain support (`firewall_backend = auto`)
and falls back to ipset when absent; `nft` / `ipset` can force a choice.

## Consequences

- Runs on both a modern nft kernel (RUTM11) and stock ipset RutOS (RUT2xx) with no
  code change — just the probe outcome.
- The walled garden must match the live backend ([0014](0014-backend-aware-walled-garden.md)).
- The `FirewallBackend` seam also gives `MockBackend` for host tests.
- Both backends are scoped to one table/one iface — never fw3's rules.

## Where it lives

`crates/portcullis-nft/src/{backend.rs,nftables_json.rs,ipset_iptables.rs}`;
`engined/compose.rs` (`detect_backend`, `probe_nft_nat`).
