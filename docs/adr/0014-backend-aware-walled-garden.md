# ADR-0014: Backend-aware walled garden (`nftset=` vs `ipset=`)

- Status: Accepted
- Recorded: 2026-07-08

## Context

Pre-auth clients must reach a small set of hosts (portal/OTP/ad/CDN + DNS). Rather
than snoop DNS, the router's own `dnsmasq-full` resolves the garden FQDNs and
injects the IPs into a firewall set. But the *directive* is backend-specific:
`nftset=` populates an nft set, `ipset=` populates an ipset. The engine has two
backends ([0008](0008-firewallbackend-trait-nft-and-ipset.md)) — emitting the wrong
directive silently populates a set the live backend never created, so the splash
page never loads.

## Decision

`GardenConfig` carries a `GardenBackend` (`Nft` | `Ipset`). The renderer emits
`nftset=/…/4#inet#wifihub#garden4` (+6) for the nft backend, or a single
`ipset=/…/wifihub_g4,wifihub_g6` for the ipset backend. The composition root
constructs the garden with the *same* backend kind that `detect_backend` picked, so
the directive always matches the live sets.

## Consequences

- The garden actually populates on both paths (this was a real silent bug on the
  ipset/RUTM11 path before the fix — G2).
- Set names are a contract with the backend; the ipset names mirror
  `portcullis_nft::{IPSET_G4,IPSET_G6}` by convention (the `garden` crate depends
  only on `portcullis-types`, so it can't import them).

## Where it lives

`crates/portcullis-garden/src/lib.rs` (`GardenBackend`, `render_dnsmasq`);
`engined/compose.rs` (garden loop constructed from `garden_backend`).
