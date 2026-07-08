# ADR-0017: UPX-pack the release binary for the flash budget (trades RAM)

- Status: Accepted (CI packs it; on-device exec validation pending)
- Recorded: 2026-07-08

## Context

Target routers are flash-poor (RUT2xx-class ~16 MB, most consumed by RutOS). The
release binary is a static musl build (~3.1 MB on mipsel after `opt-level=z` + LTO
+ strip + `panic=abort`). Every megabyte on the overlay matters.

## Decision

Compress the release binary with **UPX** (`--best --lzma`) in the release workflow:
~3.1 MB → ~0.9 MB on flash. UPX self-decompresses into RAM at exec.

## Consequences

- **Flash:** the on-flash footprint drops ~70% — the binary is a non-issue even on
  16 MB devices. (The real flash constraint there is *dependencies* —
  `nftables`/`dnsmasq-full` — not the binary; the ipset backend
  ([0008](0008-firewallbackend-trait-nft-and-ipset.md)) sidesteps the nft kmods.)
- **RAM:** the trade — the decompressed image (~3 MB) lives in anonymous RAM
  (can't be demand-paged from the file). Fine within the <30 MB RSS budget on
  256/128 MB devices; on a truly RAM-poor box, skip UPX (flash is already ample).
- **Unvalidated:** `upx -t` only checks decompression, not exec. Whether the packed
  binary runs under procd on MIPS is an on-device go/no-go — if procd can't exec
  it, drop the step.

## Where it lives

`.github/workflows/release-ipk.yml` (UPX step); `deploy/` (packaging).
