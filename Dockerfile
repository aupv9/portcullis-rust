# =============================================================================
# portcullis edge/agent engine — container image for the k3d DATA-PLANE rehearsal.
#
# NOTE: the production target is the RUTM11 router (mipsel-unknown-linux-musl,
# packaged as an .ipk via the OpenWrt SDK — see deploy/). This image is ONLY for
# running the engine as a pod in a local k3d cluster to rehearse the gRPC control
# link to the Go control plane. The ruleset/session logic is arch-independent, so
# we build natively for the container arch (arm64/amd64) — no cross-compile here.
# =============================================================================

# ── Builder ──────────────────────────────────────────────────────────────────
FROM rust:1.96-slim-bookworm AS builder

# cc/ring/build deps. protoc is VENDORED by portcullis-control/build.rs
# (protoc_bin_vendored), so no protobuf-compiler package is needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build only the daemon binary (bin name: `portcullis`).
RUN cargo build --release -p portcullis-engined \
    && strip target/release/portcullis

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# The engine's production backend is ipset + iptables/ip6tables (IpsetIptablesBackend,
# TDD §17 option B — stock RutOS has no nftables NAT), so ipset + iptables are
# REQUIRED (ensure_base is FATAL on failure). nftables kept for the alt nft backend;
# conntrack + iproute2 for accounting/neigh; dnsmasq for the garden nftset.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ipset iptables nftables conntrack iproute2 dnsmasq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/portcullis /usr/local/bin/portcullis

# Runtime state is RAM/tmpfs only (no NAND on device; no PVC here).
ENV PORTCULLIS_CONFIG=/etc/portcullis/config.toml \
    RUST_LOG=info

# gRPC control server (mTLS) 8443; redirect responder 8080.
EXPOSE 8443 8080

ENTRYPOINT ["/usr/local/bin/portcullis"]
