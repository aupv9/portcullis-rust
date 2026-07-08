# ADR-0016: gRPC contract via Buf; committed bindings; superset/reserved-tag discipline

- Status: Accepted
- Recorded: 2026-07-08

## Context

`proto/enforcement.proto` is the wire contract shared with the Go control plane —
two folders (Rust `crates/portcullis-control/src/gen/`, Go `domain/server/proto/`),
one contract. It must stay wire-compatible as features land, and codegen must be
reproducible without a `build.rs` toolchain on every build.

## Decision

Codegen is driven by **Buf** (`buf.yaml` + `buf.gen.yaml`), writing **committed**
prost+tonic bindings (remote plugins pinned to tonic 0.12/prost 0.13). `buf lint` /
`buf build` guard style + wire-compat. Evolution is **additive only**: new field
tags / enum values, never renumber; deprecated features (e.g. hotspot provisioning)
keep their tags **reserved**, never reused. Both language folders keep `package
wifihub.enforcement.v1` and field tags in sync.

## Consequences

- Additive changes are backward-compatible; the Go side regenerates when tags are
  added (not needed for v0.9.0 — it only *implemented* already-present frames).
- The proto is a stable pin point for CP integration (see the `v*` release tags).
- Cost: two copies to keep in sync — enforced by convention + review.

## Where it lives

`proto/enforcement.proto`, `buf.yaml`, `buf.gen.yaml`;
`crates/portcullis-control/src/gen/` (committed bindings).
