# portcullis on k3d — data-plane rehearsal

Runs the portcullis engine as a pod in a **dedicated** k3d cluster
(`wifihub-dataplane`) to rehearse the gRPC control link to the Go control plane.
The production target is still the RUTM11 router (`.ipk`, see `../`); this is a
local, throwaway rehearsal and does **not** touch the control-plane cluster
(`k3s-cluster`).

## Topology

```
 k3s-cluster (control plane)                 wifihub-dataplane (this)
   Go backend  ── gRPC client ──► host.k3d.internal:8443 ─┐
   (dials the engine, mTLS)                                │  k3d port map
                                          host :8443 ──────┘  8443 -> nodePort 30843
   Mac host: grpcurl ──► localhost:8443 ─────────────────►  engine pod :8443
```

The backend is the gRPC **client**; the engine is the **server**
(`proto/enforcement.proto`, `wifihub.enforcement.v1`). mTLS is **mandatory** —
with no cert material the engine disables its control server (fail-closed).

## Quick start

```bash
cd deploy/k8s
./setup-cluster.sh     # create the k3d cluster (control-plane cluster untouched)
./gen-dev-mtls.sh      # dev CA + engine server cert + client cert + hmac -> Secrets
./build-images.sh      # docker build + k3d image import (tag = Cargo version, v0.2.0)
./deploy.sh            # kubectl apply -k + wait for rollout
```

## Verify the connection

The engine log should show `gRPC Enforcement server (mTLS) listening` on
`0.0.0.0:8443` and a successful `ensure base nft ruleset`. Then stand in for the
control plane with an mTLS `Health` call from the Mac host:

```bash
grpcurl -cacert tls/ca.crt -cert tls/client.crt -key tls/client.key \
  -import-path ../../proto -proto enforcement.proto \
  localhost:8443 wifihub.enforcement.v1.Enforcement/Health
```

## Versioning / rollback

Tag = Cargo workspace version (`v0.2.0` on this branch; `v0.1.0` remains
reproducible from `main`). Immutable version tags are never deleted, so:

```bash
./rollback.sh v0.1.0   # after building v0.1.0 from main
```

## Scope note

The Go control plane does **not yet ship an enforcement gRPC client**
(no `google.golang.org/grpc` dependency, no `GrantSession` call). Verifying the
link with `grpcurl` proves reachability + mTLS end-to-end; wiring the client
into the backend is a separate task in the `domain` tree.
