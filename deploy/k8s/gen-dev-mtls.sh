#!/bin/bash
# =============================================================================
# Generate DEV mTLS material for the k3d data-plane rehearsal and load it into
# the cluster as Secrets.
#
#   - a throwaway CA
#   - engine server cert/key   -> Secret portcullis-mtls (server.crt/server.key)
#   - the CA as the client CA   -> Secret portcullis-mtls (client-ca.crt)
#   - a control-plane CLIENT cert/key signed by the same CA, written to ./tls/
#     for use by grpcurl / the Go control plane (mTLS requires a client cert)
#   - a random HMAC key         -> Secret portcullis-hmac
#
# These are DEV-only, self-signed, and gitignored. Prod material is provisioned
# per store at first boot (§13) — never reuse these.
# =============================================================================
set -euo pipefail

NS="portcullis"
CLUSTER="wifihub-dataplane"
DIR="$(cd "$(dirname "$0")" && pwd)/tls"
DAYS=3650

log() { echo "[$(date +%H:%M:%S)] $*"; }

mkdir -p "${DIR}"
cd "${DIR}"

# SANs the engine cert must answer to. Callers reach it as:
#   - localhost / 127.0.0.1      (grpcurl from the Mac host via port map)
#   - host.k3d.internal          (a pod in k3s-cluster dialing across clusters)
#   - portcullis-engine.portcullis.svc  (in-cluster clients)
cat > san.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = portcullis-engine
[ext]
# rustls (webpki) enforces EKU: the server cert MUST be valid for serverAuth.
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt
[alt]
DNS.1 = localhost
DNS.2 = host.k3d.internal
DNS.3 = host.docker.internal
DNS.4 = portcullis-engine.portcullis.svc
DNS.5 = portcullis-engine.portcullis.svc.cluster.local
IP.1  = 127.0.0.1
EOF

# The control-plane CLIENT cert MUST carry EKU clientAuth or rustls rejects it
# with 'certificate_unknown' (TLS alert 46) during the mTLS handshake.
cat > client.cnf <<'EOF'
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

log "Generating dev CA..."
openssl genrsa -out ca.key 4096 >/dev/null 2>&1
openssl req -x509 -new -nodes -key ca.key -sha256 -days "${DAYS}" \
  -subj "/CN=wifihub-dev-ca" -out ca.crt >/dev/null 2>&1

log "Generating engine server cert (SAN: localhost, host.k3d.internal, svc)..."
openssl genrsa -out server.key 4096 >/dev/null 2>&1
openssl req -new -key server.key -out server.csr -config san.cnf >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "${DAYS}" -sha256 -extensions ext -extfile san.cnf \
  -out server.crt >/dev/null 2>&1

log "Generating control-plane client cert (for grpcurl / Go backend)..."
openssl genrsa -out client.key 4096 >/dev/null 2>&1
openssl req -new -key client.key -subj "/CN=wifihub-control-plane" \
  -out client.csr >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "${DAYS}" -sha256 -extfile client.cnf -out client.crt >/dev/null 2>&1

log "Generating HMAC key..."
openssl rand -hex 32 | tr -d '\n' > hmac.key

# ── Load into the cluster ────────────────────────────────────────────────────
if kubectl config current-context 2>/dev/null | grep -q "${CLUSTER}"; then
  log "Creating namespace + Secrets in cluster '${CLUSTER}'..."
  kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f -
  # Engine wants: server.crt, server.key, client-ca.crt  (§ compose::load_tls)
  kubectl -n "${NS}" create secret generic portcullis-mtls \
    --from-file=server.crt=server.crt \
    --from-file=server.key=server.key \
    --from-file=client-ca.crt=ca.crt \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "${NS}" create secret generic portcullis-hmac \
    --from-file=hmac.key=hmac.key \
    --dry-run=client -o yaml | kubectl apply -f -
  log "Secrets applied."
else
  log "WARN: current kube-context is not '${CLUSTER}'. Skipped Secret creation."
  log "      Run setup-cluster.sh first, then re-run this script."
fi

log ""
log "Done. Client material for the control plane / grpcurl:"
log "  CA:     ${DIR}/ca.crt"
log "  cert:   ${DIR}/client.crt"
log "  key:    ${DIR}/client.key"
