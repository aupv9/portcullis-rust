#!/bin/bash
# =============================================================================
# Apply the portcullis engine manifests to the k3d data-plane cluster and wait
# for the rollout. Assumes setup-cluster.sh + gen-dev-mtls.sh + build-images.sh
# have already run.
# =============================================================================
set -euo pipefail

NS="portcullis"
CLUSTER="wifihub-dataplane"
DIR="$(cd "$(dirname "$0")" && pwd)"

log() { echo "[$(date +%H:%M:%S)] $*"; }

kubectl config use-context "k3d-${CLUSTER}" >/dev/null

# Preflight: secrets must exist (mTLS is mandatory — no certs => no gRPC server).
for s in portcullis-mtls portcullis-hmac; do
  kubectl -n "${NS}" get secret "${s}" >/dev/null 2>&1 || {
    echo "Missing secret ${s}. Run ./gen-dev-mtls.sh first."; exit 1; }
done

log "Applying manifests..."
kubectl apply -k "${DIR}"

log "Waiting for engine rollout..."
kubectl -n "${NS}" rollout status deployment/portcullis-engine --timeout=120s

log ""
log "Engine deployed. Current image:"
kubectl -n "${NS}" get deploy portcullis-engine \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
log ""
log "Tail logs:  kubectl -n ${NS} logs -f deploy/portcullis-engine"
log "Expect:     'gRPC Enforcement server (mTLS) listening' on 0.0.0.0:8443"
