#!/bin/bash
# =============================================================================
# Create the k3d cluster for the portcullis DATA-PLANE rehearsal.
#
# This is a SEPARATE cluster from the control-plane cluster (`k3s-cluster`),
# which is left completely untouched. The engine's gRPC (8443) is published on
# the host so the control plane in k3s-cluster can dial it cross-cluster:
#     host 8443  ->  serverlb  ->  nodePort 30843  ->  engine pod 8443
# From a pod in k3s-cluster, reach it at  host.k3d.internal:8443.
# From the Mac host (grpcurl), reach it at  localhost:8443.
# =============================================================================
set -euo pipefail

CLUSTER="wifihub-dataplane"

log() { echo "[$(date +%H:%M:%S)] $*"; }

command -v k3d     >/dev/null || { echo "Install k3d: brew install k3d"; exit 1; }
command -v kubectl >/dev/null || { echo "Install kubectl: brew install kubectl"; exit 1; }

if k3d cluster list | grep -q "^${CLUSTER}"; then
  log "Cluster '${CLUSTER}' already exists — leaving it in place."
  log "  (delete with: k3d cluster delete ${CLUSTER})"
else
  log "Creating k3d cluster '${CLUSTER}'..."
  k3d cluster create "${CLUSTER}" \
    --servers 1 \
    --agents 0 \
    --port "8443:30843@server:0" \
    --k3s-arg "--disable=traefik@server:0" \
    --k3s-arg "--disable=servicelb@server:0" \
    --wait
fi

kubectl config use-context "k3d-${CLUSTER}"
kubectl get nodes

log "============================================================"
log "k3d cluster '${CLUSTER}' ready (control-plane cluster untouched)."
log "  host :8443  ->  engine gRPC (nodePort 30843)"
log ""
log "Next:"
log "  ./gen-dev-mtls.sh     — dev certs + secrets"
log "  ./build-images.sh     — build & import the engine image"
log "  ./deploy.sh           — apply manifests"
log "============================================================"
