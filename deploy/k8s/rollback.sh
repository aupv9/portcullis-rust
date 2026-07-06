#!/bin/bash
# =============================================================================
# Point the running engine deployment at a specific image version and roll.
# Usage:
#   ./rollback.sh v0.2.0    # deploy/upgrade to v0.2.0
#   ./rollback.sh v0.1.0    # roll back to v0.1.0 (build it from `main` first)
#
# The version tag must already be imported into the cluster (build.sh, or still
# present from a previous build). This only flips the image tag + waits for the
# rollout. Because the engine holds no persistent state (kernel-as-truth, all
# runtime state in tmpfs) rolling back is safe — the new pod adopts the live
# nft `auth` set on start (§7.8) rather than dropping authorized clients.
# =============================================================================
set -euo pipefail

NS="portcullis"
IMAGE="portcullis-engine"
TAG="${1:?usage: $0 <version-tag, e.g. v0.2.0>}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

img="${IMAGE}:${TAG}"
log "Setting deployment/portcullis-engine image -> ${img}"
kubectl -n "${NS}" set image deployment/portcullis-engine "portcullis=${img}"

log "Waiting for rollout..."
kubectl -n "${NS}" rollout status deployment/portcullis-engine --timeout=120s

log "Done. Current image:"
kubectl -n "${NS}" get deploy portcullis-engine \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
