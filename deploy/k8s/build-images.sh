#!/bin/bash
# =============================================================================
# Build the portcullis engine image on macOS and import it into the k3d
# data-plane cluster (no registry needed — k3d imports into containerd).
#
# Versioning (mirrors the control-plane repo convention): the tag comes from the
# Cargo workspace version (override with VERSION=x.y.z). Each build is imported
# under BOTH the immutable version tag (vX.Y.Z — kept forever for rollback) and
# :latest (moving pointer). Old version tags are never deleted, so rolling back
# is just pointing the deployment at an older vX.Y.Z tag (see rollback.sh).
# =============================================================================
set -euo pipefail

CLUSTER="wifihub-dataplane"
IMAGE="portcullis-engine"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # repo root (has Dockerfile)

# Version from Cargo workspace (0.2.0 on this branch; 0.1.0 remains on main).
VERSION="${VERSION:-$(grep -m1 '^version' "${ROOT}/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')}"
TAG="v${VERSION}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

versioned="${IMAGE}:${TAG}"
latest="${IMAGE}:latest"

log "Building ${versioned} (+ :latest) from ${ROOT}..."
docker build -t "${versioned}" -t "${latest}" "${ROOT}"

log "Importing ${versioned} and ${latest} -> k3d cluster '${CLUSTER}'..."
k3d image import "${versioned}" "${latest}" -c "${CLUSTER}"

log "  ✓ ${versioned}"
log ""
log "Verify: k3d image list -c ${CLUSTER} | grep ${IMAGE}"
