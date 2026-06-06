#!/usr/bin/env bash
set -euo pipefail

# Build the modern Tenet infrastructure node image used by the sim/ framework.
#
# This image runs WireNodeRuntime (mixnodes, control_dht nodes with real
# Kademlia overlay for signed control records, experts, etc.).
#
# Compare to:
#   - deploy/client-sim/Dockerfile : specialized end-user "ask" client (Claude).
#   - deploy/Dockerfile.enclave / Dockerfile.matcher-real : TEE matcher path.
#
# Usage:
#   ./scripts/build-node-image.sh
#   IMAGE=tenet-node:dev ./scripts/build-node-image.sh
#   PLATFORM=linux/arm64 ./scripts/build-node-image.sh   # for Apple Silicon if needed

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-tenet-node:dev}"
PLATFORM="${PLATFORM:-linux/amd64}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/tenet-node-image.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cd "$ROOT"

echo "[build-node] preparing controlled context in $TMP"

mkdir -p "$TMP/deploy" "$TMP/config"

# Copy only what the Dockerfile.node needs (pyproject + lock for uv, the two source trees, the entry).
cp pyproject.toml "$TMP/" 2>/dev/null || true
cp uv.lock "$TMP/" 2>/dev/null || true
cp -a tenet "$TMP/tenet"
# Place the launcher under sim/ inside the context so the Dockerfile COPY matches
# exactly (some builders are extremely picky about the path during checksum).
mkdir -p "$TMP/sim"
cp sim/node_launcher.py "$TMP/sim/node_launcher.py"
cp deploy/Dockerfile.node "$TMP/deploy/Dockerfile.node"
cp deploy/node-entry.sh "$TMP/deploy/node-entry.sh"

# Optional: any minimal config the image might reference at build time (usually not).
cp config/live-enclave.json "$TMP/config/" 2>/dev/null || true

docker build \
  --platform "$PLATFORM" \
  -t "$IMAGE" \
  -f "$TMP/deploy/Dockerfile.node" \
  "$TMP"

echo "$IMAGE"
