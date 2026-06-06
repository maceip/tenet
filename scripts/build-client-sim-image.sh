#!/usr/bin/env bash
set -euo pipefail

# Build the "client-sim" image (specialized end-user asker + optional Claude Code).
#
# This is distinct from infrastructure nodes. For mixnet relays, control_dht
# (Kademlia) participants, and experts in simulated or containerized fleets,
# see:
#   - deploy/Dockerfile.node
#   - sim/ (the modern multi-mode simulator: all-local-docker, 2-laptop, cloud, mixed)
#
# Legacy note: natsim/, gate-b live scripts, and direct EC2 provisioning are
# retained for quick experiments and certain production paths, but are considered
# outdated relative to the unified runtime + sim framework.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-tenet-client-sim:latest}"
CLAUDE_CODE_VERSION="${CLAUDE_CODE_VERSION:-2.1.162}"
PLATFORM="${PLATFORM:-linux/amd64}"
USE_SOURCE="${USE_SOURCE:-0}"   # set to 1 to build from uv source instead of prebuilt binary
TMP="$(mktemp -d "${TMPDIR:-/tmp}/tenet-client-image.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cd "$ROOT"

mkdir -p "$TMP/config" "$TMP/deploy/client-sim"

if [[ "$USE_SOURCE" == "1" ]]; then
  echo "[build-client-sim] building from source tree (uv / pyproject.toml)"
  # Copy enough of the tree for uv to install the package + the client-sim bits.
  mkdir -p "$TMP/dist"  # no binary needed
  cp pyproject.toml uv.lock "$TMP/" 2>/dev/null || true
  cp -a tenet "$TMP/tenet"
  cp -a sim "$TMP/sim" 2>/dev/null || true
  cp deploy/client-sim/Dockerfile deploy/client-sim/entrypoint.sh "$TMP/deploy/client-sim/"
  # The Dockerfile will need a small extension for uv install; we keep the
  # original client-sim Dockerfile focused on the binary path and document the
  # source path here. For a full source-based client-sim you can add a
  # multi-stage that does `uv pip install --system -e .` and copies the entry.
  # For now we still require the binary for the classic path unless the caller
  # customizes the temp Dockerfile.
  cp config/live-enclave.json config/join-pack.json config/live-mailbox-client.json "$TMP/config/" 2>/dev/null || true

  # Simple source-friendly variant: install editable inside the image at runtime
  # via the entrypoint or by extending the Dockerfile. We just emit a warning
  # and fall through to the classic binary-based build unless the user also
  # provides a customized Dockerfile in the temp dir.
  echo "[build-client-sim] USE_SOURCE=1: you may want to extend the temp Dockerfile to do 'uv pip install --system -e .'."
else
  [[ -x dist/tenet-linux-x86_64 ]] || {
    echo "missing dist/tenet-linux-x86_64; build the Linux binary first (or set USE_SOURCE=1)" >&2
    exit 2
  }
  mkdir -p "$TMP/dist"
  cp dist/tenet-linux-x86_64 "$TMP/dist/"
  cp config/live-enclave.json config/join-pack.json config/live-mailbox-client.json "$TMP/config/"
  cp deploy/client-sim/Dockerfile deploy/client-sim/entrypoint.sh "$TMP/deploy/client-sim/"
fi

docker build \
  --platform "$PLATFORM" \
  --build-arg "CLAUDE_CODE_VERSION=$CLAUDE_CODE_VERSION" \
  -t "$IMAGE" \
  -f "$TMP/deploy/client-sim/Dockerfile" \
  "$TMP"

echo "$IMAGE"
