#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-tenet-client-sim:latest}"
CLAUDE_CODE_VERSION="${CLAUDE_CODE_VERSION:-2.1.162}"
PLATFORM="${PLATFORM:-linux/amd64}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/tenet-client-image.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cd "$ROOT"
[[ -x dist/tenet-linux-x86_64 ]] || {
  echo "missing dist/tenet-linux-x86_64; build the Linux binary first" >&2
  exit 2
}

mkdir -p "$TMP/dist" "$TMP/config" "$TMP/deploy/client-sim"
cp dist/tenet-linux-x86_64 "$TMP/dist/"
cp config/live-enclave.json config/join-pack.json config/live-mailbox-client.json "$TMP/config/"
cp deploy/client-sim/Dockerfile deploy/client-sim/entrypoint.sh "$TMP/deploy/client-sim/"

docker build \
  --platform "$PLATFORM" \
  --build-arg "CLAUDE_CODE_VERSION=$CLAUDE_CODE_VERSION" \
  -t "$IMAGE" \
  -f "$TMP/deploy/client-sim/Dockerfile" \
  "$TMP"

echo "$IMAGE"
