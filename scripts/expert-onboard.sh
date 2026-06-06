#!/usr/bin/env bash
# Expert onboarding: corpus -> opaque handle -> config -> TEE data steps (item 12).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${BETA_SECRETS:-$ROOT/config/beta-secrets.env}"
CORPUS=""
PEER_ID="${PEER_ID:-}"
WRITE_CONFIG="${WRITE_CONFIG:-1}"

usage() {
  echo "usage: $0 <expert-corpus-directory> [--peer-id ID] [--no-write-config]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --peer-id)
      [[ $# -ge 2 ]] || usage
      PEER_ID="$2"
      shift 2
      ;;
    --no-write-config) WRITE_CONFIG=0; shift ;;
    -h|--help) usage ;;
    *)
      if [[ -z "$CORPUS" ]]; then
        CORPUS="$1"
        shift
      else
        usage
      fi
      ;;
  esac
done

if [[ -z "$CORPUS" || ! -d "$CORPUS" ]]; then
  usage
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "run ./scripts/init-beta-secrets.sh first" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

ONBOARD_OUTPUT="$(PYTHONPATH="$ROOT" python3 - <<PY
import os, sys
sys.path.insert(0, "${ROOT}")
from pathlib import Path
from tenet.handles import OpaqueHandleIssuer
from tenet.experts.memory_index import IndexConfig, build_memory_index

corpus = Path("${CORPUS}")
peer_id = "${PEER_ID}" or corpus.name
built = build_memory_index(IndexConfig(peer_id=peer_id, roots=(str(corpus),)))
issuer = OpaqueHandleIssuer(bytes.fromhex("${HANDLE_SECRET_HEX}"))
handle = issuer.issue(peer_id=peer_id, manifest_digest=built.manifest.index_digest)
print(handle.token)
print(built.manifest.index_digest)
print(peer_id)
PY
)"

HANDLE_TOKEN="$(printf '%s\n' "$ONBOARD_OUTPUT" | sed -n '1p')"
MANIFEST_DIGEST="$(printf '%s\n' "$ONBOARD_OUTPUT" | sed -n '2p')"
PEER_ID_BUILT="$(printf '%s\n' "$ONBOARD_OUTPUT" | sed -n '3p')"

if [[ -z "$HANDLE_TOKEN" || -z "$MANIFEST_DIGEST" || -z "$PEER_ID_BUILT" ]]; then
  echo "[expert-onboard] failed to build handle from corpus" >&2
  exit 1
fi

PEER_ID="${PEER_ID:-$PEER_ID_BUILT}"

echo "[expert-onboard] peer_id=$PEER_ID handle=$HANDLE_TOKEN manifest=$MANIFEST_DIGEST"

EXPERT_CFG="$ROOT/config/expert-laptop.json"
if [[ "$WRITE_CONFIG" == "1" ]]; then
  "$ROOT/scripts/render-beta-config.sh" >/dev/null
  sed -i.bak "s/REPLACE_WITH_OPAQUE_HANDLE/${HANDLE_TOKEN}/g" "$EXPERT_CFG"
  rm -f "${EXPERT_CFG}.bak"
  echo "[expert-onboard] wrote $EXPERT_CFG"
else
  echo "[expert-onboard] skipped config writes"
fi

echo ""
echo "Start expert (requires ANTHROPIC_API_KEY in environment):"
echo "  cd $ROOT && python3 -m tenet run --config config/expert-laptop.json --node-id $HANDLE_TOKEN"
echo ""
echo "After REACH heartbeats, export peer_address from relay host:"
echo "  python3 scripts/export-relay-peer-address.py --peer-id $HANDLE_TOKEN > peer-address.json"
echo ""
echo "Build TEE beta data and redeploy matcher EIF:"
echo "  POR_HANDLE_TTL_SECONDS=86400 python3 scripts/build-beta-enclave-data.py \\"
echo "    --corpus $CORPUS --peer-id $PEER_ID --handle-token $HANDLE_TOKEN \\"
echo "    --handle-secret-hex \$HANDLE_SECRET_HEX \\"
echo "    --routing-kem-pk-hex $EXPERT_KEM_PK_HEX \\"
echo "    --peer-address-json peer-address.json"
echo ""
echo "Refresh public join pack for askers:"
echo "  ./scripts/render-join-pack.sh"
