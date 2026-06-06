#!/usr/bin/env bash
# Gate-b / network-beta live deployment helper (AWS Nitro + local expert).
#
# OUTDATED / LEGACY note (2026):
# The core now has a single WireNodeRuntime, real library-backed Kademlia for the
# control overlay (network-scoped DHT keys, mesh-ready publish, republish of
# persisted records on restart, size bounds, etc.), and a flexible simulator
# (sim/) that supports the five deployment shapes using deploy/Dockerfile.node.
#
# This script is kept for the specific "beta path on existing Nitro + laptop"
# live setup. When launching nodes it still works via the tenet CLI / runtime,
# but new simulation or containerized work should go through `sim/`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NITRO_HOST="${NITRO_HOST:-3.121.69.82}"
NITRO_USER="${NITRO_USER:-ec2-user}"
NITRO_KEY="${NITRO_KEY:-$HOME/.ssh/tenet-nitro.pem}"
RELAY_PORT="${REACH_RELAY_PORT:-4433}"
CORPUS="${EXPERT_CORPUS:-$ROOT/tests/fixtures/corpus/monet}"
REACH_EXPORT_DIR="${REACH_EXPORT_DIR:-/tmp/por-reach-records}"

cd "$ROOT"

if [[ ! -f config/beta-secrets.env ]]; then
  bash "$ROOT/scripts/init-beta-secrets.sh"
fi

# shellcheck disable=SC1090
source config/beta-secrets.env
export REACH_RELAY_HOST="$NITRO_HOST"
export REACH_RELAY_PORT="$RELAY_PORT"

grep -q "^REACH_RELAY_HOST=" config/beta-secrets.env && \
  sed -i.bak "s/^REACH_RELAY_HOST=.*/REACH_RELAY_HOST=${NITRO_HOST}/" config/beta-secrets.env || \
  echo "REACH_RELAY_HOST=${NITRO_HOST}" >> config/beta-secrets.env

bash "$ROOT/scripts/render-beta-config.sh"

echo "[network-beta] open UDP ${RELAY_PORT} on Nitro security group (idempotent)"
SG_ID=$(aws ec2 describe-instances --filters "Name=ip-address,Values=${NITRO_HOST}" \
  --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol udp --port "$RELAY_PORT" --cidr 0.0.0.0/0 2>/dev/null || true

echo "[network-beta] sync repo to ${NITRO_HOST}"
ssh -i "$NITRO_KEY" -o StrictHostKeyChecking=accept-new "${NITRO_USER}@${NITRO_HOST}" "mkdir -p ~/sphinx-tahoe"
rsync -az --delete -e "ssh -i $NITRO_KEY" \
  --exclude .git --exclude .venv --exclude deploy/eif-build --exclude 'oblivious-core/target' \
  "$ROOT/" "${NITRO_USER}@${NITRO_HOST}:~/sphinx-tahoe/"

echo "[network-beta] start reach relay on Nitro (background)"
ssh -i "$NITRO_KEY" "${NITRO_USER}@${NITRO_HOST}" bash -s <<REMOTE
set -euo pipefail
cd ~/sphinx-tahoe
pkill -f 'tenet run --config.*live-reach-relay' 2>/dev/null || true
for i in \$(seq 1 20); do
  if ! ss -lun | grep -q ':${RELAY_PORT} '; then
    break
  fi
  sleep 0.5
done
rm -rf "$REACH_EXPORT_DIR"
mkdir -p "$REACH_EXPORT_DIR"
nohup env POR_REACH_EXPORT_DIR="$REACH_EXPORT_DIR" \
  python3 -m tenet run --config config/live-reach-relay.json --node-id reach-beta-1 \
  > ~/reach-relay.log 2>&1 &
sleep 2
head -5 ~/reach-relay.log || true
REMOTE

echo "[network-beta] verify REACH from laptop"
REACH_RELAY_HOST="$NITRO_HOST" REACH_RELAY_PORT="$RELAY_PORT" "$ROOT/scripts/verify-reach-relay.sh"

if [[ ! -d "$CORPUS" ]]; then
  mkdir -p "$CORPUS"
  echo "Monet painted impressionist works with light and color." > "$CORPUS/notes.md"
fi

HANDLE_TOKEN="$(
  python3 -c "
from tenet.experts.memory_index import IndexConfig, build_memory_index
from tenet.handles import OpaqueHandleIssuer
manifest = build_memory_index(IndexConfig(peer_id='expert', roots=('${CORPUS}',))).manifest
print(OpaqueHandleIssuer(bytes.fromhex('${HANDLE_SECRET_HEX}')).issue(peer_id='expert', manifest_digest=manifest.index_digest).token)
"
)"

python3 - "$HANDLE_TOKEN" <<'PY'
import json
import sys
from pathlib import Path

handle = sys.argv[1]
path = Path("config/expert-laptop.json")
raw = json.loads(path.read_text(encoding="utf-8"))
daemon = next(iter(raw["daemons"].values()))
daemon["node_id"] = handle
daemon["reach_registration"]["peer_id"] = handle
raw["default_node_id"] = handle
raw["daemons"] = {handle: daemon}
path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
PY

echo "[network-beta] opaque handle: ${HANDLE_TOKEN}"

echo "[network-beta] start expert on laptop (background)"
pkill -f 'tenet run --config.*expert-laptop' 2>/dev/null || true
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "[network-beta] WARN: ANTHROPIC_API_KEY unset — expert will not call real LLM" >&2
fi
nohup env POR_PROVIDER=anthropic ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
  python3 -m tenet run --config config/expert-laptop.json --node-id "$HANDLE_TOKEN" \
  > /tmp/tenet-expert.log 2>&1 &
sleep 5
tail -20 /tmp/tenet-expert.log || true

echo "[network-beta] export peer_address from relay"
ssh -i "$NITRO_KEY" "${NITRO_USER}@${NITRO_HOST}" bash -s <<REMOTE
cd ~/sphinx-tahoe
python3 scripts/export-relay-peer-address.py \
  --export-dir "$REACH_EXPORT_DIR" \
  --peer-id "${HANDLE_TOKEN}" > /tmp/peer-address.json
cat /tmp/peer-address.json
REMOTE

scp -i "$NITRO_KEY" "${NITRO_USER}@${NITRO_HOST}:/tmp/peer-address.json" /tmp/peer-address.json

python3 scripts/build-beta-enclave-data.py \
  --corpus "$CORPUS" \
  --peer-id expert \
  --handle-secret-hex "$HANDLE_SECRET_HEX" \
  --handle-token "$HANDLE_TOKEN" \
  --routing-kem-pk-hex "$EXPERT_KEM_PK_HEX" \
  --peer-address-json /tmp/peer-address.json

echo "[network-beta] sync rebuilt beta enclave data to ${NITRO_HOST}"
rsync -az --delete -e "ssh -i $NITRO_KEY" \
  "$ROOT/deploy/data/beta/" "${NITRO_USER}@${NITRO_HOST}:~/sphinx-tahoe/deploy/data/beta/"

echo "[network-beta] beta enclave data built — redeploy Nitro EIF (item 14 prod) required:"
echo "  ssh ${NITRO_USER}@${NITRO_HOST} 'cd ~/sphinx-tahoe && ./deploy/assemble-matcher-eif.sh && ...'"
echo "[network-beta] then: ./scripts/demo-gate-b-e2e.sh"
