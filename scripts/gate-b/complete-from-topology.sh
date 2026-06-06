#!/usr/bin/env bash
# Network-beta completion using topology file (matcher EIF on Nitro; expert stays off Nitro).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOPOLOGY="${TENET_GATE_B_TOPOLOGY:-$ROOT/config/gate-b-topology.json}"
export PATH="${HOME}/.cargo/bin:${PATH:-}"

cd "$ROOT"
./scripts/gate-b/deploy-roles.sh

RELAY_HOST=$(python3 -c "import json; print(json.load(open('$TOPOLOGY'))['roles']['reach_relay']['host'])")
HANDLE=$(ssh -i ~/.ssh/tenet-nitro.pem "ubuntu@$(python3 -c "import json; print(json.load(open('$TOPOLOGY'))['roles']['expert']['host'])")" \
  "grep -o 'peer_id=[^ ]*' ~/expert-gateb.log | tail -1 | cut -d= -f2" 2>/dev/null || true)

source config/beta-secrets.env
ssh -i ~/.ssh/tenet-nitro.pem "ec2-user@${RELAY_HOST}" \
  "cd ~/sphinx-tahoe && python3 scripts/export-relay-peer-address.py \
    --config config/live-reach-relay.json --node-id reach-beta-1 --peer-id ${HANDLE}" \
  > /tmp/peer-address.json

PYTHONPATH=. python3 scripts/sync-gate-b-artifacts.py \
  --corpus tests/fixtures/corpus/monet \
  --handle-secret-hex "$HANDLE_SECRET_HEX" \
  --routing-kem-pk-hex "$EXPERT_KEM_PK_HEX" \
  --peer-address-json /tmp/peer-address.json

echo "[complete] matcher EIF update on Nitro only — see deploy/redeploy-matcher-eif.sh on $RELAY_HOST"
echo "[complete] then: TENET_RUN_LIVE=1 pytest -m network_beta_multivm"
