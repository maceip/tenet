#!/usr/bin/env bash
# Deploy public reachability relay (item 11).
#
# Prereqs: config/live-reach-relay.json (from ./scripts/render-beta-config.sh)
#          UDP @REACH_RELAY_PORT open on the VM security group
#
# Usage on the relay VM:
#   scp config/live-reach-relay.json user@relay:~/live-reach-relay.json
#   scp -r tenet user@relay:~/tenet/
#   ssh user@relay 'cd ~/tenet && python3 -m tenet run --config ~/live-reach-relay.json --node-id reach-beta-1'
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${RELAY_CONFIG:-$ROOT/config/live-reach-relay.json}"

if [[ ! -f "$CONFIG" ]]; then
  echo "missing $CONFIG — run ./scripts/init-beta-secrets.sh && ./scripts/render-beta-config.sh" >&2
  exit 1
fi

NODE_ID="$(python3 -c "import json; print(json.load(open('$CONFIG'))['default_node_id'])")"
echo "[deploy-reach-relay] starting relay node_id=$NODE_ID config=$CONFIG"
echo "[deploy-reach-relay] run on the public VM:"
echo "  python3 -m tenet run --config $CONFIG --node-id $NODE_ID"
