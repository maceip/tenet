#!/usr/bin/env bash
# Verify network beta: cross-node REACH + topology separation (real nodes).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOPOLOGY="${TENET_GATE_B_TOPOLOGY:-$ROOT/config/gate-b-topology.json}"

cd "$ROOT"
PYTHONPATH=. python3 -c "
from tenet.experts.gate_b_topology import GateBTopology
from tenet.experts.gate_b_nodes import verify_network
topo = GateBTopology.load('$TOPOLOGY')
for line in verify_network(topo):
    print('[verify-network]', line)
print('[verify-network] OK')
"
