#!/usr/bin/env bash
# Protocol regression only (loopback / pytest). Not network proof.
# Network beta proof = ./scripts/gate-b/run-network.sh on real nodes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
python3 -m pytest -q \
  tests/test_por_supernode_security.py \
  tests/test_reach_client.py \
  -m "not live"
