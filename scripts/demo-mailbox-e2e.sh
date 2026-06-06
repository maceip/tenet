#!/usr/bin/env bash
# Local mixnet product path: matcher → opaque handle → mailbox → expert reply.
#
# This is the full run_client_once envelope delivery test (in-process harness).
# Live Nitro still stops at attested match/plan until mailbox delivery is wired
# on the EIF workload + reachability relay fleet.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "[mailbox-e2e] running product test: opaque handle → mailbox → expert"
python3 -m pytest -q \
  tests/test_matcher_mailbox_linkage.py::test_plain_matcher_handle_to_mailbox_to_expert_round_trip

echo "[mailbox-e2e] ok — local mixnet envelope path green"
