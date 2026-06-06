#!/usr/bin/env bash
# Tiered test runner.
#
# Usage:
#   ./scripts/test.sh            # unit/default (same as smoke)
#   ./scripts/test.sh unit       # pytest, excludes @pytest.mark.live
#   ./scripts/test.sh integration
#   ./scripts/test.sh product
#   ./scripts/test.sh live       # item 9: aw + live match/plan, no item 13 send
#   Network beta (real nodes):   ./scripts/gate-b/run-network.sh
#   Protocol regression only:    ./scripts/gate-b/run-protocol-checks.sh
#   ./scripts/test.sh all        # unit + integration + product (not live)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

TIER="${1:-unit}"

case "$TIER" in
  unit|default|smoke)
    python3 -m pytest -q -m "not live"
    ;;
  integration)
    python3 -m pytest -q -m integration
    ;;
  product)
    python3 -m pytest -q -m product
    ;;
  live)
    if ! command -v aw >/dev/null 2>&1; then
      echo "[test] aw not on PATH — run ./scripts/install-aw.sh first" >&2
      exit 1
    fi
    TENET_RUN_LIVE=1 python3 -m pytest -q -m "live and not network_beta"
    ;;
  network|network-beta|network_beta)
    echo "[test] Network beta runs on real nodes — use: ./scripts/gate-b/run-network.sh" >&2
    exit 2
    ;;
  all)
    python3 -m pytest -q -m "not live"
    python3 -m pytest -q -m integration
    python3 -m pytest -q -m product
    ;;
  *)
    echo "usage: $0 [unit|integration|product|live|all]" >&2
    exit 2
    ;;
esac

echo "[test] $TIER ok"
