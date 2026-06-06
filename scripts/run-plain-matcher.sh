#!/usr/bin/env bash
# Local plain HTTP matcher (no TEE). Same workload shape as deploy/run_matcher.py.
#
# Usage:
#   ./scripts/run-plain-matcher.sh
#   MATCHER_PORT=9384 ./scripts/run-plain-matcher.sh
#
# Then in another terminal:
#   curl -s http://127.0.0.1:9384/healthz
#   curl -s -X POST http://127.0.0.1:9384/v1/match -H 'Content-Type: application/json' \
#     -d '{"mode":"tenet.plain_matcher.2026-06","max_records":4,"intent":{"prompt":"monet painting","requested_expertise":null,"random_seed":null}}'
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

HOST="${MATCHER_HOST:-127.0.0.1}"
PORT="${MATCHER_PORT:-9384}"

export MATCHER_HOST="$HOST"
export MATCHER_PORT="$PORT"

echo "[plain-matcher] http://${HOST}:${PORT}/ (Ctrl-C to stop)"
echo "[plain-matcher] health: curl -s http://${HOST}:${PORT}/healthz"
exec python3 "$ROOT/deploy/run_matcher.py"
