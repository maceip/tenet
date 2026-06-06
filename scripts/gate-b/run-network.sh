#!/usr/bin/env bash
# Legacy directory name. Run network beta on real nodes:
# provision → deploy → verify → asker clients.
#
# Usage:
#   EXPERT_NODE_COUNT=3 ./scripts/gate-b/run-network.sh
#   PROMPTS_FILE=prompts.txt ./scripts/gate-b/run-network.sh   # scale asker traffic
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH:-}"
EXPERT_NODE_COUNT="${EXPERT_NODE_COUNT:-1}"
PROMPTS_FILE="${PROMPTS_FILE:-}"
TOPOLOGY="${TENET_GATE_B_TOPOLOGY:-$ROOT/config/gate-b-topology.json}"

cd "$ROOT"

if [[ ! -f "$TOPOLOGY" ]]; then
  RELAY_HOST="${RELAY_HOST:-3.121.69.82}" \
    EXPERT_NODE_COUNT="$EXPERT_NODE_COUNT" \
    "$ROOT/scripts/gate-b/provision-network.sh"
fi

"$ROOT/scripts/gate-b/deploy-nodes.sh"
"$ROOT/scripts/gate-b/verify-network.sh"

if ! command -v aw >/dev/null 2>&1; then
  "$ROOT/scripts/install-aw.sh"
fi

if [[ -n "$PROMPTS_FILE" && -f "$PROMPTS_FILE" ]]; then
  echo "[run-network] asker clients (scale) from $PROMPTS_FILE"
  while IFS= read -r prompt || [[ -n "$prompt" ]]; do
    [[ -z "${prompt// }" ]] && continue
    echo "[run-network] prompt: $prompt"
    python3 -m tenet enclave send --prompt "$prompt" --timeout 120 --json || true
  done < "$PROMPTS_FILE"
else
  echo "[run-network] asker client (single prompt)"
  python3 -m tenet enclave send \
    --prompt "${PROMPT:-What is impressionism in painting?}" \
    --timeout 120 \
    --json
fi
