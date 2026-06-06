#!/usr/bin/env bash
# Alpha network: experts from agent logs → real nodes → asker clients.
#
# Usage:
#   ./scripts/alpha/run-alpha-network.sh
#   EXPERT_NODE_COUNT=4 MAX_TRANSCRIPTS=20 ./scripts/alpha/run-alpha-network.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH:-}"

EXPERT_NODE_COUNT="${EXPERT_NODE_COUNT:-3}"
MAX_TRANSCRIPTS="${MAX_TRANSCRIPTS:-$EXPERT_NODE_COUNT}"
PROMPTS_FILE="${PROMPTS_FILE:-}"
POPULATION="${ALPHA_POPULATION:-$ROOT/config/alpha-population.json}"
TOPOLOGY="${TENET_GATE_B_TOPOLOGY:-$ROOT/config/gate-b-topology.json}"

cd "$ROOT"

echo "[alpha] materialize experts from agent logs"
python3 "$ROOT/scripts/alpha/materialize-experts.py" \
  --max-transcripts "$MAX_TRANSCRIPTS" \
  --min-experts "$EXPERT_NODE_COUNT" \
  --write-groups \
  --out "config/alpha-population.json"

if [[ ! -f "$TOPOLOGY" ]]; then
  RELAY_HOST="${RELAY_HOST:-3.121.69.82}" \
    EXPERT_NODE_COUNT="$EXPERT_NODE_COUNT" \
    "$ROOT/scripts/gate-b/provision-network.sh"
fi

export ALPHA_POPULATION="$POPULATION"
"$ROOT/scripts/gate-b/deploy-nodes.sh"
"$ROOT/scripts/gate-b/verify-network.sh"

if ! command -v aw >/dev/null 2>&1; then
  "$ROOT/scripts/install-aw.sh"
fi

if [[ -n "$PROMPTS_FILE" && -f "$PROMPTS_FILE" ]]; then
  while IFS= read -r prompt || [[ -n "$prompt" ]]; do
    [[ -z "${prompt// }" ]] && continue
    echo "[alpha] asker: $prompt"
    python3 -m tenet enclave send --prompt "$prompt" --timeout 120 --json || true
  done < "$PROMPTS_FILE"
else
  python3 -m tenet enclave send \
    --prompt "${PROMPT:-How does REACH relay registration work for home experts?}" \
    --timeout 120 \
    --json
fi
