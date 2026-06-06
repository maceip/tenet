#!/usr/bin/env bash
# Expert routing plan against the live attested matcher (mixnet delivery is next).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

if ! command -v aw >/dev/null 2>&1; then
  echo "[expert-plan] aw not on PATH — run ./scripts/install-aw.sh" >&2
  exit 1
fi

PROMPT="${1:-Tell me about Monet and impressionist painting.}"
echo "[expert-plan] prompt: $PROMPT"
python3 -m tenet enclave plan --prompt "$PROMPT" --json
