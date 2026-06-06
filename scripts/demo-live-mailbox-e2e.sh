#!/usr/bin/env bash
# TEE deliver demo (item 9 shortcut — in-enclave stub expert).
# Does NOT prove item 13. See STATUS.md Commands.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

if ! command -v aw >/dev/null 2>&1; then
  echo "[live-mailbox] aw not on PATH — run ./scripts/install-aw.sh" >&2
  exit 1
fi

PROMPT="${1:-Tell me about Monet and impressionist painting.}"
echo "[live-mailbox] prompt: $PROMPT"
python3 -m tenet enclave send --prompt "$PROMPT" --via-mailbox --json
