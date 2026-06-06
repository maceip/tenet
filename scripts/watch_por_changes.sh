#!/usr/bin/env bash
# Emit coordination wakes when por/ or wire-critical paths change.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WATCH_PATHS=(
  por
  sphinxmix/OutfoxClient.py
  sphinxmix/OutfoxNode.py
  sphinxmix/mixnet.py
  test_a5_exit.py
  test_por_udp_demo.py
  scripts/check_ta_claims.py
  docs/production_arc.md
)

snapshot() {
  find "${WATCH_PATHS[@]}" -type f \( -name '*.py' -o -name '*.md' -o -name '*.txt' \) 2>/dev/null \
    | sort \
    | while read -r f; do
        stat -f '%m %z %N' "$f" 2>/dev/null || stat -c '%Y %s %n' "$f"
      done
}

BASELINE_FILE="${TMPDIR:-/tmp}/por_coord_baseline"
snapshot > "$BASELINE_FILE"

COUNT=$(wc -l < "$BASELINE_FILE" | tr -d ' ')
echo "AGENT_LOOP_WAKE_POR_COORD {\"prompt\":\"por coordination watch armed; baseline ${COUNT} files\"}"

while true; sleep 45; do
  CURRENT="$(mktemp)"
  snapshot > "$CURRENT"
  if ! diff -q "$BASELINE_FILE" "$CURRENT" >/dev/null 2>&1; then
    CHANGED="$(diff "$BASELINE_FILE" "$CURRENT" | rg '^[<>]' | head -20 || true)"
    mv "$CURRENT" "$BASELINE_FILE"
    printf 'AGENT_LOOP_WAKE_POR_COORD {"prompt":"por/wire files changed; diff head:\\n%s\\nReconcile team ownership in docs/production_arc.md"}' \
      "$(echo "$CHANGED" | tr '\n' ' ' | sed 's/"/\\"/g')"
    echo
  else
    rm -f "$CURRENT"
  fi
done
