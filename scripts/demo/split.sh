#!/usr/bin/env bash
# Split-screen stage demo: ASKER (left) | EXPERT (right), over the REAL loopback mixnet.
# Left pane runs present.py (the asker: ask -> 402 -> pay -> route -> verdict).
# Right pane shows the expert receiving the sealed packet, decrypting, and replying —
# driven by the actual in-process expert reply handler (TENET_EXPERT_LOG events).
#
# Maximize your terminal first (the wider the better). Falls back to single-pane
# present.py if tmux is missing. Pass through flags, e.g.:  ./scripts/demo/split.sh --speed 2
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$ROOT/.venv/bin/python"
LOG="/tmp/tenet-expert-pane.log"
SESSION="tenet-split"

[ -x "$PY" ] || PY="python3"

if ! command -v tmux >/dev/null 2>&1; then
  echo "[split] tmux not found — running single-pane present.py instead"
  exec "$PY" "$ROOT/scripts/demo/present.py" "$@"
fi

: > "$LOG"
tmux kill-session -t "$SESSION" 2>/dev/null || true

COLS="$(tput cols 2>/dev/null || echo 212)"
ROWS="$(tput lines 2>/dev/null || echo 50)"

tmux new-session -d -s "$SESSION" -x "$COLS" -y "$ROWS"
tmux set-option -t "$SESSION" status off
tmux set-option -t "$SESSION" pane-border-status top
tmux set-option -t "$SESSION" pane-border-format " #{pane_title} "

# LEFT pane (0) = ASKER. After the demo finishes (or Ctrl-C), one keypress kills
# the whole session (both panes) — no orphaned tail -f.
tmux select-pane -t "$SESSION":0.0 -T "ASKER  ·  your agent"
tmux send-keys -t "$SESSION":0.0 \
  "clear; TENET_VERBOSE=1 TENET_EXPERT_LOG='$LOG' '$PY' '$ROOT/scripts/demo/present.py' $*; printf '\n  \033[2mpress any key to exit\033[0m'; read -rsn1; tmux kill-session -t '$SESSION'" C-m

# RIGHT pane (1) = EXPERT
tmux split-window -h -t "$SESSION":0
tmux select-pane -t "$SESSION":0.1 -T "EXPERT  ·  expert_berlin (Berlin local)"
tmux send-keys -t "$SESSION":0.1 \
  "clear; printf '\033[2m  waiting for a sealed packet over the mixnet\342\200\246\033[0m\n\n'; tail -n +1 -f '$LOG'" C-m

tmux select-pane -t "$SESSION":0.0
tmux attach -t "$SESSION"
