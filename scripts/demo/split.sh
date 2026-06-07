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
LOG="/tmp/tenet-expert-pane.log"
SESSION="tenet-split"

# Self-healing python: verify it can import the demo; rebuild a Python-3.13 venv
# with the deps if not. Never crashes on a missing dep / wrong interpreter.
DEPS='import tenet.mixnet.node_runtime, tenet.experts.client, nacl, kademlia'
_works() { [ -x "$1" ] && "$1" -c "$DEPS" >/dev/null 2>&1; }
resolve_python() {
  for c in "$ROOT/.venv/bin/python" "$ROOT/build/demo-venv/bin/python"; do
    _works "$c" && { echo "$c"; return 0; }
  done
  if command -v python3 >/dev/null 2>&1 && python3 -c "$DEPS" >/dev/null 2>&1; then echo python3; return 0; fi
  echo "[split] one-time setup: building a venv with the demo deps (Python 3.13)…" >&2
  if command -v uv >/dev/null 2>&1; then
    { uv venv --python 3.13 "$ROOT/.venv" || uv venv "$ROOT/.venv"; } >/dev/null 2>&1 || true
    uv pip install --python "$ROOT/.venv/bin/python" -q -e "$ROOT" \
      kademlia dilithium-py "aioquic>=1.3.0" pynacl cryptography pqcrypto rpcudp py-algorand-sdk >/dev/null 2>&1 || true
  else
    { python3 -m venv "$ROOT/.venv" && "$ROOT/.venv/bin/pip" install -q -U pip \
      && "$ROOT/.venv/bin/pip" install -q -e "$ROOT" kademlia dilithium-py "aioquic>=1.3.0" \
         pynacl cryptography pqcrypto rpcudp py-algorand-sdk; } >/dev/null 2>&1 || true
  fi
  _works "$ROOT/.venv/bin/python" && { echo "$ROOT/.venv/bin/python"; return 0; }
  echo "[split] could not set up the venv. Run once, then retry:" >&2
  echo "      cd $ROOT && uv venv --python 3.13 .venv && uv pip install -e . kademlia dilithium-py 'aioquic>=1.3.0' py-algorand-sdk" >&2
  return 1
}
PY="$(resolve_python)" || exit 1

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
tmux set-option -t "$SESSION" remain-on-exit on
tmux set-option -t "$SESSION" pane-border-status top
# ASKER (pane 0) = bright cyan, EXPERT (pane 1) = bright red — bold, filled bg.
tmux set-option -t "$SESSION" pane-border-format \
  "#{?#{==:#{pane_index},0},#[bg=colour51 fg=colour16 bold],#[bg=colour196 fg=colour231 bold]}  #{pane_title}  #[default]"
# Bright, heavy vertical separator between the two panes (same color either way).
tmux set-option -t "$SESSION" pane-border-lines "heavy"
tmux set-option -t "$SESSION" pane-border-style "fg=colour51 bold"
tmux set-option -t "$SESSION" pane-active-border-style "fg=colour51 bold"

# LEFT pane (0) = ASKER. After the demo finishes (or Ctrl-C), one keypress kills
# the whole session (both panes) — no orphaned tail -f.
tmux select-pane -t "$SESSION":0.0 -T "ASKER  ·  your agent"
tmux send-keys -t "$SESSION":0.0 \
  "clear; TENET_STEP=1 TENET_VERBOSE=1 TENET_REAL_PAY='${TENET_REAL_PAY:-}' TENET_PAY_TO='${TENET_PAY_TO:-}' TENET_EXPERT_LOG='$LOG' '$PY' '$ROOT/scripts/demo/present.py' $*; printf '\n  \033[2m── demo complete · Ctrl-b then & to exit ──\033[0m\n'; while :; do sleep 86400; done" C-m

# RIGHT pane (1) = EXPERT
tmux split-window -h -t "$SESSION":0
tmux select-pane -t "$SESSION":0.1 -T "EXPERT  ·  expert_berlin (Berlin local)"
tmux send-keys -t "$SESSION":0.1 \
  "clear; printf '\033[2m  waiting for a sealed packet over the mixnet\342\200\246\033[0m\n\n'; tail -n +1 -f '$LOG'" C-m

tmux select-pane -t "$SESSION":0.0
tmux attach -t "$SESSION"
