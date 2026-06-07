#!/usr/bin/env bash
# Two-PROCESS distributed Berlin demo — expert node + asker as separate OS
# processes over real sockets (and real machines if you set the hosts).
#
#   ./scripts/demo/net.sh split          # one box, two processes, side by side (tmux)
#   ./scripts/demo/net.sh serve          # run JUST the expert node (machine A)
#   ./scripts/demo/net.sh ask [prompt]   # run JUST the asker (machine B)
#
# Two machines (Mac <-> Windows/EC2 on the same LAN):
#   on the EXPERT machine:
#     RELAY_HOST=<exA-lan-ip> EXPERT_HOST=<exA-lan-ip> ./scripts/demo/net.sh serve
#   copy the handshake files to the asker machine:
#     scp /tmp/tenet-net/{cluster.json,askpack.json,directory.json} userB@<B>:/tmp/tenet-net/
#   on the ASKER machine:
#     ./scripts/demo/net.sh ask
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
DIR="${TENET_NET_DIR:-/tmp/tenet-net}"
CMD="${1:-split}"
[ "$#" -gt 0 ] && shift || true

case "$CMD" in
  serve)
    exec env TENET_NET_DIR="$DIR" "$PY" "$ROOT/scripts/demo/berlin_serve.py" ;;
  ask)
    exec env TENET_NET_DIR="$DIR" "$PY" "$ROOT/scripts/demo/berlin_ask.py" "$@" ;;
  split)
    command -v tmux >/dev/null 2>&1 || { echo "[net] tmux required for split"; exit 1; }
    S="tenet-net"
    tmux kill-session -t "$S" 2>/dev/null || true
    rm -f "$DIR/askpack.json"
    tmux new-session -d -s "$S" -x "$(tput cols 2>/dev/null || echo 212)" -y "$(tput lines 2>/dev/null || echo 50)"
    tmux set-option -t "$S" status off
    tmux set-option -t "$S" pane-border-status top
    tmux set-option -t "$S" pane-border-format " #{pane_title} "
    # LEFT = the EXPERT NODE process (persistent)
    tmux select-pane -t "$S":0.0 -T "EXPERT NODE  ·  berlin_serve.py (process 1)"
    tmux send-keys -t "$S":0.0 "clear; TENET_NET_DIR='$DIR' '$PY' '$ROOT/scripts/demo/berlin_serve.py'" C-m
    # RIGHT = the ASKER process (waits for the node, then routes)
    tmux split-window -h -t "$S":0
    tmux select-pane -t "$S":0.1 -T "ASKER  ·  berlin_ask.py (process 2)"
    tmux send-keys -t "$S":0.1 \
      "clear; printf '  \033[2mwaiting for the expert node…\033[0m\n'; while [ ! -f '$DIR/askpack.json' ]; do sleep 0.3; done; sleep 1; TENET_NET_DIR='$DIR' '$PY' '$ROOT/scripts/demo/berlin_ask.py' $*; printf '\n  \033[2mpress any key to exit\033[0m'; read -rsn1; tmux kill-session -t '$S'" C-m
    tmux select-pane -t "$S":0.1
    tmux attach -t "$S" ;;
  *)
    echo "usage: net.sh [split|serve|ask]"; exit 1 ;;
esac
