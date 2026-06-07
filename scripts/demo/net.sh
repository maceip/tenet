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
DIR="${TENET_NET_DIR:-/tmp/tenet-net}"
CMD="${1:-split}"
[ "$#" -gt 0 ] && shift || true

# Resolve a Python that can ACTUALLY import the demo (not merely one that exists),
# and self-heal a venv if none can — so this never crashes on a missing dep or the
# wrong interpreter. The demo needs Python <=3.13 (some deps have no 3.14 wheels).
DEPS='import tenet.mixnet.node_runtime, tenet.experts.client, tenet.experts.matcher, nacl, kademlia'
_works() { [ -x "$1" ] && "$1" -c "$DEPS" >/dev/null 2>&1; }
resolve_python() {
  for c in "$ROOT/.venv/bin/python" "$ROOT/build/demo-venv/bin/python"; do
    _works "$c" && { echo "$c"; return 0; }
  done
  if command -v python3 >/dev/null 2>&1 && python3 -c "$DEPS" >/dev/null 2>&1; then
    echo python3; return 0
  fi
  echo "[net] one-time setup: building a venv with the demo deps (Python 3.13)…" >&2
  if command -v uv >/dev/null 2>&1; then
    { uv venv --python 3.13 "$ROOT/.venv" || uv venv "$ROOT/.venv"; } >/dev/null 2>&1 || true
    uv pip install --python "$ROOT/.venv/bin/python" -q -e "$ROOT" \
      kademlia dilithium-py "aioquic>=1.3.0" pynacl cryptography pqcrypto rpcudp >/dev/null 2>&1 || true
  else
    { python3 -m venv "$ROOT/.venv" && "$ROOT/.venv/bin/pip" install -q -U pip \
      && "$ROOT/.venv/bin/pip" install -q -e "$ROOT" kademlia dilithium-py "aioquic>=1.3.0" \
         pynacl cryptography pqcrypto rpcudp; } >/dev/null 2>&1 || true
  fi
  _works "$ROOT/.venv/bin/python" && { echo "$ROOT/.venv/bin/python"; return 0; }
  echo "[net] could not set up the venv automatically. Run once, then retry:" >&2
  echo "      cd $ROOT && uv venv --python 3.13 .venv && uv pip install -e . kademlia dilithium-py 'aioquic>=1.3.0'" >&2
  return 1
}
PY="$(resolve_python)" || exit 1

case "$CMD" in
  serve)
    exec env TENET_NET_DIR="$DIR" "$PY" "$ROOT/scripts/demo/berlin_serve.py" ;;
  ask)
    exec env TENET_NET_DIR="$DIR" "$PY" "$ROOT/scripts/demo/berlin_ask.py" "$@" ;;
  split)
    command -v tmux >/dev/null 2>&1 || { echo "[net] tmux required for split"; exit 1; }
    S="tenet-net"
    pkill -f "scripts/demo/berlin_serve.py" 2>/dev/null || true   # kill any stale server (frees ports)
    tmux kill-session -t "$S" 2>/dev/null || true
    sleep 0.3
    mkdir -p "$DIR"; rm -f "$DIR/askpack.json"
    tmux new-session -d -s "$S" -x "$(tput cols 2>/dev/null || echo 212)" -y "$(tput lines 2>/dev/null || echo 50)"
    tmux set-option -t "$S" status off
    tmux set-option -t "$S" remain-on-exit on
    tmux set-option -t "$S" pane-border-status top
    tmux set-option -t "$S" pane-border-format " #{pane_title} "
    # LEFT (0) = ASKER — your agent (waits for the node, routes, one key exits both)
    tmux select-pane -t "$S":0.0 -T "ASKER  ·  berlin_ask.py (process 1)"
    tmux send-keys -t "$S":0.0 \
      "clear; printf '  \033[2mconnecting to the expert node…\033[0m\n'; while [ ! -f '$DIR/askpack.json' ]; do sleep 0.3; done; sleep 1; TENET_NET_DIR='$DIR' '$PY' '$ROOT/scripts/demo/berlin_ask.py' $*; printf '\n  \033[2m── demo complete · Ctrl-b then & to exit ──\033[0m\n'" C-m
    # RIGHT (1) = EXPERT NODE — the persistent server
    tmux split-window -h -t "$S":0
    tmux select-pane -t "$S":0.1 -T "EXPERT NODE  ·  berlin_serve.py (process 2)"
    tmux send-keys -t "$S":0.1 "clear; TENET_NET_DIR='$DIR' '$PY' '$ROOT/scripts/demo/berlin_serve.py'" C-m
    tmux select-pane -t "$S":0.0
    # Attach (or switch, if already inside tmux). Never let a failed attach kill
    # the script silently — tell the user how to reach the session.
    if [ -n "${TMUX:-}" ]; then
      tmux switch-client -t "$S" 2>/dev/null || echo "[net] session ready → run:  tmux attach -t $S"
    else
      tmux attach -t "$S" 2>/dev/null || echo "[net] session ready → run:  tmux attach -t $S"
    fi ;;
  *)
    echo "usage: net.sh [split|serve|ask]"; exit 1 ;;
esac
