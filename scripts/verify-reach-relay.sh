#!/usr/bin/env bash
# Verify public reachability relay REACH register/confirm (item 11).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${BETA_SECRETS:-$ROOT/config/beta-secrets.env}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

HOST="${REACH_RELAY_HOST:-}"
PORT="${REACH_RELAY_PORT:-4433}"
PEER_ID="${VERIFY_PEER_ID:-reach-verify-peer}"

if [[ -z "$HOST" || "$HOST" == "REPLACE_WITH_PUBLIC_IP" ]]; then
  echo "[verify-reach-relay] set REACH_RELAY_HOST in config/beta-secrets.env" >&2
  exit 1
fi

python3 - <<PY
import socket
from tenet.mixnet.reach_client import ReachRelayEndpoint, register_with_relay

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3.0)
register_with_relay(sock, ReachRelayEndpoint("${HOST}", int(${PORT})), "${PEER_ID}")
print("[verify-reach-relay] OK register+confirm ${HOST}:${PORT} peer=${PEER_ID}")
PY
