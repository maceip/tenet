#!/usr/bin/env bash
# Deploy asker source + pins to Windows host via SSH + WSL (item 15.5 second asker).
#
# Requires WSL2 mirrored networking for UDP return path from the public relay.
# This script installs scripts/wslconfig-mirrored into %USERPROFILE%\.wslconfig and
# runs `wsl --shutdown` (one-time; re-run is safe).
#
# Usage:
#   ./scripts/deploy-windows-asker.sh
#   PROMPT='...' ./scripts/deploy-windows-asker.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${WINDOWS_HOST:-192.168.0.180}"
USER="${WINDOWS_USER:-mac}"
SSH_KEY="${SSH_KEY:-}"
REMOTE_WIN='C:/Users/mac/tenet'
PROMPT="${PROMPT:-In one sentence, explain Monet brushwork and color in Impressionism.}"
TIMEOUT="${TIMEOUT:-120}"

SSH_OPTS=(-o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
[[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")

ssh_cmd() { ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@"; }
scp_cmd() { scp "${SSH_OPTS[@]}" "$@"; }

cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH:-}"
./scripts/refresh-live-pins.sh >/dev/null

ssh_cmd "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path 'C:\\Users\\mac\\tenet' | Out-Null\""
scp_cmd "$ROOT/scripts/wslconfig-mirrored" "${USER}@${HOST}:C:/Users/mac/.wslconfig"
scp_cmd "$ROOT/scripts/windows-wsl-ask.sh" "${USER}@${HOST}:${REMOTE_WIN}/windows-wsl-ask.sh"
scp_cmd "$ROOT/setup.py" "$ROOT/setup.cfg" "$ROOT/requirements.txt" \
  "${USER}@${HOST}:${REMOTE_WIN}/"
scp_cmd -r "$ROOT/por" "$ROOT/tenet.packet" "$ROOT/config" "${USER}@${HOST}:${REMOTE_WIN}/"

ssh_cmd "wsl --shutdown" || true
sleep 8

ssh_cmd "wsl -e bash --noprofile --norc -c \"$(printf '%q' "PROMPT=$PROMPT") $(printf '%q' "TIMEOUT=$TIMEOUT") /mnt/c/Users/mac/tenet/windows-wsl-ask.sh\""
