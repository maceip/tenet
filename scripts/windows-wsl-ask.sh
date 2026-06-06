#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
BASE=/mnt/c/Users/mac/tenet
SRC="$HOME/tenet-src"
mkdir -p "$SRC"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete "$BASE/" "$SRC/"
else
  rm -rf "$SRC"/* "$SRC"/.[!.]* 2>/dev/null || true
  cp -a "$BASE"/. "$SRC/"
fi
cd "$SRC"
if [[ ! -f tenet/edges/cli/main.py ]]; then
  tar xzf "$BASE/sphinx-tahoe.tgz" -C "$SRC"
fi

PY=python3
if ! "$PY" -c 'import tenet' 2>/dev/null; then
  pip3 install --break-system-packages -q -e . || pip3 install --user -q -e .
fi

if ! command -v aw >/dev/null 2>&1; then
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  cargo install --git https://github.com/maceip/attested-workload \
    --rev 79a5ea2328f2b30192e57b53913355dcd5e0201e --bin aw --force
fi

PROMPT="${PROMPT:-In one sentence, name one Monet painting technique.}"
"$PY" -m tenet ask \
  --join-pack config/join-pack.json \
  --prompt "$PROMPT" \
  --timeout "${TIMEOUT:-120}" \
  --json
