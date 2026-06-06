#!/usr/bin/env bash
# Render config/join-pack.json (public pins for askers).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/scripts/render-join-pack.py"
