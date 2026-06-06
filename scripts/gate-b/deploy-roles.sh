#!/usr/bin/env bash
echo "[deploy] use ./scripts/gate-b/deploy-nodes.sh" >&2
exec "$(cd "$(dirname "$0")" && pwd)/deploy-nodes.sh" "$@"
