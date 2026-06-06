#!/usr/bin/env bash
echo "[provision] use ./scripts/gate-b/provision-network.sh" >&2
exec "$(cd "$(dirname "$0")" && pwd)/provision-network.sh" "$@"
