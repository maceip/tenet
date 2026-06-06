#!/usr/bin/env bash
# Item 15 multi-node path (legacy scripts/gate-b/* implementation).
set -euo pipefail
exec "$(cd "$(dirname "$0")/.." && pwd)/scripts/gate-b/run-network.sh" "$@"
