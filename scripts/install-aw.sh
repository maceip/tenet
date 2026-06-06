#!/usr/bin/env bash
# Install the pinned `aw` verifier from attested-workload.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=pinned-sha.sh
. "$ROOT/scripts/pinned-sha.sh"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[install-aw] cargo not found; install Rust from https://rustup.rs" >&2
  exit 1
fi

echo "[install-aw] installing aw @ ${ATTESTED_WORKLOAD_SHORT} (${ATTESTED_WORKLOAD_SHA})"
cargo install \
  --git https://github.com/maceip/attested-workload \
  --rev "$ATTESTED_WORKLOAD_SHA" \
  --bin aw \
  --force

echo "[install-aw] $(command -v aw)"
aw check --help >/dev/null 2>&1 || true
echo "[install-aw] done — verify with: ./scripts/verify-live.sh"
