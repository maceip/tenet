#!/usr/bin/env bash
# Build bountynet-bin from attested-workload for tenet EIF images.
#
# Usage:
#   ATTESTED_WORKLOAD_REPO=~/attested-workload ATTESTED_WORKLOAD_SHA=<git-sha> \
#     ./deploy/build-bountynet-bin.sh
#
# Writes ./bountynet-bin in the current directory (typically tenet repo root).
set -euo pipefail

REPO="${ATTESTED_WORKLOAD_REPO:-$HOME/attested-workload}"
SHA="${ATTESTED_WORKLOAD_SHA:-}"
OUT="${1:-./bountynet-bin}"
case "$OUT" in
  /*) ;;
  *) OUT="$(pwd)/$OUT" ;;
esac
mkdir -p "$(dirname "$OUT")"

if [[ ! -d "$REPO/.git" ]]; then
  echo "[build-bountynet-bin] clone attested-workload into $REPO first" >&2
  exit 1
fi

pushd "$REPO" >/dev/null
SAVED_REF="$(git rev-parse HEAD 2>/dev/null || true)"
if [[ -n "$SHA" ]]; then
  git fetch --quiet origin 2>/dev/null || true
  git checkout "$SHA"
fi
echo "[build-bountynet-bin] attested-workload $(git rev-parse --short HEAD)"
cargo build --release --bin bountynet
cp target/release/bountynet "$OUT"
if [[ -n "$SHA" && -n "$SAVED_REF" ]]; then
  git checkout "$SAVED_REF" 2>/dev/null || git checkout main 2>/dev/null || true
fi
popd >/dev/null
echo "[build-bountynet-bin] wrote $OUT"
