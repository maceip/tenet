#!/usr/bin/env bash
# Stage a Docker build context for the real-matcher Nitro EIF.
#
# Output: deploy/eif-build/  (docker build -f Dockerfile.matcher-real .)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/deploy/eif-build"
SHA="${ATTESTED_WORKLOAD_SHA:-79a5ea2328f2b30192e57b53913355dcd5e0201e}"

rm -rf "$OUT"
mkdir -p "$OUT/app"

echo "[assemble] bountynet-bin from attested-workload @ $SHA"
ATTESTED_WORKLOAD_SHA="$SHA" "$ROOT/deploy/build-bountynet-bin.sh" "$OUT/bountynet-bin"

echo "[assemble] matcher workload"
cp -R "$ROOT/tenet" "$OUT/app/"
cp "$ROOT/deploy/run_matcher_live.py" "$OUT/app/"
cp -R "$ROOT/deploy/data" "$OUT/app/data"
cp "$ROOT/deploy/run_matcher.py" "$OUT/app/"
cp "$ROOT/deploy/entry-matcher-stub.sh" "$OUT/entry-matcher-stub.sh"
cp -R "$ROOT/oblivious-core" "$OUT/oblivious-core"
rm -rf "$OUT/oblivious-core/target"
cp "$ROOT/deploy/entry-matcher.sh" "$OUT/"
cp "$ROOT/deploy/Dockerfile.matcher-real" "$OUT/Dockerfile"

echo "[assemble] ready: cd deploy/eif-build && docker build -t matcher-real ."
echo "[assemble] attested-workload pin: $SHA"
