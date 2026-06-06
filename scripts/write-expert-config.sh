#!/usr/bin/env bash
# Render expert-laptop.json with the opaque handle from corpus + HANDLE_SECRET_HEX.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "${BETA_SECRETS:-$ROOT/config/beta-secrets.env}"
export REACH_RELAY_HOST="${REACH_RELAY_HOST:?set REACH_RELAY_HOST}"
bash "$ROOT/scripts/render-beta-config.sh"
HANDLE="$(
  cd "$ROOT" && PYTHONPATH=. python3 -c "
from tenet.handles import OpaqueHandleIssuer
from tenet.experts.memory_index import IndexConfig, build_memory_index
import os
corpus = os.environ.get('EXPERT_CORPUS', 'tests/fixtures/corpus/monet')
built = build_memory_index(IndexConfig(peer_id='expert', roots=(corpus,), created_at_iso='2026-06-04T00:00:00+00:00'))
issuer = OpaqueHandleIssuer(bytes.fromhex('${HANDLE_SECRET_HEX}'))
rec = issuer.record(peer_id='expert', manifest_digest=built.manifest.index_digest, mailbox_id='mailbox-beta')
print(rec.handle if isinstance(rec.handle, str) else rec.handle.token)
"
)"
sed -i.bak "s/REPLACE_WITH_OPAQUE_HANDLE/${HANDLE}/g" "$ROOT/config/expert-laptop.json"
echo "$HANDLE"
