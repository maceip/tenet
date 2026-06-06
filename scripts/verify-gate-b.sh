#!/usr/bin/env bash
# Legacy filename. Network beta verification checklist (items 10–15).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "[verify-gate-b] item 10 — relay security regression tests"
python3 -m pytest -q \
  tests/test_por_supernode_security.py \
  tests/test_reach_client.py

echo "[verify-gate-b] item 14 — EIF entry is matcher-only (no stub fleet in default entry)"
if grep -q run_matcher_live "$ROOT/deploy/entry-matcher.sh"; then
  echo "[verify-gate-b] FAIL: entry-matcher.sh still starts stub fleet" >&2
  exit 1
fi
test -f "$ROOT/deploy/data/beta/snapshot.json"
test -f "$ROOT/deploy/data/beta/mailbox.json"

echo "[verify-gate-b] configs"
for f in config/templates/live-reach-relay.json config/templates/live-mailbox-client.json config/templates/expert-laptop.json; do
  test -f "$ROOT/$f"
done

ENV_FILE="$ROOT/config/beta-secrets.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  if [[ "${REACH_RELAY_HOST:-}" != "REPLACE_WITH_PUBLIC_IP" && -n "${REACH_RELAY_HOST:-}" ]]; then
    if [[ -f "$ROOT/config/live-reach-relay.json" ]]; then
      echo "[verify-gate-b] item 11 — live reach relay register"
      "$ROOT/scripts/verify-reach-relay.sh"
    else
      echo "[verify-gate-b] render configs: ./scripts/render-beta-config.sh"
    fi
    if command -v aw >/dev/null 2>&1 && [[ -f "$ROOT/config/live-mailbox-client.json" ]]; then
      echo "[verify-gate-b] item 13 — attested enclave send (requires expert + TEE beta data)"
      python3 -m tenet enclave send \
        --mailbox-config "$ROOT/config/live-mailbox-client.json" \
        --prompt "Network beta verification ping." \
        --timeout 60 \
        --json || echo "[verify-gate-b] send failed — expert/TEE/mailbox not ready (expected until ops complete)"
    fi
  else
    echo "[verify-gate-b] set REACH_RELAY_HOST in config/beta-secrets.env for live items 11–13"
  fi
else
  echo "[verify-gate-b] run ./scripts/init-beta-secrets.sh for live path"
fi

echo "[verify-gate-b] code checks OK — see STATUS.md for current runtime proof"
