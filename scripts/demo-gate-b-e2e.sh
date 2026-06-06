#!/usr/bin/env bash
# Legacy filename. Item 13 asker path: attested match → relay → remote expert.
#
# Prerequisites (see STATUS.md):
#   - Public relay running (item 11)
#   - Expert laptop running with REACH + real provider (item 12)
#   - TEE redeployed with deploy/data/beta snapshot+mailbox (item 14)
#   - ./scripts/render-beta-config.sh after setting REACH_RELAY_HOST
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

MAILBOX_CFG="${MAILBOX_CONFIG:-$ROOT/config/live-mailbox-client.json}"
ENCLAVE_CFG="${ENCLAVE_CONFIG:-$ROOT/config/live-enclave.json}"
PROMPT="${1:-Tell me about Monet and impressionist painting techniques.}"

if [[ ! -f "$MAILBOX_CFG" ]]; then
  echo "[network-beta] missing $MAILBOX_CFG — run init-beta-secrets + render-beta-config" >&2
  exit 1
fi
if ! command -v aw >/dev/null 2>&1; then
  echo "[network-beta] aw not on PATH — run ./scripts/install-aw.sh" >&2
  exit 1
fi

echo "[network-beta] 1/3 enclave check"
python3 -m tenet enclave check --config "$ENCLAVE_CFG" --json

echo "[network-beta] 2/3 reach relay (optional if REACH_RELAY_HOST set)"
if [[ -f "$ROOT/config/beta-secrets.env" ]]; then
  # shellcheck disable=SC1090
  source "$ROOT/config/beta-secrets.env"
fi
if [[ -n "${REACH_RELAY_HOST:-}" && "${REACH_RELAY_HOST}" != "REPLACE_WITH_PUBLIC_IP" ]]; then
  "$ROOT/scripts/verify-reach-relay.sh"
fi

echo "[network-beta] 3/3 enclave send (real expert — not in-TEE stub)"
python3 -m tenet enclave send \
  --config "$ENCLAVE_CFG" \
  --mailbox-config "$MAILBOX_CFG" \
  --prompt "$PROMPT" \
  --timeout "${GATE_B_TIMEOUT:-120}" \
  --json
