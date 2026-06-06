#!/usr/bin/env bash
# Verify the live attested matcher (aw check + healthz).
#
# Usage:
#   ./scripts/install-aw.sh          # once
#   ./scripts/verify-live.sh
#   ./scripts/verify-live.sh https://other-host/
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=pinned-sha.sh
. "$ROOT/scripts/pinned-sha.sh"

URL="${1:-$LIVE_ENCLAVE_URL}"
AW_BIN="${AW_BIN:-aw}"

if ! command -v "$AW_BIN" >/dev/null 2>&1; then
  echo "[verify-live] $AW_BIN not found — run: ./scripts/install-aw.sh" >&2
  exit 1
fi

URL="${URL%/}/"
HOST="${URL#https://}"
HOST="${HOST%%/*}"
PUBLIC_IP="$(dig +short "$HOST" @8.8.8.8 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
LOCAL_IP="$(dig +short "$HOST" 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
curl_healthz() {
  if [[ -n "$PUBLIC_IP" && "$LOCAL_IP" != "$PUBLIC_IP" ]]; then
    curl -fsS --resolve "${HOST}:443:${PUBLIC_IP}" "${URL}healthz"
  else
    curl -fsS "${URL}healthz"
  fi
}
if [[ -n "$PUBLIC_IP" && "$LOCAL_IP" != "$PUBLIC_IP" ]]; then
  echo "[verify-live] local DNS=${LOCAL_IP:-none} public DNS=${PUBLIC_IP}" >&2
  echo "[verify-live] using curl --resolve; flush cache or add /etc/hosts for aw check" >&2
fi

echo "[verify-live] attestation (pinned engine ${ATTESTED_WORKLOAD_SHORT})"
if ! AW_BIN="$AW_BIN" "$ROOT/deploy/verify-enclave.sh" "$URL"; then
  if [[ -n "$PUBLIC_IP" ]]; then
    echo "[verify-live] if aw failed: echo '${PUBLIC_IP} ${HOST}' | sudo tee -a /etc/hosts" >&2
  fi
  exit 1
fi

echo "[verify-live] healthz"
if command -v curl >/dev/null 2>&1; then
  curl_healthz
  echo
else
  python3 - <<PY
import json, urllib.request
print(json.load(urllib.request.urlopen("${URL}healthz", timeout=15)))
PY
fi

echo "[verify-live] client policy check (config + AttestedEnclavePlaneClient)"
python3 -m tenet enclave check --config "$ROOT/$LIVE_ENCLAVE_CONFIG"

echo "[verify-live] ok"
