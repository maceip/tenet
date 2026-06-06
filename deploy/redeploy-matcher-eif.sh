#!/usr/bin/env bash
# Replace the running Nitro matcher enclave with a new EIF (changes Value X + URL).
#
# Run ON the Nitro host (not from a laptop). Requires wildcard DNS (*.aeon.site → EIP)
# or a DNS update for the new {value_x_prefix}.aeon.site before ACME succeeds.
#
# Usage:
#   EIF=~/tenet-nitro-deploy/matcher-rust.eif ./deploy/redeploy-matcher-eif.sh
set -euo pipefail

EIF="${EIF:-}"
BOUNTYNET="${BOUNTYNET_BIN:-/usr/local/bin/bountynet}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
LOG="${LOG:-$HOME/redeploy-matcher.log}"

if [[ -z "$EIF" || ! -f "$EIF" ]]; then
  echo "usage: EIF=/path/to/matcher.eif $0" >&2
  exit 2
fi

: >"$LOG"
exec >>"$LOG" 2>&1
echo "[redeploy] $(date -Is) EIF=$EIF"

nitro-cli describe-eif --eif-path "$EIF" | tee /tmp/eif-measurements.json

sudo pkill -f "bountynet proxy" 2>/dev/null || true
sleep 2

if nitro-cli describe-enclaves 2>/dev/null | grep -q EnclaveCID; then
  ENCLAVE_ID=$(nitro-cli describe-enclaves | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["EnclaveID"])')
  echo "[redeploy] terminate $ENCLAVE_ID"
  sudo nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" || sudo nitro-cli terminate-enclave --all
  sleep 5
fi

echo "[redeploy] run enclave cid=$ENCLAVE_CID"
sudo nitro-cli run-enclave --cpu-count 2 --memory 2048 --eif-path "$EIF" --enclave-cid "$ENCLAVE_CID"
CID=$(nitro-cli describe-enclaves | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["EnclaveCID"])')

echo "[redeploy] proxy --acme cid=$CID"
nohup sudo "$BOUNTYNET" proxy --cid "$CID" --port 443 --acme >>"$LOG" 2>&1 &
sleep 10

for i in $(seq 1 60); do
  if OUT=$("$BOUNTYNET" check --json "https://127.0.0.1/" 2>/dev/null || /usr/local/bin/aw check --json "https://127.0.0.1/" 2>/dev/null); then
    echo "$OUT" >/tmp/aw-check.json
    if echo "$OUT" | grep -q value_x; then
      echo "[redeploy] attestation ok attempt=$i"
      echo "$OUT" | python3 -c 'import sys,json;j=json.load(sys.stdin);vx=j["value_x"];print("value_x",vx);print("domain",vx[:12]+".aeon.site");print("tls_spki_hash",j.get("tls_spki_hash"))'
      exit 0
    fi
  fi
  echo "[redeploy] waiting attestation $i/60"
  sleep 5
done

echo "[redeploy] timed out — see $LOG" >&2
exit 1
