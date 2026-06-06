#!/usr/bin/env bash
# Run on tenet-matcher-nitro after DNS for <value_x>.aeon.site → this host's public IP.
set -euo pipefail

DOMAIN="${1:-7d90e638b585.aeon.site}"
EXPECTED_IP="${2:-3.121.69.82}"
CID="${3:-16}"
LOG=~/acme-provision.log

echo "[acme] expect ${DOMAIN} -> ${EXPECTED_IP}" | tee "$LOG"

for i in $(seq 1 60); do
  IP=$(dig +short "$DOMAIN" A | head -1)
  if [[ "$IP" == "$EXPECTED_IP" ]]; then
    echo "[acme] DNS OK ($IP)" | tee -a "$LOG"
    break
  fi
  echo "[acme] waiting DNS (got ${IP:-none}, want $EXPECTED_IP) attempt $i/60" | tee -a "$LOG"
  sleep 10
  if [[ $i -eq 60 ]]; then
    echo "[acme] DNS never matched; abort" | tee -a "$LOG"
    exit 1
  fi
done

sudo pkill -f "bountynet proxy" 2>/dev/null || true
sleep 2

echo "[acme] starting proxy with --acme" | tee -a "$LOG"
nohup sudo /usr/local/bin/bountynet proxy --cid "$CID" --port 443 --acme >> "$LOG" 2>&1 &
sleep 3

for i in $(seq 1 90); do
  if grep -q "ACME COMPLETE" "$LOG" 2>/dev/null; then
    echo "[acme] SUCCESS" | tee -a "$LOG"
    grep "ACME COMPLETE\|https://" "$LOG" | tail -3
    exit 0
  fi
  if grep -q "ACME\] FAILED" "$LOG" 2>/dev/null; then
    echo "[acme] FAILED" | tee -a "$LOG"
    tail -20 "$LOG"
    exit 1
  fi
  sleep 5
done

echo "[acme] timed out waiting for ACME" | tee -a "$LOG"
tail -30 "$LOG"
exit 1
