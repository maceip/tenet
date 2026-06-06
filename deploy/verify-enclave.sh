#!/usr/bin/env bash
# Verify a deployed matcher enclave from any machine with `aw` installed.
#
# Usage:
#   ./deploy/verify-enclave.sh https://matcher.example/
#   ATTESTED_WORKLOAD_SHA=79a5ea2 ./deploy/verify-enclave.sh https://7d90e638b585.aeon.site/
set -euo pipefail

URL="${1:?usage: verify-enclave.sh https://host/}"
AW_BIN="${AW_BIN:-aw}"

if ! command -v "$AW_BIN" >/dev/null 2>&1; then
  echo "[verify] $AW_BIN not found; install from attested-workload:" >&2
  echo "  ./scripts/install-aw.sh" >&2
  echo "  # or: cargo install --git https://github.com/maceip/attested-workload --rev 79a5ea2 --bin aw" >&2
  exit 1
fi

URL="${URL%/}/"
echo "[verify] aw check --json $URL"
"$AW_BIN" check --json "$URL" | tee /dev/stderr | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
for line in raw.splitlines():
    if line.startswith("{"):
        j = json.loads(line)
        assert j.get("schema") == "runcard.check.v1", j
        print("[verify] OK platform=%s value_x=%s... tls_spki_hash=%s..." % (
            j.get("platform"), (j.get("value_x") or "")[:16], (j.get("tls_spki_hash") or "")[:16]))
        break
else:
    raise SystemExit("[verify] no JSON line in output")
'
