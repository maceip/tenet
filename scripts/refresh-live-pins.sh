#!/usr/bin/env bash
# Refresh config/live-enclave.json pins from live `aw check --json`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=pinned-sha.sh
. "$ROOT/scripts/pinned-sha.sh"
CFG="${LIVE_ENCLAVE_CONFIG:-$ROOT/config/live-enclave.json}"
URL="${1:-}"
if [[ -z "$URL" ]]; then
  URL="$(python3 -c "import json; print(json.load(open('$CFG'))['url'])")"
fi
URL="${URL%/}/"

export PATH="${HOME}/.cargo/bin:${PATH:-}"
command -v aw >/dev/null || "$ROOT/scripts/install-aw.sh"

python3 <<PY
import json, subprocess
from pathlib import Path

url = "$URL"
raw = subprocess.check_output(["aw", "check", "--json", url], text=True)
for line in raw.splitlines():
    if line.startswith("{"):
        check = json.loads(line)
        break
else:
    raise SystemExit("no JSON from aw check")

cfg_path = Path("$CFG")
cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
cfg["url"] = url
cfg["approved_value_x"] = [check["value_x"]]
cfg["tls_spki_hash"] = check["tls_spki_hash"]
cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
print(f"[refresh-pins] {cfg_path}")
print(f"[refresh-pins] value_x={check['value_x'][:16]}...")
print(f"[refresh-pins] spki={check['tls_spki_hash'][:16]}...")
PY

"$ROOT/scripts/render-join-pack.sh"
