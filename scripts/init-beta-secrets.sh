#!/usr/bin/env bash
# Generate local beta secrets and render config/*.json from templates (items 11–13).
#
# Usage:
#   ./scripts/init-beta-secrets.sh
#   # edit config/beta-secrets.env — set REACH_RELAY_HOST to public IP
#   ./scripts/render-beta-config.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/config/beta-secrets.env"

python3 - "$OUT" <<'PY'
import secrets
import sys
import os
from pathlib import Path

from tenet.packet.OutfoxParams import KEM_X25519

out = Path(sys.argv[1])

relay_secret = secrets.token_hex(32)
handle_secret = secrets.token_hex(32)
relay_kem_pk, relay_kem_sk = KEM_X25519.keygen()
expert_kem_pk, expert_kem_sk = KEM_X25519.keygen()
relay_host = os.environ.get("REACH_RELAY_HOST", "REPLACE_WITH_PUBLIC_IP")
relay_port = os.environ.get("REACH_RELAY_PORT", "4433")
relay_id = os.environ.get("REACH_RELAY_ID", "reach-beta-1")

out.write_text(
    "\n".join(
        [
            f"RELAY_SECRET_HEX={relay_secret}",
            f"RELAY_VERIFY_KEY_HEX={relay_secret}",
            f"RELAY_KEM_PK_HEX={relay_kem_pk.hex()}",
            f"RELAY_KEM_SK_HEX={relay_kem_sk.hex()}",
            f"EXPERT_KEM_PK_HEX={expert_kem_pk.hex()}",
            f"EXPERT_KEM_SK_HEX={expert_kem_sk.hex()}",
            f"HANDLE_SECRET_HEX={handle_secret}",
            f"REACH_RELAY_HOST={relay_host}",
            f"REACH_RELAY_PORT={relay_port}",
            f"REACH_RELAY_ID={relay_id}",
            "",
        ]
    ),
    encoding="utf-8",
)
PY

echo "[init-beta-secrets] wrote $OUT"
echo "[init-beta-secrets] set REACH_RELAY_HOST then:"
echo "  ./scripts/render-beta-config.sh"
echo "  ./scripts/render-join-pack.sh"
