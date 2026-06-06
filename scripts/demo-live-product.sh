#!/usr/bin/env bash
# Product demo: attested live matcher end-to-end (trust + match, no mixnet yet).
#
# Usage:
#   ./scripts/install-aw.sh    # once
#   ./scripts/demo-live-product.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "=== Step 1: verify live attestation + policy ==="
"$ROOT/scripts/verify-live.sh"

echo
echo "=== Step 2: attested expert match (Monet domain) ==="
python3 -m tenet enclave match --prompt "Tell me about Monet and impressionist painting techniques."

echo
echo "=== Step 3: attested expert match (Rust domain) ==="
python3 -m tenet enclave match --prompt "Explain Rust ownership and the borrow checker."

echo
echo "=== Step 4: expert-mode route plan (pre-mixnet) ==="
python3 -m tenet enclave plan --prompt "Tell me about Monet and impressionist painting."

echo
echo "=== Step 5: TEE mailbox send (stub expert — not item 13) ==="
"$ROOT/scripts/demo-live-mailbox-e2e.sh"

echo
echo "=== demo complete ==="
echo "Items 4, 5, 9: attested verify + match + plan."
echo "Step 5 is an in-enclave stub path only — see STATUS.md Commands."
