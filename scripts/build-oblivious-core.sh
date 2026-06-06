#!/usr/bin/env bash
# Build/install the PyO3 extension for oblivious-core (optional matcher hardening).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/oblivious-core"

if [[ -d "$ROOT/.venv" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/.venv/bin/activate"
fi

if ! command -v maturin >/dev/null 2>&1; then
  echo "[oblivious-core] installing maturin"
  python3 -m pip install -q maturin
fi

echo "[oblivious-core] maturin develop --release --features python"
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY="${PYO3_USE_ABI3_FORWARD_COMPATIBILITY:-1}"
maturin develop --release --features python

python3 -c "import oblivious_core; print('[oblivious-core] ok', oblivious_core.oblivious_top_k_py([5,1,9,3], 2))"
