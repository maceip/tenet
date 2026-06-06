#!/usr/bin/env bash
set -euo pipefail

# node-entry — entrypoint for tenet-node containers in the simulator (and general use).
#
# Environment / files provided by the simulator orchestrator:
#   TENET_NODE_ID          (required) e.g. "dht-1"
#   TENET_CONFIG_DIR       usually /etc/tenet
#     ${TENET_CONFIG_DIR}/node-config.json   (ClusterConfig slice or sim-specific wrapper)
#     ${TENET_CONFIG_DIR}/control-verify-keys.json (optional)
#     ${TENET_CONFIG_DIR}/bootstrap.json     (optional initial signed records)
#   TENET_DATA_DIR         /var/lib/tenet   (for PersistentControlStore if enabled)
#   TENET_LOG_DIR
#
# Optional env:
#   TENET_ROLE             (mixnode|relay|expert|any) passed to WireNodeRuntime
#   TENET_CONTROL_STORE    if set (or auto), enable durable control store under $TENET_DATA_DIR/control
#   TENET_ANTI_ENTROPY     seconds (default 0 = off for sim determinism unless asked)
#
# The entry can also do a dev-mode editable reinstall if /host-src is mounted
# (orchestrator sets this for fast local-docker iteration without full rebuilds).

CONFIG_DIR="${TENET_CONFIG_DIR:-/etc/tenet}"
DATA_DIR="${TENET_DATA_DIR:-/var/lib/tenet}"
LOG_DIR="${TENET_LOG_DIR:-/var/log/tenet}"
NODE_ID="${TENET_NODE_ID:-}"
ROLE="${TENET_ROLE:-any}"
CONTROL_STORE="${TENET_CONTROL_STORE:-1}"
ANTI_ENTROPY="${TENET_ANTI_ENTROPY:-0}"

mkdir -p "$DATA_DIR/control" "$LOG_DIR"

if [[ -z "$NODE_ID" ]]; then
  echo "TENET_NODE_ID is required" >&2
  exit 2
fi

# Dev convenience: if the orchestrator bind-mounted the live source at /host-src,
# reinstall editable so code changes are reflected without rebuilding the image.
if [[ -d /host-src ]]; then
  echo "[node-entry] /host-src present — reinstalling editable tenet from live tree" >&2
  uv pip install --system --no-cache -e /host-src || pip install --no-cache-dir -e /host-src || true
fi

NODE_CFG="$CONFIG_DIR/node-config.json"
VERIFY_KEYS="$CONFIG_DIR/control-verify-keys.json"
BOOTSTRAP="$CONFIG_DIR/bootstrap.json"

if [[ ! -f "$NODE_CFG" ]]; then
  echo "Missing $NODE_CFG (orchestrator must provide it)" >&2
  exit 3
fi

STORE_ARG=()
if [[ "$CONTROL_STORE" != "0" ]]; then
  STORE_ARG+=(--control-store-path "$DATA_DIR/control")
fi

VERIFY_ARG=()
if [[ -f "$VERIFY_KEYS" ]]; then
  VERIFY_ARG+=(--control-verify-keys "$VERIFY_KEYS")
fi

BOOTSTRAP_ARG=()
if [[ -f "$BOOTSTRAP" ]]; then
  BOOTSTRAP_ARG+=(--control-bootstrap-path "$BOOTSTRAP")
fi

ANTI_ARG=()
if [[ "$ANTI_ENTROPY" != "0" ]]; then
  ANTI_ARG+=(--control-anti-entropy-interval-seconds "$ANTI_ENTROPY")
fi

echo "[node-entry] starting node_id=$NODE_ID role=$ROLE cfg=$NODE_CFG" >&2

# Launch via the standalone node launcher (copied as a single file to avoid
# broad sim/ tree COPY issues in some Docker builders). It does exactly the
# same as the old -m sim.node_entry but is self-contained.
exec python /app/sim_node_launcher.py \
  --node-id "$NODE_ID" \
  --role "$ROLE" \
  --config "$NODE_CFG" \
  "${STORE_ARG[@]}" \
  "${VERIFY_ARG[@]}" \
  "${BOOTSTRAP_ARG[@]}" \
  "${ANTI_ARG[@]}" \
  "$@"
