#!/bin/sh
# EIF entry (item 14): matcher-only workload — no in-TEE stub expert fleet.
ip link set lo up 2>/dev/null || true
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
cd /app
SNAPSHOT="${SNAPSHOT:-/app/data/beta/snapshot.json}"
MAILBOX="${MAILBOX:-/app/data/beta/mailbox.json}"
PORT="${ENCLAVE_PLANE_PORT:-8080}"
PYTHONPATH=/app python3.11 -m tenet.enclave_plane_server \
  --snapshot "${SNAPSHOT}" \
  --mailbox "${MAILBOX}" \
  --host 127.0.0.1 \
  --port "${PORT}" &
exec bountynet enclave /app --cmd true
