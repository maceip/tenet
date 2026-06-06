#!/bin/sh
# Legacy EIF entry (stand-in plane). Superseded by `entry-matcher.sh` +
# `Dockerfile.matcher-real`, which use attested-workload app-proxy (live Jun 3).
# Kept for older `Dockerfile.enclave` recipes only.
set -eu

# 1) matcher/mailbox workload on loopback (our code; unit-tested)
/usr/local/bin/enclave-workload.sh &
WORKLOAD_PID=$!

# 2) bountynet: attest the image + serve attestation/EAT over vsock-TLS.
#    `enclave /app --cmd true` ratchets + measures /app (no build for Python),
#    collects the quote, and serves. Parent runs `bountynet proxy --cid <cid>`.
bountynet enclave /app --cmd true &
BOUNTYNET_PID=$!

# Exit if either dies; surface which one.
wait -n "${WORKLOAD_PID}" "${BOUNTYNET_PID}"
echo "[enclave-entry] a process exited; shutting down" >&2
kill "${WORKLOAD_PID}" "${BOUNTYNET_PID}" 2>/dev/null || true
exit 1
