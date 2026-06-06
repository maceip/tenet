#!/bin/sh
# The in-TEE workload bountynet launches and fronts with attested TLS (STATUS.md item 9).
#
# Binds the matcher/mailbox server to loopback; bountynet bridges vsock ->
# 127.0.0.1:9384 and terminates TLS *inside* the enclave (so the cert SPKI the
# EAT binds to is a TEE-resident key — see STATUS.md item 9).
#
# SNAPSHOT  public directory snapshot (URL or baked-in path) — matcher input
# MAILBOX   private handle->reachability file the enclave holds (mailbox input;
#           NOT public, per the #4 opaque-handle rule)
set -eu

SNAPSHOT="${SNAPSHOT:-/app/data/snapshot.json}"
MAILBOX="${MAILBOX:-/app/data/mailbox.json}"
PORT="${ENCLAVE_PLANE_PORT:-9384}"

exec python3 -m tenet.enclave_plane_server \
    --snapshot "${SNAPSHOT}" \
    --mailbox "${MAILBOX}" \
    --host 127.0.0.1 \
    --port "${PORT}"
