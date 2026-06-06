#!/usr/bin/env bash
# AWS Nitro deploy for the tenet matcher TEE image (STATUS.md item 9).
#
# Prereqs: Nitro-enabled EC2, docker, aws-nitro-enclaves-cli, build context with
# bountynet-bin (see assemble-matcher-eif.sh or build-bountynet-bin.sh).
#
# Engine: https://github.com/maceip/attested-workload (pin in STATUS.md item 9)
set -euo pipefail

IMAGE="${IMAGE:-matcher-real}"
EIF="${EIF:-matcher.eif}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MIB="${MEMORY_MIB:-2048}"
PROXY_PORT="${PROXY_PORT:-443}"
ACME_FLAG="${ACME_FLAG:---acme}"
BOUNTYNET="${BOUNTYNET_BIN:-bountynet}"

if [[ -x ./bountynet-bin ]]; then
  BOUNTYNET="$(pwd)/bountynet-bin"
elif ! command -v "$BOUNTYNET" >/dev/null 2>&1; then
  echo "[deploy] bountynet not found; set BOUNTYNET_BIN or run from eif-build with ./bountynet-bin" >&2
  exit 1
fi

echo "[deploy] one-time host setup (idempotent)"
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y 2>/dev/null || true
sudo systemctl enable --now nitro-enclaves-allocator

echo "[deploy] build the EIF (reproducible -> PCR0 / Value X)"
if [[ ! -f "${EIF}" ]]; then
  docker build -t "${IMAGE}:latest" -f "${DOCKERFILE}" .
  nitro-cli build-enclave --docker-uri "${IMAGE}:latest" --output-file "${EIF}"
fi
nitro-cli describe-eif --eif-path "${EIF}" | python3 -c \
  'import sys,json;m=json.load(sys.stdin)["Measurements"];print("[deploy] PCR0 =",m["PCR0"])'

echo "[deploy] run the enclave"
sudo nitro-cli run-enclave \
    --cpu-count "${CPU_COUNT}" --memory "${MEMORY_MIB}" --eif-path "${EIF}"
CID=$(nitro-cli describe-enclaves \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["EnclaveCID"])')
echo "[deploy] enclave CID = ${CID}"

echo "[deploy] parent vsock bridge (TLS terminates IN the enclave; app-proxy on :8080)"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[deploy] binding :443 requires root; re-exec with sudo" >&2
  exec sudo -E env PATH="$PATH" BOUNTYNET_BIN="$BOUNTYNET" "$0" "$@"
fi
"$BOUNTYNET" proxy --cid "${CID}" --port "${PROXY_PORT}" ${ACME_FLAG}

echo "[deploy] up. verify:  aw check --json https://<this-host>/"
