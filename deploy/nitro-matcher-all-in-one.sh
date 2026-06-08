#!/usr/bin/env bash
# End-to-end Nitro matcher deploy — run on a Nitro-enabled Amazon Linux instance.
#
# Prereqs: git, docker, rust/cargo (or pre-built bountynet-bin), python3, pip.
# Instance: e.g. m5.xlarge with --enclave-options Enabled=true.
#
# Usage (from anywhere):
#   curl -fsSL .../nitro-matcher-all-in-one.sh | bash
# Or clone tenet and:
#   ATTESTED_WORKLOAD_SHA=79a5ea2 ./deploy/nitro-matcher-all-in-one.sh
#
# Env:
#   TENET_REPO          default: clone maceip/tenet into $WORK/tenet
#   ATTESTED_WORKLOAD_* pin + path (see STATUS.md item 9)
#   ACME_FLAG=""        skip Let's Encrypt (staging / self-signed)
#   SKIP_RUN=1          build EIF only, do not run enclave
set -euo pipefail

SHA="${ATTESTED_WORKLOAD_SHA:-79a5ea2328f2b30192e57b53913355dcd5e0201e}"
WORK="${WORK:-$HOME/tenet-nitro-deploy}"
REPO="${TENET_REPO:-$WORK/tenet}"
AW="${ATTESTED_WORKLOAD_REPO:-$WORK/attested-workload}"

mkdir -p "$WORK"

if [[ ! -d "$REPO/.git" ]]; then
  echo "[runbook] clone tenet"
  git clone https://github.com/maceip/tenet.git "$REPO"
fi

if [[ ! -d "$AW/.git" ]]; then
  echo "[runbook] clone attested-workload"
  git clone https://github.com/maceip/attested-workload.git "$AW"
fi

echo "[runbook] assemble matcher EIF (attested-workload @ $SHA)"
export ATTESTED_WORKLOAD_REPO="$AW"
export ATTESTED_WORKLOAD_SHA="$SHA"
"$REPO/deploy/assemble-matcher-eif.sh"

EIF_DIR="$REPO/deploy/eif-build"
sudo install -m 755 "$EIF_DIR/bountynet-bin" /usr/local/bin/bountynet

echo "[runbook] PCR0 / Value X reference saved to $WORK/measurements.txt"
(
  cd "$EIF_DIR"
  docker build -t matcher-real:latest .
  nitro-cli build-enclave --docker-uri matcher-real:latest --output-file "$WORK/matcher.eif"
  nitro-cli describe-eif --eif-path "$WORK/matcher.eif"
) | tee "$WORK/measurements.txt"

if [[ "${SKIP_RUN:-0}" == "1" ]]; then
  echo "[runbook] SKIP_RUN=1 — EIF at $WORK/matcher.eif"
  exit 0
fi

echo "[runbook] run enclave + parent proxy (blocks; Ctrl-C to stop)"
cd "$EIF_DIR"
export EIF="$WORK/matcher.eif"
export DOCKERFILE=Dockerfile
exec "$REPO/deploy/nitro-deploy.sh"
