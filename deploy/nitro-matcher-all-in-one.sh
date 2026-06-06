#!/usr/bin/env bash
# End-to-end Nitro matcher deploy — run on a Nitro-enabled Amazon Linux instance.
#
# Prereqs: git, docker, rust/cargo (or pre-built bountynet-bin), python3, pip.
# Instance: e.g. m5.xlarge with --enclave-options Enabled=true.
#
# Usage (from anywhere):
#   curl -fsSL .../nitro-matcher-all-in-one.sh | bash
# Or clone sphinx-tahoe and:
#   ATTESTED_WORKLOAD_SHA=79a5ea2 ./deploy/nitro-matcher-all-in-one.sh
#
# Env:
#   SPHINX_TAHOE_REPO   default: clone maceip/sphinx-tahoe
#   ATTESTED_WORKLOAD_* pin + path (see STATUS.md item 9)
#   ACME_FLAG=""        skip Let's Encrypt (staging / self-signed)
#   SKIP_RUN=1          build EIF only, do not run enclave
set -euo pipefail

SHA="${ATTESTED_WORKLOAD_SHA:-79a5ea2328f2b30192e57b53913355dcd5e0201e}"
WORK="${WORK:-$HOME/tenet-nitro-deploy}"
SPHINX="${SPHINX_TAHOE_REPO:-$WORK/sphinx-tahoe}"
AW="${ATTESTED_WORKLOAD_REPO:-$WORK/attested-workload}"

mkdir -p "$WORK"

if [[ ! -d "$SPHINX/.git" ]]; then
  echo "[runbook] clone sphinx-tahoe"
  git clone https://github.com/maceip/sphinx-tahoe.git "$SPHINX"
fi

if [[ ! -d "$AW/.git" ]]; then
  echo "[runbook] clone attested-workload"
  git clone https://github.com/maceip/attested-workload.git "$AW"
fi

echo "[runbook] assemble matcher EIF (attested-workload @ $SHA)"
export ATTESTED_WORKLOAD_REPO="$AW"
export ATTESTED_WORKLOAD_SHA="$SHA"
"$SPHINX/deploy/assemble-matcher-eif.sh"

EIF_DIR="$SPHINX/deploy/eif-build"
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
exec "$SPHINX/deploy/nitro-deploy.sh"
