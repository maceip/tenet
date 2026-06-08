# Shared attested-workload pin for tenet deploy scripts.
# Source from other scripts: . "$(dirname "$0")/pinned-sha.sh"

ATTESTED_WORKLOAD_REPO="${ATTESTED_WORKLOAD_REPO:-$HOME/attested-workload}"
ATTESTED_WORKLOAD_SHA="${ATTESTED_WORKLOAD_SHA:-79a5ea2328f2b30192e57b53913355dcd5e0201e}"
ATTESTED_WORKLOAD_SHORT="${ATTESTED_WORKLOAD_SHA:0:7}"
LIVE_ENCLAVE_URL="${TENET_LIVE_ENCLAVE_URL:-https://5faf834eac20.aeon.site/}"
LIVE_ENCLAVE_CONFIG="${TENET_LIVE_ENCLAVE_CONFIG:-config/live-enclave.json}"
