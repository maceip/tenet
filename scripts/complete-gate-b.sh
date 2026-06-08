#!/usr/bin/env bash
# Legacy filename. Finish network-beta scale-out. Requires distinct VMs —
# use scripts/gate-b/ instead.
#
# Preferred entrypoints:
#   ./scripts/gate-b/run-network.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$ROOT/config/gate-b-topology.json" ]]; then
  exec "$ROOT/scripts/gate-b/run-network.sh"
fi
echo "[network-beta] no topology — run: ./scripts/gate-b/run-network.sh" >&2
exit 2

# Legacy direct env (still requires EXPERT_HOST != RELAY_HOST):
RELAY_HOST="${REACH_RELAY_HOST:-3.121.69.82}"
RELAY_USER="${RELAY_USER:-ec2-user}"
RELAY_KEY="${RELAY_KEY:-$HOME/.ssh/tenet-nitro.pem}"
EXPERT_HOST="${EXPERT_HOST:-35.158.168.87}"
EXPERT_USER="${EXPERT_USER:-ubuntu}"
EXPERT_KEY="${EXPERT_KEY:-$HOME/.ssh/aws-epyc.pem}"
CORPUS="${EXPERT_CORPUS:-$ROOT/tests/fixtures/corpus/monet}"

cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH:-}"

[[ -f config/beta-secrets.env ]] || bash "$ROOT/scripts/init-beta-secrets.sh"
# shellcheck disable=SC1090
source config/beta-secrets.env
export REACH_RELAY_HOST="$RELAY_HOST"
bash "$ROOT/scripts/render-beta-config.sh" >/dev/null

HANDLE="$(
  cd "$ROOT" && PYTHONPATH=. python3 -c "
from tenet.handles import OpaqueHandleIssuer
from tenet.experts.memory_index import IndexConfig, build_memory_index
built = build_memory_index(IndexConfig(peer_id='expert', roots=('$CORPUS',), created_at_iso='2026-06-04T00:00:00+00:00'))
issuer = OpaqueHandleIssuer(bytes.fromhex('${HANDLE_SECRET_HEX}'))
rec = issuer.record(peer_id='expert', manifest_digest=built.manifest.index_digest, mailbox_id='mailbox-beta')
print(rec.handle if isinstance(rec.handle, str) else rec.handle.token)
"
)"
echo "[network-beta] handle=$HANDLE relay=$RELAY_HOST expert_vm=$EXPERT_HOST"

echo "[network-beta] sync to relay host (Nitro) + expert VM"
rsync -az \
  -e "ssh -i $RELAY_KEY" \
  --exclude .git --exclude .venv --exclude 'oblivious-core/target' --exclude deploy/eif-build \
  "$ROOT/" "${RELAY_USER}@${RELAY_HOST}:~/tenet/"
rsync -az \
  -e "ssh -i $EXPERT_KEY" \
  --exclude .git --exclude .venv --exclude 'oblivious-core/target' \
  "$ROOT/" "${EXPERT_USER}@${EXPERT_HOST}:~/tenet/"

echo "[network-beta] ensure reach relay on Nitro only"
ssh -i "$RELAY_KEY" "${RELAY_USER}@${RELAY_HOST}" bash -s <<'REMOTE'
set -euo pipefail
cd ~/tenet
python3 -m pip install --user -q dilithium-py pynacl cryptography 2>/dev/null || true
pgrep -f live-reach-relay.json >/dev/null || {
  setsid python3 -m tenet run --config config/live-reach-relay.json --node-id reach-beta-1 \
    >> ~/reach-relay.log 2>&1 < /dev/null &
  disown
  sleep 2
}
tail -1 ~/reach-relay.log
REMOTE

echo "[network-beta] expert on separate VM ($EXPERT_HOST) — REACH to public relay $RELAY_HOST"
ssh -i "$EXPERT_KEY" "${EXPERT_USER}@${EXPERT_HOST}" bash -s <<REMOTE
set -euo pipefail
cd ~/tenet
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y -qq python3 python3-pip 2>/dev/null || true
python3 -m pip install --user -q dilithium-py pynacl cryptography 2>/dev/null || true
pkill -f expert-ec2.json 2>/dev/null || true
sleep 1
python3 <<'PY'
import re
from pathlib import Path
h = "${HANDLE}"
t = Path("config/templates/expert-laptop.json").read_text()
for a,b in [
    ("REPLACE_WITH_OPAQUE_HANDLE", h),
    ("@REACH_RELAY_HOST@", "${RELAY_HOST}"),
    ("@REACH_RELAY_PORT@", "${REACH_RELAY_PORT:-4433}"),
    ("@EXPERT_KEM_PK_HEX@", "${EXPERT_KEM_PK_HEX}"),
    ("@EXPERT_KEM_SK_HEX@", "${EXPERT_KEM_SK_HEX}"),
]:
    t = t.replace(a, b)
Path("config/expert-ec2.json").write_text(t)
PY
setsid env ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
  python3 -m tenet run --config config/expert-ec2.json --node-id "${HANDLE}" \
  >> ~/expert-gateb.log 2>&1 < /dev/null &
disown
sleep 5
tail -5 ~/expert-gateb.log
REMOTE

REACH_RELAY_HOST="$RELAY_HOST" VERIFY_PEER_ID="$HANDLE" "$ROOT/scripts/verify-reach-relay.sh" 2>&1 | tail -1

echo "[network-beta] peer_address from relay (Nitro)"
ssh -i "$RELAY_KEY" "${RELAY_USER}@${RELAY_HOST}" \
  "cd ~/tenet && python3 scripts/export-relay-peer-address.py \
    --config config/live-reach-relay.json --node-id reach-beta-1 --peer-id ${HANDLE}" \
  > /tmp/peer-address.json

PYTHONPATH=. python3 "$ROOT/scripts/sync-gate-b-artifacts.py" \
  --corpus "$CORPUS" \
  --handle-secret-hex "$HANDLE_SECRET_HEX" \
  --routing-kem-pk-hex "$EXPERT_KEM_PK_HEX" \
  --peer-address-json /tmp/peer-address.json >/dev/null
echo "[network-beta] synced mailbox for $HANDLE"

ssh -i "$RELAY_KEY" "${RELAY_USER}@${RELAY_HOST}" "mkdir -p ~/tenet/deploy/eif-build/app/data/beta"
rsync -az "$ROOT/deploy/data/beta/" \
  -e "ssh -i $RELAY_KEY" \
  "${RELAY_USER}@${RELAY_HOST}:~/tenet/deploy/eif-build/app/data/beta/"

echo "[network-beta] EIF rebuild on Nitro (matcher only — expert stays off this host)"
ssh -i "$RELAY_KEY" "${RELAY_USER}@${RELAY_HOST}" bash -s <<'REMOTE'
set -euo pipefail
cd ~/tenet
export ATTESTED_WORKLOAD_REPO=~/attested-workload ATTESTED_WORKLOAD_SHA=79a5ea2328f2b30192e57b53913355dcd5e0201e
[[ -d ~/attested-workload/.git ]] || git clone https://github.com/maceip/attested-workload.git ~/attested-workload
./deploy/assemble-matcher-eif.sh
cd deploy/eif-build
docker build -t matcher-beta:latest . >>/tmp/docker-build.log 2>&1
nitro-cli build-enclave --docker-uri matcher-beta:latest \
  --output-file ~/tenet-nitro-deploy/matcher-gateb-final.eif >>/tmp/nitro-build.log 2>&1
EIF=~/tenet-nitro-deploy/matcher-gateb-final.eif ~/tenet/deploy/redeploy-matcher-eif.sh >>/tmp/redeploy.log 2>&1
sudo /usr/local/bin/bountynet check --json https://127.0.0.1/ 2>/dev/null | tee /tmp/aw-check.json
REMOTE

read -r VALUE_X SPKI < <(ssh -i "$RELAY_KEY" "${RELAY_USER}@${RELAY_HOST}" \
  "python3 -c \"import json,re; t=open('/tmp/aw-check.json').read(); j=json.loads(re.search(r'\\{.*\\}',t,re.S).group()); print(j['value_x']); print(j['tls_spki_hash'])\"" )
PREFIX="${VALUE_X:0:12}"
python3 <<PY
import json
from pathlib import Path
p = Path("$ROOT/config/live-enclave.json")
d = json.loads(p.read_text())
d["url"] = f"https://${PREFIX}.aeon.site/"
d["approved_value_x"] = ["$VALUE_X"]
d["tls_spki_hash"] = "$SPKI"
p.write_text(json.dumps(d, indent=2) + "\n")
print("[network-beta] enclave url", d["url"])
PY

echo "[network-beta] asker send (this machine)"
python3 -m tenet enclave send --prompt "What is impressionism in painting?" --timeout 120 --json
