#!/usr/bin/env bash
# Gate-b live deployment (EC2/Nitro).
#
# LEGACY / OUTDATED relative to the modern architecture:
# - The unified WireNodeRuntime + real Kademlia control overlay (DHT for signed
#   control records), capabilities (control_dht etc.), and the flexible simulator
#   live in sim/ + deploy/Dockerfile.node.
# - This script rsyncs the tree and launches via `python3 -m tenet run` on remote
#   instances (still works for the current live beta/gate-b paths).
#
# For containerized or realistic simulated fleets (all-local-docker, 2-laptop
# mixed, cloud-only, cloud+local, cloud+mixed-local) with netem, restart
# contracts, and the real control plane, use the new sim/ framework.
#
# This file is retained for the specific gate-b live provisioning flow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOPOLOGY="${TENET_GATE_B_TOPOLOGY:-$ROOT/config/gate-b-topology.json}"
ALPHA_POPULATION="${ALPHA_POPULATION:-$ROOT/config/alpha-population.json}"

cd "$ROOT"
[[ -f config/beta-secrets.env ]] || ./scripts/init-beta-secrets.sh
# shellcheck disable=SC1090
source config/beta-secrets.env

RELAY_HOST=$(python3 -c "import json; print(json.load(open('$TOPOLOGY'))['roles']['reach_relay']['host'])")
export REACH_RELAY_HOST="$RELAY_HOST"
bash "$ROOT/scripts/render-beta-config.sh" >/dev/null

python3 -c "from tenet.experts.gate_b_topology import GateBTopology; GateBTopology.load('$TOPOLOGY')"

RELAY_KEY=~/.ssh/tenet-nitro.pem

echo "[deploy] reach relay node @ $RELAY_HOST"
rsync -az -e "ssh -i $RELAY_KEY" --exclude .git --exclude .venv --exclude deploy/eif-build \
  "$ROOT/" "ec2-user@${RELAY_HOST}:~/sphinx-tahoe/"
ssh -i "$RELAY_KEY" "ec2-user@${RELAY_HOST}" bash -s <<'REMOTE'
set -euo pipefail
cd ~/sphinx-tahoe
python3 -m pip install --user -q dilithium-py pynacl cryptography 2>/dev/null || true
# Align with modern pyproject/uv packaging for the core (Kademlia etc.).
python3 -m pip install --user -q uv || true
~/.local/bin/uv pip install --system -e . 2>/dev/null || python3 -m pip install --user -e . || true
pkill -f live-reach-relay.json 2>/dev/null || true
# Modern packaging step for the relay side as well (see pyproject.toml).
python3 -m pip install --user -q uv || true
~/.local/bin/uv pip install --system -e . 2>/dev/null || python3 -m pip install --user -e . || true
setsid python3 -m tenet run --config config/live-reach-relay.json --node-id reach-beta-1 \
  >> ~/reach-relay.log 2>&1 < /dev/null &
disown
sleep 2
tail -1 ~/reach-relay.log
REMOTE

export ROOT TOPOLOGY ALPHA_POPULATION
export HANDLE_SECRET_HEX EXPERT_KEM_PK_HEX EXPERT_KEM_SK_HEX
export REACH_RELAY_PORT="${REACH_RELAY_PORT:-4433}"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"

python3 <<'PY'
import json
import os
import subprocess
from pathlib import Path

root = Path(os.environ["ROOT"]).resolve()

topology_path = Path(os.environ["TOPOLOGY"])
topology = json.loads(topology_path.read_text())
experts_nodes = topology["roles"].get("experts") or [topology["roles"]["expert"]]
relay_host = topology["roles"]["reach_relay"]["host"]
key = os.path.expanduser("~/.ssh/tenet-nitro.pem")
env = os.environ

alpha_path = Path(os.environ.get("ALPHA_POPULATION", root / "config/alpha-population.json"))
if not alpha_path.is_file():
    raise SystemExit(
        f"[deploy] missing Alpha population (item 15): {alpha_path}\n"
        "  run: ./scripts/alpha/materialize-experts.py"
    )
from tenet.experts.alpha_experts import load_alpha_population

pop = load_alpha_population(alpha_path)
alpha_by_index = list(pop.experts)
print(f"[deploy] alpha population: {len(alpha_by_index)} experts from {alpha_path}")

from tenet.handles import OpaqueHandleIssuer
from tenet.experts.memory_index import IndexConfig, build_memory_index

issuer = OpaqueHandleIssuer(bytes.fromhex(env["HANDLE_SECRET_HEX"]))
created_at = "2026-06-04T00:00:00+00:00"

if len(experts_nodes) > len(alpha_by_index):
    raise SystemExit(
        f"[deploy] topology wants {len(experts_nodes)} expert nodes but Alpha "
        f"population has {len(alpha_by_index)} — materialize more experts or "
        "lower EXPERT_NODE_COUNT"
    )

for index, node in enumerate(experts_nodes):
    host = node["host"]
    spec = alpha_by_index[index]
    peer_id = spec.expert_id
    corpus = Path(spec.corpus_dir)
    if not corpus.is_absolute():
        corpus = root / corpus
    roots = (str(corpus),)
    print(f"[deploy] expert {peer_id} corpus={spec.corpus_dir} @ {host}")

    built = build_memory_index(
        IndexConfig(peer_id=peer_id, roots=roots, created_at_iso=created_at)
    )
    rec = issuer.record(
        peer_id=peer_id,
        manifest_digest=built.manifest.index_digest,
        mailbox_id="mailbox-beta",
    )
    handle = rec.handle if isinstance(rec.handle, str) else rec.handle.token

    subprocess.run(
        [
            "rsync",
            "-az",
            "-e",
            f"ssh -i {key}",
            "--exclude",
            ".git",
            "--exclude",
            ".venv",
            f"{root}/",
            f"ubuntu@{host}:~/sphinx-tahoe/",
        ],
        check=True,
    )

    remote = f"""set -euo pipefail
cd ~/sphinx-tahoe
sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-pip
python3 -m pip install --user -q dilithium-py pynacl cryptography || true
# Modern packaging: prefer uv (from pyproject.toml) so the installed tenet
# package matches the current source + dependencies (including kademlia for
# the real control DHT when nodes declare the control_dht capability).
python3 -m pip install --user -q uv || true
~/.local/bin/uv pip install --system -e . 2>/dev/null || python3 -m pip install --user -e . || true
pkill -f expert-ec2.json 2>/dev/null || true
python3 -c "
from pathlib import Path
h = '{handle}'
t = Path('config/templates/expert-laptop.json').read_text()
for a, b in [
    ('REPLACE_WITH_OPAQUE_HANDLE', h),
    ('@REACH_RELAY_HOST@', '{relay_host}'),
    ('@REACH_RELAY_PORT@', '{env.get("REACH_RELAY_PORT", "4433")}'),
    ('@EXPERT_KEM_PK_HEX@', '{env["EXPERT_KEM_PK_HEX"]}'),
    ('@EXPERT_KEM_SK_HEX@', '{env["EXPERT_KEM_SK_HEX"]}'),
]:
    t = t.replace(a, b)
Path('config/expert-ec2.json').write_text(t)
"
setsid env ANTHROPIC_API_KEY="{env.get("ANTHROPIC_API_KEY", "")}" \\
  python3 -m tenet run --config config/expert-ec2.json --node-id "{handle}" \\
  >> ~/expert-node.log 2>&1 < /dev/null &
disown
sleep 4
grep reach_registered ~/expert-node.log | tail -1
"""
    subprocess.run(["ssh", "-i", key, f"ubuntu@{host}", "bash", "-s"], input=remote, text=True, check=True)
PY

echo "[deploy] nodes up — run: ./scripts/gate-b/verify-network.sh"
