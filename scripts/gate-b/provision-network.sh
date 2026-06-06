#!/usr/bin/env bash
# Provision network beta: reach relay on Nitro + N expert nodes on dedicated EC2s.
#
# Usage:
#   RELAY_HOST=3.121.69.82 EXPERT_NODE_COUNT=3 ./scripts/gate-b/provision-network.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RELAY_HOST="${RELAY_HOST:-3.121.69.82}"
RELAY_PORT="${REACH_RELAY_PORT:-4433}"
EXPERT_NODE_COUNT="${EXPERT_NODE_COUNT:-1}"
MATCHER_URL="${MATCHER_URL:-}"
KEY_NAME="${KEY_NAME:-tenet-nitro}"
OUT="${TENET_GATE_B_TOPOLOGY:-$ROOT/config/gate-b-topology.json}"
SUBNET="${SUBNET_ID:-subnet-08c648e7bb93e4497}"
SG="${SECURITY_GROUP_ID:-sg-01e82ad2abca4f21c}"

if [[ -z "$MATCHER_URL" && -f "$ROOT/config/live-enclave.json" ]]; then
  MATCHER_URL="$(python3 -c "import json; print(json.load(open('$ROOT/config/live-enclave.json'))['url'])")"
fi
[[ -n "$MATCHER_URL" ]] || { echo "set MATCHER_URL=" >&2; exit 2; }

AMI=$(aws ec2 describe-images --owners amazon \
  --filters 'Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*' 'Name=state,Values=available' \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

EXPERT_IPS=()
for i in $(seq 1 "$EXPERT_NODE_COUNT"); do
  ID=$(aws ec2 run-instances \
    --image-id "$AMI" \
    --instance-type t3.small \
    --key-name "$KEY_NAME" \
    --subnet-id "$SUBNET" \
    --security-group-ids "$SG" \
    --associate-public-ip-address \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=tenet-expert-gateb-${i}}]" \
    --query 'Instances[0].InstanceId' --output text)
  aws ec2 wait instance-running --instance-ids "$ID"
  IP=$(aws ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  EXPERT_IPS+=("$IP")
  echo "[provision] expert node $i: $ID @ $IP"
done

for IP in "${EXPERT_IPS[@]}"; do
  [[ "$IP" != "$RELAY_HOST" ]] || {
    echo "[provision] FATAL: expert node IP equals relay host $RELAY_HOST" >&2
    exit 1
  }
done

aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol udp --port 1024-65535 \
  --cidr "${RELAY_HOST}/32" 2>/dev/null || true

EXPERT_JSON=$(python3 -c "import json; print(json.dumps([{'node_id': f'expert-{i+1}', 'host': ip, 'ssh_user': 'ubuntu', 'ssh_key': '~/.ssh/tenet-nitro.pem'} for i, ip in enumerate('${EXPERT_IPS[*]}'.split())]))" 2>/dev/null || python3 <<PY
import json, os
ips = """$(printf '%s\n' "${EXPERT_IPS[@]}")""".strip().split()
print(json.dumps([{"node_id": f"expert-{i+1}", "host": ip, "ssh_user": "ubuntu", "ssh_key": "~/.ssh/tenet-nitro.pem"} for i, ip in enumerate(ips) if ip]))
PY
)

python3 <<PY
import json
from pathlib import Path
experts = json.loads('''$EXPERT_JSON''')
out = Path("$OUT")
out.write_text(json.dumps({
  "version": "tenet.gate_b_topology.2026-06",
  "roles": {
    "reach_relay": {
      "host": "$RELAY_HOST",
      "port": int("$RELAY_PORT"),
      "ssh_user": "ec2-user",
      "ssh_key": "~/.ssh/tenet-nitro.pem",
    },
    "experts": experts,
    "matcher": {
      "url": "$MATCHER_URL".rstrip("/") + "/",
      "host": "$RELAY_HOST",
      "ssh_user": "ec2-user",
      "ssh_key": "~/.ssh/tenet-nitro.pem",
    },
    "asker": {"host": "local"},
  },
}, indent=2) + "\n", encoding="utf-8")
print("[provision] wrote", out, "experts=", len(experts))
PY

echo "[provision] next: ./scripts/gate-b/deploy-nodes.sh"
