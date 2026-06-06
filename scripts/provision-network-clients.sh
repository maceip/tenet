#!/usr/bin/env bash
# Provision N EC2 network clients (askers) for item 15 second-human proof.
#
# Usage:
#   CLIENT_NODE_COUNT=2 ./scripts/provision-network-clients.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAY_HOST="${RELAY_HOST:-3.121.69.82}"
CLIENT_NODE_COUNT="${CLIENT_NODE_COUNT:-2}"
KEY_NAME="${KEY_NAME:-tenet-nitro}"
OUT="${TENET_NETWORK_CLIENTS:-$ROOT/config/network-clients.json}"
SUBNET="${SUBNET_ID:-subnet-08c648e7bb93e4497}"
SG="${SECURITY_GROUP_ID:-sg-01e82ad2abca4f21c}"
REGION="${AWS_REGION:-eu-central-1}"

export AWS_DEFAULT_REGION="$REGION"

MATCHER_URL=""
if [[ -f "$ROOT/config/live-enclave.json" ]]; then
  MATCHER_URL="$(python3 -c "import json; print(json.load(open('$ROOT/config/live-enclave.json'))['url'])")"
fi
[[ -n "$MATCHER_URL" ]] || { echo "missing config/live-enclave.json url" >&2; exit 2; }

AMI=$(aws ec2 describe-images --owners amazon \
  --filters 'Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*' 'Name=state,Values=available' \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

CLIENTS=()
for i in $(seq 1 "$CLIENT_NODE_COUNT"); do
  ID=$(aws ec2 run-instances \
    --image-id "$AMI" \
    --instance-type t3.small \
    --key-name "$KEY_NAME" \
    --subnet-id "$SUBNET" \
    --security-group-ids "$SG" \
    --associate-public-ip-address \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=tenet-network-client-${i}},{Key=tenet-role,Value=network-client}]" \
    --query 'Instances[0].InstanceId' --output text)
  aws ec2 wait instance-running --instance-ids "$ID"
  IP=$(aws ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  CLIENTS+=("$IP")
  echo "[provision-client] client-$i: $ID @ $IP"
done

for IP in "${CLIENTS[@]}"; do
  [[ "$IP" != "$RELAY_HOST" ]] || {
    echo "[provision-client] FATAL: client IP equals relay host" >&2
    exit 1
  }
done

aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol udp --port 1024-65535 \
  --cidr "${RELAY_HOST}/32" 2>/dev/null || true

python3 <<PY
import json
from pathlib import Path

clients = [
    {"client_id": f"client-{i+1}", "host": ip, "ssh_user": "ubuntu", "ssh_key": "~/.ssh/tenet-nitro.pem"}
    for i, ip in enumerate("""$(printf '%s\n' "${CLIENTS[@]}")""".strip().split())
    if ip
]
out = Path("$OUT")
out.write_text(
    json.dumps(
        {
            "version": "tenet.network_clients.2026-06",
            "reach_relay_host": "$RELAY_HOST",
            "matcher_url": "$MATCHER_URL".rstrip("/") + "/",
            "clients": clients,
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
print("[provision-client] wrote", out, "clients=", len(clients))
for c in clients:
    print(" ", c["client_id"], c["host"])
PY

echo "[provision-client] next: ./scripts/deploy-network-clients.sh"
