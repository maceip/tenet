#!/usr/bin/env bash
# Allocate (if needed) and associate an Elastic IP with the Nitro parent instance.
#
# Usage:
#   ./deploy/associate-elastic-ip.sh i-069a473107424b7df
#   ALLOCATION_ID=eipalloc-... ./deploy/associate-elastic-ip.sh i-069a473107424b7df
#
# After association the public IP changes to the Elastic IP. Update DNS:
#   aeon.site, *.aeon.site, 7d90e638b585.aeon.site → new EIP
set -euo pipefail

INSTANCE_ID="${1:?usage: associate-elastic-ip.sh <instance-id>}"
REGION="${AWS_DEFAULT_REGION:-eu-central-1}"
NAME="${EIP_NAME:-tenet-matcher-nitro-eip}"

existing="$(aws ec2 describe-addresses --region "$REGION" \
  --filters "Name=instance-id,Values=$INSTANCE_ID" \
  --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"

if [[ -n "$existing" && "$existing" != "None" ]]; then
  ALLOC="$existing"
  PUBLIC_IP="$(aws ec2 describe-addresses --region "$REGION" --allocation-ids "$ALLOC" --query 'Addresses[0].PublicIp' --output text)"
  echo "[eip] already associated: $PUBLIC_IP ($ALLOC)"
else
  ALLOC="${ALLOCATION_ID:-}"
  if [[ -z "$ALLOC" ]]; then
    echo "[eip] allocating new Elastic IP in $REGION"
    ALLOC="$(aws ec2 allocate-address --region "$REGION" --domain vpc \
      --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=$NAME}]" \
      --query AllocationId --output text)"
  fi
  PUBLIC_IP="$(aws ec2 describe-addresses --region "$REGION" --allocation-ids "$ALLOC" --query 'Addresses[0].PublicIp' --output text)"
  echo "[eip] associating $PUBLIC_IP ($ALLOC) → $INSTANCE_ID"
  aws ec2 associate-address --region "$REGION" --instance-id "$INSTANCE_ID" --allocation-id "$ALLOC" >/dev/null
fi

echo "[eip] public IP: $PUBLIC_IP"
echo "[eip] update DNS A records (aeon.site, *.aeon.site, 7d90e638b585.aeon.site) → $PUBLIC_IP"
echo "[eip] then: ./scripts/verify-live.sh"
