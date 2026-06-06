#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-tenet-client-sim:latest}"
PLATFORM="${PLATFORM:-linux/amd64}"
CLIENT_COUNT="${CLIENT_COUNT:-1}"
NAME_PREFIX="${NAME_PREFIX:-tenet-client}"
NAT_PROFILE="${NAT_PROFILE:-nat}"
MODE="${MODE:-ask}"
PROMPT="${PROMPT:-Monet}"
POR_TIMEOUT="${POR_TIMEOUT:-120}"
DETACH="${DETACH:-0}"
FRY_ENV="${FRY_ENV:-/Users/mac/fry-core/.env}"

if [[ -z "${ANTHROPIC_API_KEY:-}" && -f "$FRY_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$FRY_ENV"
  set +a
fi

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ANTHROPIC_API_KEY is not set and was not found in $FRY_ENV" >&2
  exit 2
fi

KEY_ENV="$(mktemp "${TMPDIR:-/tmp}/tenet-client-key.XXXXXX")"
trap 'rm -f "$KEY_ENV"' EXIT
chmod 600 "$KEY_ENV"
printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY" > "$KEY_ENV"

cd "$ROOT"
for i in $(seq 1 "$CLIENT_COUNT"); do
  name="${NAME_PREFIX}-${i}"
  docker rm -f "$name" >/dev/null 2>&1 || true
  args=(
    --name "$name"
    --env-file "$KEY_ENV"
    -e "TENET_CLIENT_ID=$name"
    -e "TENET_NAT_PROFILE=$NAT_PROFILE"
    -e "PROMPT=$PROMPT"
    -e "POR_TIMEOUT=$POR_TIMEOUT"
  )
  if [[ "${TENET_APPLY_NETEM:-0}" == "1" ]]; then
    args+=(--cap-add NET_ADMIN -e TENET_APPLY_NETEM=1)
  fi
  if [[ "$DETACH" == "1" ]]; then
    docker run --platform "$PLATFORM" -d "${args[@]}" "$IMAGE" "$MODE"
  else
    docker run --platform "$PLATFORM" --rm "${args[@]}" "$IMAGE" "$MODE"
  fi
done
