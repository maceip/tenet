#!/usr/bin/env bash
# Render beta configs from templates + config/beta-secrets.env
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${BETA_SECRETS:-$ROOT/config/beta-secrets.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE — run ./scripts/init-beta-secrets.sh" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

if [[ "${REACH_RELAY_HOST:-}" == "REPLACE_WITH_PUBLIC_IP" || -z "${REACH_RELAY_HOST:-}" ]]; then
  echo "set REACH_RELAY_HOST in $ENV_FILE before rendering" >&2
  exit 1
fi

render() {
  local template=$1 out=$2
  sed \
    -e "s|@REACH_RELAY_HOST@|${REACH_RELAY_HOST}|g" \
    -e "s|@REACH_RELAY_PORT@|${REACH_RELAY_PORT}|g" \
    -e "s|@REACH_RELAY_ID@|${REACH_RELAY_ID}|g" \
    -e "s|@RELAY_SECRET_HEX@|${RELAY_SECRET_HEX}|g" \
    -e "s|@RELAY_VERIFY_KEY_HEX@|${RELAY_VERIFY_KEY_HEX}|g" \
    -e "s|@RELAY_KEM_PK_HEX@|${RELAY_KEM_PK_HEX}|g" \
    -e "s|@RELAY_KEM_SK_HEX@|${RELAY_KEM_SK_HEX}|g" \
    -e "s|@EXPERT_KEM_PK_HEX@|${EXPERT_KEM_PK_HEX}|g" \
    -e "s|@EXPERT_KEM_SK_HEX@|${EXPERT_KEM_SK_HEX}|g" \
    < "$template" > "$out"
  echo "[render] $out"
}

render "$ROOT/config/templates/live-reach-relay.json" "$ROOT/config/live-reach-relay.json"
render "$ROOT/config/templates/live-mailbox-client.json" "$ROOT/config/live-mailbox-client.json"
render "$ROOT/config/templates/expert-laptop.json" "$ROOT/config/expert-laptop.json"
