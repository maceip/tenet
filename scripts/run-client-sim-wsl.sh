#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WINDOWS_HOST="${WINDOWS_HOST:-192.168.0.180}"
WINDOWS_USER="${WINDOWS_USER:-mac}"
REMOTE_ROOT="${REMOTE_ROOT:-/tmp/tenet-client-sim}"
REMOTE_ARCHIVE_WIN="${REMOTE_ARCHIVE_WIN:-C:/Users/mac/tenet/client-sim-wsl.tgz}"
REMOTE_ARCHIVE_WSL="${REMOTE_ARCHIVE_WSL:-/mnt/c/Users/mac/tenet/client-sim-wsl.tgz}"
IMAGE="${IMAGE:-tenet-client-sim:latest}"
CLIENT_COUNT="${CLIENT_COUNT:-1}"
NAT_PROFILE="${NAT_PROFILE:-nat}"
MODE="${MODE:-ask}"
PROMPT="${PROMPT:-Monet}"
POR_TIMEOUT="${POR_TIMEOUT:-120}"
FRY_ENV="${FRY_ENV:-/Users/mac/fry-core/.env}"
REBUILD="${REBUILD:-1}"

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

SSH_OPTS=(-o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
REMOTE="${WINDOWS_USER}@${WINDOWS_HOST}"
KEY_ENV="$(mktemp "${TMPDIR:-/tmp}/tenet-client-key.XXXXXX")"
CTX="$(mktemp -d "${TMPDIR:-/tmp}/tenet-client-wsl.XXXXXX")"
ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/tenet-client-wsl.XXXXXX.tgz")"
trap 'rm -f "$KEY_ENV" "$ARCHIVE"; rm -rf "$CTX"' EXIT
chmod 600 "$KEY_ENV"
printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY" > "$KEY_ENV"

cd "$ROOT"
[[ -x dist/tenet-linux-x86_64 ]] || {
  echo "missing dist/tenet-linux-x86_64; build the Linux binary first" >&2
  exit 2
}

mkdir -p "$CTX/dist" "$CTX/config" "$CTX/deploy/client-sim" "$CTX/scripts"
cp dist/tenet-linux-x86_64 "$CTX/dist/"
cp config/live-enclave.json config/join-pack.json config/live-mailbox-client.json "$CTX/config/"
cp deploy/client-sim/Dockerfile deploy/client-sim/entrypoint.sh "$CTX/deploy/client-sim/"
cp scripts/build-client-sim-image.sh scripts/run-client-sim.sh "$CTX/scripts/"
cp "$KEY_ENV" "$CTX/anthropic.env"
cat >"$CTX/run-wsl.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
trap 'rm -f "$REMOTE_ROOT/anthropic.env"' EXIT
cd "$REMOTE_ROOT"
chmod +x dist/tenet-linux-x86_64 deploy/client-sim/entrypoint.sh scripts/*.sh
chmod 600 anthropic.env
if [[ "$REBUILD" == "1" ]]; then
  IMAGE="$IMAGE" ./scripts/build-client-sim-image.sh
fi
FRY_ENV="$REMOTE_ROOT/anthropic.env" \
IMAGE="$IMAGE" \
CLIENT_COUNT="$CLIENT_COUNT" \
NAT_PROFILE="$NAT_PROFILE" \
MODE="$MODE" \
PROMPT="$PROMPT" \
POR_TIMEOUT="$POR_TIMEOUT" \
./scripts/run-client-sim.sh
EOF
chmod +x "$CTX/run-wsl.sh"

COPYFILE_DISABLE=1 tar --no-xattrs -C "$CTX" -czf "$ARCHIVE" .
scp "${SSH_OPTS[@]}" "$ARCHIVE" "$REMOTE:$REMOTE_ARCHIVE_WIN"
ssh "${SSH_OPTS[@]}" "$REMOTE" \
  "wsl -e bash --noprofile --norc -lc \"rm -rf '$REMOTE_ROOT' && mkdir -p '$REMOTE_ROOT' && tar xzf '$REMOTE_ARCHIVE_WSL' -C '$REMOTE_ROOT' && rm -f '$REMOTE_ARCHIVE_WSL'\""
ssh "${SSH_OPTS[@]}" "$REMOTE" "wsl -e bash --noprofile --norc $REMOTE_ROOT/run-wsl.sh"
