#!/usr/bin/env bash
set -euo pipefail

load_secret() {
  if [[ -z "${ANTHROPIC_API_KEY:-}" && -f /run/secrets/anthropic_api_key ]]; then
    export ANTHROPIC_API_KEY
    ANTHROPIC_API_KEY="$(tr -d '\r\n' </run/secrets/anthropic_api_key)"
  fi
  if [[ -f /etc/tenet/agent.env ]]; then
    set -a
    # shellcheck disable=SC1091
    . /etc/tenet/agent.env
    set +a
  fi
}

seed_context() {
  local ctx="${TENET_CONTEXT_DIR:-/var/lib/tenet-client/context}"
  local logs="${TENET_LOG_DIR:-/var/log/tenet-client}"
  mkdir -p "$ctx" "$logs" /workspace
  if [[ ! -f "$ctx/session.json" ]]; then
    cat >"$ctx/session.json" <<EOF
{"client_id":"${TENET_CLIENT_ID:-client-sim}","profile":"${TENET_NAT_PROFILE:-nat}","created_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","purpose":"tenet client simulation","agent":"claude-code"}
EOF
  fi
  if [[ ! -f "$logs/transcript.jsonl" ]]; then
    cat >"$logs/transcript.jsonl" <<EOF
{"role":"system","content":"Synthetic coding-agent context for Tenet network simulation."}
{"role":"user","content":"Inspect a small client repository, ask the live network, and record whether the relay return path completes."}
EOF
  fi
  if [[ ! -f /workspace/task.md ]]; then
    cat >/workspace/task.md <<EOF
# Tenet Client Simulation Task

Client: ${TENET_CLIENT_ID:-client-sim}
NAT profile: ${TENET_NAT_PROFILE:-nat}

Run the live client path and record whether the response returns with ok=true and fallback_used=false.
EOF
  fi
}

apply_nat_profile() {
  local profile="${TENET_NAT_PROFILE:-nat}"
  case "$profile" in
    public|nat)
      ;;
    cgnat)
      if [[ "${TENET_APPLY_NETEM:-0}" == "1" ]] && command -v tc >/dev/null 2>&1; then
        tc qdisc add dev eth0 root netem delay 80ms 20ms loss 0.2% 2>/dev/null || true
      fi
      ;;
    udp-hostile)
      if [[ "${TENET_APPLY_NETEM:-0}" == "1" ]] && command -v iptables >/dev/null 2>&1; then
        iptables -A INPUT -p udp -j DROP 2>/dev/null || true
      fi
      ;;
    *)
      echo "unknown TENET_NAT_PROFILE=$profile" >&2
      exit 64
      ;;
  esac
}

run_ask() {
  /usr/local/bin/tenet ask \
    --join-pack "${JOIN_PACK:-/etc/tenet/join-pack.json}" \
    --prompt "${PROMPT:-Monet}" \
    --timeout "${POR_TIMEOUT:-120}" \
    --json
}

run_loop() {
  local count="${CLIENT_LOOP_COUNT:-10}"
  local gap="${CLIENT_LOOP_GAP:-1}"
  local i
  for i in $(seq 1 "$count"); do
    PROMPT="${PROMPT_PREFIX:-Monet} ${i}" run_ask
    [[ "$i" == "$count" ]] || sleep "$gap"
  done
}

load_secret
seed_context
apply_nat_profile

case "${1:-ask}" in
  ask)
    run_ask
    ;;
  loop)
    run_loop
    ;;
  agent-smoke)
    claude --version
    ;;
  shell)
    exec bash
    ;;
  *)
    exec "$@"
    ;;
esac
