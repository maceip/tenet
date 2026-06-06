#!/usr/bin/env bash
# Item 15.6: repeat/load sanity - 10x same prompt + 10x varied prompts.
#
# Usage:
#   ./scripts/run-item-15-6-load.sh              # local tenet ask
#   RUN_ON=remote ./scripts/run-item-15-6-load.sh # first EC2 in network-clients.json
#   RUN_ON=both ./scripts/run-item-15-6-load.sh   # alternate client-1 / client-2
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ON="${RUN_ON:-local}"
CLIENTS_CFG="${TENET_NETWORK_CLIENTS:-$ROOT/config/network-clients.json}"
JOIN_PACK="${JOIN_PACK:-$ROOT/config/join-pack.json}"
SAME_PROMPT="${SAME_PROMPT:-In one sentence, name one Monet painting technique.}"
REPEATS="${REPEATS:-10}"
GAP_SEC="${GAP_SEC:-3}"
TIMEOUT="${TIMEOUT:-120}"
OUT="${LOAD_REPORT:-$ROOT/config/item-15-6-report.json}"

export PATH="${HOME}/.cargo/bin:${PATH:-}"
cd "$ROOT"
if [[ "${REFRESH_PINS:-0}" == "1" ]]; then
  ./scripts/refresh-live-pins.sh >/dev/null
fi
./scripts/render-join-pack.sh >/dev/null
[[ "$RUN_ON" != "local" ]] && ./scripts/package-asker-bundle.sh >/dev/null

VARIED_PROMPTS=(
  "In one sentence, name one Monet painting technique."
  "What is broken brushwork in impressionist painting?"
  "How did Monet use light in his haystack series?"
  "Name one characteristic of impressionist color theory."
  "How did Monet paint water lilies in terms of color and brushwork?"
  "Describe Monet approach to water reflections in one sentence."
  "What is a key difference between Monet and classical landscape painting?"
  "How did Monet capture atmosphere in his garden paintings?"
  "Name one material Monet favored on his palette."
  "In one phrase, what is optical color mixing in impressionism?"
)

_run_local() {
  python3 -m tenet ask --join-pack "$JOIN_PACK" --prompt "$1" --timeout "$TIMEOUT" --json
}

_run_remote() {
  local host=$1
  local prompt=$2
  local key="${SSH_KEY:-$HOME/.ssh/tenet-nitro.pem}"
  ssh -i "$key" -o StrictHostKeyChecking=accept-new "ubuntu@${host}" \
    "export PATH=\$HOME/.cargo/bin:\$HOME/.local/bin:\$PATH; cd ~/asker-bundle && python3 -m tenet ask --join-pack join-pack.json --prompt $(printf '%q' "$prompt") --timeout $TIMEOUT --json" 2>&1
}

pick_host() {
  local n=$1
  python3 -c "
import json
from pathlib import Path
c = json.loads(Path('$CLIENTS_CFG').read_text())['clients']
print(c[$n % len(c)]['host'])
"
}

ask_once() {
  local label=$1
  local prompt=$2
  local host=""
  local out=""
  local rc=0
  local t0=$(date +%s)
  case "$RUN_ON" in
    local) out=$(_run_local "$prompt" 2>&1) || rc=$? ;;
    remote)
      host=$(pick_host 0)
      out=$(_run_remote "$host" "$prompt" 2>&1) || rc=$?
      ;;
    both)
      host=$(pick_host "${label##*-}")
      out=$(_run_remote "$host" "$prompt" 2>&1) || rc=$?
      ;;
    *)
      echo "unknown RUN_ON=$RUN_ON" >&2
      return 1
      ;;
  esac
  local t1=$(date +%s)
  printf '%s' "$out" | ASK_LABEL="$label" ASK_HOST="$host" ASK_T0="$t0" ASK_T1="$t1" ASK_RC="$rc" ASK_PROMPT="$prompt" python3 -c "
import json, os, sys
raw = sys.stdin.read().strip()
start = raw.find('{')
end = raw.rfind('}')
if start >= 0 and end >= start:
    try:
        d = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        d = None
else:
    d = None
if d is None:
    print(json.dumps({
        'ok': False,
        'label': os.environ['ASK_LABEL'],
        'prompt': os.environ.get('ASK_PROMPT', ''),
        'elapsed_s': int(os.environ['ASK_T1']) - int(os.environ['ASK_T0']),
        'command_rc': int(os.environ.get('ASK_RC', '0')),
        'error': 'invalid_json',
        'raw': raw[:4000],
    }))
    raise SystemExit(0)
d['elapsed_s'] = int(os.environ['ASK_T1']) - int(os.environ['ASK_T0'])
d['label'] = os.environ['ASK_LABEL']
command_rc = int(os.environ.get('ASK_RC', '0'))
if command_rc:
    d['command_rc'] = command_rc
host = os.environ.get('ASK_HOST', '')
if host:
    d['host'] = host
print(json.dumps(d))
"
}

TMP_RESULTS="$(mktemp "${TMPDIR:-/tmp}/por-load.XXXXXX")"
trap 'rm -f "$TMP_RESULTS"' EXIT
fail=0

echo "[15.6] phase A: ${REPEATS}x same prompt (gap ${GAP_SEC}s, run_on=${RUN_ON})"
for i in $(seq 1 "$REPEATS"); do
  line=$(ask_once "same-$i" "$SAME_PROMPT") || { line='{"ok":false,"label":"same-'$i'","error":"ask_failed"}'; }
  printf '%s\n' "$line" >> "$TMP_RESULTS"
  ok=$(printf '%s' "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('ok'))")
  [[ "$ok" == "True" ]] || fail=$((fail + 1))
  echo "[15.6] same-$i ok=$ok elapsed=$(printf '%s' "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('elapsed_s','?'))")"
  [[ $i -lt $REPEATS ]] && sleep "$GAP_SEC"
done

echo "[15.6] phase B: ${#VARIED_PROMPTS[@]} varied prompts"
idx=0
for prompt in "${VARIED_PROMPTS[@]}"; do
  idx=$((idx + 1))
  line=$(ask_once "varied-$idx" "$prompt") || { line='{"ok":false,"label":"varied-'$idx'","error":"ask_failed"}'; }
  printf '%s\n' "$line" >> "$TMP_RESULTS"
  ok=$(printf '%s' "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('ok'))")
  [[ "$ok" == "True" ]] || fail=$((fail + 1))
  echo "[15.6] varied-$idx ok=$ok"
  [[ $idx -lt ${#VARIED_PROMPTS[@]} ]] && sleep "$GAP_SEC"
done

python3 <<PY
import json
from datetime import datetime, timezone
from pathlib import Path

lines = Path("$TMP_RESULTS").read_text(encoding="utf-8").splitlines()
rows = [json.loads(l) for l in lines if l.strip()]
summary = {
    "item": "15.6",
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "run_on": "$RUN_ON",
    "total": len(rows),
    "ok": sum(1 for r in rows if r.get("ok")),
    "fail": sum(1 for r in rows if not r.get("ok")),
    "same_prompt": "$SAME_PROMPT",
    "gap_sec": int("$GAP_SEC"),
    "runs": rows,
}
out = Path("$OUT")
out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(f"[15.6] wrote {out}")
print(f"[15.6] ok={summary['ok']}/{summary['total']} fail={summary['fail']}")
PY

[[ "$fail" -eq 0 ]]
