#!/usr/bin/env bash
# Deploy asker bundle to network clients and run tenet ask (item 15 proof).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENTS_CFG="${TENET_NETWORK_CLIENTS:-$ROOT/config/network-clients.json}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/tenet-nitro.pem}"
PROMPT="${PROMPT:-In one sentence, name one Monet painting technique.}"
TIMEOUT="${TIMEOUT:-120}"

cd "$ROOT"
[[ -f "$CLIENTS_CFG" ]] || {
  echo "missing $CLIENTS_CFG - run ./scripts/provision-network-clients.sh" >&2
  exit 1
}

export PATH="${HOME}/.cargo/bin:${PATH:-}"
if ! command -v aw >/dev/null 2>&1; then
  echo "[deploy-clients] installing aw locally (for reference)..." >&2
  "$ROOT/scripts/install-aw.sh" || true
fi

"$ROOT/scripts/package-asker-bundle.sh" >/dev/null

export ROOT
python3 <<'PY'
import json, os, subprocess, sys
from pathlib import Path

root = Path(os.environ["ROOT"])
cfg = json.loads((root / "config/network-clients.json").read_text())
bundle = root / "dist/asker-bundle.zip"
prompt = __import__("os").environ.get("PROMPT", "In one sentence, name one Monet painting technique.")
timeout = __import__("os").environ.get("TIMEOUT", "120")
results = []

remote_setup = r'''
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv curl ca-certificates unzip \
  build-essential pkg-config libssl-dev
if ! command -v aw >/dev/null; then
  if ! command -v cargo >/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
  fi
  . "$HOME/.cargo/env" 2>/dev/null || true
  cargo install --git https://github.com/maceip/attested-workload \
    --rev 79a5ea2328f2b30192e57b53913355dcd5e0201e --bin aw --locked 2>/dev/null \
    || cargo install --git https://github.com/maceip/attested-workload \
    --rev 79a5ea2328f2b30192e57b53913355dcd5e0201e --bin aw --force
fi
mkdir -p ~/tenet ~/asker-bundle
'''


def _ssh_cmd(client):
    user = client.get("ssh_user", "ubuntu")
    remote = f"{user}@{client['host']}"
    cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    key = os.environ.get("SSH_KEY") or client.get("ssh_key")
    if key:
        cmd.extend(["-i", str(Path(key).expanduser())])
    return cmd, remote


def _scp_cmd(client):
    cmd = ["scp", "-o", "StrictHostKeyChecking=accept-new"]
    key = os.environ.get("SSH_KEY") or client.get("ssh_key")
    if key:
        cmd.extend(["-i", str(Path(key).expanduser())])
    return cmd


def _ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def _remote_powershell(script):
    return 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + script.replace('"', '`"') + '"'


def _deploy_windows_native(client, cid):
    binary = root / client.get("binary", "dist/tenet-windows-x86_64.exe")
    if not binary.is_file():
        raise FileNotFoundError(f"missing Windows binary: {binary}")
    remote_dir = f"C:/Users/{client.get('ssh_user', 'mac')}/tenet/tenet-client/{cid}"
    remote_win_dir = remote_dir.replace("/", "\\")
    ssh_base, remote = _ssh_cmd(client)
    scp_base = _scp_cmd(client)
    subprocess.run(
        ssh_base
        + [
            remote,
            _remote_powershell(
                f"New-Item -ItemType Directory -Force -Path {_ps_quote(remote_win_dir)} | Out-Null"
            ),
        ],
        check=True,
    )
    subprocess.run(
        scp_base
        + [
            str(binary),
            str(root / "config/join-pack.json"),
            str(root / "config/live-mailbox-client.json"),
            f"{remote}:{remote_dir}/",
        ],
        check=True,
    )
    ps = (
        f"cd {_ps_quote(remote_win_dir)}; "
        "Set-Item -Path Env:PATH -Value 'C:\\Windows\\System32;C:\\Windows'; "
        f".\\{binary.name} ask --join-pack join-pack.json "
        f"--prompt {_ps_quote(prompt)} --timeout {timeout} --json"
    )
    return subprocess.run(
        ssh_base
        + [remote, _remote_powershell(ps)],
        text=True,
        capture_output=True,
    )


def _deploy_windows_wsl(client, cid):
    binary = root / client.get("binary", "dist/tenet-linux-x86_64")
    if not binary.is_file():
        raise FileNotFoundError(f"missing Linux binary: {binary}")
    remote_dir = f"C:/Users/{client.get('ssh_user', 'mac')}/tenet/tenet-client/{cid}"
    remote_win_dir = remote_dir.replace("/", "\\")
    remote_wsl_dir = remote_dir.replace("C:/", "/mnt/c/")
    ssh_base, remote = _ssh_cmd(client)
    scp_base = _scp_cmd(client)
    subprocess.run(
        ssh_base
        + [
            remote,
            _remote_powershell(
                f"New-Item -ItemType Directory -Force -Path {_ps_quote(remote_win_dir)} | Out-Null"
            ),
        ],
        check=True,
    )
    subprocess.run(
        scp_base
        + [
            str(binary),
            str(root / "config/join-pack.json"),
            str(root / "config/live-mailbox-client.json"),
            f"{remote}:{remote_dir}/",
        ],
        check=True,
    )
    subprocess.run(
        ssh_base + [remote, "wsl", "-e", "chmod", "+x", f"{remote_wsl_dir}/{binary.name}"],
        check=True,
    )
    return subprocess.run(
        ssh_base
        + [
            remote,
            "wsl",
            "-e",
            "env",
            "PATH=/usr/bin:/bin",
            f"{remote_wsl_dir}/{binary.name}",
            "ask",
            "--join-pack",
            f"{remote_wsl_dir}/join-pack.json",
            "--prompt",
            prompt,
            "--timeout",
            timeout,
            "--json",
        ],
        text=True,
        capture_output=True,
    )


def _deploy_legacy_linux(client):
    host = client["host"]
    user = client.get("ssh_user", "ubuntu")
    key = Path(os.environ.get("SSH_KEY") or client.get("ssh_key", "~/.ssh/tenet-nitro.pem")).expanduser()
    remote = f"{user}@{host}"
    subprocess.run(
        ["rsync", "-az", "-e", f"ssh -i {key} -o StrictHostKeyChecking=accept-new",
         "--exclude", ".git", "--exclude", "build", "--exclude", "dist", "--exclude", "deploy/eif-build",
         str(root) + "/", f"{remote}:~/tenet/"],
        check=True,
    )
    subprocess.run(
        ["scp", "-i", str(key), "-o", "StrictHostKeyChecking=accept-new",
         str(bundle), f"{remote}:~/asker-bundle.zip"],
        check=True,
    )
    cmd = f"""
{remote_setup}
cd ~/tenet
python3 -m pip install --user -q -e . 2>/dev/null || python3 -m pip install --user -q .
cd ~
rm -rf asker-bundle && unzip -o -q asker-bundle.zip
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
cd ~/asker-bundle
python3 -m tenet ask --join-pack join-pack.json --prompt {json.dumps(prompt)} --timeout {timeout} --json
"""
    return subprocess.run(
        ["ssh", "-i", str(key), "-o", "StrictHostKeyChecking=accept-new",
         remote, "bash", "-s"],
        input=cmd,
        text=True,
        capture_output=True,
    )


for index, client in enumerate(cfg["clients"]):
    host = client["host"]
    cid = client["client_id"]
    user = client.get("ssh_user", "ubuntu")
    remote = f"{user}@{host}"
    print(f"[deploy-clients] === {cid} @ {remote} ===", flush=True)
    platform = str(client.get("platform", "linux"))
    if platform == "windows-x86_64":
        proc = _deploy_windows_native(client, cid)
    elif client.get("wsl") or platform == "linux-x86_64":
        proc = _deploy_windows_wsl(client, cid)
    else:
        proc = _deploy_legacy_linux(client)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    ok = (
        proc.returncode == 0
        and '"ok": true' in proc.stdout
        and '"response_text": ""' not in proc.stdout
        and '"response_text": "' in proc.stdout
    )
    results.append((cid, host, ok, proc.returncode))
    if index < len(cfg["clients"]) - 1:
        import time
        time.sleep(3)
    if not ok:
        print(f"[deploy-clients] FAIL {cid}", file=sys.stderr)

print("[deploy-clients] summary:")
for cid, host, ok, rc in results:
    print(f"  {cid} {host}: ok={ok} rc={rc}")
if not all(r[2] for r in results):
    sys.exit(1)
print("[deploy-clients] item 15 second-human path OK on all clients")
PY
