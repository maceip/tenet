"""Legacy module name for network-beta operations.

Use from ops scripts under ``scripts/gate-b/``. Pytest is optional for protocol
regression; item 15 proof runs on live VMs via ``run-network.sh``.
"""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

from tenet.experts.gate_b_topology import GateBTopology, RoleHost

ROOT = Path(__file__).resolve().parent.parent.parent


def ssh_argv(host: RoleHost) -> list[str]:
    key = os.path.expanduser(host.ssh_key or "~/.ssh/tenet-nitro.pem")
    return [
        "ssh",
        "-i",
        key,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{host.ssh_user}@{host.host}",
    ]


def ssh_run(host: RoleHost, remote_script: str, *, timeout: float = 120.0) -> str:
    proc = subprocess.run(
        ssh_argv(host) + ["bash", "-s"],
        input=remote_script,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(ROOT),
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"ssh {host.ssh_user}@{host.host} failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc.stdout


def rsync_repo(host: RoleHost) -> None:
    key = os.path.expanduser(host.ssh_key or "~/.ssh/tenet-nitro.pem")
    dest = f"{host.ssh_user}@{host.host}:~/tenet/"
    subprocess.run(
        [
            "rsync",
            "-az",
            "-e",
            f"ssh -i {key} -o StrictHostKeyChecking=accept-new",
            "--exclude",
            ".git",
            "--exclude",
            ".venv",
            "--exclude",
            "oblivious-core/target",
            "--exclude",
            "deploy/eif-build",
            f"{ROOT}/",
            dest,
        ],
        check=True,
        timeout=300,
        cwd=str(ROOT),
    )


def reach_register_from_expert_node(topology: GateBTopology, expert: RoleHost, peer_id: str) -> None:
    relay_host, relay_port = topology.relay_endpoint()
    script = textwrap.dedent(
        f"""
        set -euo pipefail
        cd ~/tenet
        python3 -m pip install --user -q dilithium-py pynacl cryptography 2>/dev/null || true
        python3 -c "
        import socket
        from tenet.mixnet.reach_client import ReachRelayEndpoint, register_with_relay
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        register_with_relay(s, ReachRelayEndpoint('{relay_host}', {relay_port}), '{peer_id}')
        print('reach_ok')
        "
        """
    )
    out = ssh_run(expert, script, timeout=30)
    if "reach_ok" not in out:
        raise RuntimeError(f"REACH register failed on {expert.host}: {out}")


def export_peer_address_on_relay(topology: GateBTopology, peer_id: str) -> dict:
    script = textwrap.dedent(
        f"""
        set -euo pipefail
        cd ~/tenet
        python3 scripts/export-relay-peer-address.py \\
          --config config/live-reach-relay.json \\
          --node-id reach-beta-1 \\
          --peer-id {peer_id}
        """
    )
    return json.loads(ssh_run(topology.reach_relay, script, timeout=30))


def verify_network(topology: GateBTopology) -> list[str]:
    """Cross-node checks. Returns log lines (raises on failure)."""
    import socket

    from tenet.mixnet.reach_client import ReachRelayEndpoint, register_with_relay

    lines: list[str] = []
    relay_host, relay_port = topology.relay_endpoint()

    for expert in topology.experts:
        if expert.host == relay_host:
            raise ValueError(f"expert node {expert.host} must not equal reach relay {relay_host}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    register_with_relay(
        sock,
        ReachRelayEndpoint(relay_host, relay_port),
        "gateb-asker-probe01",
    )
    lines.append(f"asker→relay REACH ok {relay_host}:{relay_port}")

    probe_id = "gateb-expert-probe01"
    reach_register_from_expert_node(topology, topology.experts[0], probe_id)
    lines.append(f"expert→relay REACH ok expert={topology.experts[0].host}")

    record = export_peer_address_on_relay(topology, probe_id)
    if record.get("peer_id") != probe_id:
        raise ValueError("peer_address export mismatch")
    lines.append("relay exported peer_address")

    return lines
