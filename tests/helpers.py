"""Helpers shared across tenet tests."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from tenet.packet.OutfoxParams import OutfoxParams

from tenet.config import DEFAULT_PAYLOAD_SIZE, DEFAULT_ROUTING_SIZE
from tenet.experts.directory import PublicManifestDirectory
from tenet.experts.expert_route import PeerObservation
from tenet.experts.memory_index import IndexConfig, build_memory_index
from tenet.mixnet.wire_frame import encode_shutdown


def reserve_udp_ports(count: int) -> list[int]:
    """Reserve ephemeral ports by bind-then-close. **Subprocess use only.**

    This is the TOCTOU pattern (a port can be stolen between close and the
    child's rebind), tolerable *only* because subprocess nodes must bind ports
    chosen by the parent in advance and cannot inherit a held-open socket.
    In-process tests must use ``tests.harness.mixnet_harness`` /
    ``wire_cluster`` (bind-once, hold-open) instead.
    """
    socks: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            socks.append(sock)
        return [sock.getsockname()[1] for sock in socks]
    finally:
        for sock in socks:
            sock.close()


def write_wire_cluster(
    tmp_path: Path,
    *,
    node_ids: tuple[str, ...],
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    routing_size: int = DEFAULT_ROUTING_SIZE,
) -> tuple[Path, dict[str, object]]:
    params = OutfoxParams(payload_size=payload_size, routing_size=routing_size, max_hops=5)
    ports = reserve_udp_ports(len(node_ids) + 1)
    nodes: dict[str, object] = {}
    for node_id, port in zip(node_ids, ports[:-1]):
        pk, sk = params.kem.keygen()
        nodes[node_id] = {
            "host": "127.0.0.1",
            "port": port,
            "kem_pk": pk.hex(),
            "kem_sk": sk.hex(),
            "role": "expert" if node_id.startswith("expert") else "relay",
        }
    harness = {
        "params": {
            "payload_size": payload_size,
            "routing_size": routing_size,
            "max_hops": 5,
        },
        "client": {"host": "127.0.0.1", "port": ports[-1]},
        "nodes": nodes,
    }
    config_path = tmp_path / "cluster.json"
    config_path.write_text(json.dumps(harness), encoding="utf-8")
    return config_path, harness


def demo_node_ids(node_count: int) -> list[str]:
    base = ["relay1", "relay2", "expert_art", "expert_sys", "relay3"]
    return base[:node_count]


def write_process_wire_cluster(tmp_path: Path, *, node_count: int):
    node_ids = tuple(demo_node_ids(node_count))
    config_path, cluster = write_wire_cluster(tmp_path, node_ids=node_ids)
    return config_path, cluster, list(node_ids)


def demo_directory(tmp_path: Path) -> PublicManifestDirectory:
    art_root = tmp_path / "expert_art_memory"
    sys_root = tmp_path / "expert_sys_memory"
    art_root.mkdir(exist_ok=True)
    sys_root.mkdir(exist_ok=True)
    (art_root / "impressionism.md").write_text(
        "Monet Degas Renoir Impressionism Paris Salon color light brushwork modern painting.",
        encoding="utf-8",
    )
    (sys_root / "systems.md").write_text(
        "QUIC UDP congestion control packet loss stream transport scheduler.",
        encoding="utf-8",
    )
    art_manifest = build_memory_index(IndexConfig(peer_id="expert_art", roots=(str(art_root),))).manifest
    sys_manifest = build_memory_index(IndexConfig(peer_id="expert_sys", roots=(str(sys_root),))).manifest
    return PublicManifestDirectory.from_manifests(
        (art_manifest, sys_manifest),
        (
            PeerObservation(peer_id="expert_art", p50_latency_ms=80, completion_rate=0.99),
            PeerObservation(peer_id="expert_sys", p50_latency_ms=60, completion_rate=0.99),
        ),
        source="test-directory",
    )


def start_process_nodes(config_path: Path, node_ids: Sequence[str]) -> list[subprocess.Popen]:
    procs = []
    for node_id in node_ids:
        subcommand = "expert" if node_id.startswith("expert") else "relay"
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "tenet",
                    subcommand,
                    "--config",
                    str(config_path),
                    "--node-id",
                    node_id,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        )
    return procs


def shutdown_process_nodes(cluster: dict, node_ids: Sequence[str]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for node_id in node_ids:
            node = cluster["nodes"][node_id]
            sock.sendto(encode_shutdown(), (node["host"], node["port"]))
    finally:
        sock.close()


def collect_process_logs(procs: Sequence[subprocess.Popen]) -> str:
    chunks = []
    for proc in procs:
        try:
            out, _ = proc.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            out, _ = proc.communicate(timeout=2.0)
        chunks.append(out)
    return "".join(chunks)


def parse_json_log_events(text: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("schema") == "por.log.v1" and "event" in item:
            events.append(item)
    return events


def has_log_event(
    events: list[dict[str, object]],
    event: str,
    *,
    field: str | None = None,
    value: object | None = None,
) -> bool:
    for item in events:
        if item.get("event") != event:
            continue
        if field is None:
            return True
        fields = item.get("fields")
        if isinstance(fields, dict) and fields.get(field) == value:
            return True
    return False
