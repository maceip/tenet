"""Helpers shared across P-OR tests."""

from __future__ import annotations

import json
import socket
from pathlib import Path

from sphinxmix.OutfoxParams import OutfoxParams

from por.config import DEFAULT_PAYLOAD_SIZE, DEFAULT_ROUTING_SIZE


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
