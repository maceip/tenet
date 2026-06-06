"""Client/runtime helpers for live mixnet control-record sync."""

from __future__ import annotations

import socket
import time
from typing import Sequence

from tenet.config import CAPABILITY_CONTROL_DHT, ClusterConfig
from tenet.mixnet.control.records import ControlRecordError, SignedControlRecord
from tenet.mixnet.control.service import MixnetControlService
from tenet.mixnet.control.wire import (
    ControlWireMessage,
    MSG_SYNC,
    MSG_SYNC_RESPONSE,
    decode_control_message,
    encode_control_message,
)

CONTROL_SYNC_PREFIXES: tuple[str, ...] = (
    "trust/",
    "mixnode/",
    "pool/",
    "client/",
    "name/",
    "match/",
    "expert/",
    "topic/",
    "review/",
)


def sync_control_from_cluster(
    service: MixnetControlService | None,
    cluster: ClusterConfig,
    *,
    node_ids: Sequence[str] = (),
    prefixes: Sequence[str] = CONTROL_SYNC_PREFIXES,
    timeout: float = 0.25,
    limit: int = 100,
) -> int:
    """Best-effort live sync from known mixnet/control nodes into ``service``.

    This does not create network truth from static config: static config only
    names initial mixnet contacts. Every returned record still has to pass the
    service's signature, expiry, network, and direct-dial validation.
    """

    if service is None:
        return 0
    targets = _target_addrs(cluster, node_ids=node_ids)
    if not targets:
        return 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(min(timeout, 0.2))
    stored = 0
    deadline = time.time() + max(0.0, timeout)
    try:
        for _node_id, addr in targets:
            for prefix in prefixes:
                if time.time() >= deadline:
                    return stored
                message = ControlWireMessage(
                    MSG_SYNC,
                    {"prefix": str(prefix), "cursor": "", "limit": int(limit)},
                )
                try:
                    sock.sendto(encode_control_message(message), addr)
                except OSError:
                    continue
        while time.time() < deadline:
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                message = decode_control_message(data)
            except (ValueError, UnicodeDecodeError):
                continue
            if message.kind != MSG_SYNC_RESPONSE:
                continue
            records = message.body.get("records") or ()
            if not isinstance(records, list):
                continue
            for raw in records:
                if not isinstance(raw, dict):
                    continue
                try:
                    service.put_signed(SignedControlRecord.from_dict(raw))
                    stored += 1
                except (ControlRecordError, ValueError, TypeError):
                    continue
    finally:
        sock.close()
    return stored


def _target_addrs(
    cluster: ClusterConfig,
    *,
    node_ids: Sequence[str],
) -> tuple[tuple[str, tuple[str, int]], ...]:
    selected = set(str(node_id) for node_id in node_ids if node_id)
    targets = []
    for node in cluster.nodes.values():
        if selected and node.node_id not in selected:
            continue
        if selected or node.has_capability(CAPABILITY_CONTROL_DHT):
            targets.append((node.node_id, (node.host, int(node.port))))
    return tuple(sorted(targets, key=lambda item: item[0]))
