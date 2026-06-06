"""Legacy / test helper for control-record responsibility (xor sort).

This module contains the original small "pseudo-DHT" used for unit tests and
for environments that do not enable CAPABILITY_CONTROL_DHT. It is a pure
local sort over a provided peer list and does *not* provide routing tables,
iterative lookups, liveness, churn handling, or bootstrap recovery.

Production nodes with the control_dht capability use the real Kademlia
implementation from kademlia_overlay (library-backed, actual Kademlia
behavior for the control record overlay). The toy functions here remain
available for tests that want deterministic local plans without a network.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from tenet.mixnet.control.records import SignedControlRecord


@dataclass(frozen=True)
class ControlDhtPeer:
    node_id: str
    node_key: str | None = None

    @property
    def key_bytes(self) -> bytes:
        return dht_key_bytes(self.node_key or self.node_id)


@dataclass(frozen=True)
class ControlDhtPlan:
    key: str
    key_hash: str
    replication_factor: int
    responsible_nodes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "key_hash": self.key_hash,
            "replication_factor": self.replication_factor,
            "responsible_nodes": list(self.responsible_nodes),
        }


def dht_key_bytes(value: str | bytes) -> bytes:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return sha256(b"tenet.mixnet.control.dht.2026-06" + raw).digest()


def xor_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("DHT keys must have equal length")
    return int.from_bytes(bytes(a ^ b for a, b in zip(left, right)), "big")


def responsible_nodes(
    key: str,
    peers: Sequence[ControlDhtPeer],
    *,
    replication_factor: int = 5,
) -> tuple[ControlDhtPeer, ...]:
    if replication_factor < 1:
        raise ValueError("replication_factor must be positive")
    key_hash = dht_key_bytes(key)
    ordered = sorted(
        peers,
        key=lambda peer: (xor_distance(key_hash, peer.key_bytes), peer.node_id),
    )
    return tuple(ordered[:replication_factor])


def replication_plan(
    signed: SignedControlRecord,
    peers: Sequence[ControlDhtPeer],
    *,
    replication_factor: int = 5,
) -> ControlDhtPlan:
    selected = responsible_nodes(
        signed.record.key,
        peers,
        replication_factor=replication_factor,
    )
    return ControlDhtPlan(
        key=signed.record.key,
        key_hash=dht_key_bytes(signed.record.key).hex(),
        replication_factor=replication_factor,
        responsible_nodes=tuple(peer.node_id for peer in selected),
    )
