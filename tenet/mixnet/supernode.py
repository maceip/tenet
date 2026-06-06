"""Relay inline forward — user-space UDP relay for NAT'd peers.

Any relay with a public IP can forward packets for registered peers who
can't accept inbound connections. There is no special "supernode" role —
this is just a relay that opted into the REACH forwarding table.

Flow:
  1. Expert registers with supernode via PeerAddressRelay (challenge/confirm)
  2. Supernode stores (peer_id → last_seen_addr) in forwarding table
  3. Client dials supernode endpoint from directory/peer address record
  4. Supernode receives packet, looks up destination peer, forwards via UDP

This module does NOT parse Outfox headers, circuit packets, prompts, or
envelopes. It forwards opaque bytes based on a routing prefix.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Sequence

from tenet.mixnet.peer_address import (
    PeerAddressRelay,
    UdpEndpoint,
    AddressExposurePolicy,
    REGISTRATION_TTL_SECONDS,
    HEARTBEAT_INTERVAL_SECONDS,
)


@dataclass
class _ForwardEntry:
    peer_id: str
    addr: tuple[str, int]
    last_seen: float
    expires: float


class SupernodeForwarder:
    """Inline UDP forwarder for registered peers.

    The supernode listens on its public endpoint. When a packet arrives
    whose first 16 bytes (after type byte) match a registered peer's
    routing prefix, it forwards the packet to that peer's last-known
    address. When the peer sends a packet, the supernode forwards it
    to the original sender.

    This is NOT mix-network routing — it's a dumb relay for NAT traversal.
    The supernode sees encrypted bytes only.
    """

    def __init__(
        self,
        relay: PeerAddressRelay,
        *,
        ttl: int = REGISTRATION_TTL_SECONDS,
    ):
        self.relay = relay
        self.ttl = ttl
        self._peers: dict[str, _ForwardEntry] = {}
        self._addr_to_peer: dict[tuple[str, int], str] = {}

    def register_peer(self, peer_id: str, addr: tuple[str, int]) -> None:
        now = time.time()
        existing = self._peers.get(peer_id)
        if existing is not None and existing.addr != addr:
            self._addr_to_peer.pop(existing.addr, None)
        self._peers[peer_id] = _ForwardEntry(
            peer_id=peer_id,
            addr=addr,
            last_seen=now,
            expires=now + self.ttl,
        )
        self._addr_to_peer[addr] = peer_id

    def heartbeat(self, peer_id: str, addr: tuple[str, int]) -> bool:
        entry = self._peers.get(peer_id)
        if entry is None:
            return False
        now = time.time()
        if now >= entry.expires:
            self._remove(peer_id)
            return False
        if entry.addr != addr:
            self._addr_to_peer.pop(entry.addr, None)
        entry.addr = addr
        entry.last_seen = now
        entry.expires = now + self.ttl
        self._addr_to_peer[addr] = peer_id
        return True

    def lookup_peer_addr(self, peer_id: str) -> tuple[str, int] | None:
        entry = self._peers.get(peer_id)
        if entry is None:
            return None
        if time.time() >= entry.expires:
            self._remove(peer_id)
            return None
        return entry.addr

    def lookup_peer_by_addr(self, addr: tuple[str, int]) -> str | None:
        return self._addr_to_peer.get(addr)

    def purge_expired(self) -> int:
        now = time.time()
        expired = [pid for pid, e in self._peers.items() if now >= e.expires]
        for pid in expired:
            self._remove(pid)
        return len(expired)

    def peer_count(self) -> int:
        return len(self._peers)

    def _remove(self, peer_id: str) -> None:
        entry = self._peers.pop(peer_id, None)
        if entry:
            self._addr_to_peer.pop(entry.addr, None)


def run_supernode_forwarder(
    *,
    bind_host: str,
    bind_port: int,
    relay: PeerAddressRelay,
    forward_to_node: callable,
    ttl: int = REGISTRATION_TTL_SECONDS,
) -> SupernodeForwarder:
    """Create a SupernodeForwarder. The caller manages the event loop.

    forward_to_node: callback(sock, data, addr) for packets that should
    be processed by this node's own WireNodeRuntime (e.g. forward Outfox
    packets where this supernode is a relay hop).
    """
    return SupernodeForwarder(relay, ttl=ttl)
