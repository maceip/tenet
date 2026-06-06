"""REACH_* UDP control codec for PeerAddressRelay signaling.

Binary register/challenge/confirm/heartbeat messages for supernode
reachability. Separate from Outfox mix framing (0x00/0x01/0x02) and
from opaque forwarded payloads.

Wire layout (all messages):

  tag (1 byte) || payload (variable)

Tags:
  0x10  REACH_REGISTER   peer_id(16) transports(1) policy_flags(1)
  0x11  REACH_CHALLENGE   relay_id(16) observed_host(4) observed_port(2) cookie(16) expires(8)
  0x12  REACH_CONFIRM     peer_id(16) cookie(16) transports(1) policy_flags(1)
  0x13  REACH_HEARTBEAT   peer_id(16) [observed_host(4) observed_port(2)]

Transport byte: bitmask of supported transports
  bit 0 = quic_datagram
  bit 1 = webtransport
  bit 2 = h3_websocket

Policy flags byte:
  bit 0 = expose_direct_endpoint
  bit 1 = stable_relay_only
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Sequence

from tenet.mixnet.peer_address import (
    TRANSPORT_QUIC_DATAGRAM,
    TRANSPORT_WEBTRANSPORT,
    TRANSPORT_H3_WEBSOCKET,
    AddressExposurePolicy,
    UdpEndpoint,
)


REACH_REGISTER = b'\x10'
REACH_CHALLENGE = b'\x11'
REACH_CONFIRM = b'\x12'
REACH_HEARTBEAT = b'\x13'

REACH_TAGS = {REACH_REGISTER, REACH_CHALLENGE, REACH_CONFIRM, REACH_HEARTBEAT}

_TRANSPORT_BITS = {
    TRANSPORT_QUIC_DATAGRAM: 0x01,
    TRANSPORT_WEBTRANSPORT: 0x02,
    TRANSPORT_H3_WEBSOCKET: 0x04,
}
_BITS_TRANSPORT = {v: k for k, v in _TRANSPORT_BITS.items()}

PEER_ID_SIZE = 16
RELAY_ID_SIZE = 16
COOKIE_SIZE = 16


def _encode_transports(transports: Sequence[str]) -> int:
    bits = 0
    for t in transports:
        bits |= _TRANSPORT_BITS.get(t, 0)
    return bits or 0x01


def _decode_transports(byte: int) -> tuple[str, ...]:
    result = []
    for bit, name in sorted(_BITS_TRANSPORT.items()):
        if byte & bit:
            result.append(name)
    return tuple(result) or (TRANSPORT_QUIC_DATAGRAM,)


def _encode_policy(policy: AddressExposurePolicy) -> int:
    flags = 0
    if policy.expose_direct_endpoint:
        flags |= 0x01
    if policy.stable_relay_only:
        flags |= 0x02
    return flags


def _decode_policy(byte: int) -> AddressExposurePolicy:
    return AddressExposurePolicy(
        expose_direct_endpoint=bool(byte & 0x01),
        stable_relay_only=bool(byte & 0x02),
    )


def _pad_id(value: str) -> bytes:
    raw = value.encode("ascii")[:PEER_ID_SIZE]
    return raw + b'\x00' * (PEER_ID_SIZE - len(raw))


def _read_id(data: bytes) -> str:
    return data[:PEER_ID_SIZE].rstrip(b'\x00').decode("ascii")


def _encode_endpoint(ep: UdpEndpoint) -> bytes:
    ip_bytes = socket.inet_aton(ep.host)
    return ip_bytes + struct.pack(">H", ep.port)


def _decode_endpoint(data: bytes) -> UdpEndpoint:
    host = socket.inet_ntoa(data[:4])
    port = struct.unpack(">H", data[4:6])[0]
    return UdpEndpoint(host=host, port=port)


# ── Encoders ────────────────────────────────────────────────────────

def encode_register(
    peer_id: str,
    transports: Sequence[str] = (TRANSPORT_QUIC_DATAGRAM,),
    policy: AddressExposurePolicy | None = None,
) -> bytes:
    policy = policy or AddressExposurePolicy()
    return (
        REACH_REGISTER
        + _pad_id(peer_id)
        + bytes([_encode_transports(transports)])
        + bytes([_encode_policy(policy)])
    )


def encode_challenge(
    relay_id: str,
    observed_endpoint: UdpEndpoint,
    cookie: bytes,
    expires_at: float,
) -> bytes:
    return (
        REACH_CHALLENGE
        + _pad_id(relay_id)
        + _encode_endpoint(observed_endpoint)
        + cookie[:COOKIE_SIZE]
        + struct.pack(">Q", int(expires_at * 1000))
    )


def encode_confirm(
    peer_id: str,
    cookie: bytes,
    transports: Sequence[str] = (TRANSPORT_QUIC_DATAGRAM,),
    policy: AddressExposurePolicy | None = None,
) -> bytes:
    policy = policy or AddressExposurePolicy()
    return (
        REACH_CONFIRM
        + _pad_id(peer_id)
        + cookie[:COOKIE_SIZE]
        + bytes([_encode_transports(transports)])
        + bytes([_encode_policy(policy)])
    )


def encode_heartbeat(
    peer_id: str,
    observed_endpoint: UdpEndpoint | None = None,
) -> bytes:
    data = REACH_HEARTBEAT + _pad_id(peer_id)
    if observed_endpoint is not None:
        data += _encode_endpoint(observed_endpoint)
    return data


# ── Decoder ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ReachAction:
    kind: str
    peer_id: str = ""
    relay_id: str = ""
    observed_endpoint: UdpEndpoint | None = None
    cookie: bytes = b""
    expires_at: float = 0.0
    transports: tuple[str, ...] = ()
    policy: AddressExposurePolicy = AddressExposurePolicy()


def is_reach_datagram(data: bytes) -> bool:
    return len(data) >= 1 and data[0:1] in REACH_TAGS


def decode_reach_datagram(data: bytes) -> ReachAction:
    if len(data) < 1:
        raise ValueError("empty datagram")

    tag = data[0:1]
    body = data[1:]

    if tag == REACH_REGISTER:
        if len(body) < PEER_ID_SIZE + 2:
            raise ValueError("REACH_REGISTER too short")
        peer_id = _read_id(body)
        transports = _decode_transports(body[PEER_ID_SIZE])
        policy = _decode_policy(body[PEER_ID_SIZE + 1])
        return ReachAction(kind="register", peer_id=peer_id,
                           transports=transports, policy=policy)

    if tag == REACH_CHALLENGE:
        if len(body) < RELAY_ID_SIZE + 6 + COOKIE_SIZE + 8:
            raise ValueError("REACH_CHALLENGE too short")
        relay_id = _read_id(body)
        off = RELAY_ID_SIZE
        endpoint = _decode_endpoint(body[off:off + 6])
        off += 6
        cookie = body[off:off + COOKIE_SIZE]
        off += COOKIE_SIZE
        expires_ms = struct.unpack(">Q", body[off:off + 8])[0]
        return ReachAction(kind="challenge", relay_id=relay_id,
                           observed_endpoint=endpoint, cookie=cookie,
                           expires_at=expires_ms / 1000.0)

    if tag == REACH_CONFIRM:
        if len(body) < PEER_ID_SIZE + COOKIE_SIZE + 2:
            raise ValueError("REACH_CONFIRM too short")
        peer_id = _read_id(body)
        off = PEER_ID_SIZE
        cookie = body[off:off + COOKIE_SIZE]
        off += COOKIE_SIZE
        transports = _decode_transports(body[off])
        policy = _decode_policy(body[off + 1])
        return ReachAction(kind="confirm", peer_id=peer_id, cookie=cookie,
                           transports=transports, policy=policy)

    if tag == REACH_HEARTBEAT:
        if len(body) < PEER_ID_SIZE:
            raise ValueError("REACH_HEARTBEAT too short")
        peer_id = _read_id(body)
        endpoint = None
        if len(body) >= PEER_ID_SIZE + 6:
            endpoint = _decode_endpoint(body[PEER_ID_SIZE:PEER_ID_SIZE + 6])
        return ReachAction(kind="heartbeat", peer_id=peer_id,
                           observed_endpoint=endpoint)

    raise ValueError(f"unknown REACH tag: {tag.hex()}")
