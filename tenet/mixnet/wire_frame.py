"""Canonical binary wire framing for tenet datagrams.

Each UDP datagram is one tenet frame:

  0x00 || header || payload     Forward Outfox packet
  0x01 || circuit_packet_body   Return circuit packet (already typed internally)
  0x02                          Shutdown control

Header/payload split for forward packets: the receiver knows payload_size
from config, so header_len = len(datagram) - 1 - payload_size.

This module is the ONLY place that defines wire byte layout for production
daemons.
"""

from __future__ import annotations

FORWARD = b'\x00'
CIRCUIT = b'\x01'
SHUTDOWN = b'\x02'


def encode_forward(header: bytes, payload: bytes) -> bytes:
    return FORWARD + header + payload


def encode_circuit(circuit_packet: bytes) -> bytes:
    if circuit_packet[0:1] == CIRCUIT:
        return circuit_packet
    return CIRCUIT + circuit_packet


def encode_shutdown() -> bytes:
    return SHUTDOWN


def decode_datagram(data: bytes, payload_size: int) -> tuple[str, bytes, bytes | None]:
    """Decode a raw datagram into (kind, body_a, body_b).

    Returns:
      ("forward", header, payload)
      ("circuit", circuit_packet, None)
      ("shutdown", b"", None)
      ("unknown", raw_data, None)
    """
    if not data:
        return ("unknown", data, None)

    tag = data[0:1]
    if tag == SHUTDOWN:
        return ("shutdown", b"", None)
    if tag == FORWARD:
        body = data[1:]
        header_len = len(body) - payload_size
        if header_len <= 0:
            return ("unknown", data, None)
        return ("forward", body[:header_len], body[header_len:])
    if tag == CIRCUIT:
        return ("circuit", data, None)

    return ("unknown", data, None)
