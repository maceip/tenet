"""Outfox client-side packet creation and SURB handling.

Implements LMC.PacketCreate, LMC.SurbCreate, LMC.SurbUse,
LMC.SurbCheck, and LMC.SurbRecover from Rial et al. (2025).

Extended with tenet additions: per-layer timestamps, dummy flag,
ML-DSA-65 signatures, and return-path circuit setup material.
"""

import hmac as _hmac
import struct
from os import urandom
from collections import namedtuple

from tenet.packet.OutfoxParams import (
    OutfoxParams, KEM_X25519,
    aead_encrypt, aead_decrypt, hkdf, derive_circuit_key,
    AEAD_TAG_SIZE, TIMESTAMP_SIZE, FLAG_SIZE,
    FLAG_REAL, FLAG_DUMMY,
    make_timestamp, sign_payload, generate_signing_keypair,
)

pki_entry = namedtuple("pki_entry", ["id", "x", "y"])


def pad_body(total_size, body):
    body = body + b"\x7f"
    if len(body) > total_size:
        raise ValueError("Insufficient space for body")
    body = body + (b"\xff" * (total_size - len(body)))
    return body


def unpad_body(body):
    body = bytes(body)
    l = len(body) - 1
    while body[l] == 0xff and l > 0:
        l -= 1
    if body[l] == 0x7f:
        return body[:l]
    return b''


def _build_header(params, route, public_keys, flag=FLAG_REAL, circuit_setup=None):
    """Build nested AEAD header and collect per-hop keys.

    Each layer's AEAD plaintext:
      routing(16) + timestamp(8) + flag(1) [+ circuit_fields] [+ inner_header]

    circuit_setup: optional list of per-hop dicts with keys:
      inbound_link_cid (16 bytes), key_seed (16 bytes),
      next_hop (routing_size bytes), outbound_link_cid (16 bytes),
      ttl (int, seconds). When present, flag bit 0x02 is set for that hop.
    """
    n = len(route)
    assert n == len(public_keys)

    hop_data = []
    for i in range(n):
        shk, c = params.kem.encapsulate(public_keys[i])
        s_h, s_p = params.derive_keys(shk, c, public_keys[i])
        hop_data.append((s_h, s_p, c))

    headers_by_layer = []
    header = None
    for i in range(n - 1, -1, -1):
        s_h, s_p, c = hop_data[i]
        padded = (route[i] + b'\x00' * params.routing_size)[:params.routing_size]
        ts = make_timestamp()

        hop_flag = flag
        circuit_bytes = b''
        if circuit_setup is not None and i < len(circuit_setup):
            cs = circuit_setup[i]
            hop_flag = bytes([flag[0] | 0x02])
            next_hop_padded = (cs["next_hop"] + b'\x00' * params.routing_size)[:params.routing_size]
            circuit_bytes = (
                cs["inbound_link_cid"]
                + cs["key_seed"]
                + next_hop_padded
                + cs["outbound_link_cid"]
                + struct.pack(">H", cs["ttl"])
            )

        meta = padded + ts + hop_flag + circuit_bytes
        if header is None:
            plaintext = meta
        else:
            plaintext = meta + header
        beta, gamma = aead_encrypt(s_h, plaintext)
        header = c + beta + gamma
        headers_by_layer.append(header)

    headers_by_layer.reverse()
    return header, hop_data, headers_by_layer


def _surb_size(params, num_hops):
    """Compute SURB byte size for a given path length."""
    sizes = params.header_sizes(num_hops)
    return sizes[0] + params.k


def surb_create(params, route, public_keys):
    """LMC.SurbCreate: create a single-use reply block.

    Returns (surb, idsurb, sksurb) where:
      surb = (header_bytes, payload_key) — given to the receiver
      idsurb = innermost header — used by sender to identify replies
      sksurb = list of per-hop payload keys — used by sender to decrypt
    """
    n = len(route)
    header, hop_data, headers_by_layer = _build_header(params, route, public_keys)

    _, s_p_last, _ = hop_data[n - 1]
    surb = (header, s_p_last)

    idsurb = headers_by_layer[n - 1]

    sksurb = [s_p for (_, s_p, _) in hop_data]

    return surb, idsurb, sksurb


def surb_use(params, surb, reply_message):
    """LMC.SurbUse: receiver creates a reply packet using a SURB.

    surb: (header_bytes, payload_key)
    reply_message: plaintext reply bytes

    Returns packet = (header, payload)
    """
    header, s_p_key = surb

    from struct import pack as struct_pack
    surb_field = struct_pack(">H", 0) + b'\x00' * params.surb_size
    inner = (b'\x00' * params.k) + surb_field + reply_message
    payload = pad_body(params.payload_size, inner)
    payload = params.se_enc(s_p_key, payload)

    return header, payload


def surb_check(packet_header, idsurb):
    """LMC.SurbCheck: check if a packet is a reply matching this SURB."""
    return packet_header[-len(idsurb):] == idsurb


def surb_recover(params, packet_payload, sksurb):
    """LMC.SurbRecover: sender decrypts a reply packet.

    sksurb: list of per-hop payload keys [s_0^p, ..., s_k^p]

    The reply was encrypted once with s_k^p by the receiver.
    Each relay applied SE.Dec. To reverse: apply SE.Enc for hops k-1..0,
    then SE.Dec with s_k^p to get the plaintext.
    """
    payload = packet_payload
    for i in range(len(sksurb) - 2, -1, -1):
        payload = params.se_enc(sksurb[i], payload)
    payload = params.se_dec(sksurb[-1], payload)

    if not _hmac.compare_digest(payload[:params.k], b'\x00' * params.k):
        raise ValueError("Modified reply payload")

    msg_start = params.k + 2 + params.surb_size
    return unpad_body(payload[msg_start:])


def packet_create_repliable(params, fwd_route, fwd_keys,
                            rply_route, rply_keys, message,
                            install_circuit=False):
    """Create a repliable request with embedded SURB.

    Returns (packet, idsurb, sksurb) when install_circuit is False.
    Returns (packet, idsurb, sksurb, circuit_info) when install_circuit is True,
    where circuit_info contains per-hop link CIDs and keys for client decryption.
    """
    surb, idsurb, sksurb = surb_create(params, rply_route, rply_keys)

    circuit_setup = None
    circuit_info = None
    if install_circuit:
        n = len(fwd_route)
        logical_circuit = urandom(16)
        client_inbound = urandom(16)

        inbound_cids = [urandom(16) for _ in range(n)]
        outbound_cids = [None] * n
        seeds = [urandom(16) for _ in range(n)]

        # Link binding: hop[i].outbound = hop[i-1].inbound (toward client)
        # hop[0] (first relay) outbound = client_inbound
        # hop[n-1] (exit) outbound = hop[n-2].inbound
        outbound_cids[0] = client_inbound
        for i in range(1, n):
            outbound_cids[i] = inbound_cids[i - 1]

        keys = [derive_circuit_key(seeds[i], inbound_cids[i]) for i in range(n)]

        circuit_setup = []
        for i in range(n):
            if i == 0:
                next_hop = b"client"
            else:
                next_hop = fwd_route[i - 1]
            circuit_setup.append({
                "inbound_link_cid": inbound_cids[i],
                "key_seed": seeds[i],
                "next_hop": next_hop,
                "outbound_link_cid": outbound_cids[i],
                "ttl": 120,
            })

        circuit_info = {
            "logical_circuit": logical_circuit,
            "client_inbound": client_inbound,
            "exit_outbound": outbound_cids[n - 1],
            "keys": list(reversed(keys)),
        }

    packet = packet_create(params, fwd_route, fwd_keys, message,
                           surb=surb, circuit_setup=circuit_setup)

    if install_circuit:
        return packet, idsurb, sksurb, circuit_info
    return packet, idsurb, sksurb


def packet_create_signed(params, route, public_keys, message,
                         signing_sk, sender_id, receiver_id,
                         surb=None):
    """Create a forward packet with ML-DSA-65 signed payload.

    The signature covers (sender_id, receiver_id, timestamp, message),
    providing integrity and non-repudiation independent of mpTLS.
    """
    ts = make_timestamp()
    signed_content = sender_id + receiver_id + ts + message
    signature = sign_payload(signing_sk, signed_content)

    sig_len = len(signature)
    inner_msg = struct.pack(">H", sig_len) + signature + signed_content

    return packet_create(params, route, public_keys, inner_msg, surb=surb)


def packet_create_dummy(params, route, public_keys):
    """Create a dummy (cover traffic) packet. Indistinguishable from real."""
    dummy_msg = urandom(64)
    return packet_create(params, route, public_keys, dummy_msg, flag=FLAG_DUMMY)


def packet_create(params, route, public_keys, message, surb=None, flag=FLAG_REAL,
                   circuit_setup=None):
    """LMC.PacketCreate: create a request packet.

    route: list of routing info bytes, one per hop (including receiver)
    public_keys: list of KEM public keys, one per hop (including receiver)
    message: plaintext message bytes
    surb: optional SURB to embed for repliability
    flag: FLAG_REAL or FLAG_DUMMY
    circuit_setup: optional per-hop circuit setup dicts (see _build_header)

    Returns packet = (header, payload)
    """
    n = len(route)
    header, hop_data, _ = _build_header(params, route, public_keys, flag=flag,
                                        circuit_setup=circuit_setup)

    from struct import pack as struct_pack
    if surb is not None:
        surb_header, surb_key = surb
        surb_bytes = surb_header + surb_key
        surb_len = len(surb_bytes)
        surb_field = struct_pack(">H", surb_len) + surb_bytes
        surb_field = surb_field + b'\x00' * (params.surb_size + 2 - len(surb_field))
        inner = (b'\x00' * params.k) + surb_field + message
    else:
        surb_field = struct_pack(">H", 0) + b'\x00' * params.surb_size
        inner = (b'\x00' * params.k) + surb_field + message

    payload = pad_body(params.payload_size, inner)

    for i in range(n - 1, -1, -1):
        _, s_p, _ = hop_data[i]
        payload = params.se_enc(s_p, payload)

    return header, payload
