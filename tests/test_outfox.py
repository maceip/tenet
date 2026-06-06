"""Tests for the Outfox post-quantum packet format with P-OR extensions.

Verifies: per-hop KEM, nested AEAD, HKDF, per-layer timestamps,
dummy flag, ML-DSA-65 signatures, return-path circuit processing,
and self-healing.
"""

from sphinxmix.OutfoxParams import (
    OutfoxParams, KEM_X25519,
    aead_encrypt, aead_decrypt, hkdf,
    make_timestamp, check_timestamp, sign_payload, verify_payload,
    generate_signing_keypair,
    FLAG_REAL, FLAG_DUMMY, CIRCUIT_TTL_SECONDS,
)
from sphinxmix.OutfoxClient import (
    pki_entry, packet_create, packet_create_repliable,
    packet_create_signed, packet_create_dummy,
    surb_create, surb_use, surb_check, surb_recover,
    pad_body, unpad_body,
)
from sphinxmix.OutfoxNode import (
    outfox_process, circuit_process, circuit_self_heal,
    circuit_packet_create, circuit_packet_process, circuit_packet_decrypt,
)
from sphinxmix.OutfoxParams import derive_circuit_key, CIRCUIT_MAGIC
from os import urandom
import struct
import time


def make_pki(params, n=10):
    pkiPriv = {}
    pkiPub = {}
    for i in range(n):
        nid = bytes([i])
        pk, sk = params.kem.keygen()
        pkiPriv[nid] = pki_entry(nid, sk, pk)
        pkiPub[nid] = pki_entry(nid, None, pk)
    return pkiPriv, pkiPub


def pad_route(nid, params):
    return (nid + b'\x00' * params.routing_size)[:params.routing_size]


def test_primitives():
    params = OutfoxParams()
    pk, sk = params.kem.keygen()
    shk, c = params.kem.encapsulate(pk)
    assert params.kem.decapsulate(c, sk) == shk

    s_h, s_p = params.derive_keys(shk, c, pk)
    pt = b"hello world!!!!!" * 4
    ct, tag = aead_encrypt(s_h, pt)
    assert aead_decrypt(s_h, ct, tag) == pt

    msg = urandom(128)
    assert params.se_dec(s_p, params.se_enc(s_p, msg)) == msg

    print("[PASS] Primitives: KEM, KDF, AEAD, SE.")


def test_timestamps():
    ts = make_timestamp()
    assert len(ts) == 8
    assert check_timestamp(ts, max_age_sec=5)

    old_ts = struct.pack(">Q", 0)
    assert not check_timestamp(old_ts, max_age_sec=5)

    future_ts = struct.pack(">Q", int((time.time() + 1) * 1000))
    assert check_timestamp(future_ts, max_age_sec=5)

    far_future_ts = struct.pack(">Q", int((time.time() + 10) * 1000))
    assert not check_timestamp(far_future_ts, max_age_sec=5)

    print("[PASS] Timestamps: fresh accepted, skew tolerated, expired rejected.")


def test_dilithium_signatures():
    pk, sk = generate_signing_keypair()
    msg = b"test payload content"
    sig = sign_payload(sk, msg)
    assert verify_payload(pk, msg, sig)
    assert not verify_payload(pk, b"tampered", sig)

    print("[PASS] ML-DSA-65 signatures: sign, verify, reject tampered.")


def test_forward_message():
    params = OutfoxParams(payload_size=1024)
    pkiPriv, pkiPub = make_pki(params)
    path = [bytes([i]) for i in range(5)]

    route = list(path)
    keys = [pkiPub[nid].y for nid in path]
    message = b"hello outfox world"
    header, payload = packet_create(params, route, keys, message)

    for i in range(len(path)):
        nid = path[i]
        is_last = (i == len(path) - 1)
        result = outfox_process(params, pkiPriv[nid].x, pkiPriv[nid].y,
                                (header, payload), is_last=is_last)
        assert result is not None, f"Processing failed at hop {i}"

        if is_last:
            routing, flag, msg, surb_info = result
            assert routing == pad_route(nid, params)
            assert flag == FLAG_REAL
            assert msg == message
            assert surb_info is None
        else:
            routing, flag, (header, payload) = result
            assert routing == pad_route(nid, params)
            assert flag == FLAG_REAL

    print("[PASS] Forward message: 5-hop delivery with timestamps and flags.")


def test_dummy_traffic():
    params = OutfoxParams(payload_size=1024)
    pkiPriv, pkiPub = make_pki(params)
    path = [bytes([0]), bytes([1])]

    route = list(path)
    keys = [pkiPub[nid].y for nid in path]

    header, payload = packet_create_dummy(params, route, keys)

    result = outfox_process(params, pkiPriv[path[0]].x, pkiPriv[path[0]].y,
                            (header, payload))
    assert result is not None
    routing, flag, (next_h, next_p) = result
    assert flag == FLAG_DUMMY

    print("[PASS] Dummy traffic: flag=DUMMY propagated through header.")


def test_signed_payload():
    params = OutfoxParams(payload_size=4096)
    pkiPriv, pkiPub = make_pki(params)
    path = [bytes([0]), bytes([1])]

    sign_pk, sign_sk = generate_signing_keypair()
    sender_id = b"alice_id_1234567"
    receiver_id = b"bob_id_12345678"

    route = list(path)
    keys = [pkiPub[nid].y for nid in path]

    header, payload = packet_create_signed(
        params, route, keys, b"secret prompt",
        sign_sk, sender_id, receiver_id)

    for i in range(len(path)):
        is_last = (i == len(path) - 1)
        result = outfox_process(params, pkiPriv[path[i]].x, pkiPriv[path[i]].y,
                                (header, payload), is_last=is_last)
        if is_last:
            routing, flag, msg, _ = result
            sig_len = struct.unpack(">H", msg[:2])[0]
            signature = msg[2:2 + sig_len]
            signed_content = msg[2 + sig_len:]
            assert verify_payload(sign_pk, signed_content, signature)
            assert sender_id in signed_content
            assert receiver_id in signed_content
            assert b"secret prompt" in signed_content
        else:
            routing, flag, (header, payload) = result

    print("[PASS] Signed payload: ML-DSA-65 signature verified at exit.")


def test_surb_reply():
    params = OutfoxParams(payload_size=1024)
    pkiPriv, pkiPub = make_pki(params)

    fwd_path = [bytes([i]) for i in range(4)]
    rply_relays = [bytes([i + 4]) for i in range(3)]
    sender_id = bytes([9])

    fwd_route = list(fwd_path)
    fwd_keys = [pkiPub[nid].y for nid in fwd_path]
    rply_route = list(rply_relays) + [sender_id]
    rply_keys = [pkiPub[nid].y for nid in rply_relays] + [pkiPub[sender_id].y]

    message = b"request with reply"
    (header, payload), idsurb, sksurb = packet_create_repliable(
        params, fwd_route, fwd_keys, rply_route, rply_keys, message)

    for i in range(len(fwd_path)):
        is_last = (i == len(fwd_path) - 1)
        result = outfox_process(params, pkiPriv[fwd_path[i]].x,
                                pkiPriv[fwd_path[i]].y,
                                (header, payload), is_last=is_last)
        if is_last:
            routing, flag, msg, surb_info = result
            assert msg == message
            assert surb_info is not None
            surb_header, surb_key = surb_info
        else:
            routing, flag, (header, payload) = result

    reply_msg = b"here is my reply"
    reply_header, reply_payload = surb_use(params, (surb_header, surb_key), reply_msg)

    for i in range(len(rply_relays)):
        nid = rply_relays[i]
        routing, flag, (reply_header, reply_payload) = outfox_process(
            params, pkiPriv[nid].x, pkiPriv[nid].y,
            (reply_header, reply_payload), is_last=False)

    assert surb_check(reply_header, idsurb)
    received = surb_recover(params, reply_payload, list(sksurb))
    assert received == reply_msg

    print("[PASS] SURB reply: full repliable round-trip with timestamps.")


def test_aead_integrity():
    params = OutfoxParams(payload_size=1024)
    pkiPriv, pkiPub = make_pki(params)
    path = [bytes([0]), bytes([1])]
    route = list(path)
    keys = [pkiPub[nid].y for nid in path]
    header, payload = packet_create(params, route, keys, b"test")

    tampered = bytearray(header)
    tampered[40] ^= 0xFF
    try:
        outfox_process(params, pkiPriv[path[0]].x, pkiPriv[path[0]].y,
                       (bytes(tampered), payload))
        assert False
    except ValueError:
        pass

    print("[PASS] AEAD integrity: header tampering detected.")


def test_payload_tagging():
    params = OutfoxParams(payload_size=1024)
    pkiPriv, pkiPub = make_pki(params)
    path = [bytes([0]), bytes([1]), bytes([2])]
    route = list(path)
    keys = [pkiPub[nid].y for nid in path]
    header, payload = packet_create(params, route, keys, b"secret msg")

    tagged = bytearray(payload)
    tagged[50] ^= 0xFF

    h, p = header, bytes(tagged)
    for i in range(len(path)):
        result = outfox_process(params, pkiPriv[path[i]].x, pkiPriv[path[i]].y,
                                (h, p), is_last=(i == len(path) - 1))
        if i == len(path) - 1:
            assert result is None
        else:
            _, _, (h, p) = result

    print("[PASS] Payload tagging: PRP destroys contents, detected at exit.")


def test_circuit_symmetric():
    """Test return-path symmetric circuit processing."""
    params = OutfoxParams(payload_size=1024)
    key = urandom(params.k)
    token_data = pad_body(params.payload_size, b"streaming token data here")

    encrypted = params.aes_ctr(key, token_data)
    decrypted = circuit_process(params, key, encrypted)
    assert decrypted == token_data

    healed = circuit_self_heal(params, params.payload_size)
    assert len(healed) == params.payload_size
    assert healed != token_data

    print("[PASS] Circuit symmetric: encrypt/decrypt + self-healing.")


def test_multiple_path_lengths():
    params = OutfoxParams(payload_size=1024)
    pkiPriv, pkiPub = make_pki(params)

    for num_hops in [1, 2, 3, 4, 5, 7]:
        path = [bytes([i]) for i in range(num_hops)]
        route = list(path)
        keys = [pkiPub[nid].y for nid in path]
        message = f"path length {num_hops}".encode()
        header, payload = packet_create(params, route, keys, message)

        for i in range(num_hops):
            is_last = (i == num_hops - 1)
            result = outfox_process(params, pkiPriv[path[i]].x,
                                    pkiPriv[path[i]].y,
                                    (header, payload), is_last=is_last)
            assert result is not None, f"Failed at {num_hops} hops, hop {i}"
            if is_last:
                _, _, msg, _ = result
                assert msg == message
            else:
                _, _, (header, payload) = result

    print("[PASS] Variable path lengths: 1 through 7 hops all work.")


# ═══════════════════════════════════════════════════════════════════
# Phase 1: Circuit packet tests
# ═══════════════════════════════════════════════════════════════════


def test_derive_circuit_key():
    """derive_circuit_key produces deterministic 16-byte keys."""
    seed = urandom(16)
    cid = urandom(16)
    k1 = derive_circuit_key(seed, cid)
    k2 = derive_circuit_key(seed, cid)
    assert k1 == k2
    assert len(k1) == 16

    k3 = derive_circuit_key(seed, urandom(16))
    assert k3 != k1

    k4 = derive_circuit_key(urandom(16), cid)
    assert k4 != k1

    print("[PASS] derive_circuit_key: deterministic, 16 bytes, varies with inputs.")


def test_circuit_packet_round_trip_single_hop():
    """Single-hop circuit: create at exit, decrypt at client."""
    params = OutfoxParams(payload_size=256)
    exit_key = urandom(16)
    circuit_id = urandom(16)
    token = b"hello streaming world"

    packet = circuit_packet_create(params, circuit_id, 1, token, [exit_key])
    assert len(packet) == params.payload_size

    result = circuit_packet_decrypt(params, exit_key, packet)
    assert result == token

    print("[PASS] Circuit packet: single-hop create/decrypt round-trip.")


def test_circuit_packet_round_trip_multi_hop():
    """Multi-hop relay-additive circuit: exit creates, relays add, client peels."""
    params = OutfoxParams(payload_size=512)
    circuit_id = urandom(16)

    exit_key = urandom(16)
    key_a = urandom(16)
    key_b = urandom(16)

    token = b"multi-hop token data here"
    packet = circuit_packet_create(params, circuit_id, 42, token, [exit_key])
    assert len(packet) == params.payload_size

    # Relay B is closest to the exit and adds its layer first.
    cid, nonce, packet = circuit_packet_process(params, key_b, packet)
    assert cid == circuit_id
    assert nonce == 42

    # Relay A is closest to the client and adds the outermost layer.
    cid, nonce, packet = circuit_packet_process(params, key_a, packet)
    assert cid == circuit_id
    assert nonce == 42

    # Client peels client-side relay, exit-side relay, then exit.
    result = circuit_packet_decrypt(params, [key_a, key_b, exit_key], packet)
    assert result == token

    print("[PASS] Circuit packet: relay-additive 3-layer round-trip.")


def test_circuit_packet_variable_hops():
    """Relay-additive circuit packets work for 1-5 hops."""
    params = OutfoxParams(payload_size=512)
    circuit_id = urandom(16)

    for num_hops in range(1, 6):
        keys = [urandom(16) for _ in range(num_hops)]
        token = f"hops={num_hops}".encode()
        packet = circuit_packet_create(params, circuit_id, 1, token, [keys[0]])

        # Relay processing adds layers from exit-side toward client-side.
        for i in range(1, num_hops):
            _, _, packet = circuit_packet_process(params, keys[i], packet)

        result = circuit_packet_decrypt(params, list(reversed(keys[1:])) + [keys[0]], packet)
        assert result == token, f"Failed at {num_hops} hops"

    print("[PASS] Circuit packet: relay-additive 1-5 hop round-trips all work.")


def test_circuit_packet_nonce_in_header():
    """Nonce is readable from the packet header without decryption."""
    params = OutfoxParams(payload_size=256)
    key = urandom(16)
    circuit_id = urandom(16)

    for nonce_val in [0, 1, 255, 65535, 2**32, 2**63 - 1]:
        packet = circuit_packet_create(params, circuit_id, nonce_val, b"x", [key])
        read_nonce = struct.unpack(">Q", packet[17:25])[0]
        assert read_nonce == nonce_val

    print("[PASS] Circuit packet: nonce readable from header at all values.")


def test_circuit_packet_magic_corruption():
    """Corrupted magic field causes client decrypt to return None."""
    params = OutfoxParams(payload_size=256)
    exit_key = urandom(16)
    circuit_id = urandom(16)

    packet = circuit_packet_create(params, circuit_id, 1, b"test", [exit_key])
    assert circuit_packet_decrypt(params, exit_key, packet) == b"test"

    # Corrupt one byte in the encrypted region (which contains magic)
    corrupted = bytearray(packet)
    corrupted[28] ^= 0xFF
    result = circuit_packet_decrypt(params, exit_key, bytes(corrupted))
    assert result is None

    print("[PASS] Circuit packet: magic corruption detected, returns None.")


def test_circuit_packet_wrong_key():
    """Wrong exit key produces magic mismatch."""
    params = OutfoxParams(payload_size=256)
    real_key = urandom(16)
    wrong_key = urandom(16)
    circuit_id = urandom(16)

    packet = circuit_packet_create(params, circuit_id, 1, b"secret", [real_key])
    result = circuit_packet_decrypt(params, wrong_key, packet)
    assert result is None

    print("[PASS] Circuit packet: wrong key produces None (magic mismatch).")


def test_circuit_packet_fixed_size():
    """All circuit packets pad to exactly payload_size regardless of token length."""
    params = OutfoxParams(payload_size=512)
    key = urandom(16)
    cid = urandom(16)

    for token_len in [0, 1, 16, 100, 400]:
        token = urandom(token_len)
        packet = circuit_packet_create(params, cid, 1, token, [key])
        assert len(packet) == params.payload_size
        assert circuit_packet_decrypt(params, key, packet) == token

    print("[PASS] Circuit packet: fixed-size padding for all token lengths.")


def test_circuit_packet_derived_keys():
    """Relay-additive round-trip with derive_circuit_key."""
    params = OutfoxParams(payload_size=512)
    circuit_id = urandom(16)
    seeds = [urandom(16) for _ in range(3)]
    keys = [derive_circuit_key(s, circuit_id) for s in seeds]

    token = b"derived key round trip"
    packet = circuit_packet_create(params, circuit_id, 7, token, [keys[0]])

    _, _, packet = circuit_packet_process(params, keys[1], packet)
    _, _, packet = circuit_packet_process(params, keys[2], packet)

    result = circuit_packet_decrypt(params, [keys[2], keys[1], keys[0]], packet)
    assert result == token

    print("[PASS] Circuit packet: relay-additive full round-trip with HKDF-derived keys.")


def test_circuit_header_budget():
    """Circuit setup fields fit within header budget at max_hops."""
    for max_hops in [3, 5, 7]:
        params = OutfoxParams(payload_size=1024, max_hops=max_hops)
        sizes_plain = params.header_sizes(max_hops, circuit_setup=False)
        sizes_circuit = params.header_sizes(max_hops, circuit_setup=True)

        for i in range(max_hops):
            assert sizes_circuit[i] > sizes_plain[i]

        pkiPriv, pkiPub = make_pki(params, n=max_hops)
        path = [bytes([i]) for i in range(max_hops)]
        route = list(path)
        keys_list = [pkiPub[nid].y for nid in path]

        from sphinxmix.OutfoxClient import packet_create_repliable
        from sphinxmix.OutfoxParams import derive_circuit_key
        (header, payload), _, _, circuit_info = packet_create_repliable(
            params, route, keys_list, route, keys_list, b"budget test",
            install_circuit=True)

        h, p = header, payload
        for i in range(max_hops):
            is_last = (i == max_hops - 1)
            circuits_installed = []
            def _capture(cid, ck, nh, outbound_cid, ttl):
                circuits_installed.append(cid)
            result = outfox_process(params, pkiPriv[path[i]].x,
                                    pkiPriv[path[i]].y, (h, p),
                                    is_last=is_last, on_circuit=_capture)
            assert result is not None, f"Failed at hop {i}/{max_hops}"
            assert len(circuits_installed) == 1, f"No circuit installed at hop {i}"
            if not is_last:
                _, _, (h, p) = result

    print("[PASS] Circuit header budget: 3, 5, 7 hops all fit with circuit setup.")


if __name__ == "__main__":
    print("=" * 60)
    print("Outfox + P-OR Extensions Test Suite")
    print("=" * 60)
    print()

    test_primitives()
    test_timestamps()
    test_dilithium_signatures()
    test_forward_message()
    test_dummy_traffic()
    test_signed_payload()
    test_surb_reply()
    test_aead_integrity()
    test_payload_tagging()
    test_circuit_symmetric()
    test_multiple_path_lengths()

    print()
    print("--- Phase 1: Circuit Packets ---")
    test_derive_circuit_key()
    test_circuit_packet_round_trip_single_hop()
    test_circuit_packet_round_trip_multi_hop()
    test_circuit_packet_variable_hops()
    test_circuit_packet_nonce_in_header()
    test_circuit_packet_magic_corruption()
    test_circuit_packet_wrong_key()
    test_circuit_packet_fixed_size()
    test_circuit_packet_derived_keys()
    test_circuit_header_budget()

    print()
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)
