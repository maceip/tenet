"""REACH_* control codec tests — round-trip, bad cookie, expired, unknown tag."""

import time
import pytest

from tenet.mixnet.reach_wire import (
    encode_register, encode_challenge, encode_confirm, encode_heartbeat,
    decode_reach_datagram, is_reach_datagram, ReachAction,
    REACH_REGISTER, REACH_CHALLENGE, REACH_CONFIRM, REACH_HEARTBEAT,
)
from tenet.mixnet.peer_address import (
    UdpEndpoint, AddressExposurePolicy,
    TRANSPORT_QUIC_DATAGRAM, TRANSPORT_H3_WEBSOCKET,
)


def test_register_round_trip():
    data = encode_register("expert_art", policy=AddressExposurePolicy(expose_direct_endpoint=True))
    assert is_reach_datagram(data)
    action = decode_reach_datagram(data)
    assert action.kind == "register"
    assert action.peer_id == "expert_art"
    assert action.policy.expose_direct_endpoint is True
    assert TRANSPORT_QUIC_DATAGRAM in action.transports


def test_challenge_round_trip():
    ep = UdpEndpoint("127.0.0.1", 8080)
    cookie = b"0123456789abcdef"
    expires = time.time() + 30
    data = encode_challenge("supernode_1", ep, cookie, expires)
    assert is_reach_datagram(data)
    action = decode_reach_datagram(data)
    assert action.kind == "challenge"
    assert action.relay_id == "supernode_1"
    assert action.observed_endpoint == ep
    assert action.cookie == cookie
    assert abs(action.expires_at - expires) < 0.01


def test_confirm_round_trip():
    cookie = b"abcdef0123456789"
    data = encode_confirm(
        "expert_art", cookie,
        transports=(TRANSPORT_QUIC_DATAGRAM, TRANSPORT_H3_WEBSOCKET),
        policy=AddressExposurePolicy(stable_relay_only=True),
    )
    assert is_reach_datagram(data)
    action = decode_reach_datagram(data)
    assert action.kind == "confirm"
    assert action.peer_id == "expert_art"
    assert action.cookie == cookie
    assert TRANSPORT_QUIC_DATAGRAM in action.transports
    assert TRANSPORT_H3_WEBSOCKET in action.transports
    assert action.policy.stable_relay_only is True


def test_heartbeat_round_trip():
    data = encode_heartbeat("expert_art")
    action = decode_reach_datagram(data)
    assert action.kind == "heartbeat"
    assert action.peer_id == "expert_art"
    assert action.observed_endpoint is None


def test_heartbeat_with_endpoint():
    ep = UdpEndpoint("192.168.1.5", 4321)
    data = encode_heartbeat("expert_art", observed_endpoint=ep)
    action = decode_reach_datagram(data)
    assert action.kind == "heartbeat"
    assert action.observed_endpoint == ep


def test_unknown_tag_raises():
    with pytest.raises(ValueError, match="unknown REACH tag"):
        decode_reach_datagram(b'\x1f' + b'\x00' * 20)


def test_truncated_register_raises():
    with pytest.raises(ValueError, match="too short"):
        decode_reach_datagram(REACH_REGISTER + b'\x00' * 5)


def test_not_reach_datagram():
    assert not is_reach_datagram(b'\x00' + b'\x00' * 50)
    assert not is_reach_datagram(b'\x01' + b'\x00' * 50)
    assert not is_reach_datagram(b'\x02')
    assert not is_reach_datagram(b'')
    assert is_reach_datagram(REACH_REGISTER + b'\x00' * 20)


def test_outfox_bytes_not_reach():
    assert not is_reach_datagram(b'\x00' + b'\x00' * 100)
    assert not is_reach_datagram(b'\x01' + b'\x00' * 100)
