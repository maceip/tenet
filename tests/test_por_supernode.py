"""Supernode reachability and peer-address control-plane tests."""

from __future__ import annotations

import time
from os import urandom

import pytest

from tenet.config import TrustedReachabilityRelayConfig
from tenet.edges.cli.supernode import SupernodeDaemon
from tenet.envelope import PromptRequestEnvelope
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.mixnet.peer_address import (
    ROUTE_DIRECT,
    ROUTE_RELAY,
    TRANSPORT_H3_WEBSOCKET,
    TRANSPORT_QUIC_DATAGRAM,
    AddressExposurePolicy,
    PeerAddressRelay,
    RelayCandidate,
    UdpEndpoint,
    build_dial_plan,
    peer_address_record_from_dict,
    verify_record_signature,
)
from tenet.mixnet.supernode import SupernodeForwarder
from tenet.mixnet.transport_dial import resolve_dial_target, send_prepared_envelope_via_plan
from tests.harness import static_wire_cluster


def _assist(*, ttl_seconds: int = 270):
    return PeerAddressRelay(
        relay_id="relay-a",
        relay_endpoint=UdpEndpoint("203.0.113.10", 4433),
        secret=b"peer-address-test-secret",
        ttl_seconds=ttl_seconds,
    )


@pytest.mark.parametrize(
    "allow_direct,prefer_direct,expose_direct,expected_primary,expected_fallback_kind",
    [
        (False, False, False, ROUTE_RELAY, None),
        (True, False, True, ROUTE_RELAY, ROUTE_DIRECT),
        (True, True, True, ROUTE_DIRECT, ROUTE_RELAY),
    ],
)
def test_dial_plan_relay_first_and_policy(
    allow_direct,
    prefer_direct,
    expose_direct,
    expected_primary,
    expected_fallback_kind,
):
    assist = _assist()
    challenge = assist.request_registration(
        peer_id="expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.20", 50000),
        now=100.0,
    )
    policy = AddressExposurePolicy(
        expose_direct_endpoint=expose_direct,
        stable_relay_only=not expose_direct,
    )
    record = assist.confirm_registration(
        challenge,
        supported_transports=(TRANSPORT_QUIC_DATAGRAM, TRANSPORT_H3_WEBSOCKET),
        address_policy=policy,
        now=101.0,
    )

    plan = build_dial_plan(record, allow_direct=allow_direct, prefer_direct=prefer_direct, now=102.0)
    assert plan.contactable is True
    assert plan.primary is not None
    assert plan.primary.kind == expected_primary
    if expected_fallback_kind is None:
        assert plan.fallbacks == ()
    else:
        assert plan.fallbacks[0].kind == expected_fallback_kind


def test_registration_security_and_heartbeat_refresh():
    assist = _assist()
    challenge = assist.request_registration(
        peer_id="expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.20", 50000),
        now=200.0,
    )
    tampered = challenge.__class__(
        **{**challenge.__dict__, "cookie": b"\x00" * len(challenge.cookie)}
    )
    with pytest.raises(ValueError, match="invalid peer address challenge cookie"):
        assist.confirm_registration(tampered, now=201.0)

    record = assist.confirm_registration(
        challenge,
        address_policy=AddressExposurePolicy(expose_direct_endpoint=True, stable_relay_only=False),
        now=201.0,
    )
    refreshed = assist.heartbeat(
        "expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.21", 50010),
        now=250.0,
    )
    assert refreshed is not None
    assert refreshed.expires_at > record.expires_at
    assert refreshed.observed_udp_endpoints == (UdpEndpoint("198.51.100.21", 50010),)


def test_peer_address_record_expires_from_ttl():
    assist = _assist(ttl_seconds=1)
    challenge = assist.request_registration(
        peer_id="expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.20", 50000),
        now=600.0,
    )
    record = assist.confirm_registration(challenge, now=601.0)
    expired_plan = build_dial_plan(record, now=603.0)
    assert expired_plan.contactable is False
    assert assist.address_record("expert-art", now=603.0) is None


def test_peer_address_record_signature_verifies_and_detects_tamper():
    assist = _assist()
    challenge = assist.request_registration(
        peer_id="expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.20", 50000),
        now=700.0,
    )
    record = assist.confirm_registration(challenge, now=701.0)
    public_record = peer_address_record_from_dict(record.to_public_dict())

    assert verify_record_signature(public_record, b"peer-address-test-secret") is True
    assert verify_record_signature(public_record, b"wrong-peer-address-secret") is False

    tampered = record.to_public_dict()
    tampered["relay_candidates"][0]["endpoint"]["port"] = 4444
    tampered_record = peer_address_record_from_dict(tampered)

    assert verify_record_signature(tampered_record, "706565722d616464726573732d746573742d736563726574") is False


def test_dial_target_uses_trusted_relay_endpoint_not_record_endpoint():
    assist = _assist()
    challenge = assist.request_registration(
        peer_id="expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.20", 50000),
        now=800.0,
    )
    record = assist.confirm_registration(challenge, now=801.0)
    plan = build_dial_plan(record, now=802.0)
    trusted = (
        TrustedReachabilityRelayConfig(
            relay_id="relay-a",
            host="192.0.2.44",
            port=9443,
            verify_key=b"peer-address-test-secret".hex(),
        ),
    )

    target = resolve_dial_target(plan, trusted)

    assert target is not None
    assert target.relay_id == "relay-a"
    assert target.host == "192.0.2.44"
    assert target.port == 9443


def test_dial_target_rejects_untrusted_relay_and_can_skip_to_trusted_fallback():
    assist = _assist()
    challenge = assist.request_registration(
        peer_id="expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.20", 50000),
        now=820.0,
    )
    signed_record = assist.confirm_registration(challenge, now=821.0)
    untrusted_first = signed_record.__class__(
        **{
            **signed_record.__dict__,
            "relay_candidates": (
                RelayCandidate(
                    relay_id="relay-bad",
                    endpoint=UdpEndpoint("203.0.113.250", 5555),
                ),
            )
            + signed_record.relay_candidates,
        }
    )
    plan = build_dial_plan(untrusted_first, now=822.0)

    assert resolve_dial_target(plan, ()) is None

    target = resolve_dial_target(
        plan,
        (
            TrustedReachabilityRelayConfig(
                relay_id="relay-a",
                host="192.0.2.44",
                port=9443,
                verify_key=b"peer-address-test-secret".hex(),
            ),
        ),
    )

    assert target is not None
    assert target.relay_id == "relay-a"
    assert target.host == "192.0.2.44"


def test_send_prepared_envelope_via_plan_hands_transport_verified_target():
    assist = _assist()
    challenge = assist.request_registration(
        peer_id="expert-art",
        observed_endpoint=UdpEndpoint("198.51.100.20", 50000),
        now=840.0,
    )
    record = assist.confirm_registration(challenge, now=841.0)
    plan = build_dial_plan(record, now=842.0)
    envelope = PromptRequestEnvelope.visible_prompt(
        "What did Monet change?",
        selected_peer_id="expert-art",
        requested_expertise="Impressionist art history",
    )
    sent = {}

    def sender(target, payload):
        sent["target"] = target
        sent["payload"] = payload

    target = send_prepared_envelope_via_plan(
        envelope=envelope,
        plan=plan,
        trusted_reachability_relays=(
            TrustedReachabilityRelayConfig(
                relay_id="relay-a",
                host="192.0.2.44",
                port=9443,
                verify_key=b"peer-address-test-secret".hex(),
            ),
        ),
        sender=sender,
    )

    assert target == sent["target"]
    assert sent["payload"] is envelope
    assert target is not None
    assert target.host == "192.0.2.44"


def test_supernode_forwarder_tracks_peers_and_expires():
    relay = PeerAddressRelay(
        relay_id="supernode",
        relay_endpoint=UdpEndpoint("127.0.0.1", 9999),
        secret=urandom(32),
        ttl_seconds=1,
    )
    forwarder = SupernodeForwarder(relay, ttl=1)
    forwarder.register_peer("expert_art", ("127.0.0.1", 8888))
    assert forwarder.lookup_peer_addr("expert_art") == ("127.0.0.1", 8888)
    assert forwarder.lookup_peer_by_addr(("127.0.0.1", 8888)) == "expert_art"
    assert forwarder.heartbeat("expert_art", ("127.0.0.1", 8889)) is True

    time.sleep(1.1)
    assert forwarder.lookup_peer_addr("expert_art") is None
    assert forwarder.purge_expired() == 0


class _RecordingSocket:
    """Captures sendto() calls so the opaque NAT-return path can be asserted
    without binding real ports."""

    def __init__(self):
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))


def test_supernode_opaque_return_relays_registered_peer_to_client_session():
    """Real SupernodeDaemon: a forward establishes a client session, then an
    opaque datagram from the registered peer is relayed back to that client."""
    cluster = static_wire_cluster(("bootstrap-1", "relay"))
    runtime = WireNodeRuntime(cluster, "bootstrap-1", role="relay")
    daemon = SupernodeDaemon(runtime, relay_secret=b"x" * 32)
    rec = _RecordingSocket()
    daemon.attach_socket(rec)

    peer_addr = ("203.0.113.7", 5000)
    client_addr = ("198.51.100.9", 6000)
    daemon.forwarder.register_peer("peer-art", peer_addr)

    # Forward to the NAT'd peer records the return session.
    assert daemon.forward_to_peer("peer-art", b"\x00forward-bytes", client_addr) is True
    assert (b"\x00forward-bytes", peer_addr) in rec.sent

    # Opaque bytes from the peer are relayed back to the client that dialed.
    daemon._handle_opaque(b"\x01return-bytes", peer_addr)
    assert (b"\x01return-bytes", client_addr) in rec.sent


def test_supernode_opaque_from_unknown_peer_is_dropped():
    """An opaque datagram from an unregistered source is not forwarded."""
    cluster = static_wire_cluster(("bootstrap-1", "relay"))
    runtime = WireNodeRuntime(cluster, "bootstrap-1", role="relay")
    daemon = SupernodeDaemon(runtime, relay_secret=b"x" * 32)
    rec = _RecordingSocket()
    daemon.attach_socket(rec)

    daemon._handle_opaque(b"\x01stray", ("203.0.113.250", 7000))
    assert rec.sent == []


def test_supernode_refuses_forward_to_unregistered_peer():
    """T5 security: forwarding to a peer that never registered is refused."""
    cluster = static_wire_cluster(("supernode", "relay"))
    runtime = WireNodeRuntime(cluster, "supernode", role="relay")
    daemon = SupernodeDaemon(runtime, relay_secret=urandom(32))
    daemon.attach_socket(_RecordingSocket())

    assert daemon.forwarder.lookup_peer_addr("unknown_peer") is None
    assert (
        daemon.forward_to_peer("unknown_peer", b"payload", ("127.0.0.1", 9999))
        is False
    )
