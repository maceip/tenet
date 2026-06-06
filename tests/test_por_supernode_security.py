"""Reachability-relay security regression tests (item 10)."""

import json
from pathlib import Path

import pytest

from tenet.edges.cli.supernode import SupernodeDaemon
from tenet.mixnet.peer_address import UdpEndpoint
from tenet.mixnet.node_runtime import WireNodeRuntime
from tests.harness import static_wire_cluster
from tests.test_por_supernode import _RecordingSocket


def test_reach_confirm_from_wrong_endpoint_rejected():
    cluster = static_wire_cluster(("relay-1", "relay"))
    runtime = WireNodeRuntime(cluster, "relay-1", role="relay")
    daemon = SupernodeDaemon(runtime, relay_secret=b"x" * 32)
    challenge = daemon.relay.request_registration(
        peer_id="peer-a",
        observed_endpoint=UdpEndpoint("10.0.0.1", 1000),
    )
    with pytest.raises(ValueError, match="invalid peer address challenge cookie"):
        daemon.relay.pending_challenge(
            "peer-a",
            cookie=challenge.cookie,
            observed_endpoint=UdpEndpoint("10.0.0.2", 1000),
        )
    assert daemon.forwarder.lookup_peer_addr("peer-a") is None


def test_opaque_return_routes_by_circuit_session_not_latest_peer_client():
    cluster = static_wire_cluster(("relay-1", "relay"))
    runtime = WireNodeRuntime(cluster, "relay-1", role="relay")
    daemon = SupernodeDaemon(runtime, relay_secret=b"y" * 32)
    rec = _RecordingSocket()
    daemon.attach_socket(rec)

    peer_addr = ("203.0.113.7", 5000)
    client_a = ("198.51.100.9", 6000)
    client_b = ("198.51.100.10", 6001)
    daemon.forwarder.register_peer("peer-a", peer_addr)
    session_a = "01" * 16
    session_b = "02" * 16
    assert (
        daemon.forward_to_peer(
            "peer-a",
            b"\x00fwd",
            client_a,
            return_session=session_a,
        )
        is True
    )
    assert (
        daemon.forward_to_peer(
            "peer-a",
            b"\x00other",
            client_b,
            return_session=session_b,
        )
        is True
    )
    rec.sent.clear()
    daemon._handle_opaque(b"\x01" + bytes.fromhex(session_a) + b"reply-a", peer_addr)
    daemon._handle_opaque(b"\x01" + bytes.fromhex(session_b) + b"reply-b", peer_addr)
    destinations = {addr for _data, addr in rec.sent}
    assert destinations == {client_a, client_b}


def test_supernode_cluster_uses_configured_relay_secret(monkeypatch):
    from tenet.config import DaemonConfig, PorConfig
    from tenet.edges.cli.supernode import run_supernode_cluster
    from tenet.mixnet.node_runtime import WireNodeRuntime

    secret_hex = "ab" * 32
    por_cfg = PorConfig.from_dict(
        {
            "version": "por.config.v1",
            "default_node_id": "relay-1",
            "daemons": {
                "relay-1": {
                    "role": "relay",
                    "node_id": "relay-1",
                    "kem_pk_hex": "01" * 32,
                    "kem_sk_hex": "02" * 32,
                    "transport": {"kind": "udp", "host": "127.0.0.1", "port": 4433},
                    "supernode": {
                        "enabled": True,
                        "public_ip": "203.0.113.1",
                        "relay_secret_hex": secret_hex,
                        "advertise_relay": True,
                    },
                }
            },
        }
    )
    daemon = por_cfg.daemon("relay-1")
    captured: list[bytes] = []

    def _serve(self):
        captured.append(self.supernode_daemon.relay.secret)
        return 0

    monkeypatch.setattr(WireNodeRuntime, "serve_forever", _serve)
    assert run_supernode_cluster(daemon, por_cfg) == 0
    assert captured == [bytes.fromhex(secret_hex)]


def test_live_configs_do_not_enable_dev_untrusted_relays():
    root = Path(__file__).resolve().parent.parent / "config"
    for path in root.glob("live*.json"):
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw.get("dev_allow_untrusted_reachability_relays") is not True, path.name
