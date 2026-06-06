"""Wire framing and binary runtime integration tests."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time

import pytest

from tenet.mixnet.node_runtime import WireNodeRuntime

from tenet.experts.client import send_prepared_envelope
from tenet.config import ClusterConfig
from tenet.experts.directory import PublicManifestDirectory
from tenet.envelope import PromptRequestEnvelope
from tenet.experts.expert_mode import ExpertModeConfig, prepare_expert_mode_request
from tenet.experts.expert_route import PeerObservation, RouteIntent
from tenet.experts.memory_index import IndexConfig, build_memory_index
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.mixnet.wire_frame import (
    CIRCUIT,
    FORWARD,
    decode_datagram,
    encode_circuit,
    encode_forward,
    encode_shutdown,
)

from tests.harness import mixnet_harness, static_wire_cluster
from tests.helpers import has_log_event, parse_json_log_events


@pytest.mark.parametrize(
    ("raw", "payload_size", "expected_kind", "header_len", "payload_len"),
    [
        (encode_shutdown(), 2048, "shutdown", 0, 0),
        (
            encode_forward(b"h" * 48, b"p" * 2048),
            2048,
            "forward",
            48,
            2048,
        ),
        (encode_circuit(CIRCUIT + b"\x00" * 100), 2048, "circuit", 101, 0),
    ],
)
def test_wire_frame_round_trip(raw, payload_size, expected_kind, header_len, payload_len):
    kind, body_a, body_b = decode_datagram(raw, payload_size=payload_size)
    assert kind == expected_kind
    if expected_kind == "forward":
        assert len(body_a) == header_len
        assert len(body_b) == payload_len
    elif expected_kind == "circuit":
        assert len(body_a) == header_len
        assert body_b is None
    else:
        assert body_a == b""
        assert body_b is None


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff",
        FORWARD + b"short",
        FORWARD + b"x" * 10,
    ],
)
def test_wire_frame_rejects_invalid_datagrams(raw):
    kind, _, _ = decode_datagram(raw, payload_size=2048)
    assert kind == "unknown"


def test_wire_runtime_logs_unknown_binary_datagram(capsys):
    cluster = static_wire_cluster(("relay1", "relay"), payload_size=2048)
    runtime = WireNodeRuntime(cluster, "relay1", role="relay")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        runtime._dispatch_binary(sock, b"\xffbad", ("127.0.0.1", 1))
    finally:
        sock.close()

    events = parse_json_log_events(capsys.readouterr().out)
    assert has_log_event(events, "wire_unknown", field="wire", value="binary")


def test_truncated_forward_header_rejected():
    """Forward packet with header shorter than payload_size → unknown."""
    truncated = FORWARD + b"x" * 100
    kind, _, _ = decode_datagram(truncated, payload_size=2048)
    assert kind == "unknown"


def test_corrupt_reach_tag_no_crash(tmp_path, capsys):
    """Corrupt REACH-range tag doesn't crash or dispatch to mix."""
    from tenet.mixnet.reach_wire import REACH_REGISTER
    cluster = static_wire_cluster(("relay1", "relay"), payload_size=2048)
    runtime = WireNodeRuntime(cluster, "relay1", role="relay")
    reach_calls = []
    runtime.on_reach_control = lambda data, addr: reach_calls.append(data)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        runtime._dispatch_binary(sock, REACH_REGISTER + b"\x00" * 3, ("127.0.0.1", 1))
    finally:
        sock.close()

    assert len(reach_calls) == 1


def test_circuit_replay_nonce_rejected(tmp_path, capsys):
    """Duplicate nonce on circuit packet → circuit_replay event."""
    from tenet.packet.OutfoxParams import OutfoxParams
    from tenet.packet.OutfoxNode import circuit_packet_create
    from os import urandom

    cluster = static_wire_cluster(("relay1", "relay"), payload_size=512)
    runtime = WireNodeRuntime(cluster, "relay1", role="relay")
    key = urandom(16)
    cid = urandom(16)
    runtime.circuits[cid.hex()] = {
        "key": key.hex(), "outbound_cid": urandom(16).hex(),
        "next_id": "client", "high_watermark": 5, "last_active": time.time(),
    }

    params = OutfoxParams(payload_size=512)
    pkt = circuit_packet_create(params, cid, 3, b"replay", [key])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        runtime._handle_circuit_binary(sock, pkt)
    finally:
        sock.close()

    events = parse_json_log_events(capsys.readouterr().out)
    assert has_log_event(events, "circuit_replay")


def test_shutdown_stops_runtime():
    """0x02 shutdown sets _shutdown flag cleanly."""
    cluster = static_wire_cluster(("relay1", "relay"), payload_size=2048)
    runtime = WireNodeRuntime(cluster, "relay1", role="relay")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        runtime._dispatch_binary(sock, encode_shutdown(), ("127.0.0.1", 1))
    finally:
        sock.close()
    assert runtime._shutdown is True


@pytest.mark.integration
@pytest.mark.product
def test_binary_wire_subprocess_uses_client_send_path(tmp_path, wire_cluster_factory):
    """Production path: tenet relay/expert subprocesses + send_prepared_envelope."""
    config_path, harness = wire_cluster_factory("relay1", "relay2", "expert_art")
    nodes = harness["nodes"]
    node_ids = ("relay1", "relay2", "expert_art")

    art_dir = tmp_path / "art_mem"
    art_dir.mkdir()
    (art_dir / "art.md").write_text("Monet Impressionism light color painting", encoding="utf-8")
    manifest = build_memory_index(IndexConfig(peer_id="expert_art", roots=(str(art_dir),))).manifest
    directory = PublicManifestDirectory.from_manifests(
        (manifest,),
        (PeerObservation(peer_id="expert_art", p50_latency_ms=80),),
        source="wire-integration",
    )
    prepared = prepare_expert_mode_request(
        RouteIntent(prompt="What did Monet change?", requested_expertise="art", random_seed=1),
        directory,
        ExpertModeConfig(min_pool_size=1, allow_degraded_pool=True),
    )
    assert prepared.envelope is not None

    procs = []
    for node_id in node_ids:
        role = "expert" if node_id.startswith("expert") else "relay"
        procs.append(
            subprocess.Popen(
                [sys.executable, "-m", "tenet", role, "--config", str(config_path), "--node-id", node_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        )
    time.sleep(0.5)

    try:
        cluster = ClusterConfig.load(config_path)
        response, logs = send_prepared_envelope(
            cluster=cluster,
            forward_path=["relay1", "relay2", "expert_art"],
            envelope=prepared.envelope,
            timeout=8.0,
        )
        assert len(response) > 0
        assert "wire=binary" in "\n".join(logs)
    finally:
        shutdown_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for node_id in node_ids:
            shutdown_sock.sendto(
                encode_shutdown(),
                ("127.0.0.1", nodes[node_id]["port"]),
            )
        shutdown_sock.close()

        all_logs = []
        for proc in procs:
            try:
                out, _ = proc.communicate(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.terminate()
                out, _ = proc.communicate(timeout=2.0)
            all_logs.append(out or "")

    node_logs = "".join(all_logs)
    events = parse_json_log_events(node_logs)
    assert has_log_event(events, "forward_hop")
    assert has_log_event(events, "expert_exit")
    assert has_log_event(events, "circuit_hop")
    assert has_log_event(events, "expert_exit", field="prompt_visible", value=True)
    assert has_log_event(events, "started", field="wire", value="binary")


@pytest.mark.integration
@pytest.mark.product
def test_wire_node_runtime_threaded_end_to_end():
    """WireNodeRuntime hot path without subprocess — relay → expert → client.

    Deterministic via the harness: bind-once held sockets, joined serve threads,
    and a client socket the send path reuses (no rebind race)."""
    with mixnet_harness() as net:
        cluster, nodes, client_sock = net.wire_cluster(
            ("relay1", "relay"),
            ("expert_art", "expert"),
        )
        envelope = PromptRequestEnvelope.visible_prompt(
            prompt="Quick test",
            selected_peer_id="expert_art",
            requested_expertise="general",
        )

        net.serve(WireNodeRuntime(cluster, "relay1", role="relay"), nodes["relay1"].sock)
        net.serve(
            WireNodeRuntime(cluster, "expert_art", role="expert"),
            nodes["expert_art"].sock,
        )

        response, logs = send_prepared_envelope(
            cluster=cluster,
            forward_path=["relay1", "expert_art"],
            envelope=envelope,
            timeout=6.0,
            client_sock=client_sock,
        )
        assert len(response) > 0
        assert any("wire=binary" in line for line in logs)
