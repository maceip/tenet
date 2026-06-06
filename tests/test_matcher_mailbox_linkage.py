import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler

import pytest
from tenet.packet.OutfoxParams import OutfoxParams

from tenet.experts.client import run_client_once
from tenet.config import (
    ClusterConfig,
    PeerAddressConfig,
    ProviderConfig,
    TrustedReachabilityRelayConfig,
)
from tenet.edges.cli.supernode import SupernodeDaemon
from tenet.experts.directory import DiscoveryRequest, PeerRecord
from tenet.experts.match_workload import PlainEnclavePlaneHttpClient, make_plain_enclave_plane_handler
from tenet.experts.expert_mode import ExpertModeConfig
from tenet.experts.expert_route import RouteIntent
from tenet.experts.matcher import (
    PLAIN_MATCHER_V1,
    OpaqueHandleIssuer,
    PlainEnclavePlaneDiscoveryProvider,
    PlainMailbox,
    PlainMailboxDelivery,
    PlainMatcher,
)
from tenet.experts.memory_index import IndexConfig, build_memory_index
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.llm.provider import make_reply_handler
from tenet.mixnet.reach_wire import REACH_CHALLENGE, decode_reach_datagram, encode_confirm, encode_register
from tenet.mixnet.transport_dial import DialTarget
from tests.harness import mixnet_harness


@pytest.mark.product
def test_plain_matcher_handle_to_mailbox_to_expert_round_trip(tmp_path, monkeypatch):
    params = OutfoxParams(payload_size=2048, routing_size=16, max_hops=5)
    relay_pk, relay_sk = params.kem.keygen()
    expert_pk, expert_sk = params.kem.keygen()
    relay_secret = b"plain-mailbox-reachability-secret"
    handle_secret = b"plain-matcher-handle-secret"
    packet = {"payload_size": 2048, "routing_size": 16, "max_hops": 5}

    with mixnet_harness() as net:
        relay_sock = net.reserve()
        expert_sock = net.reserve()
        mailbox_sock = net.reserve()
        relay_addr = relay_sock.getsockname()
        expert_addr = expert_sock.getsockname()
        mailbox_addr = mailbox_sock.getsockname()
        expert_sock.settimeout(0.2)

        root = tmp_path / "peer-art"
        root.mkdir()
        (root / "notes.md").write_text(
            "Monet Impressionism color light painting.",
            encoding="utf-8",
        )
        manifest = build_memory_index(
            IndexConfig(peer_id="peer-art", roots=(str(root),))
        ).manifest
        issuer = OpaqueHandleIssuer(handle_secret)
        handle_record = issuer.record(
            peer_id="peer-art",
            manifest_digest=manifest.index_digest,
            mailbox_id="mailbox-a",
            now=1000.0,
        )
        handle = handle_record.handle
        assert handle != "peer-art"
        assert len(handle) == 16

        client_cluster = ClusterConfig.from_dict(
            {
                "params": packet,
                "client": {"host": mailbox_addr[0], "port": mailbox_addr[1]},
                "nodes": {
                    "bootstrap-1": {
                        "host": relay_addr[0],
                        "port": relay_addr[1],
                        "kem_pk": relay_pk.hex(),
                        "kem_sk": relay_sk.hex(),
                        "role": "relay",
                    },
                },
            }
        )
        relay_runtime = WireNodeRuntime(client_cluster, "bootstrap-1", role="relay")
        relay_daemon = SupernodeDaemon(
            relay_runtime,
            relay_secret=relay_secret,
            advertise_host=relay_addr[0],
        )
        relay_daemon.attach_socket(relay_sock)

        expert_cluster = ClusterConfig.from_dict(
            {
                "params": packet,
                "client": {"host": mailbox_addr[0], "port": mailbox_addr[1]},
                "nodes": {
                    "bootstrap-1": {
                        "host": relay_addr[0],
                        "port": relay_addr[1],
                        "kem_pk": relay_pk.hex(),
                        "kem_sk": relay_sk.hex(),
                        "role": "relay",
                    },
                    "peer-art": {
                        "host": expert_addr[0],
                        "port": expert_addr[1],
                        "kem_pk": expert_pk.hex(),
                        "kem_sk": expert_sk.hex(),
                        "role": "expert",
                    },
                },
            }
        )
        provider_server = net.serve_http(_anthropic_handler("matched via opaque handle"))
        monkeypatch.setenv("TEST_ANTHROPIC_KEY", "test-key")
        expert_runtime = WireNodeRuntime(
            expert_cluster,
            "peer-art",
            role="expert",
            reply_handler=make_reply_handler(
                ProviderConfig(
                    provider="anthropic",
                    base_url=f"http://127.0.0.1:{provider_server.server_address[1]}",
                    api_key_env="TEST_ANTHROPIC_KEY",
                )
            ),
        )

        net.serve(relay_runtime, relay_sock)
        _register_handle_via_reach(expert_sock, relay_addr, relay_daemon, handle)
        net.serve(expert_runtime, expert_sock)

        handle_address = relay_daemon.relay.address_record(handle)
        assert handle_address is not None
        mailbox = PlainMailbox()
        mailbox.add(
            record=handle_record,
            routing_kem_pk_hex=expert_pk.hex(),
            peer_address=handle_address.to_public_dict(),
        )
        matcher = PlainMatcher.from_records(
            [PeerRecord(manifest=manifest)],
            {"peer-art": handle_record},
            top_k=3,
        )
        delivery_provider = PlainEnclavePlaneDiscoveryProvider(
            matcher,
            mailbox,
            PlainMailboxDelivery(
                mailbox,
                mailbox_sock=mailbox_sock,
                peer_address_config=PeerAddressConfig(enabled=True),
                trusted_reachability_relays=(
                    TrustedReachabilityRelayConfig(
                        relay_id="bootstrap-1",
                        host=relay_addr[0],
                        port=relay_addr[1],
                        verify_key=relay_secret.hex(),
                    ),
                ),
            ),
        )
        plane_server = net.serve_http(make_plain_enclave_plane_handler(delivery_provider))
        enclave_plane = PlainEnclavePlaneHttpClient(
            f"http://127.0.0.1:{plane_server.server_address[1]}"
        )
        discovery = enclave_plane.discover(
            DiscoveryRequest(
                RouteIntent(
                    prompt="What did Monet change?",
                    requested_expertise="Impressionist art history",
                ),
                mode=PLAIN_MATCHER_V1,
            )
        )
        assert discovery.candidates[0].manifest.peer_id == handle
        assert discovery.candidates[0].observation is None

        result = run_client_once(
            cluster=client_cluster,
            discovery_provider=enclave_plane,
            prompt="What did Monet change?",
            requested_expertise="Impressionist art history",
            expert_mode_config=ExpertModeConfig(
                discovery_mode=PLAIN_MATCHER_V1,
                min_pool_size=1,
            ),
            peer_address_config=PeerAddressConfig(enabled=True),
            trusted_reachability_relays=(
                TrustedReachabilityRelayConfig(
                    relay_id="bootstrap-1",
                    host=relay_addr[0],
                    port=relay_addr[1],
                    verify_key=relay_secret.hex(),
                ),
            ),
            random_seed=0,
            timeout=5.0,
        )

        assert result.fallback_used is False
        assert result.selected_peer_id == handle
        assert result.response_text == "matched via opaque handle"
        assert handle in result.client_logs
        assert "event=mailbox_delivery_plan" in result.client_logs
        assert "via=mailbox" in result.client_logs
        assert "peer-art" not in result.client_logs
        assert "peer-art" not in result.response_text
        assert relay_daemon.forwarder.lookup_peer_addr(handle) == expert_addr


def test_plain_mailbox_delivery_uses_request_isolated_udp_sockets():
    relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay_sock.bind(("127.0.0.1", 0))
    relay_sock.settimeout(0.2)
    relay_addr = relay_sock.getsockname()
    seen_sources: list[tuple[str, int]] = []
    stop = threading.Event()

    def relay() -> None:
        while not stop.is_set() and len(seen_sources) < 2:
            try:
                data, addr = relay_sock.recvfrom(65535)
            except socket.timeout:
                continue
            seen_sources.append(addr)
            if data == b"slow":
                time.sleep(0.1)
            relay_sock.sendto(b"reply:" + data, addr)

    thread = threading.Thread(target=relay, daemon=True)
    thread.start()
    mailbox_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mailbox_sock.bind(("127.0.0.1", 0))
    delivery = _FixedTargetMailboxDelivery(
        relay_addr,
        PlainMailbox(),
        mailbox_sock=mailbox_sock,
    )

    def first_packet(payload: bytes) -> bytes:
        packets = delivery.deliver_to_handle("handle", payload, timeout=2.0)
        try:
            return next(packets)
        finally:
            packets.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(first_packet, b"slow"),
                pool.submit(first_packet, b"fast"),
            )
            replies = {future.result(timeout=3.0) for future in futures}
        assert replies == {b"reply:slow", b"reply:fast"}
        assert len({source[1] for source in seen_sources}) == 2
        assert mailbox_sock.getsockname() not in seen_sources
    finally:
        stop.set()
        thread.join(timeout=1.0)
        mailbox_sock.close()
        relay_sock.close()


def _register_handle_via_reach(
    expert_sock: socket.socket,
    relay_addr: tuple[str, int],
    relay_daemon: SupernodeDaemon,
    handle: str,
) -> None:
    expert_sock.sendto(encode_register(handle), relay_addr)
    deadline = time.time() + 2.0
    cookie = None
    while time.time() < deadline:
        try:
            data, _addr = expert_sock.recvfrom(65535)
        except socket.timeout:
            continue
        if data[:1] != REACH_CHALLENGE:
            continue
        action = decode_reach_datagram(data)
        cookie = action.cookie
        break
    assert cookie is not None
    expert_sock.sendto(encode_confirm(handle, cookie), relay_addr)
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if relay_daemon.forwarder.lookup_peer_addr(handle) is not None:
            return
        time.sleep(0.01)
    raise AssertionError("handle never registered with supernode")


class _FixedTargetMailboxDelivery(PlainMailboxDelivery):
    def __init__(self, relay_addr, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._relay_addr = relay_addr

    def _dial_target(self, handle: str) -> DialTarget:
        return DialTarget(
            peer_id=handle,
            route_kind="relay",
            transport="udp",
            host=self._relay_addr[0],
            port=self._relay_addr[1],
            relay_id="relay-test",
        )


def _anthropic_handler(text: str):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            payload = {
                "content": [
                    {
                        "type": "text",
                        "text": text,
                    }
                ]
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    return Handler
