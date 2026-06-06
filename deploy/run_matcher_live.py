"""In-enclave matcher with embedded relay + expert — **engineering shortcut only**.

NOT the product shape. The product runs experts on human laptops behind NAT;
see STATUS.md item 9 engineering shortcut.

This workload exists to prove /v1/deliver on Nitro without a remote expert
online: attested HTTP on loopback :8080 plus an internal Outfox relay/expert
fleet on loopback UDP. External clients use attested HTTPS (/v1/match,
/v1/deliver) while sealed datagrams traverse the in-enclave mixnet.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tenet.config import ClusterConfig, PeerAddressConfig, ProviderConfig, TrustedReachabilityRelayConfig
from tenet.edges.cli.supernode import SupernodeDaemon
from tenet.experts.directory import PeerRecord
from tenet.experts.enclave_plane_server import serve_enclave_plane
from tenet.handles import opaque_handle_record_from_dict
from tenet.experts.matcher import (
    PlainEnclavePlaneDiscoveryProvider,
    PlainMailbox,
    PlainMailboxDelivery,
    PlainMatcher,
)
from tenet.experts.memory_index import MemoryManifest
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.experts.oblivious import rust_backend_available
from tenet.llm.provider import make_reply_handler
from tenet.mixnet.reach_wire import REACH_CHALLENGE, decode_reach_datagram, encode_confirm, encode_register


DEFAULT_FLEET = Path(__file__).resolve().parent / "data" / "live-fleet.json"


def _load_fleet(path: Path) -> dict[str, object]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("version") != "por.live_fleet.v1":
        raise ValueError(f"unsupported fleet file version: {raw.get('version')!r}")
    return raw


def _bind_udp(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    return sock


def _serve_runtime(runtime: WireNodeRuntime, sock: socket.socket) -> threading.Event:
    stop = threading.Event()
    thread = threading.Thread(
        target=runtime.serve_on_socket,
        args=(sock,),
        kwargs={"stop": stop},
        daemon=True,
        name=f"live-{runtime.node_id}",
    )
    thread.start()
    return stop


def _stub_provider_handler(reply_text: str):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            payload = {"content": [{"type": "text", "text": reply_text}]}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            return

    return Handler


def _register_handle_via_reach(
    expert_sock: socket.socket,
    relay_addr: tuple[str, int],
    relay_daemon: SupernodeDaemon,
    handle: str,
) -> None:
    expert_sock.sendto(encode_register(handle), relay_addr)
    deadline = time.time() + 5.0
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
    if cookie is None:
        raise RuntimeError("handle registration challenge timed out")
    expert_sock.sendto(encode_confirm(handle, cookie), relay_addr)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if relay_daemon.forwarder.lookup_peer_addr(handle) is not None:
            return
        time.sleep(0.05)
    raise RuntimeError("handle never registered with relay")


def build_provider(fleet_path: Path) -> PlainEnclavePlaneDiscoveryProvider:
    fleet = _load_fleet(fleet_path)
    relay_id = str(fleet["relay_id"])
    relay_host = str(fleet["relay_host"])
    relay_port = int(fleet["relay_port"])
    expert_id = str(fleet["expert_id"])
    expert_host = str(fleet["expert_host"])
    expert_port = int(fleet["expert_port"])
    mailbox_port = int(fleet["mailbox_port"])
    relay_secret = bytes.fromhex(str(fleet["relay_secret_hex"]))
    packet = {"payload_size": 2048, "routing_size": 16, "max_hops": 5}

    relay_sock = _bind_udp(relay_host, relay_port)
    expert_sock = _bind_udp(expert_host, expert_port)
    mailbox_sock = _bind_udp(relay_host, mailbox_port)
    relay_addr = relay_sock.getsockname()
    expert_addr = expert_sock.getsockname()
    expert_sock.settimeout(0.5)

    relay_cluster = ClusterConfig.from_dict(
        {
            "params": packet,
            "client": {"host": relay_host, "port": mailbox_port},
            "nodes": {
                relay_id: {
                    "host": relay_addr[0],
                    "port": relay_addr[1],
                    "kem_pk": str(fleet["relay_kem_pk_hex"]),
                    "kem_sk": str(fleet["relay_kem_sk_hex"]),
                    "role": "relay",
                },
            },
        }
    )
    relay_runtime = WireNodeRuntime(relay_cluster, relay_id, role="relay")
    relay_daemon = SupernodeDaemon(
        relay_runtime,
        relay_secret=relay_secret,
        advertise_host=relay_addr[0],
    )
    relay_daemon.attach_socket(relay_sock)
    _serve_runtime(relay_runtime, relay_sock)

    stub = ThreadingHTTPServer(("127.0.0.1", 0), _stub_provider_handler(str(fleet["expert_reply"])))
    stub_thread = threading.Thread(target=stub.serve_forever, daemon=True, name="live-stub-provider")
    stub_thread.start()
    os.environ["LIVE_EXPERT_PROVIDER_KEY"] = "live-demo-key"

    expert_cluster = ClusterConfig.from_dict(
        {
            "params": packet,
            "client": {"host": relay_host, "port": mailbox_port},
            "nodes": {
                relay_id: {
                    "host": relay_addr[0],
                    "port": relay_addr[1],
                    "kem_pk": str(fleet["relay_kem_pk_hex"]),
                    "kem_sk": str(fleet["relay_kem_sk_hex"]),
                    "role": "relay",
                },
                expert_id: {
                    "host": expert_addr[0],
                    "port": expert_addr[1],
                    "kem_pk": str(fleet["expert_kem_pk_hex"]),
                    "kem_sk": str(fleet["expert_kem_sk_hex"]),
                    "role": "expert",
                },
            },
        }
    )
    expert_runtime = WireNodeRuntime(
        expert_cluster,
        expert_id,
        role="expert",
        reply_handler=make_reply_handler(
            ProviderConfig(
                provider="anthropic",
                base_url=f"http://127.0.0.1:{stub.server_address[1]}",
                api_key_env="LIVE_EXPERT_PROVIDER_KEY",
            )
        ),
    )
    _serve_runtime(expert_runtime, expert_sock)

    handle_record = opaque_handle_record_from_dict(dict(fleet["handle_record"]))
    manifest = MemoryManifest.from_json(json.dumps(fleet["manifest"]))
    _register_handle_via_reach(expert_sock, relay_addr, relay_daemon, handle_record.handle)

    handle_address = relay_daemon.relay.address_record(handle_record.handle)
    if handle_address is None:
        raise RuntimeError("relay did not publish handle address record")

    mailbox = PlainMailbox()
    mailbox.add(
        record=handle_record,
        routing_kem_pk_hex=str(fleet["expert_kem_pk_hex"]),
        peer_address=handle_address.to_public_dict(),
    )
    matcher = PlainMatcher.from_records(
        [PeerRecord(manifest=manifest)],
        {manifest.peer_id: handle_record},
        top_k=3,
    )
    trusted = (
        TrustedReachabilityRelayConfig(
            relay_id=relay_id,
            host=relay_addr[0],
            port=relay_addr[1],
            verify_key=relay_secret.hex(),
        ),
    )
    return PlainEnclavePlaneDiscoveryProvider(
        matcher,
        mailbox,
        PlainMailboxDelivery(
            mailbox,
            mailbox_sock=mailbox_sock,
            peer_address_config=PeerAddressConfig(enabled=True),
            trusted_reachability_relays=trusted,
        ),
    )


def main() -> None:
    fleet_path = Path(os.environ.get("LIVE_FLEET_FILE", DEFAULT_FLEET))
    host = os.environ.get("MATCHER_HOST", "127.0.0.1")
    port = int(os.environ.get("MATCHER_PORT", "8080"))
    provider = build_provider(fleet_path)
    server = serve_enclave_plane(provider, host=host, port=port)
    backend = "rust" if rust_backend_available() else "python"
    print(
        f"live matcher workload serving on http://{host}:{port} "
        f"(oblivious selector: {backend}, mailbox delivery: enabled)",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
