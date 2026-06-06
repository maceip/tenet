"""REACH client registration (item 12)."""

import socket
import threading
import time

from tenet.edges.cli.supernode import SupernodeDaemon
from tenet.mixnet.reach_client import ReachRelayEndpoint, register_with_relay
from tenet.mixnet.reach_wire import REACH_TAGS
from tenet.mixnet.node_runtime import WireNodeRuntime
from tests.harness import static_wire_cluster


def _pump_reach(daemon: SupernodeDaemon, sock: socket.socket, stop: threading.Event) -> None:
    sock.settimeout(0.05)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if data and data[:1] in REACH_TAGS:
            daemon._handle_reach(data, addr)


def test_register_with_relay_against_supernode():
    cluster = static_wire_cluster(("bootstrap-1", "relay"))
    runtime = WireNodeRuntime(cluster, "bootstrap-1", role="relay")
    daemon = SupernodeDaemon(runtime, relay_secret=b"reach-client-test-secret!!")
    relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay_sock.bind(("127.0.0.1", 0))
    daemon.attach_socket(relay_sock)
    relay_addr = relay_sock.getsockname()

    stop = threading.Event()
    pump = threading.Thread(
        target=_pump_reach,
        args=(daemon, relay_sock, stop),
        daemon=True,
    )
    pump.start()

    expert_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    expert_sock.bind(("127.0.0.1", 0))
    expert_sock.settimeout(2.0)
    try:
        register_with_relay(
            expert_sock,
            ReachRelayEndpoint(relay_addr[0], relay_addr[1]),
            "peer-beta-test01",
        )
    finally:
        stop.set()
        pump.join(timeout=1.0)
        relay_sock.close()
        expert_sock.close()

    deadline = time.time() + 2.0
    while time.time() < deadline:
        if daemon.forwarder.lookup_peer_addr("peer-beta-test01") is not None:
            break
        time.sleep(0.01)
    else:
        raise AssertionError("peer not registered")
