"""Durable integration-test harness for tenet mixnet nodes.

One module owns UDP socket + serve-thread lifecycle so individual tests stop
re-implementing (and re-breaking) it.

Key invariant — **bind once, hold open**: a node's port is bound a single time
and kept open until teardown. It is never closed and rebound, which removes the
cross-test datagram races (recycled ephemeral ports receiving stray packets)
behind flaky full-suite runs. Threads are real ``Event``-stopped workers that
are ``join()``ed on teardown — no orphaned ``recvfrom`` loops leaking into the
next test.

Typical use::

    with mixnet_harness() as net:
        relay_sock = net.reserve()      # bound 127.0.0.1:<ephemeral>, held open
        expert_sock = net.reserve()
        client_sock = net.reserve()
        # ... build cluster config from the reserved ports ...
        net.serve(relay_runtime, relay_sock)
        net.serve(expert_runtime, expert_sock)
        result = run_client_once(..., client_sock=client_sock)
"""

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterator

from tenet.config import ClusterConfig
from tenet.mixnet.node_runtime import WireNodeRuntime


def bind_local_udp() -> socket.socket:
    """Bind a fresh UDP socket to an ephemeral 127.0.0.1 port and return it open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    return sock


def static_wire_cluster(
    *node_specs: tuple[str, str],
    payload_size: int = 2048,
    routing_size: int = 16,
    max_hops: int = 5,
    base_port: int = 49000,
) -> ClusterConfig:
    """Build a ClusterConfig with KEM keys but **no** bound sockets.

    For unit tests that construct a runtime and call ``_dispatch_binary``
    directly (no real network IO), so they never touch the socket-reservation
    path at all. Ports are fixed placeholders that are never bound.
    """
    from tenet.packet.OutfoxParams import OutfoxParams

    params = OutfoxParams(
        payload_size=payload_size, routing_size=routing_size, max_hops=max_hops
    )
    nodes: dict[str, object] = {}
    for index, (node_id, role) in enumerate(node_specs):
        pk, sk = params.kem.keygen()
        nodes[node_id] = {
            "host": "127.0.0.1",
            "port": base_port + index,
            "kem_pk": pk.hex(),
            "kem_sk": sk.hex(),
            "role": role,
        }
    return ClusterConfig.from_dict(
        {
            "params": {
                "payload_size": payload_size,
                "routing_size": routing_size,
                "max_hops": max_hops,
            },
            "client": {"host": "127.0.0.1", "port": base_port + len(node_specs)},
            "nodes": nodes,
        }
    )


@dataclass
class WireNode:
    """A reserved node: held-open socket + KEM identity, ready to serve."""

    node_id: str
    role: str
    sock: socket.socket
    host: str
    port: int
    kem_pk: bytes
    kem_sk: bytes


class HarnessNode:
    """A runtime serving on a caller-owned, held-open socket via a joined thread."""

    def __init__(
        self,
        runtime: WireNodeRuntime,
        sock: socket.socket,
    ) -> None:
        self.runtime = runtime
        self.sock = sock
        self.host, self.port = sock.getsockname()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "HarnessNode":
        self._thread = threading.Thread(
            target=self.runtime.serve_on_socket,
            args=(self.sock,),
            kwargs={"stop": self._stop},
            daemon=True,
            name=f"harness-{self.runtime.node_id}",
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        try:
            self.sock.close()
        except OSError:
            pass


class MixnetHarness:
    """Owns reserved sockets and serve threads for one test; cleans both up."""

    def __init__(self) -> None:
        self._nodes: list[HarnessNode] = []
        self._sockets: list[socket.socket] = []
        self._http: list[tuple[ThreadingHTTPServer, threading.Thread]] = []

    def serve_http(
        self,
        handler: Callable[..., BaseHTTPRequestHandler],
    ) -> ThreadingHTTPServer:
        """Start a localhost ``ThreadingHTTPServer`` on an ephemeral port.

        The server + its thread are shut down and ``join()``ed on teardown, so
        tests stop hand-rolling the start/shutdown/join dance for the directory
        snapshot / local-HTTP servers. Read the port from
        ``server.server_address[1]``.
        """
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(
            target=server.serve_forever, daemon=True, name="harness-http"
        )
        thread.start()
        self._http.append((server, thread))
        return server

    def reserve(self) -> socket.socket:
        """Bind and hold a local UDP socket. Never closed until teardown."""
        sock = bind_local_udp()
        self._sockets.append(sock)
        return sock

    def wire_cluster(
        self,
        *node_specs: tuple[str, str],
        payload_size: int = 2048,
        routing_size: int = 16,
        max_hops: int = 5,
    ) -> "tuple[ClusterConfig, dict[str, WireNode], socket.socket]":
        """Reserve held-open sockets + KEM keys for nodes and a client.

        ``node_specs`` are ``(node_id, role)`` pairs. Returns the built
        ``ClusterConfig``, a ``{node_id: WireNode}`` map (pass each node's
        ``sock`` to :meth:`serve`), and the held-open client socket (pass to
        ``run_client_once``/``send_prepared_envelope`` as ``client_sock``).

        Replaces the old ``write_wire_cluster``/``reserve_udp_ports`` idiom that
        bound ports only to close and rebind them later.
        """
        from tenet.packet.OutfoxParams import OutfoxParams

        params = OutfoxParams(
            payload_size=payload_size, routing_size=routing_size, max_hops=max_hops
        )
        client_sock = self.reserve()
        nodes: dict[str, object] = {}
        node_objs: dict[str, WireNode] = {}
        for node_id, role in node_specs:
            sock = self.reserve()
            host, port = sock.getsockname()
            pk, sk = params.kem.keygen()
            nodes[node_id] = {
                "host": host,
                "port": port,
                "kem_pk": pk.hex(),
                "kem_sk": sk.hex(),
                "role": role,
            }
            node_objs[node_id] = WireNode(node_id, role, sock, host, port, pk, sk)

        client_host, client_port = client_sock.getsockname()
        cluster = ClusterConfig.from_dict(
            {
                "params": {
                    "payload_size": payload_size,
                    "routing_size": routing_size,
                    "max_hops": max_hops,
                },
                "client": {"host": client_host, "port": client_port},
                "nodes": nodes,
            }
        )
        return cluster, node_objs, client_sock

    def serve(
        self,
        runtime: WireNodeRuntime,
        sock: socket.socket,
    ) -> HarnessNode:
        """Start a joined serve thread for ``runtime`` on a reserved ``sock``."""
        node = HarnessNode(runtime, sock).start()
        self._nodes.append(node)
        return node

    def close(self) -> None:
        for node in self._nodes:
            node.stop()
        for server, thread in self._http:
            server.shutdown()
            thread.join(timeout=2.0)
            server.server_close()
        for sock in self._sockets:
            # Served sockets are already closed by node.stop(); double close of
            # a UDP socket is a harmless no-op. This also closes reserved-but-
            # unserved sockets (e.g. a client socket handed to run_client_once).
            try:
                sock.close()
            except OSError:
                pass


@contextmanager
def mixnet_harness() -> Iterator[MixnetHarness]:
    net = MixnetHarness()
    try:
        yield net
    finally:
        net.close()
