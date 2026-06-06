"""QUIC-based runtime for production tenet daemons.

Wraps WireNodeRuntime's binary dispatch over QUIC DATAGRAM frames
(RFC 9221). TLS 1.3 is mandatory — all tenet wire traffic is encrypted.

The QUIC server receives datagrams, dispatches through the same demux
as UDP (REACH → Outfox → opaque), and sends responses back through
the QUIC connection. Forward hops to next relays use the UDP send path
for now (QUIC client-to-relay connections are a future optimization).
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from pathlib import Path

from tenet.mixnet.quic_transport import (
    AIOQUIC_AVAILABLE,
    QuicDatagramServer,
    QuicEndpoint,
    InMemorySessionTicketStore,
    make_server_config,
    write_localhost_self_signed_cert,
    POR_QUIC_ALPN,
)
from tenet.mixnet.wire_frame import decode_datagram, encode_forward


def serve_quic_forever(
    runtime,
    *,
    certfile: str | Path | None = None,
    keyfile: str | Path | None = None,
    dev_localhost: bool = False,
) -> int:
    """Run a WireNodeRuntime over QUIC datagrams with TLS. Blocking.

    Replaces serve_forever() for QUIC transport. Same demux, same
    handlers, but incoming datagrams arrive via QUIC with TLS 1.3
    instead of raw UDP.

    Responses to clients are pushed back through the QUIC connection.
    Forward hops to next relays still use UDP sendto (relay-to-relay
    QUIC is a future optimization — TLS on the ingress is the security
    boundary that matters now).
    """
    if not AIOQUIC_AVAILABLE:
        raise RuntimeError("aioquic is required for QUIC runtime")

    return asyncio.run(_serve_quic_async(
        runtime, certfile=certfile, keyfile=keyfile, dev_localhost=dev_localhost))


async def _serve_quic_async(runtime, *, certfile, keyfile, dev_localhost):
    if certfile is None or keyfile is None:
        if not dev_localhost:
            raise ValueError(
                "certfile and keyfile are required for production. "
                "Use dev_localhost=True for local testing with self-signed certs."
            )
        tmpdir = tempfile.mkdtemp(prefix="por-quic-cert-")
        certfile, keyfile = write_localhost_self_signed_cert(
            Path(tmpdir) / "cert.pem", Path(tmpdir) / "key.pem")

    endpoint = QuicEndpoint(runtime.identity.host, runtime.identity.port)
    config = make_server_config(
        certfile, keyfile,
        alpn=POR_QUIC_ALPN,
        max_datagram_frame_size=runtime.params.payload_size + 512,
    )

    # For forward processing, the runtime sends to next hops via UDP.
    # For circuit return packets that should go back to the QUIC client,
    # we intercept _send_binary when target is "client" and push through
    # the QUIC connection tracker instead of UDP.
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tickets = InMemorySessionTicketStore()

    server = QuicDatagramServer(
        endpoint,
        configuration=config,
        session_ticket_store=tickets,
    )

    # Patch _send_binary to route "client" responses through QUIC
    _orig_send = runtime._send_binary.__func__ if hasattr(runtime._send_binary, '__func__') else None

    def _quic_send_binary(sock, target_id, data, *, src_addr=None, return_session=None):
        if return_session:
            proto = server.connections.active_protocol
            if proto is not None:
                server.connections.bind_session(return_session, proto)
        if target_id == "client" and server.connections.count > 0:
            session_id = return_session or _return_session_from_circuit_datagram(data)
            if session_id and server.connections.send_to_session(session_id, data):
                return
            if server.connections.count == 1 and server.connections.send_to_any(data):
                return
        else:
            # Forward to next relay via UDP
            if target_id == "client":
                target = runtime.cluster.client
            elif target_id in runtime.cluster.nodes:
                target = runtime.cluster.node(target_id)
            else:
                return
            sock.sendto(data, (target.host, target.port))

    runtime._send_binary = lambda sock, target_id, data, **kw: _quic_send_binary(sock, target_id, data, **kw)

    def _handler(data: bytes) -> bytes | None:
        from tenet.mixnet.reach_wire import is_reach_datagram

        if is_reach_datagram(data):
            if runtime.on_reach_control is not None:
                runtime.on_reach_control(data, (endpoint.host, endpoint.port))
            return None

        kind, a, b = decode_datagram(data, runtime.params.payload_size)
        if kind == "shutdown":
            runtime._shutdown = True
            return None
        if kind == "forward":
            runtime._handle_forward_binary(udp_sock, a, b,
                                            src_addr=(endpoint.host, endpoint.port))
            return None
        if kind == "circuit":
            runtime._handle_circuit_binary(udp_sock, a,
                                            src_addr=(endpoint.host, endpoint.port))
            return None
        return None

    server.datagram_handler = _handler
    await server.start()
    runtime._log("started", fields={
        "wire": "quic",
        "tls": "enabled",
        "addr": f"{endpoint.host}:{endpoint.port}",
    })

    try:
        while not runtime._shutdown:
            await asyncio.sleep(0.1)
    finally:
        udp_sock.close()
        server.close()
        runtime._log("stopped", fields={"wire": "quic"})

    return 0


def _return_session_from_circuit_datagram(data: bytes) -> str | None:
    if len(data) < 17 or data[:1] != b"\x01":
        return None
    return data[1:17].hex()
