"""QUIC-based runtime and client for production P-OR daemons.

Wraps WireNodeRuntime's binary dispatch over QUIC DATAGRAM frames
(RFC 9221) instead of raw UDP. TLS 1.3 is mandatory — all P-OR wire
traffic is encrypted at the transport layer.

For dev/localhost, auto-generated self-signed certs are used.
For production, operators provide real certs via config.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Sequence

from .quic_transport import (
    AIOQUIC_AVAILABLE,
    QuicDatagramClient,
    QuicDatagramServer,
    QuicEndpoint,
    InMemorySessionTicketStore,
    make_server_config,
    make_client_config,
    write_localhost_self_signed_cert,
    POR_QUIC_ALPN,
)
from .wire_frame import encode_forward, encode_shutdown, decode_datagram


async def serve_quic_runtime(
    runtime,
    *,
    certfile: str | Path | None = None,
    keyfile: str | Path | None = None,
    dev_localhost: bool = False,
) -> None:
    """Run a WireNodeRuntime over QUIC datagrams with TLS.

    If certfile/keyfile are not provided and dev_localhost=True,
    generates a temporary self-signed localhost cert.
    """
    if not AIOQUIC_AVAILABLE:
        raise RuntimeError("aioquic is required for QUIC runtime")

    if certfile is None or keyfile is None:
        if not dev_localhost:
            raise ValueError(
                "certfile and keyfile are required for production. "
                "Use dev_localhost=True for local testing with self-signed certs."
            )
        tmpdir = tempfile.mkdtemp(prefix="por-quic-cert-")
        certfile, keyfile = write_localhost_self_signed_cert(
            Path(tmpdir) / "cert.pem",
            Path(tmpdir) / "key.pem",
        )

    endpoint = QuicEndpoint(runtime.identity.host, runtime.identity.port)
    config = make_server_config(
        certfile, keyfile,
        alpn=POR_QUIC_ALPN,
        max_datagram_frame_size=runtime.params.payload_size + 512,
    )

    def _handler(data: bytes) -> bytes | None:
        from .reach_wire import is_reach_datagram

        if is_reach_datagram(data):
            if runtime.on_reach_control is not None:
                runtime.on_reach_control(data, (endpoint.host, endpoint.port))
            return None

        kind, a, b = decode_datagram(data, runtime.params.payload_size)
        if kind == "shutdown":
            runtime._shutdown = True
            return None
        if kind == "forward":
            result = _process_forward_sync(runtime, a, b)
            return result
        if kind == "circuit":
            result = _process_circuit_sync(runtime, a)
            return result
        return None

    tickets = InMemorySessionTicketStore()
    server = QuicDatagramServer(
        endpoint,
        configuration=config,
        datagram_handler=_handler,
        session_ticket_store=tickets,
    )
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
        server.close()
        runtime._log("stopped", fields={"wire": "quic"})


def _process_forward_sync(runtime, header, payload):
    """Process a forward packet and return the response to send, if any."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        runtime._handle_forward_binary(sock, header, payload, src_addr=None)
    finally:
        sock.close()
    return None


def _process_circuit_sync(runtime, packet):
    """Process a circuit packet."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        runtime._handle_circuit_binary(sock, packet, src_addr=None)
    finally:
        sock.close()
    return None


async def send_via_quic(
    endpoint: QuicEndpoint,
    data: bytes,
    *,
    verify_tls: bool = True,
    dev_allow_insecure_tls: bool = False,
    timeout: float = 5.0,
) -> list[bytes]:
    """Send a datagram via QUIC and collect responses."""
    if not AIOQUIC_AVAILABLE:
        raise RuntimeError("aioquic is required")

    config = make_client_config(
        alpn=POR_QUIC_ALPN,
        verify_tls=verify_tls,
        dev_allow_insecure_tls=dev_allow_insecure_tls,
    )
    tickets = InMemorySessionTicketStore()
    responses = []

    async with QuicDatagramClient(
        endpoint, configuration=config, session_ticket_store=tickets,
    ) as client:
        client.send(data)
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                resp = await client.receive(timeout=0.5)
                responses.append(resp)
            except asyncio.TimeoutError:
                if responses:
                    break
                continue

    return responses
