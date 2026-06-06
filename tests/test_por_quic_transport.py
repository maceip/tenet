import asyncio
import datetime as dt
import ipaddress
import socket
import ssl

import pytest

from tenet.mixnet.quic_transport import (
    AIOQUIC_AVAILABLE,
    H3WebSocketClient,
    H3WebSocketServer,
    InMemorySessionTicketStore,
    POR_H3_ALPN,
    QuicDatagramClient,
    QuicDatagramServer,
    QuicEndpoint,
    make_client_config,
    make_server_config,
)


pytestmark = pytest.mark.skipif(not AIOQUIC_AVAILABLE, reason="aioquic is not installed")


def _free_udp_port() -> int:
    """Reserve an ephemeral port for an aioquic server (bind-then-close).

    Quarantined TOCTOU, like ``tests.helpers.reserve_udp_ports``: aioquic's
    ``serve()`` binds its own socket to a port chosen in advance and cannot adopt
    a held-open socket, so this case can't use the bind-once ``mixnet_harness``.
    Localhost + skip-gated, so the race window is negligible here.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _write_self_signed_cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "localhost.crt"
    key_path = tmp_path / "localhost.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_client_config_verifies_tls_by_default():
    config = make_client_config()

    assert config.verify_mode != ssl.CERT_NONE


def test_disabling_tls_verification_requires_dev_opt_in():
    with pytest.raises(ValueError, match="dev_allow_insecure_tls"):
        make_client_config(verify_tls=False)

    config = make_client_config(verify_tls=False, dev_allow_insecure_tls=True)

    assert config.verify_mode == ssl.CERT_NONE


def test_client_receive_queues_are_bounded():
    endpoint = QuicEndpoint("127.0.0.1", 4433)
    datagram_client = QuicDatagramClient(
        endpoint,
        configuration=make_client_config(
            verify_tls=False,
            dev_allow_insecure_tls=True,
        ),
        receive_queue_size=3,
    )
    h3_client = H3WebSocketClient(
        endpoint,
        configuration=make_client_config(
            verify_tls=False,
            dev_allow_insecure_tls=True,
            alpn=POR_H3_ALPN,
        ),
        receive_queue_size=5,
    )

    assert datagram_client._queue.maxsize == 3
    assert h3_client._queue.maxsize == 5
    assert h3_client._accepted.maxsize == 1


def test_quic_datagram_round_trip_over_localhost(tmp_path):
    async def run():
        cert_path, key_path = _write_self_signed_cert(tmp_path)
        endpoint = QuicEndpoint("127.0.0.1", _free_udp_port())
        server = QuicDatagramServer(
            endpoint,
            configuration=make_server_config(cert_path, key_path),
            datagram_handler=lambda data: b"ack:" + data,
        )
        await server.start()
        try:
            async with QuicDatagramClient(
                endpoint,
                configuration=make_client_config(
                    verify_tls=False,
                    dev_allow_insecure_tls=True,
                ),
            ) as client:
                client.send(b"\x00por-forward-frame")
                assert await client.receive(timeout=2.0) == b"ack:\x00por-forward-frame"

                client.send(b"\x01por-circuit-frame")
                assert await client.receive(timeout=2.0) == b"ack:\x01por-circuit-frame"
        finally:
            server.close()
            await asyncio.sleep(0)

    asyncio.run(run())


def test_quic_datagram_session_ticket_is_cached_and_offered(tmp_path):
    class CountingTicketStore(InMemorySessionTicketStore):
        def __init__(self):
            super().__init__()
            self.fetch_count = 0

        def fetch(self, label: bytes):
            self.fetch_count += 1
            return super().fetch(label)

    async def run():
        cert_path, key_path = _write_self_signed_cert(tmp_path)
        endpoint = QuicEndpoint("127.0.0.1", _free_udp_port())
        server_tickets = CountingTicketStore()
        client_tickets = InMemorySessionTicketStore()
        server = QuicDatagramServer(
            endpoint,
            configuration=make_server_config(cert_path, key_path),
            datagram_handler=lambda data: b"ack:" + data,
            session_ticket_store=server_tickets,
        )
        await server.start()
        try:
            async with QuicDatagramClient(
                endpoint,
                configuration=make_client_config(
                    verify_tls=False,
                    dev_allow_insecure_tls=True,
                ),
                session_ticket_store=client_tickets,
            ) as client:
                client.send(b"first")
                assert await client.receive(timeout=2.0) == b"ack:first"
                await asyncio.sleep(0.1)

            assert client_tickets.latest is not None

            expected_ticket = client_tickets.latest
            second_config = make_client_config(
                verify_tls=False,
                dev_allow_insecure_tls=True,
            )
            second_client = QuicDatagramClient(
                endpoint,
                configuration=second_config,
                session_ticket_store=client_tickets,
            )
            assert second_config.session_ticket is expected_ticket
            async with second_client as client:
                client.send(b"second")
                assert await client.receive(timeout=2.0) == b"ack:second"

            assert server_tickets.fetch_count >= 1
        finally:
            server.close()
            await asyncio.sleep(0)

    asyncio.run(run())


def test_h3_websocket_extended_connect_round_trip(tmp_path):
    async def run():
        cert_path, key_path = _write_self_signed_cert(tmp_path)
        endpoint = QuicEndpoint("127.0.0.1", _free_udp_port())
        server = H3WebSocketServer(
            endpoint,
            configuration=make_server_config(cert_path, key_path, alpn=POR_H3_ALPN),
            websocket_handler=lambda data: b"ws:" + data,
        )
        await server.start()
        try:
            async with H3WebSocketClient(
                endpoint,
                configuration=make_client_config(
                    verify_tls=False,
                    dev_allow_insecure_tls=True,
                    alpn=POR_H3_ALPN,
                ),
                authority=f"localhost:{endpoint.port}",
                path="/por",
            ) as client:
                client.send(b"\x00por-forward-frame")
                assert await client.receive(timeout=2.0) == b"ws:\x00por-forward-frame"

                client.send(b"\x01por-circuit-frame")
                assert await client.receive(timeout=2.0) == b"ws:\x01por-circuit-frame"
        finally:
            server.close()
            await asyncio.sleep(0)

    asyncio.run(run())


def test_h3_websocket_buffers_full_frame_when_stream_fragments(tmp_path):
    async def run():
        cert_path, key_path = _write_self_signed_cert(tmp_path)
        endpoint = QuicEndpoint("127.0.0.1", _free_udp_port())
        seen = []
        server = H3WebSocketServer(
            endpoint,
            configuration=make_server_config(cert_path, key_path, alpn=POR_H3_ALPN),
            websocket_handler=lambda data: seen.append(data) or b"ok",
            buffer_messages=True,
        )
        await server.start()
        try:
            payload = b"por-frame:" + (b"x" * 4096)
            async with H3WebSocketClient(
                endpoint,
                configuration=make_client_config(
                    verify_tls=False,
                    dev_allow_insecure_tls=True,
                    alpn=POR_H3_ALPN,
                ),
                authority=f"localhost:{endpoint.port}",
                path="/por",
            ) as client:
                client.send(payload, end_stream=True)
                assert await client.receive(timeout=2.0) == b"ok"
            assert seen == [payload]
        finally:
            server.close()
            await asyncio.sleep(0)

    asyncio.run(run())
