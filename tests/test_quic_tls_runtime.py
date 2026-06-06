"""TLS foundation test: QUIC datagram runtime with mandatory TLS.

Proves: production daemons use TLS 1.3 via QUIC. Self-signed certs
work for localhost dev. verify_tls=False requires explicit opt-in.
"""

import asyncio
import pytest

from por.quic_transport import (
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
from por.wire_frame import encode_shutdown

pytestmark = pytest.mark.skipif(not AIOQUIC_AVAILABLE, reason="aioquic not installed")


def _free_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_quic_datagram_with_tls(tmp_path):
    """Binary wire over QUIC DATAGRAM with TLS 1.3."""
    cert, key = write_localhost_self_signed_cert(
        tmp_path / "cert.pem", tmp_path / "key.pem")

    port = _free_port()
    endpoint = QuicEndpoint("127.0.0.1", port)

    received = []
    def handler(data):
        received.append(data)
        return b"ack:" + data[:8]

    async def run():
        server_config = make_server_config(cert, key, max_datagram_frame_size=65535)
        server = QuicDatagramServer(
            endpoint, configuration=server_config, datagram_handler=handler)
        await server.start()

        try:
            client_config = make_client_config(
                verify_tls=False, dev_allow_insecure_tls=True,
                max_datagram_frame_size=65535)

            async with QuicDatagramClient(
                endpoint, configuration=client_config,
            ) as client:
                client.send(b"hello-tls")
                resp = await asyncio.wait_for(client.receive(), timeout=2.0)
                assert resp == b"ack:hello-tl"
        finally:
            server.close()

    asyncio.run(run())
    assert b"hello-tls" in received


def test_tls_required_no_insecure_by_default():
    """Client refuses verify_tls=False without explicit dev flag."""
    with pytest.raises(ValueError, match="dev_allow_insecure_tls"):
        make_client_config(verify_tls=False)


def test_production_quic_runtime_requires_cert():
    """QUIC runtime without cert and dev_localhost=False raises."""
    from por.quic_runtime import serve_quic_runtime

    class FakeRuntime:
        identity = type("I", (), {"host": "127.0.0.1", "port": 0})()
        params = type("P", (), {"payload_size": 1024})()
        on_reach_control = None
        _shutdown = True
        def _log(self, *a, **kw): pass

    async def run():
        with pytest.raises(ValueError, match="certfile"):
            await serve_quic_runtime(FakeRuntime(), dev_localhost=False)

    asyncio.run(run())
