"""QUIC transport helpers for tenet packet bytes.

This module carries already-built tenet frames over real QUIC connections. It
does not parse Outfox headers, circuit packets, prompts, or peer address
records.

Two carriers are intentionally separate:

* ``POR_DATAGRAM_ALPN`` carries small QUIC DATAGRAM control/test frames.
* ``POR_H3_ALPN`` carries full tenet frames over HTTP/3 Extended CONNECT.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import ssl
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from aioquic.asyncio import connect, serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.asyncio.server import QuicServer
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ConnectionTerminated, DatagramFrameReceived, QuicEvent
    from aioquic.tls import SessionTicket

    AIOQUIC_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without optional dep
    AIOQUIC_AVAILABLE = False
    QuicConnectionProtocol = object
    QuicServer = object
    QuicConfiguration = object
    SessionTicket = object
    ConnectionTerminated = object
    DatagramFrameReceived = object
    H3Connection = None
    H3Event = object
    HeadersReceived = object
    DataReceived = object


POR_DATAGRAM_ALPN = "por-quic-datagram-v1"
POR_H3_ALPN = "h3"
POR_QUIC_ALPN = POR_DATAGRAM_ALPN
DEFAULT_MAX_DATAGRAM_FRAME_SIZE = 1200
DEFAULT_RECEIVE_QUEUE_SIZE = 1024
DEFAULT_MAX_H3_MESSAGE_SIZE = 1_048_576

DatagramHandler = Callable[[bytes], bytes | None]
WebSocketHandler = Callable[[bytes], bytes | None]

# Demux callbacks — same order as UDP (I2P SSU2 style):
#   1. REACH_* → on_reach_datagram
#   2. Outfox 0x00/0x01/0x02 → on_mix_datagram
#   3. Unknown → on_opaque_datagram (or drop)
ReachDatagramHandler = Callable[[bytes], None]
MixDatagramHandler = Callable[[bytes], None]
OpaqueDatagramHandler = Callable[[bytes], None]


def demux_datagram(
    data: bytes,
    *,
    on_reach: ReachDatagramHandler | None = None,
    on_mix: MixDatagramHandler | None = None,
    on_opaque: OpaqueDatagramHandler | None = None,
) -> None:
    """Classify and dispatch a QUIC DATAGRAM frame (same order as UDP demux)."""
    from tenet.mixnet.reach_wire import is_reach_datagram

    if is_reach_datagram(data):
        if on_reach is not None:
            on_reach(data)
        return

    if data and data[0:1] in (b'\x00', b'\x01', b'\x02'):
        if on_mix is not None:
            on_mix(data)
        return

    if on_opaque is not None:
        on_opaque(data)


class QuicTransportUnavailable(RuntimeError):
    """Raised when the optional QUIC dependency is not installed."""


@dataclass(frozen=True)
class QuicEndpoint:
    host: str
    port: int


class InMemorySessionTicketStore:
    """Tiny in-memory QUIC session-ticket store for local clients/servers."""

    def __init__(self) -> None:
        self.tickets: dict[bytes, "SessionTicket"] = {}
        self.latest: "SessionTicket | None" = None

    def save(self, ticket: "SessionTicket") -> None:
        self.tickets[ticket.ticket] = ticket
        self.latest = ticket

    def fetch(self, label: bytes) -> "SessionTicket | None":
        return self.tickets.get(label)


def _require_aioquic() -> None:
    if not AIOQUIC_AVAILABLE:
        raise QuicTransportUnavailable(
            "aioquic is required for tenet.mixnet.quic_transport; install aioquic to use QUIC"
        )


def make_server_config(
    certfile: str | Path,
    keyfile: str | Path,
    *,
    alpn: str = POR_QUIC_ALPN,
    max_datagram_frame_size: int = DEFAULT_MAX_DATAGRAM_FRAME_SIZE,
) -> "QuicConfiguration":
    """Build a QUIC server config with DATAGRAM support enabled."""

    _require_aioquic()
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[alpn],
        max_datagram_frame_size=max_datagram_frame_size,
    )
    config.load_cert_chain(str(certfile), str(keyfile))
    return config


def make_client_config(
    *,
    alpn: str = POR_QUIC_ALPN,
    verify_tls: bool = True,
    dev_allow_insecure_tls: bool = False,
    max_datagram_frame_size: int = DEFAULT_MAX_DATAGRAM_FRAME_SIZE,
) -> "QuicConfiguration":
    """Build a QUIC client config with DATAGRAM support enabled.

    TLS verification is on by default. Localhost development runs with generated
    self-signed certificates must explicitly set both ``verify_tls=False`` and
    ``dev_allow_insecure_tls=True``.
    """

    _require_aioquic()
    if not verify_tls and not dev_allow_insecure_tls:
        raise ValueError("verify_tls=False requires dev_allow_insecure_tls=True")
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=[alpn],
        max_datagram_frame_size=max_datagram_frame_size,
    )
    if not verify_tls:
        config.verify_mode = ssl.CERT_NONE
    return config


def _bounded_queue(maxsize: int = DEFAULT_RECEIVE_QUEUE_SIZE) -> asyncio.Queue[bytes]:
    if maxsize <= 0:
        raise ValueError("queue maxsize must be positive")
    return asyncio.Queue(maxsize=maxsize)


def _put_or_close(
    queue: asyncio.Queue,
    item: object,
    protocol: "QuicConnectionProtocol",
    *,
    reason: str,
) -> bool:
    try:
        queue.put_nowait(item)
        return True
    except asyncio.QueueFull:
        protocol._quic.close(error_code=0, reason_phrase=reason)
        protocol.transmit()
        return False


class _DatagramProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        *args,
        receive_queue: asyncio.Queue[bytes] | None = None,
        datagram_handler: DatagramHandler | None = None,
        connection_tracker: "ConnectionTracker | None" = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.receive_queue = receive_queue
        self.datagram_handler = datagram_handler
        self._connection_tracker = connection_tracker

    def connection_made(self, transport) -> None:
        super().connection_made(transport)
        if self._connection_tracker is not None:
            self._connection_tracker.add(self)

    def connection_lost(self, exc) -> None:
        if self._connection_tracker is not None:
            self._connection_tracker.remove(self)
        super().connection_lost(exc)

    def quic_event_received(self, event: "QuicEvent") -> None:
        super().quic_event_received(event)
        if isinstance(event, DatagramFrameReceived):
            data = bytes(event.data)
            if self.receive_queue is not None:
                if not _put_or_close(
                    self.receive_queue,
                    data,
                    self,
                    reason="datagram receive queue full",
                ):
                    return
            if self.datagram_handler is not None:
                if self._connection_tracker is not None:
                    self._connection_tracker.enter_handler(self)
                try:
                    response = self.datagram_handler(data)
                    if response is not None:
                        self.send_datagram(response)
                finally:
                    if self._connection_tracker is not None:
                        self._connection_tracker.exit_handler(self)

    def send_datagram(self, data: bytes) -> None:
        self._quic.send_datagram_frame(data)
        self.transmit()


class ConnectionTracker:
    """Track connected QUIC clients for server-push (bidirectional datagrams).

    The server can push datagrams to any connected client — not just respond
    to incoming datagrams. This enables circuit streaming where the exit
    pushes tokens back through the QUIC connection.
    """

    def __init__(self) -> None:
        self._protocols: set[_DatagramProtocol] = set()
        self._session_protocols: dict[str, _DatagramProtocol] = {}
        self._active_protocol: _DatagramProtocol | None = None

    def add(self, protocol: _DatagramProtocol) -> None:
        self._protocols.add(protocol)

    def remove(self, protocol: _DatagramProtocol) -> None:
        self._protocols.discard(protocol)
        if self._active_protocol is protocol:
            self._active_protocol = None
        for session, owner in list(self._session_protocols.items()):
            if owner is protocol:
                self._session_protocols.pop(session, None)

    def enter_handler(self, protocol: _DatagramProtocol) -> None:
        self._active_protocol = protocol

    def exit_handler(self, protocol: _DatagramProtocol) -> None:
        if self._active_protocol is protocol:
            self._active_protocol = None

    @property
    def active_protocol(self) -> _DatagramProtocol | None:
        return self._active_protocol

    def bind_session(self, session_id: str, protocol: _DatagramProtocol) -> None:
        self._session_protocols[session_id] = protocol

    def send_to_session(self, session_id: str, data: bytes) -> bool:
        proto = self._session_protocols.get(session_id)
        if proto is None:
            return False
        try:
            proto.send_datagram(data)
            return True
        except Exception:
            self._protocols.discard(proto)
            for session, owner in list(self._session_protocols.items()):
                if owner is proto:
                    self._session_protocols.pop(session, None)
            return False

    def broadcast(self, data: bytes) -> int:
        """Send a datagram to all connected clients. Returns count sent."""
        sent = 0
        for proto in list(self._protocols):
            try:
                proto.send_datagram(data)
                sent += 1
            except Exception:
                self._protocols.discard(proto)
        return sent

    def send_to_any(self, data: bytes) -> bool:
        """Send to one connected client (first available)."""
        for proto in list(self._protocols):
            try:
                proto.send_datagram(data)
                return True
            except Exception:
                self._protocols.discard(proto)
        return False

    @property
    def count(self) -> int:
        return len(self._protocols)


class QuicDatagramServer:
    """Small QUIC DATAGRAM server for local tenet transport tests.

    ``datagram_handler`` runs on the QUIC event loop and must not block.
    Production node logic should hand work to a task/queue and return quickly.

    For supernode demux, pass ``on_reach_datagram``, ``on_mix_datagram``,
    and/or ``on_opaque_datagram`` instead of ``datagram_handler``. The
    demux callbacks use the same order as UDP (REACH → Outfox → opaque).
    When demux callbacks are set, ``datagram_handler`` is ignored.
    """

    def __init__(
        self,
        endpoint: QuicEndpoint,
        *,
        configuration: "QuicConfiguration",
        datagram_handler: DatagramHandler | None = None,
        session_ticket_store: InMemorySessionTicketStore | None = None,
        on_reach_datagram: ReachDatagramHandler | None = None,
        on_mix_datagram: MixDatagramHandler | None = None,
        on_opaque_datagram: OpaqueDatagramHandler | None = None,
    ) -> None:
        _require_aioquic()
        self.endpoint = endpoint
        self.configuration = configuration
        self.session_ticket_store = session_ticket_store
        self.connections = ConnectionTracker()
        self._server: QuicServer | None = None

        if on_reach_datagram or on_mix_datagram or on_opaque_datagram:
            def _demux_handler(data: bytes) -> bytes | None:
                demux_datagram(
                    data,
                    on_reach=on_reach_datagram,
                    on_mix=on_mix_datagram,
                    on_opaque=on_opaque_datagram,
                )
                return None
            self.datagram_handler = _demux_handler
        else:
            self.datagram_handler = datagram_handler

    async def start(self) -> "QuicDatagramServer":
        self._server = await serve(
            self.endpoint.host,
            self.endpoint.port,
            configuration=self.configuration,
            create_protocol=self._create_protocol,
            session_ticket_fetcher=(
                self.session_ticket_store.fetch if self.session_ticket_store else None
            ),
            session_ticket_handler=(
                self.session_ticket_store.save if self.session_ticket_store else None
            ),
        )
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None

    def _create_protocol(self, *args, **kwargs) -> _DatagramProtocol:
        return _DatagramProtocol(
            *args,
            datagram_handler=self.datagram_handler,
            connection_tracker=self.connections,
            **kwargs,
        )


class QuicDatagramClient(AbstractAsyncContextManager):
    """Async client for sending and receiving QUIC DATAGRAM frames."""

    def __init__(
        self,
        endpoint: QuicEndpoint,
        *,
        configuration: "QuicConfiguration",
        session_ticket_store: InMemorySessionTicketStore | None = None,
        receive_queue_size: int = DEFAULT_RECEIVE_QUEUE_SIZE,
    ) -> None:
        _require_aioquic()
        self.endpoint = endpoint
        self.configuration = configuration
        self.session_ticket_store = session_ticket_store
        if self.session_ticket_store and self.session_ticket_store.latest is not None:
            self.configuration.session_ticket = self.session_ticket_store.latest
        self._queue = _bounded_queue(receive_queue_size)
        self._connect_cm = None
        self._protocol: _DatagramProtocol | None = None

    async def __aenter__(self) -> "QuicDatagramClient":
        self._connect_cm = connect(
            self.endpoint.host,
            self.endpoint.port,
            configuration=self.configuration,
            create_protocol=self._create_protocol,
            session_ticket_handler=(
                self.session_ticket_store.save if self.session_ticket_store else None
            ),
        )
        self._protocol = await self._connect_cm.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._connect_cm is not None:
            await self._connect_cm.__aexit__(exc_type, exc, tb)
            self._connect_cm = None
            self._protocol = None

    def send(self, data: bytes) -> None:
        if self._protocol is None:
            raise RuntimeError("QUIC client is not connected")
        self._protocol.send_datagram(data)

    async def receive(self, timeout: float = 1.0) -> bytes:
        return await asyncio.wait_for(self._queue.get(), timeout=timeout)

    def _create_protocol(self, *args, **kwargs) -> _DatagramProtocol:
        return _DatagramProtocol(*args, receive_queue=self._queue, **kwargs)


class _H3WebSocketProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        *args,
        receive_queue: asyncio.Queue[bytes] | None = None,
        accepted_queue: asyncio.Queue[bool] | None = None,
        websocket_handler: WebSocketHandler | None = None,
        buffer_messages: bool = False,
        max_message_size: int = DEFAULT_MAX_H3_MESSAGE_SIZE,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self.receive_queue = receive_queue
        self.accepted_queue = accepted_queue
        self.websocket_handler = websocket_handler
        self.buffer_messages = buffer_messages
        self.max_message_size = max_message_size
        self._stream_buffers: dict[int, bytearray] = {}
        self.stream_id: int | None = None

    def quic_event_received(self, event: "QuicEvent") -> None:
        if isinstance(event, ConnectionTerminated):
            return
        for http_event in self._http.handle_event(event):
            self._h3_event_received(http_event)

    def connect_websocket(
        self,
        *,
        authority: str,
        path: str = "/",
        scheme: str = "https",
    ) -> int:
        stream_id = self._quic.get_next_available_stream_id()
        self.stream_id = stream_id
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":scheme", scheme.encode("ascii")),
                (b":authority", authority.encode("ascii")),
                (b":path", path.encode("ascii")),
                (b":protocol", b"websocket"),
            ],
            end_stream=False,
        )
        self.transmit()
        return stream_id

    def send_websocket_data(self, data: bytes, *, end_stream: bool = False) -> None:
        if self.stream_id is None:
            raise RuntimeError("H3 WebSocket stream is not open")
        self._http.send_data(self.stream_id, data, end_stream=end_stream)
        self.transmit()

    def _h3_event_received(self, event: "H3Event") -> None:
        if isinstance(event, HeadersReceived):
            headers = dict(event.headers)
            if headers.get(b":method") == b"CONNECT" and headers.get(b":protocol") == b"websocket":
                self.stream_id = event.stream_id
                self._http.send_headers(
                    stream_id=event.stream_id,
                    headers=[(b":status", b"200")],
                    end_stream=False,
                )
                self.transmit()
                return

            status = headers.get(b":status")
            if self.accepted_queue is not None and status is not None:
                _put_or_close(
                    self.accepted_queue,
                    status == b"200",
                    self,
                    reason="websocket accept queue full",
                )
                return

        if isinstance(event, DataReceived):
            data = bytes(event.data)
            if self.buffer_messages:
                buffer = self._stream_buffers.setdefault(event.stream_id, bytearray())
                buffer.extend(data)
                if len(buffer) > self.max_message_size:
                    self._stream_buffers.pop(event.stream_id, None)
                    self._quic.close(error_code=0, reason_phrase="h3 message too large")
                    self.transmit()
                    return
                if not event.stream_ended:
                    return
                data = bytes(buffer)
                self._stream_buffers.pop(event.stream_id, None)

            if self.receive_queue is not None:
                if not _put_or_close(
                    self.receive_queue,
                    data,
                    self,
                    reason="websocket receive queue full",
                ):
                    return
            if self.websocket_handler is not None:
                response = self.websocket_handler(data)
                if response is not None:
                    self.stream_id = event.stream_id
                    self.send_websocket_data(response, end_stream=False)


class H3WebSocketServer:
    """Minimal HTTP/3 Extended CONNECT carrier for WebSocket-protocol bytes.

    ``websocket_handler`` runs on the QUIC event loop and must not block.
    Production node logic should hand work to a task/queue and return quickly.
    This is a frame carrier, not a complete WebSocket API implementation.
    """

    def __init__(
        self,
        endpoint: QuicEndpoint,
        *,
        configuration: "QuicConfiguration",
        websocket_handler: WebSocketHandler | None = None,
        session_ticket_store: InMemorySessionTicketStore | None = None,
        buffer_messages: bool = False,
        max_message_size: int = DEFAULT_MAX_H3_MESSAGE_SIZE,
    ) -> None:
        _require_aioquic()
        self.endpoint = endpoint
        self.configuration = configuration
        self.websocket_handler = websocket_handler
        self.session_ticket_store = session_ticket_store
        self.buffer_messages = buffer_messages
        self.max_message_size = max_message_size
        self._server: QuicServer | None = None

    async def start(self) -> "H3WebSocketServer":
        self._server = await serve(
            self.endpoint.host,
            self.endpoint.port,
            configuration=self.configuration,
            create_protocol=self._create_protocol,
            session_ticket_fetcher=(
                self.session_ticket_store.fetch if self.session_ticket_store else None
            ),
            session_ticket_handler=(
                self.session_ticket_store.save if self.session_ticket_store else None
            ),
        )
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None

    def _create_protocol(self, *args, **kwargs) -> _H3WebSocketProtocol:
        return _H3WebSocketProtocol(
            *args,
            websocket_handler=self.websocket_handler,
            buffer_messages=self.buffer_messages,
            max_message_size=self.max_message_size,
            **kwargs,
        )


class H3WebSocketClient(AbstractAsyncContextManager):
    """Client for HTTP/3 Extended CONNECT with `:protocol = websocket`.

    This sends opaque byte frames over H3 streams. It is not a browser WebSocket
    compatibility layer.
    """

    def __init__(
        self,
        endpoint: QuicEndpoint,
        *,
        configuration: "QuicConfiguration",
        authority: str = "localhost",
        path: str = "/",
        session_ticket_store: InMemorySessionTicketStore | None = None,
        receive_queue_size: int = DEFAULT_RECEIVE_QUEUE_SIZE,
    ) -> None:
        _require_aioquic()
        self.endpoint = endpoint
        self.configuration = configuration
        self.authority = authority
        self.path = path
        self.session_ticket_store = session_ticket_store
        if self.session_ticket_store and self.session_ticket_store.latest is not None:
            self.configuration.session_ticket = self.session_ticket_store.latest
        self._queue = _bounded_queue(receive_queue_size)
        self._accepted: asyncio.Queue[bool] = asyncio.Queue(maxsize=1)
        self._connect_cm = None
        self._protocol: _H3WebSocketProtocol | None = None

    async def __aenter__(self) -> "H3WebSocketClient":
        self._connect_cm = connect(
            self.endpoint.host,
            self.endpoint.port,
            configuration=self.configuration,
            create_protocol=self._create_protocol,
            session_ticket_handler=(
                self.session_ticket_store.save if self.session_ticket_store else None
            ),
        )
        self._protocol = await self._connect_cm.__aenter__()
        self._protocol.connect_websocket(
            authority=self.authority,
            path=self.path,
        )
        accepted = await asyncio.wait_for(self._accepted.get(), timeout=2.0)
        if not accepted:
            raise RuntimeError("H3 WebSocket CONNECT was rejected")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._connect_cm is not None:
            await self._connect_cm.__aexit__(exc_type, exc, tb)
            self._connect_cm = None
            self._protocol = None

    def send(self, data: bytes, *, end_stream: bool = False) -> None:
        if self._protocol is None:
            raise RuntimeError("H3 WebSocket client is not connected")
        self._protocol.send_websocket_data(data, end_stream=end_stream)

    async def receive(self, timeout: float = 1.0) -> bytes:
        return await asyncio.wait_for(self._queue.get(), timeout=timeout)

    def _create_protocol(self, *args, **kwargs) -> _H3WebSocketProtocol:
        return _H3WebSocketProtocol(
            *args,
            receive_queue=self._queue,
            accepted_queue=self._accepted,
            **kwargs,
        )


def write_localhost_self_signed_cert(
    cert_path: str | Path,
    key_path: str | Path,
    *,
    valid_days: int = 1,
) -> tuple[Path, Path]:
    """Write a short-lived localhost certificate for local QUIC daemons."""

    _require_aioquic()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cert_path = Path(cert_path)
    key_path = Path(key_path)
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
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=valid_days))
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
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path
