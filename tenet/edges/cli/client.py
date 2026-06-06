"""tenet client daemon entry point."""

from __future__ import annotations

import argparse
import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Sequence
from uuid import uuid4

from tenet.experts.client import ClientRunResult, run_client_once
from tenet.config import ClusterConfig, DaemonConfig, LoggingConfig, PorConfig
from tenet.experts.directory import load_public_snapshot_directory
from tenet.experts.expert_mode import ExpertModeConfig
from tenet.log_events import PorLogEvent, emit_log_event


ClientRunner = Callable[..., ClientRunResult]


@dataclass(frozen=True)
class ClientSessionStats:
    session_id: str
    request_count: int
    active_requests: int
    completed_requests: int
    failed_requests: int
    last_duration_ms: int | None
    last_error: str | None
    started_at: str


class PersistentClientSession:
    """Long-lived client role state for ``tenet run``.

    This intentionally sits above the wire send/receive code. It reuses the
    loaded config, directory snapshot, and local process session across
    requests; the packet framing and transport IO stay in ``tenet.experts.client``.
    """

    def __init__(
        self,
        *,
        daemon: DaemonConfig,
        cluster: ClusterConfig,
        discovery_provider,
        runner: ClientRunner = run_client_once,
    ) -> None:
        self.daemon = daemon
        self.cluster = cluster
        self.discovery_provider = discovery_provider
        self.runner = runner
        self.session_id = uuid4().hex
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._request_count = 0
        self._active_requests = 0
        self._completed_requests = 0
        self._failed_requests = 0
        self._last_duration_ms: int | None = None
        self._last_error: str | None = None
        self._lock = threading.Lock()
        self._slots = threading.Semaphore(daemon.client.max_concurrent_requests)

    @classmethod
    def from_config(
        cls,
        *,
        daemon: DaemonConfig,
        por_config: PorConfig,
        directory_source: str,
        runner: ClientRunner = run_client_once,
    ) -> "PersistentClientSession":
        return cls(
            daemon=daemon,
            cluster=por_config.to_cluster_config(client_node_id=daemon.node_id),
            discovery_provider=load_public_snapshot_directory(directory_source),
            runner=runner,
        )

    @property
    def stats(self) -> ClientSessionStats:
        with self._lock:
            return ClientSessionStats(
                session_id=self.session_id,
                request_count=self._request_count,
                active_requests=self._active_requests,
                completed_requests=self._completed_requests,
                failed_requests=self._failed_requests,
                last_duration_ms=self._last_duration_ms,
                last_error=self._last_error,
                started_at=self.started_at,
            )

    def request(
        self,
        *,
        prompt: str,
        expertise: str | None = None,
        request_id: str | None = None,
        on_chunk: Callable[[dict[str, object]], None] | None = None,
    ) -> ClientRunResult:
        request_id = request_id or uuid4().hex
        if not self._slots.acquire(blocking=False):
            raise RuntimeError("client session concurrency limit reached")
        with self._lock:
            self._request_count += 1
            self._active_requests += 1
            request_index = self._request_count
        started = time.monotonic()
        _emit_client_log(
            self.daemon.logging,
            "session_request_start",
            node_id=self.daemon.node_id,
            request_id=request_id,
            fields={
                "session_id": self.session_id,
                "request_index": request_index,
                "warm_session": request_index > 1,
            },
        )
        _emit_client_log(
            self.daemon.logging,
            "client_send_start",
            node_id=self.daemon.node_id,
            request_id=request_id,
            fields={"relay_count": len(self.daemon.client.relay_path)},
        )

        def wrapped_chunk(chunk: dict[str, object]) -> None:
            done = bool(chunk.get("done"))
            data = str(chunk.get("data", ""))
            _emit_client_log(
                self.daemon.logging,
                "client_stream_done" if done else "client_stream_chunk",
                node_id=self.daemon.node_id,
                request_id=request_id,
                fields={
                    "seq": chunk.get("seq"),
                    "bytes": len(data.encode("utf-8")),
                },
            )
            if on_chunk is not None:
                on_chunk(chunk)

        try:
            result = self.runner(
                cluster=self.cluster,
                discovery_provider=self.discovery_provider,
                prompt=prompt,
                requested_expertise=expertise or self.daemon.client.expertise,
                relay_path=self.daemon.client.relay_path,
                timeout=self.daemon.client.timeout_seconds,
                expert_mode_config=ExpertModeConfig.from_routing(self.daemon.expert_routing),
                random_seed=self.daemon.client.random_seed,
                peer_address_config=self.daemon.peer_address,
                trusted_reachability_relays=self.daemon.client.trusted_reachability_relays,
                dev_allow_untrusted_reachability_relays=(
                    self.daemon.client.dev_allow_untrusted_reachability_relays
                ),
                provider_config=self.daemon.provider,
                on_chunk=wrapped_chunk,
            )
        except Exception as exc:
            with self._lock:
                self._failed_requests += 1
                self._last_error = f"{exc.__class__.__name__}: {exc}"
            _emit_client_log(
                self.daemon.logging,
                "session_request_error",
                node_id=self.daemon.node_id,
                request_id=request_id,
                fields={"error": str(exc), "error_type": exc.__class__.__name__},
            )
            raise
        finally:
            with self._lock:
                self._active_requests = max(0, self._active_requests - 1)
            self._slots.release()
        duration_ms = int((time.monotonic() - started) * 1000)
        with self._lock:
            self._completed_requests += 1
            self._last_duration_ms = duration_ms
            self._last_error = None
        _emit_client_log(
            self.daemon.logging,
            "session_request_complete",
            node_id=self.daemon.node_id,
            request_id=request_id,
            fields={
                "session_id": self.session_id,
                "request_index": request_index,
                "duration_ms": duration_ms,
            },
        )
        return result


def run_send(
    *,
    config_path: str,
    directory_snapshot: str,
    prompt: str,
    expertise: str | None = None,
    relay_path: Sequence[str] = (),
    timeout: float = 8.0,
    peer_address_config=None,
    logging: LoggingConfig | None = None,
) -> int:
    logging = logging or LoggingConfig()
    _emit_client_log(
        logging,
        "client_request_start",
        fields={"directory_source": directory_snapshot, "relay_count": len(tuple(relay_path))},
    )
    result = run_client_once(
        cluster=ClusterConfig.load(config_path),
        discovery_provider=load_public_snapshot_directory(directory_snapshot),
        prompt=prompt,
        requested_expertise=expertise,
        relay_path=tuple(relay_path),
        timeout=timeout,
        peer_address_config=peer_address_config,
    )
    _emit_client_log(
        logging,
        "client_request_complete",
        peer_id=result.selected_peer_id,
        fields={
            "fallback_used": result.fallback_used,
            "degraded_anonymity": result.degraded_anonymity,
        },
    )
    print("client event=response_begin")
    print(result.response_text)
    print("client event=response_end")
    print("client event=client_logs_begin")
    print(result.client_logs)
    print("client event=client_logs_end")
    return 0


def run_client_from_daemon(daemon: DaemonConfig, por_config: PorConfig) -> int:
    """Run client role from one por.config.v1 file."""

    if daemon.client.local_http.enabled:
        return run_local_http_client(daemon, por_config)
    if daemon.client.prompt is None:
        raise SystemExit(
            "tenet run: client role requires client.prompt or client.local_http.enabled=true"
        )
    directory_source = daemon.client.directory_snapshot or daemon.directory.snapshot_path
    if directory_source is None:
        raise SystemExit("tenet run: client role requires client.directory_snapshot")
    session = PersistentClientSession.from_config(
        daemon=daemon,
        por_config=por_config,
        directory_source=directory_source,
    )
    result = session.request(
        prompt=daemon.client.prompt,
        expertise=daemon.client.expertise,
    )
    _emit_client_log(
        daemon.logging,
        "client_request_complete",
        node_id=daemon.node_id,
        peer_id=result.selected_peer_id,
        fields={
            "fallback_used": result.fallback_used,
            "degraded_anonymity": result.degraded_anonymity,
        },
    )
    print(result.response_text)
    print(result.client_logs)
    return 0


def run_local_http_client(daemon: DaemonConfig, por_config: PorConfig) -> int:
    directory_source = daemon.client.directory_snapshot or daemon.directory.snapshot_path
    if directory_source is None:
        raise SystemExit("tenet run: local HTTP client requires client.directory_snapshot")
    session = PersistentClientSession.from_config(
        daemon=daemon,
        por_config=por_config,
        directory_source=directory_source,
    )
    handler = make_client_http_handler(
        daemon=daemon,
        session=session,
    )
    bind = daemon.client.local_http.bind
    server = ThreadingHTTPServer((bind.host, bind.port), handler)
    host, port = server.server_address
    _emit_client_log(
        daemon.logging,
        "local_http_started",
        node_id=daemon.node_id,
        fields={
            "addr": f"{host}:{port}",
            "path": daemon.client.local_http.path,
            "status_path": daemon.client.local_http.status_path,
        },
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    _emit_client_log(daemon.logging, "local_http_stopped", node_id=daemon.node_id)
    return 0


def make_client_http_handler(
    *,
    daemon: DaemonConfig,
    cluster: ClusterConfig | None = None,
    discovery_provider=None,
    runner: ClientRunner = run_client_once,
    session: PersistentClientSession | None = None,
):
    """Build the optional local HTTP/SSE adapter for the same client process."""

    path = daemon.client.local_http.path
    status_path = daemon.client.local_http.status_path
    if session is None:
        if cluster is None or discovery_provider is None:
            raise ValueError("cluster and discovery_provider are required without session")
        session = PersistentClientSession(
            daemon=daemon,
            cluster=cluster,
            discovery_provider=discovery_provider,
            runner=runner,
        )

    class ClientHttpHandler(BaseHTTPRequestHandler):
        server_version = "tenet-client-http/0.1"

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send_json(_health_payload(daemon, session))
                return
            if self.path == status_path:
                self._send_json(_status_payload(daemon, session))
                return
            self.send_error(404, "not found")

        def do_POST(self) -> None:
            if self.path != path:
                self.send_error(404, "not found")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                body = json.loads(raw.decode("utf-8"))
                prompt = str(body["prompt"])
                expertise = body.get("expertise")
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                self.send_error(400, f"bad request: {exc}")
                return

            request_id = uuid4().hex
            _emit_client_log(
                daemon.logging,
                "local_http_request_start",
                node_id=daemon.node_id,
                request_id=request_id,
                fields={"path": path},
            )
            self._start_sse()
            streamed = False

            def on_chunk(chunk: dict[str, object]) -> None:
                nonlocal streamed
                if chunk.get("done"):
                    return
                streamed = True
                self._write_sse(
                    "chunk",
                    {
                        "request_id": request_id,
                        "seq": chunk.get("seq"),
                        "data": chunk.get("data", ""),
                    },
                )

            try:
                result = session.request(
                    prompt=prompt,
                    expertise=str(expertise) if expertise else daemon.client.expertise,
                    request_id=request_id,
                    on_chunk=on_chunk,
                )
            except Exception as exc:  # pragma: no cover - exercised by HTTP clients
                _emit_client_log(
                    daemon.logging,
                    "local_http_request_error",
                    node_id=daemon.node_id,
                    request_id=request_id,
                    fields={"error": str(exc), "error_type": exc.__class__.__name__},
                )
                self._write_sse(
                    "error",
                    {
                        "request_id": request_id,
                        "error": str(exc),
                        "error_type": exc.__class__.__name__,
                    },
                )
                return

            message = {
                "request_id": request_id,
                "response": result.response_text,
                "selected_peer_id": result.selected_peer_id,
                "fallback_used": result.fallback_used,
                "degraded_anonymity": result.degraded_anonymity,
                "streamed": streamed,
            }
            self._write_sse(
                "message",
                {
                    key: value
                    for key, value in message.items()
                    if key != "response" or not streamed
                },
            )
            self._write_sse("done", message)
            _emit_client_log(
                daemon.logging,
                "local_http_request_complete",
                node_id=daemon.node_id,
                request_id=request_id,
                fields={
                    "streamed": streamed,
                    "fallback_used": result.fallback_used,
                    "degraded_anonymity": result.degraded_anonymity,
                },
            )

        def log_message(self, _format: str, *_args) -> None:
            return

        def _start_sse(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

        def _write_sse(self, event: str, data: dict[str, object]) -> None:
            self.wfile.write(_sse_event(event, data))
            self.wfile.flush()

        def _send_bytes(self, data: bytes, *, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, data: dict[str, object]) -> None:
            self._send_bytes(
                (json.dumps(data, sort_keys=True) + "\n").encode("utf-8"),
                content_type="application/json; charset=utf-8",
            )

    return ClientHttpHandler


def _sse_event(event: str, data: dict[str, object]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, sort_keys=True)}\n\n".encode("utf-8")


def _health_payload(daemon: DaemonConfig, session: PersistentClientSession) -> dict[str, object]:
    stats = session.stats
    return {
        "ok": True,
        "node_id": daemon.node_id,
        "role": daemon.role,
        "session_id": stats.session_id,
        "active_requests": stats.active_requests,
        "failed_requests": stats.failed_requests,
    }


def _status_payload(daemon: DaemonConfig, session: PersistentClientSession) -> dict[str, object]:
    stats = session.stats
    return {
        "schema": "por.client_status.v1",
        "node_id": daemon.node_id,
        "role": daemon.role,
        "local_http": {
            "path": daemon.client.local_http.path,
            "status_path": daemon.client.local_http.status_path,
        },
        "limits": {
            "max_concurrent_requests": daemon.client.max_concurrent_requests,
            "timeout_seconds": daemon.client.timeout_seconds,
        },
        "session": {
            "session_id": stats.session_id,
            "started_at": stats.started_at,
            "request_count": stats.request_count,
            "active_requests": stats.active_requests,
            "completed_requests": stats.completed_requests,
            "failed_requests": stats.failed_requests,
            "last_duration_ms": stats.last_duration_ms,
            "last_error": stats.last_error,
        },
    }


def _sse_payload(data: dict[str, object]) -> bytes:
    return (
        "event: message\n"
        f"data: {json.dumps(data, sort_keys=True)}\n\n"
        "event: done\n"
        "data: {}\n\n"
    ).encode("utf-8")


def _emit_client_log(
    logging: LoggingConfig,
    event: str,
    *,
    node_id: str | None = None,
    peer_id: str | None = None,
    request_id: str | None = None,
    fields: dict[str, object] | None = None,
) -> None:
    emit_log_event(
        PorLogEvent(
            event=event,
            component="tenet-client",
            node_id=node_id,
            role="client",
            request_id=request_id,
            peer_id=peer_id,
            fields=fields or {},
        ),
        fmt=logging.fmt,
        redact_fields=frozenset(logging.redact_fields),
    )


def main(argv: Sequence[str] | None = None) -> int:
    from tenet.edges.cli.main import legacy_client_main

    return legacy_client_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
