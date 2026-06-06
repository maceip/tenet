"""Public P-OR directory snapshot server."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Sequence

from por.config import LoggingConfig
from por.directory import DirectorySnapshot
from por.log_events import PorLogEvent, emit_log_event


def make_directory_handler(
    snapshot_path: str | Path | None,
    *,
    route: str = "/snapshot",
    snapshot_json: str | None = None,
):
    """Build a request handler that serves one public directory snapshot file."""

    path = Path(snapshot_path) if snapshot_path is not None else None
    if not route.startswith("/"):
        raise ValueError("route must start with /")

    class DirectorySnapshotHandler(BaseHTTPRequestHandler):
        server_version = "por-directory/0.1"

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send_bytes(b"ok\n", content_type="text/plain; charset=utf-8")
                return
            if self.path != route:
                self.send_error(404, "not found")
                return
            try:
                data = (
                    snapshot_json.encode("utf-8")
                    if snapshot_json is not None
                    else path.read_bytes()
                )
            except OSError as exc:
                self.send_error(503, f"snapshot unavailable: {exc}")
                return
            self._send_bytes(data, content_type="application/json")

        def log_message(self, _format: str, *_args) -> None:
            return

        def _send_bytes(self, data: bytes, *, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return DirectorySnapshotHandler


def run_directory_server(
    *,
    snapshot_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8088,
    route: str = "/snapshot",
    logging: LoggingConfig | None = None,
    node_id: str | None = None,
    snapshot_json: str | None = None,
) -> int:
    logging = logging or LoggingConfig()
    handler = make_directory_handler(snapshot_path, route=route, snapshot_json=snapshot_json)
    server = ThreadingHTTPServer((host, port), handler)
    bound_host, bound_port = server.server_address
    _emit_directory_log(
        logging,
        "directory_started",
        node_id=node_id,
        fields={"addr": f"{bound_host}:{bound_port}", "path": route},
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    _emit_directory_log(logging, "directory_stopped", node_id=node_id)
    return 0


def run_directory_from_daemon(daemon, por_config=None) -> int:
    snapshot_json = None
    if por_config is not None:
        supernodes = por_config.supernode_directory_records()
        peer_address_records = por_config.peer_address_directory_records()
        if supernodes or peer_address_records:
            if daemon.directory.snapshot_path is None:
                snapshot = DirectorySnapshot(
                    records=(),
                    generated_at=datetime.now(timezone.utc).isoformat(),
                    source="por.config.v1",
                )
            else:
                snapshot = DirectorySnapshot.load(daemon.directory.snapshot_path)
            if supernodes:
                snapshot = snapshot.with_supernodes(supernodes)
            if peer_address_records:
                snapshot = snapshot.with_peer_address_records(peer_address_records)
            snapshot_json = snapshot.to_json() + "\n"
    if daemon.directory.snapshot_path is None and snapshot_json is None:
        raise SystemExit("por run: directory role requires directory.snapshot_path in config")
    bind = daemon.transport.bind
    return run_directory_server(
        snapshot_path=daemon.directory.snapshot_path,
        host=bind.host,
        port=bind.port,
        route="/snapshot",
        logging=daemon.logging,
        node_id=daemon.node_id,
        snapshot_json=snapshot_json,
    )


def _emit_directory_log(
    logging: LoggingConfig,
    event: str,
    *,
    node_id: str | None = None,
    fields: dict[str, object] | None = None,
) -> None:
    emit_log_event(
        PorLogEvent(
            event=event,
            component="por-directory",
            node_id=node_id,
            role="directory",
            fields=fields or {},
        ),
        fmt=logging.fmt,
        redact_fields=frozenset(logging.redact_fields),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve a public P-OR directory snapshot.")
    parser.add_argument("--snapshot", required=True, help="Directory snapshot JSON file")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--path", default="/snapshot")
    args = parser.parse_args(argv)

    return run_directory_server(
        snapshot_path=args.snapshot,
        host=args.host,
        port=args.port,
        route=args.path,
    )


if __name__ == "__main__":
    raise SystemExit(main())
