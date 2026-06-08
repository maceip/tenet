"""Local HTTP/SSE bridge for the website xterm demo (``tenet serve``)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from uuid import uuid4

from tenet.edges.cli.http_cors import handle_cors_preflight, send_cors_headers


def run_serve(
    *,
    join_pack_path: str | None = "config/join-pack.json",
    host: str = "127.0.0.1",
    port: int = 8766,
    path: str = "/v1/expert",
    status_path: str = "/v1/status",
    timeout: float = 120.0,
    offline: bool = False,
) -> int:
    pack = None
    if not offline:
        from tenet.edges.cli.join_pack import JoinPack

        pack = JoinPack.load(join_pack_path)
    lock = threading.Lock()
    stats = {
        "request_count": 0,
        "active_requests": 0,
        "completed_requests": 0,
        "failed_requests": 0,
        "last_error": None,
    }

    if offline:
        def run_ask(prompt: str, expertise: str | None) -> dict[str, object]:
            from tenet.edges.cli.web_demo import offline_ask_summary

            return offline_ask_summary(prompt, expertise)
    else:
        def run_ask(prompt: str, expertise: str | None) -> dict[str, object]:
            from tenet.experts.live_client import LiveMailboxClientConfig, send_live_enclave_summary
            from tenet.experts.live_enclave import LiveEnclaveConfig

            enclave = LiveEnclaveConfig.from_dict(pack.matcher)
            mailbox = LiveMailboxClientConfig.load(pack.asker_mailbox_config)
            return send_live_enclave_summary(
                enclave,
                mailbox,
                prompt=prompt,
                requested_expertise=expertise,
                timeout=timeout,
                control_service=pack.to_control_service(),
                match_gossip_salt=pack.query_epoch_salt,
                default_pool=pack.default_pool,
                dataset_commitment=pack.dataset_commitment,
            )

    handler = _make_handler(
        pack=pack,
        offline=offline,
        path=path,
        status_path=status_path,
        run_ask=run_ask,
        stats=stats,
        lock=lock,
    )
    server = ThreadingHTTPServer((host, port), handler)
    bound_host, bound_port = server.server_address
    mode = "tenet-serve-offline" if offline else "tenet-serve-live"
    print(
        f"tenet serve: http://{bound_host}:{bound_port}{path} "
        f"({mode}, healthz /healthz, CORS enabled)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("", flush=True)
    finally:
        server.server_close()
    return 0


def _make_handler(
    *,
    pack,
    offline: bool,
    path: str,
    status_path: str,
    run_ask: Callable[[str, str | None], dict[str, object]],
    stats: dict[str, object],
    lock: threading.Lock,
):
    class ServeHandler(BaseHTTPRequestHandler):
        server_version = "tenet-serve/0.2"

        def do_OPTIONS(self) -> None:
            handle_cors_preflight(self)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                with lock:
                    active = stats["active_requests"]
                    failed = stats["failed_requests"]
                payload = {
                    "ok": True,
                    "mode": "tenet-serve-offline" if offline else "tenet-serve-live",
                    "network": not offline,
                    "active_requests": active,
                    "failed_requests": failed,
                }
                if pack is not None:
                    payload["join_pack"] = str(pack.pack_path)
                    payload["matcher"] = pack.matcher.get("url")
                self._send_json(payload)
                return
            if self.path == status_path:
                with lock:
                    payload = {
                        "schema": "tenet.serve_status.2026-06",
                        "path": path,
                        "status_path": status_path,
                        "offline": offline,
                        "stats": dict(stats),
                    }
                if pack is not None:
                    payload["matcher"] = pack.matcher.get("url")
                self._send_json(payload)
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
                if expertise is not None:
                    expertise = str(expertise)
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                self.send_error(400, f"bad request: {exc}")
                return

            request_id = uuid4().hex
            with lock:
                stats["request_count"] = int(stats["request_count"]) + 1
                stats["active_requests"] = int(stats["active_requests"]) + 1

            self._start_sse()
            if offline:
                from tenet.edges.cli.web_demo import stream_offline_ask

                try:
                    stream_offline_ask(
                        prompt,
                        expertise=expertise,
                        write=lambda event, data: self._write_sse(
                            event, {**data, "request_id": data.get("request_id", request_id)}
                        ),
                    )
                except Exception as exc:  # pragma: no cover
                    with lock:
                        stats["active_requests"] = int(stats["active_requests"]) - 1
                        stats["failed_requests"] = int(stats["failed_requests"]) + 1
                        stats["last_error"] = str(exc)
                    self._write_sse(
                        "error",
                        {
                            "request_id": request_id,
                            "error": str(exc),
                            "error_type": exc.__class__.__name__,
                        },
                    )
                    return
                with lock:
                    stats["active_requests"] = int(stats["active_requests"]) - 1
                    stats["completed_requests"] = int(stats["completed_requests"]) + 1
                    stats["last_error"] = None
                return

            self._write_sse("status", {"request_id": request_id, "text": "matching experts…"})
            try:
                result = run_ask(prompt, expertise)
            except Exception as exc:  # pragma: no cover - network path
                with lock:
                    stats["active_requests"] = int(stats["active_requests"]) - 1
                    stats["failed_requests"] = int(stats["failed_requests"]) + 1
                    stats["last_error"] = str(exc)
                self._write_sse(
                    "error",
                    {
                        "request_id": request_id,
                        "error": str(exc),
                        "error_type": exc.__class__.__name__,
                    },
                )
                return

            with lock:
                stats["active_requests"] = int(stats["active_requests"]) - 1
                stats["completed_requests"] = int(stats["completed_requests"]) + 1
                stats["last_error"] = None if result.get("ok") else str(result.get("error") or "ask failed")

            response_text = str(result.get("response_text") or "")
            if response_text:
                self._write_sse(
                    "chunk",
                    {"request_id": request_id, "seq": 1, "data": response_text},
                )
            self._write_sse(
                "done",
                {
                    "request_id": request_id,
                    "ok": bool(result.get("ok")),
                    "response": response_text,
                    "selected_handle": result.get("selected_handle"),
                    "fallback_used": result.get("fallback_used"),
                    "degraded_anonymity": result.get("degraded_anonymity"),
                    "offline": False,
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
            send_cors_headers(self)
            self.end_headers()

        def _write_sse(self, event: str, data: dict[str, object]) -> None:
            payload = f"event: {event}\ndata: {json.dumps(data, sort_keys=True)}\n\n"
            self.wfile.write(payload.encode("utf-8"))
            self.wfile.flush()

        def _send_json(self, data: dict[str, object]) -> None:
            body = (json.dumps(data, sort_keys=True) + "\n").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            send_cors_headers(self)
            self.end_headers()
            self.wfile.write(body)

    return ServeHandler
