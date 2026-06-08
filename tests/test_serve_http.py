from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from tenet.edges.cli.join_pack import JoinPack
from tenet.edges.cli.serve import _make_handler
from tenet.edges.cli.web_demo import offline_ask_summary


def _start_server(handler, port: int = 0) -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_serve_healthz_and_cors_preflight():
    pack = JoinPack.load("config/join-pack.json")
    stats = {
        "request_count": 0,
        "active_requests": 0,
        "completed_requests": 0,
        "failed_requests": 0,
        "last_error": None,
    }
    handler = _make_handler(
        pack=pack,
        offline=False,
        path="/v1/expert",
        status_path="/v1/status",
        run_ask=lambda prompt, expertise: {
            "ok": True,
            "response_text": f"echo:{prompt}",
            "selected_handle": "demo.expert~tenet",
        },
        stats=stats,
        lock=threading.Lock(),
    )
    server, port = _start_server(handler)
    try:
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(f"{base}/healthz") as resp:
            assert resp.status == 200
            assert resp.headers["Access-Control-Allow-Origin"] == "*"
            body = json.loads(resp.read().decode("utf-8"))
            assert body["ok"] is True
            assert body["mode"] == "tenet-serve-live"

        req = urllib.request.Request(f"{base}/v1/expert", method="OPTIONS")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 204
            assert resp.headers["Access-Control-Allow-Methods"] == "GET, POST, OPTIONS"
    finally:
        server.shutdown()
        server.server_close()


def test_serve_offline_healthz_has_no_network():
    stats = {
        "request_count": 0,
        "active_requests": 0,
        "completed_requests": 0,
        "failed_requests": 0,
        "last_error": None,
    }
    handler = _make_handler(
        pack=None,
        offline=True,
        path="/v1/expert",
        status_path="/v1/status",
        run_ask=lambda prompt, expertise: offline_ask_summary(prompt, expertise),
        stats=stats,
        lock=threading.Lock(),
    )
    server, port = _start_server(handler)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz") as resp:
            body = json.loads(resp.read().decode("utf-8"))
            assert body["mode"] == "tenet-serve-offline"
            assert body["network"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_serve_post_streams_done_event():
    pack = JoinPack.load("config/join-pack.json")
    stats = {
        "request_count": 0,
        "active_requests": 0,
        "completed_requests": 0,
        "failed_requests": 0,
        "last_error": None,
    }
    handler = _make_handler(
        pack=pack,
        offline=False,
        path="/v1/expert",
        status_path="/v1/status",
        run_ask=lambda prompt, expertise: {
            "ok": True,
            "response_text": "book listing B",
            "selected_handle": "berlin.expert~tenet",
        },
        stats=stats,
        lock=threading.Lock(),
    )
    server, port = _start_server(handler)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/expert",
            data=json.dumps({"prompt": "find me an airbnb in berlin"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            text = resp.read().decode("utf-8")
            assert "event: done" in text
            assert "book listing B" in text
    finally:
        server.shutdown()
        server.server_close()
