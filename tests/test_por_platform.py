"""CLI, config dispatch, logging, and daemon entrypoint tests."""

from __future__ import annotations

import json
import socket
import threading
from io import StringIO
from urllib.request import Request, urlopen

import pytest

from tenet.experts.client import ClientRunResult
from tenet.edges.cli.cli_display import (
    AskDisplay,
    AskNetworkDisplay,
    DashboardDisplay,
    DashboardSnapshot,
    ExperimentalSceneRenderer,
    PayoutsDisplay,
    ServiceCard,
    should_show_interactive_display,
    terminal_rendering_options,
)
from tenet.config import ClusterConfig, DaemonConfig
from tenet.edges.cli.client import PersistentClientSession, make_client_http_handler
from tenet.edges.cli.expert import run_expert_cluster
from tenet.edges.cli.main import build_parser, dispatch, legacy_client_main, legacy_expert_main, legacy_relay_main
from tenet.edges.cli.relay import run_relay_cluster
from tenet.experts.directory import PublicManifestDirectory
from tenet.log_events import PorLogEvent, emit_log_event, format_log_event
from tenet.mixnet.node_runtime import WireNodeRuntime
from tests.harness import mixnet_harness


def test_cli_parser_and_legacy_entrypoints():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
    assert all(callable(fn) for fn in (legacy_relay_main, legacy_expert_main, legacy_client_main))
    args = parser.parse_args(["ask", "--prompt", "hello"])
    assert args.command == "ask"
    assert args.join_pack == "config/join-pack.json"
    plain_args = parser.parse_args(["ask", "--prompt", "hello", "--plain"])
    assert plain_args.plain is True
    status_args = parser.parse_args(["status", "--render-options"])
    assert status_args.command == "status"
    assert status_args.render_options is True


class _TtyStringIO(StringIO):
    def isatty(self):
        return True


def test_cli_display_respects_plain_and_no_color(monkeypatch):
    stream = _TtyStringIO()
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert should_show_interactive_display(stream) is True
    assert should_show_interactive_display(stream, plain=True) is False

    monkeypatch.setenv("NO_COLOR", "1")
    assert should_show_interactive_display(stream) is False


def test_ask_display_renders_status_map_without_protocol_state():
    stream = StringIO()
    display = AskDisplay(
        AskNetworkDisplay.from_join_pack(
            {
                "url": "https://5faf834eac20.aeon.site/",
                "approved_value_x": ["5faf834eac20adaf"],
            },
            {
                "relay_id": "reach-beta-1",
                "host": "3.121.69.82",
                "port": 4433,
            },
            relay_count=1,
            route_mode="reachability-relay",
        ),
        stream=stream,
        enabled=True,
    )

    rail = display.start()
    rail.stop()
    display.finish(
        {
            "ok": True,
            "selected_peer_id": "expert-art",
            "via_mailbox": False,
            "degraded_anonymity": False,
        }
    )

    rendered = stream.getvalue()
    assert "tenet live network" in rendered
    assert "you -> matcher -> reach-beta-1" in rendered
    assert "value_x=5faf834eac20..." in rendered
    assert "selected=expert-art" in rendered


def test_cli_display_punts_payments_but_renders_terminal_scene():
    with pytest.raises(NotImplementedError, match="CLI_UI_TODO"):
        PayoutsDisplay().render(())

    scene = ExperimentalSceneRenderer().render_network_scene(
        AskNetworkDisplay(
            matcher_host="matcher",
            value_x_prefix="abc123",
            relay_id="relay",
            relay_endpoint="127.0.0.1:4433",
            relay_count=1,
            route_mode="reachability-relay",
        )
    )
    assert "network map" in scene
    assert "matcher" in scene
    assert "relay" in scene


def test_dashboard_display_renders_broad_service_stack():
    network = AskNetworkDisplay(
        matcher_host="matcher.example",
        value_x_prefix="abc123",
        relay_id="reach-beta-1",
        relay_endpoint="203.0.113.10:4433",
        relay_count=1,
        route_mode="reachability-relay",
    )
    snapshot = DashboardSnapshot(
        "tenet service dashboard",
        network,
        (
            ServiceCard("attested matcher", "configured", "value_x=abc123", "TEE"),
            ServiceCard("reachability relay", "configured", "203.0.113.10:4433", "REACH"),
        ),
        ("payments/payouts omitted",),
    )
    rendered = DashboardDisplay(enabled=False).render(snapshot)
    assert "tenet service dashboard" in rendered
    assert "attested matcher: configured" in rendered
    assert "payments/payouts omitted" in rendered


def test_terminal_rendering_options_assess_3d_without_new_dependency():
    options = terminal_rendering_options()
    names = {option.name for option in options}
    assert "ANSI scene renderer" in names
    assert "Yoga flex layout" in names
    assert any(option.verdict == "ship" for option in options)
    assert any("not a terminal UI framework" in option.note for option in options)


@pytest.mark.parametrize(
    "argv,attr,expected_node",
    [
        (["run", "--config", "{config}", "--node-id", "relay1"], "tenet.edges.cli.relay.run_relay_cluster", "relay1"),
        (["run", "--config", "{config}"], "tenet.edges.cli.client.run_client_from_daemon", "client1"),
    ],
)
def test_por_run_dispatches_roles(monkeypatch, tmp_path, argv, attr, expected_node):
    path = tmp_path / "por.json"
    path.write_text(
        json.dumps(
            {
                "version": "por.config.v1",
                "default_node_id": "client1",
                "daemons": {
                    "client1": {
                        "role": "client",
                        "client": {"prompt": "hello", "directory_snapshot": "snapshot.json"},
                    },
                    "relay1": {
                        "role": "relay",
                        "transport": {"port": 7001},
                        "kem_pk": "01" * 32,
                        "kem_sk": "02" * 32,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    seen = {}

    def recording_runner(*args, **kwargs):
        if "run_relay_cluster" in attr:
            seen["node_id"] = args[0].node_id
            seen["cluster_nodes"] = tuple(args[1].to_cluster_config().nodes)
        else:
            seen["node_id"] = args[0].node_id
            seen["daemon_count"] = len(args[1].daemons)
        return 0

    monkeypatch.setattr(attr, recording_runner)
    parsed = [part.replace("{config}", str(path)) for part in argv]
    args = build_parser().parse_args(parsed)
    assert dispatch(args) == 0
    assert seen["node_id"] == expected_node


def test_structured_logging_redacts_sensitive_fields():
    line = format_log_event(
        PorLogEvent(
            event="expert_selected",
            component="tenet-client",
            node_id="client-a",
            fields={"prompt": "private text", "score": 0.91, "nested": {"token": "secret"}},
        )
    )
    data = json.loads(line)
    assert data["schema"] == "por.log.v1"
    assert data["fields"]["prompt"] == "[redacted]"
    assert data["fields"]["nested"]["token"] == "[redacted]"
    assert data["fields"]["score"] == 0.91

    stream = StringIO()
    emit_log_event(
        PorLogEvent(
            event="circuit_hop",
            component="tenet-relay",
            node_id="relay-a",
            role="relay",
            link_cid="abcd1234",
            fields={"next": "relay-b"},
        ),
        stream=stream,
        fmt="plain",
    )
    line = stream.getvalue()
    assert "event=circuit_hop" in line
    assert "link_cid=abcd1234" in line


def test_relay_and_expert_cluster_entrypoints_emit_start_log(monkeypatch, tmp_path):
    path = tmp_path / "por.json"
    path.write_text(
        json.dumps(
            {
                "version": "por.config.v1",
                "default_node_id": "relay1",
                "daemons": {
                    "relay1": {
                        "role": "relay",
                        "transport": {"port": 7001},
                        "kem_pk": "01" * 32,
                        "kem_sk": "02" * 32,
                    },
                    "expert_art": {
                        "role": "expert",
                        "transport": {"port": 7002},
                        "kem_pk": "03" * 32,
                        "kem_sk": "04" * 32,
                        "provider": {
                            "provider": "openai",
                            "model": "gpt-test",
                            "api_key_env": "OPENAI_API_KEY",
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    from tenet.config import load_config

    por_config = load_config(path)
    seen = []

    monkeypatch.setattr(
        WireNodeRuntime,
        "serve_forever",
        lambda self: seen.append((self.role, self._reply_handler is not None)) or 0,
    )
    assert run_relay_cluster(por_config.daemon("relay1"), por_config) == 0
    assert run_expert_cluster(por_config.daemon("expert_art"), por_config) == 0
    # A relay never answers (no reply handler); an expert is wired with one (Seam A).
    assert seen == [("relay", False), ("expert", True)]


def test_local_http_sse_on_client_process(tmp_path):
    daemon = DaemonConfig.from_dict(
        {
            "node_id": "client1",
            "role": "client",
            "client": {
                "local_http": {
                    "enabled": True,
                    "host": "127.0.0.1",
                    "port": 0,
                    "path": "/v1/expert",
                }
            },
        }
    )
    cluster = ClusterConfig.from_dict(
        {
            "params": {"payload_size": 2048, "routing_size": 96, "max_hops": 5},
            "client": {"host": "127.0.0.1", "port": 7000},
            "nodes": {
                "expert_art": {
                    "host": "127.0.0.1",
                    "port": 7001,
                    "kem_pk": "01" * 32,
                    "kem_sk": "02" * 32,
                    "role": "expert",
                }
            },
        }
    )

    def response_runner(**_kwargs):
        return ClientRunResult(
            selected_peer_id="expert_art",
            degraded_anonymity=False,
            fallback_used=False,
            response_text="hello from expert",
            client_logs="client event=test",
        )

    handler = make_client_http_handler(
        daemon=daemon,
        cluster=cluster,
        discovery_provider=PublicManifestDirectory(records=tuple()),
        runner=response_runner,
    )
    with mixnet_harness() as net:
        server = net.serve_http(handler)
        req = Request(
            f"http://127.0.0.1:{server.server_address[1]}/v1/expert",
            data=json.dumps({"prompt": "hi"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
            method="POST",
        )
        with urlopen(req, timeout=2.0) as response:
            body = response.read().decode("utf-8")
        assert response.headers["Content-Type"].startswith("text/event-stream")
        assert "event: message" in body
        assert "hello from expert" in body
        assert "event: done" in body


@pytest.mark.product
def test_local_http_status_reports_session_counters():
    daemon = DaemonConfig.from_dict(
        {
            "node_id": "client1",
            "role": "client",
            "client": {
                "local_http": {
                    "enabled": True,
                    "host": "127.0.0.1",
                    "port": 0,
                    "path": "/v1/expert",
                    "status_path": "/v1/status",
                }
            },
        }
    )
    cluster = ClusterConfig.from_dict(
        {
            "client": {"host": "127.0.0.1", "port": 7000},
            "nodes": {
                "expert_art": {
                    "host": "127.0.0.1",
                    "port": 7001,
                    "kem_pk": "01" * 32,
                    "kem_sk": "02" * 32,
                    "role": "expert",
                }
            },
        }
    )

    def response_runner(**_kwargs):
        return ClientRunResult(
            selected_peer_id="expert_art",
            degraded_anonymity=False,
            fallback_used=False,
            response_text="hello",
            client_logs="client event=test",
        )

    handler = make_client_http_handler(
        daemon=daemon,
        cluster=cluster,
        discovery_provider=PublicManifestDirectory(records=tuple()),
        runner=response_runner,
    )
    with mixnet_harness() as net:
        server = net.serve_http(handler)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urlopen(f"{base}/healthz", timeout=2.0) as response:
            health = json.loads(response.read().decode("utf-8"))
        assert health["ok"] is True
        assert health["node_id"] == "client1"
        assert health["active_requests"] == 0

        req = Request(
            f"{base}/v1/expert",
            data=json.dumps({"prompt": "hi"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
            method="POST",
        )
        with urlopen(req, timeout=2.0) as response:
            assert "event: done" in response.read().decode("utf-8")

        with urlopen(f"{base}/v1/status", timeout=2.0) as response:
            status = json.loads(response.read().decode("utf-8"))
        assert status["schema"] == "por.client_status.v1"
        assert status["session"]["request_count"] == 1
        assert status["session"]["completed_requests"] == 1
        assert status["session"]["active_requests"] == 0
        assert status["limits"]["max_concurrent_requests"] == 8
        assert status["local_http"]["path"] == "/v1/expert"


@pytest.mark.product
def test_persistent_client_session_reuses_loaded_state(capsys):
    daemon = DaemonConfig.from_dict(
        {
            "node_id": "client1",
            "role": "client",
            "client": {"max_concurrent_requests": 2},
        }
    )
    cluster = ClusterConfig.from_dict(
        {
            "client": {"host": "127.0.0.1", "port": 7000},
            "nodes": {
                "expert_art": {
                    "host": "127.0.0.1",
                    "port": 7001,
                    "kem_pk": "01" * 32,
                    "kem_sk": "02" * 32,
                    "role": "expert",
                }
            },
        }
    )
    discovery = PublicManifestDirectory(records=tuple())
    seen_discovery_ids = []

    def response_runner(**kwargs):
        seen_discovery_ids.append(id(kwargs["discovery_provider"]))
        return ClientRunResult(
            selected_peer_id=None,
            degraded_anonymity=False,
            fallback_used=True,
            response_text=f"response:{kwargs['prompt']}",
            client_logs="client event=test",
        )

    session = PersistentClientSession(
        daemon=daemon,
        cluster=cluster,
        discovery_provider=discovery,
        runner=response_runner,
    )

    assert session.request(prompt="first").response_text == "response:first"
    assert session.request(prompt="second").response_text == "response:second"

    assert session.stats.request_count == 2
    assert seen_discovery_ids == [id(discovery), id(discovery)]
    events = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("{")
    ]
    starts = [event for event in events if event["event"] == "session_request_start"]
    assert starts[0]["fields"]["warm_session"] is False
    assert starts[1]["fields"]["warm_session"] is True


@pytest.mark.product
def test_local_http_sse_flushes_chunk_before_request_finishes():
    daemon = DaemonConfig.from_dict(
        {
            "node_id": "client1",
            "role": "client",
            "client": {
                "local_http": {
                    "enabled": True,
                    "host": "127.0.0.1",
                    "port": 0,
                    "path": "/v1/expert",
                }
            },
        }
    )
    cluster = ClusterConfig.from_dict(
        {
            "client": {"host": "127.0.0.1", "port": 7000},
            "nodes": {
                "expert_art": {
                    "host": "127.0.0.1",
                    "port": 7001,
                    "kem_pk": "01" * 32,
                    "kem_sk": "02" * 32,
                    "role": "expert",
                }
            },
        }
    )
    release = threading.Event()

    def streaming_runner(**kwargs):
        kwargs["on_chunk"]({"seq": 0, "data": "first-token", "done": False})
        assert release.wait(timeout=2.0)
        kwargs["on_chunk"]({"seq": 1, "data": "second-token", "done": False})
        return ClientRunResult(
            selected_peer_id="expert_art",
            degraded_anonymity=False,
            fallback_used=False,
            response_text="first-tokensecond-token",
            client_logs="client event=test",
        )

    handler = make_client_http_handler(
        daemon=daemon,
        cluster=cluster,
        discovery_provider=PublicManifestDirectory(records=tuple()),
        runner=streaming_runner,
    )
    with mixnet_harness() as net:
        server = net.serve_http(handler)
        sock = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=2.0)
        sock.settimeout(2.0)
        try:
            body = json.dumps({"prompt": "hi"}).encode("utf-8")
            request = (
                "POST /v1/expert HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{server.server_address[1]}\r\n"
                "Content-Type: application/json\r\n"
                "Accept: text/event-stream\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii") + body
            sock.sendall(request)

            first = _recv_until(sock, b"first-token")
            assert b"event: chunk" in first
            assert b"event: done" not in first

            release.set()
            rest = _recv_until(sock, b"event: done")
            assert b"second-token" in rest
        finally:
            release.set()
            sock.close()


def _recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data
