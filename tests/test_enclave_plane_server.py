"""The enclave-plane server entry point actually binds and serves over HTTP."""

import json
import threading
from urllib.request import urlopen

from tenet.experts.directory import DiscoveryRequest
from tenet.experts.match_workload import PlainEnclavePlaneHttpClient
from tenet.experts.enclave_plane_server import build_provider_from_files, serve_enclave_plane
from tenet.experts.expert_route import RouteIntent
from tenet.experts.matcher import (
    PLAIN_MATCHER_V1,
    PlainEnclavePlaneDiscoveryProvider,
    PlainMailbox,
    PlainMatcher,
)


def _serve(provider):
    server = serve_enclave_plane(provider, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_build_provider_from_files_enables_mailbox_delivery(tmp_path):
    mailbox_path = tmp_path / "mailbox.json"
    mailbox_path.write_text(
        json.dumps(
            {
                "version": "por.enclave_mailbox_file.v1",
                "trusted_reachability_relays": [
                    {
                        "relay_id": "relay-1",
                        "host": "203.0.113.1",
                        "port": 4433,
                        "verify_key": "ab" * 32,
                    }
                ],
                "entries": [],
            }
        ),
        encoding="utf-8",
    )
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "version": "por.directory_snapshot.v1",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "records": [],
            }
        ),
        encoding="utf-8",
    )
    provider = build_provider_from_files(snapshot=snapshot_path, mailbox=mailbox_path)
    assert provider.mailbox_delivery_enabled is True


def test_server_serves_healthz_and_empty_match():
    provider = PlainEnclavePlaneDiscoveryProvider(
        PlainMatcher([], top_k=3), PlainMailbox()
    )
    server = _serve(provider)
    try:
        port = server.server_address[1]
        with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as response:
            health = json.loads(response.read())
        assert health["ok"] is True

        client = PlainEnclavePlaneHttpClient(f"http://127.0.0.1:{port}")
        result = client.discover(
            DiscoveryRequest(
                RouteIntent(prompt="hello", requested_expertise="anything"),
                mode=PLAIN_MATCHER_V1,
            )
        )
        assert result.mode == PLAIN_MATCHER_V1
        assert result.candidates == ()
        assert result.private_query_used is False
    finally:
        server.shutdown()
