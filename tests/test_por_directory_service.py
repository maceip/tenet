import json

import pytest

from por.config import PorConfig
from por.daemon.directory import make_directory_handler, run_directory_from_daemon
from tests.harness import mixnet_harness
from por.directory import (
    DIRECTORY_SNAPSHOT_VERSION,
    PUBLIC_SNAPSHOT_V1,
    DirectorySnapshot,
    DirectorySnapshotFetchError,
    DirectorySnapshotFormatError,
    DiscoveryRequest,
    PublicManifestDirectory,
    load_public_snapshot_directory,
    load_records_from_snapshot_file,
)
from por.expert_route import PeerObservation, RouteIntent, plan_expert_route
from por.memory_index import IndexConfig, build_memory_index
from por.peer_address import (
    PeerAddressRelay,
    UdpEndpoint,
    peer_address_record_from_dict,
    verify_record_signature,
)


def _manifest(tmp_path, peer_id, text):
    root = tmp_path / peer_id
    root.mkdir()
    (root / "notes.md").write_text(text, encoding="utf-8")
    return build_memory_index(IndexConfig(peer_id=peer_id, roots=(str(root),))).manifest


def test_directory_snapshot_file_round_trip_preserves_records(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    observation = PeerObservation(peer_id="peer-art", p50_latency_ms=80, price_units=2)
    directory = PublicManifestDirectory.from_manifests(
        [manifest],
        [observation],
        source="test-file-snapshot",
    )

    path = tmp_path / "directory-snapshot.json"
    directory.save_snapshot(path, generated_at="2026-05-30T00:00:00+00:00")

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["version"] == DIRECTORY_SNAPSHOT_VERSION
    assert raw["source"] == "test-file-snapshot"
    assert raw["records"][0]["manifest"]["peer_id"] == "peer-art"
    assert raw["records"][0]["observation"]["p50_latency_ms"] == 80

    loaded = load_public_snapshot_directory(path)
    result = loaded.discover(DiscoveryRequest(RouteIntent(prompt="Monet?")))

    assert result.snapshot_size == 1
    assert result.candidates[0].manifest.peer_id == "peer-art"
    assert result.candidates[0].observation == observation


def test_public_snapshot_discovery_does_not_send_exact_query_or_pretruncate(tmp_path):
    weak = _manifest(tmp_path, "peer-systems", "QUIC UDP transport packets.")
    strong = _manifest(
        tmp_path,
        "peer-art",
        "Monet Impressionism painting Paris color light.",
    )
    directory = PublicManifestDirectory.from_manifests([weak, strong])
    path = tmp_path / "directory-snapshot.json"
    DirectorySnapshot.from_directory(directory, generated_at="2026-05-30T00:00:00+00:00").save(path)

    loaded = load_public_snapshot_directory(path)
    intent = RouteIntent(
        prompt="What did Monet change?",
        requested_expertise="Impressionism",
        random_seed=0,
    )
    discovery = loaded.discover(
        DiscoveryRequest(intent, mode=PUBLIC_SNAPSHOT_V1, max_records=1)
    )
    plan = plan_expert_route(intent, discovery.candidates)

    assert discovery.snapshot_size == 2
    assert len(discovery.candidates) == 2
    assert discovery.exact_query_sent is False
    assert discovery.private_query_used is False
    assert "max_records ignored" in discovery.note
    assert plan.selected_peer_id == "peer-art"


def test_load_records_from_snapshot_file(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    path = tmp_path / "directory-snapshot.json"
    PublicManifestDirectory.from_manifests([manifest]).save_snapshot(path)

    records = load_records_from_snapshot_file(path)

    assert len(records) == 1
    assert records[0].peer_id == "peer-art"


def test_public_snapshot_directory_loads_from_http(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    path = tmp_path / "directory-snapshot.json"
    PublicManifestDirectory.from_manifests([manifest]).save_snapshot(path)
    with mixnet_harness() as net:
        server = net.serve_http(make_directory_handler(path))
        url = f"http://127.0.0.1:{server.server_address[1]}/snapshot"

        loaded = load_public_snapshot_directory(url)
        result = loaded.discover(DiscoveryRequest(RouteIntent(prompt="Monet?")))

        assert result.snapshot_size == 1
        assert result.candidates[0].manifest.peer_id == "peer-art"


def test_public_snapshot_directory_round_trips_peer_address_record_over_http(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    directory = PublicManifestDirectory.from_manifests([manifest])
    peer_record, secret = _peer_address_public_record("peer-art")
    path = tmp_path / "directory-snapshot.json"
    directory.snapshot(
        generated_at="2026-05-30T00:00:00+00:00",
    ).with_peer_address_records({"peer-art": peer_record}).save(path)
    with mixnet_harness() as net:
        server = net.serve_http(make_directory_handler(path))
        url = f"http://127.0.0.1:{server.server_address[1]}/snapshot"

        loaded = load_public_snapshot_directory(url)
        records = loaded.peer_address_records()

        assert records["peer-art"]["signature"] == peer_record["signature"]
        parsed = loaded.records[0].peer_address
        assert parsed is not None
        assert verify_record_signature(peer_address_record_from_dict(parsed), secret.hex())


def test_http_snapshot_loader_enforces_size_limit(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    path = tmp_path / "directory-snapshot.json"
    PublicManifestDirectory.from_manifests([manifest]).save_snapshot(path)
    with mixnet_harness() as net:
        server = net.serve_http(make_directory_handler(path))
        url = f"http://127.0.0.1:{server.server_address[1]}/snapshot"

        with pytest.raises(DirectorySnapshotFetchError, match="max_bytes"):
            load_public_snapshot_directory(url, max_bytes=10)


def test_directory_snapshot_rejects_unknown_version(tmp_path):
    path = tmp_path / "directory-snapshot.json"
    path.write_text(
        json.dumps(
            {
                "version": "por.directory_snapshot.v999",
                "generated_at": "2026-05-30T00:00:00+00:00",
                "records": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(DirectorySnapshotFormatError):
        load_public_snapshot_directory(path)


def test_directory_daemon_registers_configured_supernodes(monkeypatch):
    config = PorConfig.from_dict(
        {
            "version": "por.config.v1",
            "default_node_id": "directory-a",
            "daemons": {
                "directory-a": {
                    "role": "directory",
                    "transport": {"host": "127.0.0.1", "port": 0},
                },
                "relay-a": {
                    "role": "relay",
                    "transport": {"host": "127.0.0.1", "port": 7001},
                    "kem_pk": "01" * 32,
                    "kem_sk": "02" * 32,
                    "supernode": {
                        "enabled": True,
                        "public_ip": "203.0.113.10",
                        "advertise_relay": True,
                        "register_directory": True,
                    },
                },
            },
        }
    )
    seen = {}

    def fake_run_directory_server(**kwargs):
        seen.update(kwargs)
        return 0

    monkeypatch.setattr("por.daemon.directory.run_directory_server", fake_run_directory_server)

    assert run_directory_from_daemon(config.daemon("directory-a"), config) == 0

    snapshot = DirectorySnapshot.from_json(seen["snapshot_json"])
    assert snapshot.supernodes[0]["relay_handle"] == "relay-a@203.0.113.10:7001"
    assert seen["snapshot_path"] is None


def test_directory_daemon_serves_configured_peer_address_record(monkeypatch, tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    snapshot_path = tmp_path / "directory-snapshot.json"
    PublicManifestDirectory.from_manifests([manifest]).save_snapshot(snapshot_path)
    peer_record, secret = _peer_address_public_record("peer-art")
    config = PorConfig.from_dict(
        {
            "version": "por.config.v1",
            "default_node_id": "directory-a",
            "daemons": {
                "directory-a": {
                    "role": "directory",
                    "transport": {"host": "127.0.0.1", "port": 0},
                    "directory": {"snapshot_path": str(snapshot_path)},
                },
                "peer-art": {
                    "role": "expert",
                    "transport": {"host": "127.0.0.1", "port": 7003},
                    "peer_address": {
                        "enabled": True,
                        "records": {"peer-art": peer_record},
                    },
                },
            },
        }
    )
    seen = {}

    def fake_run_directory_server(**kwargs):
        seen.update(kwargs)
        return 0

    monkeypatch.setattr("por.daemon.directory.run_directory_server", fake_run_directory_server)

    assert run_directory_from_daemon(config.daemon("directory-a"), config) == 0

    snapshot = DirectorySnapshot.from_json(seen["snapshot_json"])
    assert snapshot.records[0].peer_address is not None
    assert snapshot.records[0].peer_address["signature"] == peer_record["signature"]
    assert verify_record_signature(
        peer_address_record_from_dict(snapshot.records[0].peer_address),
        secret.hex(),
    )
    assert seen["snapshot_path"] == str(snapshot_path)




def _peer_address_public_record(peer_id):
    secret = b"directory-peer-address-secret"
    relay = PeerAddressRelay(
        relay_id="bootstrap-1",
        relay_endpoint=UdpEndpoint("203.0.113.10", 4433),
        secret=secret,
    )
    challenge = relay.request_registration(
        peer_id=peer_id,
        observed_endpoint=UdpEndpoint("127.0.0.1", 7003),
        now=900.0,
    )
    record = relay.confirm_registration(challenge, now=901.0).to_public_dict()
    return record, secret
