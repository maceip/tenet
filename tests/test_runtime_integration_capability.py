from __future__ import annotations

import json
import shutil
import socket
import threading
import time
from urllib.parse import urlparse

import pytest
from nacl.signing import SigningKey

from tenet.config import ClusterConfig, PeerAddressConfig, TrustedReachabilityRelayConfig
from tenet.enclave.attested_transport import EnclaveAttestationError
from tenet.edges.cli.supernode import SupernodeDaemon
from tenet.experts.client import run_client_once
from tenet.experts.directory import (
    DirectorySnapshot,
    DirectorySnapshotFormatError,
    DiscoveryRequest,
    PublicManifestDirectory,
    load_public_snapshot_directory,
)
from tenet.experts.expert_mode import ExpertModeConfig
from tenet.experts.expert_route import RouteIntent
from tenet.experts.enclave_plane_server import serve_enclave_plane
from tenet.experts.live_enclave import LiveEnclaveConfig, check_live_enclave
from tenet.experts.match_workload import MatchWorkloadClient
from tenet.experts.matcher import PLAIN_MATCHER_V1, PlainEnclavePlaneDiscoveryProvider, PlainMailbox, PlainMatcher
from tenet.handles import OpaqueHandleIssuer
from tenet.mixnet.control import (
    BOOTSTRAP_SCHEMA,
    ControlBootstrap,
    MixnetControlService,
    MixnodeDescriptor,
    PoolDescriptor,
    sync_control_from_cluster,
)
from tenet.mixnet.control.records import sign_control_record
from tenet.mixnet.control.wire import control_put, decode_control_message, encode_control_message
from tenet.mixnet.node_runtime import WireNodeRuntime
from tenet.mixnet.peer_address import PeerAddressRelay, UdpEndpoint
from tests.helpers import demo_directory, write_process_wire_cluster


def test_real_node_runtime_bootstraps_control_dht_and_carries_expert_packet_flow(monkeypatch, tmp_path):
    monkeypatch.setenv("POR_CLIENT_REQUEST_REPEATS", "1")
    monkeypatch.setenv("POR_STREAM_CHUNK_REPEATS", "1")
    monkeypatch.setenv("POR_STREAM_DONE_REPEATS", "1")
    config_path, _raw, _node_ids = write_process_wire_cluster(tmp_path, node_count=3)
    cluster = ClusterConfig.load(config_path)
    bootstrap, signing_key = _runtime_bootstrap(cluster)
    bootstrap_path = tmp_path / "control-bootstrap.json"
    bootstrap_path.write_text(json.dumps(bootstrap.to_dict()), encoding="utf-8")

    relay_sock = _bound_node_socket(cluster, "relay1")
    expert_sock = _bound_node_socket(cluster, "expert_art")
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.bind((cluster.client.host, cluster.client.port))
    client_sock.settimeout(0.5)
    stop = threading.Event()
    seen_prompts: list[str] = []

    def reply_handler(envelope, node_id):
        seen_prompts.append(envelope.prompt_text())
        return [f"{node_id} saw {envelope.intent_descriptor['requested_expertise']}"]

    relay = WireNodeRuntime(
        cluster,
        "relay1",
        control_bootstrap_path=str(bootstrap_path),
        control_store_path=str(tmp_path / "relay-control-store.json"),
        control_replication_factor=2,
    )
    expert = WireNodeRuntime(
        cluster,
        "expert_art",
        control_bootstrap_path=str(bootstrap_path),
        control_store_path=str(tmp_path / "expert-control-store.json"),
        control_replication_factor=2,
        reply_handler=reply_handler,
    )
    supernode = SupernodeDaemon(
        relay,
        relay_secret=b"runtime-integration-reach-secret",
        advertise_host=cluster.node("relay1").host,
    )
    supernode.attach_socket(relay_sock)
    relay_thread = threading.Thread(target=relay.serve_on_socket, args=(relay_sock,), kwargs={"stop": stop}, daemon=True)
    expert_thread = threading.Thread(target=expert.serve_on_socket, args=(expert_sock,), kwargs={"stop": stop}, daemon=True)
    threads = (relay_thread, expert_thread)
    for thread in threads:
        thread.start()

    try:
        pool = PoolDescriptor.from_name("monet.expert~tenet", topic_tags=("impressionism",), min_pool_size=1)
        signed_pool = sign_control_record(
            relay.control.make_unsigned_pool_descriptor(pool, seq=2),
            signing_key_hex=signing_key.encode().hex(),
            key_id="root",
        )
        client_sock.sendto(
            encode_control_message(control_put(signed_pool)),
            (cluster.node("relay1").host, cluster.node("relay1").port),
        )
        data, _addr = client_sock.recvfrom(65535)
        assert decode_control_message(data).kind == "have"
        _eventually(lambda: expert.control.get(pool.key) is not None)
        fresh = MixnetControlService(
            network_id="default",
            verify_keys={"root": signing_key.verify_key.encode().hex()},
        )
        assert sync_control_from_cluster(
            fresh,
            cluster,
            node_ids=("expert_art",),
            prefixes=("pool/",),
            timeout=1.0,
        ) >= 1
        assert fresh.pool_descriptor("monet.expert~tenet") == pool

        directory = _directory_round_trip(tmp_path, demo_directory(tmp_path))
        discovery_provider, handle = _plain_enclave_provider(tmp_path, cluster, directory)
        supernode.forwarder.register_peer(
            handle,
            (cluster.node("expert_art").host, cluster.node("expert_art").port),
        )
        result = run_client_once(
            cluster=cluster,
            discovery_provider=discovery_provider,
            prompt="What did Monet do with color and light?",
            requested_expertise="impressionism",
            timeout=2.0,
            random_seed=1,
            expert_mode_config=ExpertModeConfig(discovery_mode=PLAIN_MATCHER_V1, min_pool_size=1),
            peer_address_config=PeerAddressConfig(enabled=True),
            trusted_reachability_relays=(
                TrustedReachabilityRelayConfig(
                    relay_id="relay1",
                    host=cluster.node("relay1").host,
                    port=cluster.node("relay1").port,
                    verify_key=b"runtime-integration-reach-secret".hex(),
                ),
            ),
            client_sock=client_sock,
        )
    finally:
        stop.set()
        for sock in (relay_sock, expert_sock, client_sock):
            sock.close()
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=2.0)

    assert result.fallback_used is False
    assert result.selected_handle == handle
    assert result.response_text == "expert_art saw impressionism"
    assert f"selected={handle}" in result.client_logs
    assert "wire=binary" in result.client_logs
    assert seen_prompts == ["What did Monet do with color and light?"]
    assert (tmp_path / "relay-control-store.json").is_file()
    assert (tmp_path / "expert-control-store.json").is_file()


def test_live_nitro_attestation_uses_real_artifacts_or_fails_closed():
    config = LiveEnclaveConfig.load("config/live-enclave.json")
    dockerfile = _read("deploy/Dockerfile.matcher-real")
    entry = _read("deploy/entry-matcher.sh")
    pinned = _read("scripts/pinned-sha.sh")
    host = urlparse(config.url).hostname or ""

    assert host.startswith(config.approved_value_x[0][:12])
    assert len(config.approved_value_x[0]) == 96
    assert len(config.tls_spki_hash) == 64
    assert config.attested_workload_sha
    assert config.attested_workload_sha in pinned
    assert "FROM public.ecr.aws/amazonlinux/amazonlinux:2023" in dockerfile
    assert "COPY bountynet-bin /usr/local/bin/bountynet" in dockerfile
    assert "COPY entry-matcher.sh /entry-matcher.sh" in dockerfile
    assert "tenet.enclave_plane_server" in entry
    assert "entry-matcher-stub" not in entry

    if shutil.which(config.aw_bin):
        summary = check_live_enclave(config)
        assert summary["ok"] is True
        assert summary["value_x"] in config.approved_value_x
        assert str(summary["tls_spki_hash"]).lower() == config.tls_spki_hash
        assert summary["pinned"] is True
    else:
        with pytest.raises(EnclaveAttestationError, match="could not run"):
            check_live_enclave(config)


def test_plain_enclave_plane_workload_serves_real_matcher_and_mailbox_routes(tmp_path):
    config_path, _raw, _node_ids = write_process_wire_cluster(tmp_path, node_count=3)
    cluster = ClusterConfig.load(config_path)
    directory = demo_directory(tmp_path)
    provider, handle = _plain_enclave_provider(tmp_path, cluster, directory)
    server = serve_enclave_plane(provider, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    try:
        client = MatchWorkloadClient(f"http://{host}:{port}", timeout=2.0)
        result = client.discover(
            DiscoveryRequest(
                RouteIntent(
                    prompt="Monet brushwork and color",
                    requested_expertise="impressionism",
                ),
                mode=PLAIN_MATCHER_V1,
                max_records=2,
            )
        )
        assert result.mode == PLAIN_MATCHER_V1
        assert result.exact_query_sent is True
        assert handle in {candidate.manifest.peer_id for candidate in result.candidates}
        assert client.routing_kem_pk_hex(handle) == cluster.node("expert_art").kem_pk_hex
        assert client.relay_path_for_handle(handle) == ("relay1",)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _runtime_bootstrap(cluster: ClusterConfig) -> tuple[ControlBootstrap, SigningKey]:
    signing_key = SigningKey.generate()
    service = MixnetControlService(
        network_id="default",
        verify_keys={"root": signing_key.verify_key.encode().hex()},
    )
    records = []
    for seq, node_id in enumerate(("relay1", "expert_art"), start=1):
        descriptor = MixnodeDescriptor(
            node_id=node_id,
            node_key=cluster.node(node_id).kem_pk_hex,
            claim_refs=(f"claim/{node_id}/mixnet",),
        )
        records.append(
            sign_control_record(
                service.make_unsigned_mixnode_descriptor(descriptor, seq=seq),
                signing_key_hex=signing_key.encode().hex(),
                key_id="root",
            )
        )
    bootstrap = ControlBootstrap(
        network_id="default",
        update_roots={"root": signing_key.verify_key.encode().hex()},
        bootstrap_relays=("relay1",),
        records=tuple(records),
        schema=BOOTSTRAP_SCHEMA,
    )
    return bootstrap, signing_key


def _directory_round_trip(tmp_path, directory: PublicManifestDirectory) -> PublicManifestDirectory:
    snapshot_path = tmp_path / "directory-snapshot.json"
    snapshot = directory.snapshot().with_supernodes(
        [{"node_id": "relay1", "endpoint": {"host": "127.0.0.1", "port": 1}}]
    )
    snapshot.save(snapshot_path)
    loaded = load_public_snapshot_directory(snapshot_path)
    with pytest.raises(DirectorySnapshotFormatError):
        DirectorySnapshot.from_dict(
            {
                **snapshot.to_dict(),
                "records": [
                    {
                        **snapshot.to_dict()["records"][0],
                        "peer_address": {"host": "127.0.0.1", "port": 1},
                    }
                ],
            }
        )
    return loaded


def _plain_enclave_provider(
    tmp_path,
    cluster: ClusterConfig,
    directory: PublicManifestDirectory,
) -> tuple[PlainEnclavePlaneDiscoveryProvider, str]:
    record = next(item for item in directory.records if item.peer_id == "expert_art")
    handle_record = OpaqueHandleIssuer(b"runtime-integration-handle-secret").record(
        peer_id="expert_art",
        manifest_digest=record.manifest.index_digest,
        mailbox_id="mailbox-a",
        now=1000.0,
    )
    relay = PeerAddressRelay(
        relay_id="relay1",
        relay_endpoint=UdpEndpoint(
            cluster.node("relay1").host,
            cluster.node("relay1").port,
        ),
        secret=b"runtime-integration-reach-secret",
    )
    challenge = relay.request_registration(
        peer_id=handle_record.handle,
        observed_endpoint=UdpEndpoint(
            cluster.node("expert_art").host,
            cluster.node("expert_art").port,
        ),
        now=time.time(),
    )
    peer_address = relay.confirm_registration(challenge).to_public_dict()
    mailbox = PlainMailbox()
    mailbox.add(
        record=handle_record,
        routing_kem_pk_hex=cluster.node("expert_art").kem_pk_hex,
        peer_address=peer_address,
    )
    matcher = PlainMatcher.from_records(
        directory.records,
        {"expert_art": handle_record},
        top_k=2,
    )
    return PlainEnclavePlaneDiscoveryProvider(matcher, mailbox), handle_record.handle


def _bound_node_socket(cluster: ClusterConfig, node_id: str) -> socket.socket:
    node = cluster.node(node_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((node.host, node.port))
    return sock


def _eventually(predicate, *, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate()


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()
