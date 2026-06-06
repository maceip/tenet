"""Product gate for home-client expert routing.

The "download client, run at home" path: a client with no static expert host
reaches a NAT'd expert purely through a directory-published, signed
PeerAddressRecord pointing at a trusted reachability relay (the supernode). The
relay is a real mix hop that resolves the expert's NAT address from its REACH
forward table — the client never learns the expert's home address.

Socket and thread lifecycle is owned by ``tests.harness`` (bind-once, hold-open,
joined threads) so this gate is deterministic under full-suite load.
"""

from __future__ import annotations

import json
import socket
import time

import pytest
from sphinxmix.OutfoxParams import OutfoxParams

from por.client import run_client_once
from por.config import ClusterConfig, PorConfig
from por.daemon.directory import make_directory_handler
from por.daemon.supernode import SupernodeDaemon
from por.directory import DirectorySnapshot, PeerRecord, PublicManifestDirectory, load_public_snapshot_directory
from por.reach_wire import REACH_CHALLENGE, decode_reach_datagram
from por.memory_index import IndexConfig, build_memory_index
from por.node_runtime import WireNodeRuntime
from por.reach_wire import encode_confirm, encode_register
from tests.harness import mixnet_harness


@pytest.mark.product
def test_home_client_completes_with_directory_trusted_relay_and_no_static_expert_host(tmp_path):
    params = OutfoxParams(payload_size=2048, routing_size=16, max_hops=5)
    relay_pk, relay_sk = params.kem.keygen()
    expert_pk, expert_sk = params.kem.keygen()
    record_secret = b"home-client-peer-address-secret"
    packet = {"payload_size": 2048, "routing_size": 16, "max_hops": 5}

    with mixnet_harness() as net:
        # Bind once, hold open: ports are never released before the runtime owns
        # them, so no recycled-port datagram races across the suite.
        relay_sock = net.reserve()
        expert_sock = net.reserve()
        client_sock = net.reserve()
        relay_addr = relay_sock.getsockname()
        expert_addr = expert_sock.getsockname()
        client_addr = client_sock.getsockname()
        expert_sock.settimeout(0.2)

        root = tmp_path / "peer-art"
        root.mkdir()
        (root / "notes.md").write_text(
            "Monet Impressionism color light painting.",
            encoding="utf-8",
        )
        manifest = build_memory_index(
            IndexConfig(peer_id="peer-art", roots=(str(root),))
        ).manifest

        cluster_dict = {
            "params": packet,
            "client": {"host": client_addr[0], "port": client_addr[1]},
            "nodes": {
                "bootstrap-1": {
                    "host": relay_addr[0],
                    "port": relay_addr[1],
                    "kem_pk": relay_pk.hex(),
                    "kem_sk": relay_sk.hex(),
                    "role": "relay",
                },
            },
        }
        cluster_path = tmp_path / "cluster.json"
        cluster_path.write_text(json.dumps(cluster_dict), encoding="utf-8")
        cluster = ClusterConfig.load(str(cluster_path))

        relay_runtime = WireNodeRuntime(cluster, "bootstrap-1", role="relay")
        relay_daemon = SupernodeDaemon(
            relay_runtime,
            relay_secret=record_secret,
            advertise_host=relay_addr[0],
        )
        relay_daemon.attach_socket(relay_sock)

        expert_cluster_dict = {
            **cluster_dict,
            "nodes": {
                **cluster_dict["nodes"],
                "peer-art": {
                    "host": expert_addr[0],
                    "port": expert_addr[1],
                    "kem_pk": expert_pk.hex(),
                    "kem_sk": expert_sk.hex(),
                    "role": "expert",
                },
            },
        }
        expert_cluster_path = tmp_path / "expert-cluster.json"
        expert_cluster_path.write_text(json.dumps(expert_cluster_dict), encoding="utf-8")
        expert_cluster = ClusterConfig.load(str(expert_cluster_path))
        expert_runtime = WireNodeRuntime(expert_cluster, "peer-art", role="expert")

        # Relay serves first so it can answer the expert's REACH registration.
        net.serve(relay_runtime, relay_sock)
        _register_expert_via_reach(expert_sock, relay_addr, relay_daemon)
        # Registration done synchronously on expert_sock; now hand it to the
        # serve thread for the request/return path.
        net.serve(expert_runtime, expert_sock)

        peer_address = relay_daemon.relay.address_record("peer-art")
        assert peer_address is not None

        snapshot_path = tmp_path / "directory-snapshot.json"
        PublicManifestDirectory.from_manifests(
            [manifest],
            observations=(),
        ).snapshot(generated_at="2026-05-30T00:00:00+00:00").with_peer_address_records(
            {"peer-art": peer_address.to_public_dict()}
        ).save(snapshot_path)

        snapshot = DirectorySnapshot.load(snapshot_path)
        records = list(snapshot.records)
        records[0] = PeerRecord(
            manifest=records[0].manifest,
            observation=records[0].observation,
            descriptor={"kem_pk": expert_pk.hex()},
            peer_address=records[0].peer_address,
        )
        snapshot = snapshot.__class__(
            records=tuple(records),
            generated_at=snapshot.generated_at,
            supernodes=snapshot.supernodes,
            source=snapshot.source,
        )
        snapshot.save(snapshot_path)

        server = net.serve_http(make_directory_handler(snapshot_path))
        directory_url = f"http://127.0.0.1:{server.server_address[1]}/snapshot"
        config = PorConfig.from_dict(
            {
                "version": "por.config.v1",
                "default_node_id": "client-home",
                "daemons": {
                    "client-home": {
                        "role": "client",
                        "transport": {"host": client_addr[0], "port": client_addr[1]},
                        "packet": packet,
                        "client": {
                            "directory_snapshot": directory_url,
                            "trusted_reachability_relays": [
                                {
                                    "relay_id": "bootstrap-1",
                                    "host": relay_addr[0],
                                    "port": relay_addr[1],
                                    "verify_key": record_secret.hex(),
                                }
                            ],
                        },
                        "peer_address": {"enabled": True},
                    },
                    "bootstrap-1": {
                        "role": "relay",
                        "transport": {"host": relay_addr[0], "port": relay_addr[1]},
                        "packet": packet,
                        "kem_pk": relay_pk.hex(),
                        "kem_sk": relay_sk.hex(),
                    },
                },
            }
        )

        assert "peer-art" not in config.to_cluster_config().nodes
        result = run_client_once(
            cluster=config.to_cluster_config(client_node_id="client-home"),
            discovery_provider=load_public_snapshot_directory(directory_url),
            prompt="What did Monet change?",
            requested_expertise="Impressionist art history",
            peer_address_config=config.daemon("client-home").peer_address,
            trusted_reachability_relays=(
                config.daemon("client-home").client.trusted_reachability_relays
            ),
            random_seed=0,
            timeout=5.0,
            client_sock=client_sock,
        )

        assert result.fallback_used is False
        assert result.selected_peer_id == "peer-art"
        assert "event=dial_target" in result.client_logs
        assert "event=send_prepared_envelope" in result.client_logs
        assert relay_addr[0] in result.client_logs
        assert "frontier_fallback" not in result.response_text
        assert result.response_text


def _register_expert_via_reach(
    expert_sock: socket.socket,
    relay_addr: tuple[str, int],
    relay_daemon: SupernodeDaemon,
) -> None:
    expert_sock.sendto(encode_register("peer-art"), relay_addr)
    deadline = time.time() + 2.0
    cookie = None
    while time.time() < deadline:
        try:
            data, _addr = expert_sock.recvfrom(65535)
        except socket.timeout:
            continue
        if data[:1] != REACH_CHALLENGE:
            continue
        action = decode_reach_datagram(data)
        cookie = action.cookie
        break
    assert cookie is not None
    expert_sock.sendto(encode_confirm("peer-art", cookie), relay_addr)
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if relay_daemon.forwarder.lookup_peer_addr("peer-art") is not None:
            return
        time.sleep(0.01)
    raise AssertionError("expert never registered with supernode")
