import json
from pathlib import Path

import pytest

from tenet.config import (
    CONFIG_VERSION,
    ROLE_CLIENT,
    ROLE_EXPERT,
    ROLE_RELAY,
    TRANSPORT_QUIC_H3,
    DaemonConfig,
    EndpointConfig,
    ClusterConfig,
    PorConfig,
    TransportConfig,
    TrustedReachabilityRelayConfig,
    load_config,
)
from tenet.experts.directory import DirectorySnapshot
from tenet.experts.expert_mode import ExpertModeConfig


def test_single_daemon_config_loads_with_secure_transport_default(tmp_path):
    path = tmp_path / "client.json"
    path.write_text(
        json.dumps(
            {
                "node_id": "client-a",
                "role": ROLE_CLIENT,
                "transport": {"kind": TRANSPORT_QUIC_H3, "host": "127.0.0.1", "port": 4443},
            }
        ),
        encoding="utf-8",
    )

    config = load_config(path)
    daemon = config.daemon()

    assert daemon.node_id == "client-a"
    assert daemon.transport.verify_tls is True
    assert daemon.transport.bind == EndpointConfig("127.0.0.1", 4443)


def test_multi_daemon_config_round_trips_and_exports_expert_mode_config():
    config = PorConfig.from_dict(
        {
            "version": CONFIG_VERSION,
            "default_node_id": "relay-a",
            "daemons": {
                "relay-a": {
                    "role": ROLE_RELAY,
                    "transport": {"port": 5001},
                    "peers": {"expert-a": {"host": "127.0.0.1", "port": 5002}},
                },
                "expert-a": {
                    "role": ROLE_EXPERT,
                    "transport": {"port": 5002},
                    "provider": {"provider": "anthropic", "model": "claude", "api_key_env": "ANTHROPIC_API_KEY"},
                    "expert_routing": {"min_pool_size": 5, "fallback_provider": "frontier"},
                },
            },
        }
    )

    relay = config.daemon()
    expert = config.daemon("expert-a")

    assert relay.peers["expert-a"].endpoint.port == 5002
    assert expert.provider is not None
    assert expert.provider.resolve_api_key({"ANTHROPIC_API_KEY": "secret"}) == "secret"
    assert ExpertModeConfig.from_routing(expert.expert_routing).min_pool_size == 5
    assert config.to_dict()["daemons"]["expert-a"]["role"] == ROLE_EXPERT


def test_por_config_builds_cluster_view_from_one_file():
    config = PorConfig.from_dict(
        {
            "version": CONFIG_VERSION,
            "default_node_id": "client-a",
            "daemons": {
                "client-a": {
                    "role": ROLE_CLIENT,
                    "transport": {"host": "127.0.0.1", "port": 7000},
                },
                "relay-a": {
                    "role": ROLE_RELAY,
                    "transport": {"host": "127.0.0.1", "port": 7001},
                    "kem_pk": "01" * 32,
                    "kem_sk": "02" * 32,
                },
                "expert-a": {
                    "role": ROLE_EXPERT,
                    "transport": {"host": "127.0.0.1", "port": 7002},
                    "kem_pk": "03" * 32,
                    "kem_sk": "04" * 32,
                },
            },
        }
    )

    cluster = config.to_cluster_config()

    assert cluster.client.port == 7000
    assert cluster.node("relay-a").role == ROLE_RELAY
    assert cluster.node("expert-a").kem_pk_hex == "03" * 32


def test_cluster_view_requires_kem_identity_for_relay_expert():
    config = PorConfig.from_dict(
        {
            "daemons": {
                "client-a": {"role": ROLE_CLIENT},
                "relay-a": {"role": ROLE_RELAY},
            }
        }
    )

    with pytest.raises(ValueError, match="kem_pk_hex"):
        config.to_cluster_config()


def test_supernode_promotion_requires_explicit_enabled_and_public_ip():
    with pytest.raises(ValueError, match="enabled"):
        PorConfig.from_dict(
            {
                "node_id": "relay-a",
                "role": ROLE_RELAY,
                "supernode": {"advertise_relay": True},
            }
        )

    with pytest.raises(ValueError, match="public_ip"):
        PorConfig.from_dict(
            {
                "node_id": "relay-a",
                "role": ROLE_RELAY,
                "supernode": {"enabled": True, "advertise_relay": True},
            }
        )

    config = PorConfig.from_dict(
        {
            "node_id": "relay-a",
            "role": ROLE_RELAY,
            "kem_pk": "01" * 32,
            "kem_sk": "02" * 32,
            "supernode": {
                "enabled": True,
                "public_ip": "203.0.113.10",
                "advertise_relay": True,
                "register_directory": True,
            },
        }
    )

    assert config.daemon().supernode.enabled is True
    assert config.daemon().supernode.public_ip == "203.0.113.10"


def test_supernode_promotion_is_observable_in_directory_snapshot():
    config = PorConfig.from_dict(
        {
            "version": CONFIG_VERSION,
            "daemons": {
                "relay-a": {
                    "role": ROLE_RELAY,
                    "transport": {"host": "127.0.0.1", "port": 7001},
                    "kem_pk": "01" * 32,
                    "kem_sk": "02" * 32,
                    "supernode": {
                        "enabled": True,
                        "public_ip": "203.0.113.10",
                        "advertise_relay": True,
                        "register_directory": True,
                        "accept_inbound_mix": True,
                    },
                }
            },
        }
    )

    records = config.supernode_directory_records()
    snapshot = DirectorySnapshot(
        records=(),
        generated_at="2026-05-30T00:00:00+00:00",
    ).with_supernodes(records)
    raw = snapshot.to_dict()

    assert raw["supernodes"][0]["node_id"] == "relay-a"
    assert raw["supernodes"][0]["relay_handle"] == "relay-a@203.0.113.10:7001"
    assert raw["supernodes"][0]["accept_inbound_mix"] is True
    loaded = DirectorySnapshot.from_dict(raw)
    assert loaded.supernodes[0]["endpoint"]["host"] == "203.0.113.10"


def test_example_home_client_supernode_config_parses():
    path = Path(__file__).resolve().parents[1] / "examples" / "home-client-supernode.config.json"

    config = load_config(path)
    client = config.daemon("client-home")
    supernode = config.daemon("bootstrap-1")

    assert client.client.trusted_reachability_relays[0].relay_id == "bootstrap-1"
    assert client.client.trusted_reachability_relays[0].host == "203.0.113.10"
    assert client.client.trusted_reachability_relays[0].port == 4433
    assert client.peer_address.enabled is True
    assert supernode.role == ROLE_RELAY
    assert supernode.transport.bind.host == "0.0.0.0"
    assert supernode.transport.bind.port == 4433
    assert supernode.supernode.enabled is True
    assert supernode.supernode.register_directory is True


def test_client_config_concurrency_limit_is_validated():
    with pytest.raises(ValueError, match="max_concurrent_requests"):
        DaemonConfig.from_dict(
            {
                "node_id": "client-a",
                "role": ROLE_CLIENT,
                "client": {"max_concurrent_requests": 0},
            }
        )


def test_local_http_status_path_is_validated():
    with pytest.raises(ValueError, match="status_path"):
        DaemonConfig.from_dict(
            {
                "node_id": "client-a",
                "role": ROLE_CLIENT,
                "client": {
                    "local_http": {
                        "path": "/v1/expert",
                        "status_path": "status",
                    }
                },
            }
        )

    with pytest.raises(ValueError, match="differ"):
        DaemonConfig.from_dict(
            {
                "node_id": "client-a",
                "role": ROLE_CLIENT,
                "client": {
                    "local_http": {
                        "path": "/v1/expert",
                        "status_path": "/v1/expert",
                    }
                },
            }
        )


def test_client_trusted_reachability_relays_parse_and_validate():
    config = DaemonConfig.from_dict(
        {
            "node_id": "client-a",
            "role": ROLE_CLIENT,
            "client": {
                "trusted_reachability_relays": [
                    {
                        "relay_id": "bootstrap-1",
                        "host": "203.0.113.10",
                        "port": 4433,
                        "verify_key": "aa" * 16,
                    }
                ]
            },
        }
    )

    relay = config.client.trusted_reachability_relays[0]
    assert relay == TrustedReachabilityRelayConfig(
        relay_id="bootstrap-1",
        host="203.0.113.10",
        port=4433,
        verify_key="aa" * 16,
    )

    with pytest.raises(ValueError, match="verify_key"):
        DaemonConfig.from_dict(
            {
                "node_id": "client-a",
                "role": ROLE_CLIENT,
                "client": {
                    "trusted_reachability_relays": [
                        {
                            "relay_id": "bootstrap-1",
                            "host": "203.0.113.10",
                            "port": 4433,
                            "verify_key": "not-hex",
                        }
                    ]
                },
            }
        )


def test_client_trusted_reachability_relays_reject_duplicate_ids():
    relay = {
        "relay_id": "bootstrap-1",
        "host": "203.0.113.10",
        "port": 4433,
        "verify_key": "aa" * 16,
    }
    with pytest.raises(ValueError, match="unique"):
        DaemonConfig.from_dict(
            {
                "node_id": "client-a",
                "role": ROLE_CLIENT,
                "client": {"trusted_reachability_relays": [relay, relay]},
            }
        )


def test_insecure_tls_requires_dev_opt_in():
    with pytest.raises(ValueError, match="dev_allow_insecure_tls"):
        TransportConfig(verify_tls=False)

    config = TransportConfig(verify_tls=False, dev_allow_insecure_tls=True)

    assert config.verify_tls is False


def test_daemon_config_rejects_bad_role():
    with pytest.raises(ValueError, match="unsupported daemon role"):
        DaemonConfig(node_id="node-a", role="bad-role")


def test_cluster_config_loads_current_demo_shape(tmp_path):
    path = tmp_path / "cluster.json"
    path.write_text(
        json.dumps(
            {
                "params": {"payload_size": 2048, "routing_size": 96, "max_hops": 5},
                "client": {"host": "127.0.0.1", "port": 7000},
                "nodes": {
                    "relay1": {
                        "host": "127.0.0.1",
                        "port": 7001,
                        "kem_pk": "00" * 32,
                        "kem_sk": "11" * 32,
                        "role": "relay",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    cluster = ClusterConfig.load(path)

    assert cluster.params.routing_size == 96
    assert cluster.node("relay1").kem_pk_hex == "00" * 32
    assert cluster.to_legacy_dict()["nodes"]["relay1"]["kem_sk"] == "11" * 32
