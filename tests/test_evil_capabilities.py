from __future__ import annotations

import inspect
import json
import time

import pytest
from nacl.signing import SigningKey

from tenet.edges.cli.join_pack import JoinPack
from tenet.experts.client import run_client_once
from tenet.experts.live_client import send_live_enclave, send_live_enclave_summary
from tenet.experts.matcher import PLAIN_MATCHER_V1, PlainEnclavePlaneDiscoveryProvider, PlainMailbox, PlainMatcher
from tenet.experts.expert_mode import ExpertModeConfig
from tenet.handles import OpaqueHandleIssuer
from tenet.llm.provider import ProviderError
from tenet.mixnet.control import MatchCandidateDescriptor, MatchResultDescriptor, MixnetControlService, PoolDescriptor, query_commitment
from tenet.mixnet.control.records import ControlRecordError, sign_control_record
from tenet.mixnet.peer_address import PeerAddressRelay, UdpEndpoint
from tenet.config import ClusterConfig, PeerAddressConfig, TrustedReachabilityRelayConfig
from tests.helpers import demo_directory, write_process_wire_cluster


def test_evil_static_join_pack_without_control_bootstrap_is_rejected(tmp_path):
    mailbox = tmp_path / "mailbox.json"
    mailbox.write_text(json.dumps(_cluster_raw()), encoding="utf-8")
    pack = tmp_path / "join-pack.json"
    pack.write_text(
        json.dumps(
            {
                "schema": "tenet.join_pack.2026-06",
                "matcher": {
                    "schema": "tenet.live_enclave.2026-06",
                    "url": "https://5faf834eac20.aeon.site/",
                    "approved_value_x": ["a" * 96],
                    "tls_spki_hash": "b" * 64,
                },
                "reachability_relay": {"relay_id": "r", "host": "127.0.0.1", "port": 1},
                "directory": {"mode": "attested_matcher"},
                "asker": {"mailbox_config": "mailbox.json"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="control_bootstrap"):
        JoinPack.load(pack)


def test_evil_live_ask_path_accepts_control_bootstrap_injection():
    assert "control_service" in inspect.signature(send_live_enclave).parameters
    assert "control_service" in inspect.signature(send_live_enclave_summary).parameters


def test_evil_forged_match_result_is_not_gossip_usable(tmp_path):
    cluster, discovery_provider, _handle, _relay_secret, manifest_digest = _empty_match_fixture(tmp_path)
    trusted = SigningKey.generate()
    attacker = SigningKey.generate()
    control = MixnetControlService(
        network_id="net",
        verify_keys={"tee": trusted.verify_key.encode().hex()},
    )
    result = MatchResultDescriptor(
        query_commitment=query_commitment(
            prompt="p",
            pool_name="monet.expert~tenet",
            requested_expertise="e",
            salt="s",
        ),
        pool_name="monet.expert~tenet",
        matcher_id="evil",
        candidates=(MatchCandidateDescriptor(handle="h" + "1" * 15, manifest_digest=manifest_digest),),
        result_nonce="n",
    )
    signed = sign_control_record(
        control.make_unsigned_match_result(result, seq=1),
        signing_key_hex=attacker.encode().hex(),
        key_id="tee",
    )

    with pytest.raises(ControlRecordError, match="signature threshold"):
        control.put_signed(signed)


def test_evil_match_gossip_wrong_query_commitment_does_not_route(monkeypatch, tmp_path):
    cluster, discovery_provider, handle, relay_secret, manifest_digest = _empty_match_fixture(tmp_path)
    sk = SigningKey.generate()
    control = MixnetControlService(network_id="net", verify_keys={"tee": sk.verify_key.encode().hex()})
    pool_name = "monet.expert~tenet"
    result = MatchResultDescriptor(
        query_commitment=query_commitment(
            prompt="different prompt",
            pool_name=pool_name,
            requested_expertise="impressionism",
            salt="query-epoch",
        ),
        pool_name=pool_name,
        matcher_id="nitro-matcher-a",
        candidates=(MatchCandidateDescriptor(handle=handle, manifest_digest=manifest_digest),),
        result_nonce="nonce-a",
    )
    control.put_signed(
        sign_control_record(
            control.make_unsigned_match_result(result, seq=1),
            signing_key_hex=sk.encode().hex(),
            key_id="tee",
        )
    )

    def forbidden_send(**_kwargs):
        raise AssertionError("wrong query commitment must not route")

    monkeypatch.setattr("tenet.experts.client.send_prepared_envelope", forbidden_send)

    with pytest.raises(ProviderError):
        run_client_once(
            cluster=cluster,
            discovery_provider=discovery_provider,
            prompt="real prompt",
            requested_expertise="impressionism",
            service_name=pool_name,
            control_service=control,
            match_gossip_salt="query-epoch",
            expert_mode_config=ExpertModeConfig(discovery_mode=PLAIN_MATCHER_V1, min_pool_size=1),
            peer_address_config=PeerAddressConfig(enabled=True),
            trusted_reachability_relays=(
                TrustedReachabilityRelayConfig(
                    relay_id="relay1",
                    host=cluster.node("relay1").host,
                    port=cluster.node("relay1").port,
                    verify_key=relay_secret.hex(),
                ),
            ),
        )


def test_evil_control_records_cannot_smuggle_direct_endpoints():
    service = MixnetControlService(network_id="net")
    record = service.make_unsigned_name_descriptor(
        "alice@monet.expert~tenet",
        value={"opaque_handle": "h" + "1" * 15, "metadata": {"host": "127.0.0.1", "port": 1}},
        seq=1,
    )

    with pytest.raises(ControlRecordError, match="direct dial"):
        record.validate()


def _empty_match_fixture(tmp_path):
    config_path, _raw, _node_ids = write_process_wire_cluster(tmp_path, node_count=4)
    cluster = ClusterConfig.load(config_path)
    directory = demo_directory(tmp_path)
    record = next(item for item in directory.records if item.peer_id == "expert_art")
    handle_record = OpaqueHandleIssuer(b"evil-capability-handle-secret").record(
        peer_id="expert_art",
        manifest_digest=record.manifest.index_digest,
        mailbox_id="mailbox-a",
        now=1000.0,
    )
    relay_secret = b"evil-capability-reach-secret"
    relay = PeerAddressRelay(
        relay_id="relay1",
        relay_endpoint=UdpEndpoint("127.0.0.1", 7001),
        secret=relay_secret,
    )
    challenge = relay.request_registration(
        peer_id=handle_record.handle,
        observed_endpoint=UdpEndpoint("127.0.0.1", 7003),
        now=time.time(),
    )
    peer_address = relay.confirm_registration(challenge).to_public_dict()
    mailbox = PlainMailbox()
    mailbox.add(
        record=handle_record,
        routing_kem_pk_hex=cluster.node("expert_art").kem_pk_hex,
        peer_address=peer_address,
    )
    discovery_provider = PlainEnclavePlaneDiscoveryProvider(PlainMatcher.from_records([], {}), mailbox)
    control = MixnetControlService(network_id="net")
    sk = SigningKey.generate()
    control.verify_keys["root"] = sk.verify_key.encode().hex()
    pool = PoolDescriptor.from_name("monet.expert~tenet", topic_tags=("impressionism",))
    control.put_signed(
        sign_control_record(
            control.make_unsigned_pool_descriptor(pool, seq=1),
            signing_key_hex=sk.encode().hex(),
            key_id="root",
        )
    )
    return cluster, discovery_provider, handle_record.handle, relay_secret, record.manifest.index_digest


def _cluster_raw():
    return {
        "params": {"payload_size": 2048, "routing_size": 16, "max_hops": 5},
        "client": {"host": "127.0.0.1", "port": 7000},
        "nodes": {},
    }
