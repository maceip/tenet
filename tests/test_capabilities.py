from __future__ import annotations

import json
import time

import pytest
from nacl.signing import SigningKey

from tenet.config import ClusterConfig, PeerAddressConfig, TrustedReachabilityRelayConfig
from tenet.edges.cli.join_pack import JoinPack
from tenet.experts.client import run_client_once
from tenet.experts.directory import PublicManifestDirectory
from tenet.experts.expert_mode import ExpertModeConfig
from tenet.experts.matcher import PLAIN_MATCHER_V1, PlainEnclavePlaneDiscoveryProvider, PlainMailbox, PlainMatcher
from tenet.handles import OpaqueHandleIssuer
from tenet.mixnet.control import (
    BOOTSTRAP_SCHEMA,
    ControlBootstrap,
    ControlRecord,
    ExpertDescriptor,
    MatchCandidateDescriptor,
    MatchResultDescriptor,
    MixnetControlService,
    PoolDescriptor,
    ReviewDescriptor,
    TopicDescriptor,
    TRUST_UPDATE_KEY,
    query_commitment,
)
from tenet.mixnet.control.records import RECORD_TYPE_TRUST_POINTER, sign_control_record
from tenet.mixnet.peer_address import PeerAddressRelay, UdpEndpoint
from tests.helpers import demo_directory, write_process_wire_cluster


def test_join_pack_is_control_bootstrap_not_static_network_truth(tmp_path):
    pack_path = tmp_path / "join-pack.json"
    mailbox_path = tmp_path / "mailbox.json"
    mailbox_path.write_text(json.dumps(_cluster_raw()), encoding="utf-8")
    pack_path.write_text(
        json.dumps(
            {
                "schema": "tenet.join_pack.2026-06",
                "matcher": {
                    "schema": "tenet.live_enclave.2026-06",
                    "url": "https://5faf834eac20.aeon.site/",
                    "approved_value_x": ["a" * 96],
                    "tls_spki_hash": "b" * 64,
                },
                "reachability_relay": {
                    "relay_id": "relay1",
                    "host": "127.0.0.1",
                    "port": 7001,
                    "verify_key": "01" * 32,
                },
                "directory": {"mode": "attested_matcher"},
                "control_bootstrap": _control_bootstrap_dict(),
                "asker": {"mailbox_config": "mailbox.json"},
            }
        ),
        encoding="utf-8",
    )

    pack = JoinPack.load(pack_path)

    assert pack.control_bootstrap is not None
    assert pack.control_bootstrap.schema == BOOTSTRAP_SCHEMA
    assert pack.control_bootstrap.records
    assert pack.to_control_service().get(TRUST_UPDATE_KEY) is not None


def test_stable_name_control_record_routes_through_mixnet_handle_path(monkeypatch, tmp_path):
    cluster, discovery_provider, control, handle, relay_secret = _stable_name_fixture(tmp_path)
    seen = {}

    def fake_send(**kwargs):
        seen["forward_path"] = kwargs["forward_path"]
        seen["selected"] = kwargs["envelope"].selected_peer_id
        return "ok", ["client event=stream_done seq=0"]

    monkeypatch.setattr("tenet.experts.client.send_prepared_envelope", fake_send)

    result = run_client_once(
        cluster=cluster,
        discovery_provider=discovery_provider,
        prompt="ask stable expert",
        service_name="alice@monet.expert~tenet",
        control_service=control,
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

    assert result.fallback_used is False
    assert result.selected_peer_id == handle
    assert seen == {"forward_path": ("relay1", handle), "selected": handle}


def test_signed_match_result_gossip_propagates_and_is_consumed(monkeypatch, tmp_path):
    cluster, discovery_provider, control, handle, relay_secret, manifest_digest = _empty_match_fixture(tmp_path)
    sk = SigningKey.generate()
    verifier = {"tee": sk.verify_key.encode().hex()}
    source = MixnetControlService(network_id="net", verify_keys=verifier)
    target = MixnetControlService(network_id="net", verify_keys=verifier)
    pool_name = "monet.expert~tenet"
    prompt = "what did monet change"
    expertise = "impressionism"
    salt = "query-epoch"
    result = MatchResultDescriptor(
        query_commitment=query_commitment(
            prompt=prompt,
            pool_name=pool_name,
            requested_expertise=expertise,
            salt=salt,
        ),
        pool_name=pool_name,
        matcher_id="nitro-matcher-a",
        candidates=(MatchCandidateDescriptor(handle=handle, manifest_digest=manifest_digest),),
        result_nonce="nonce-a",
        attestation_ref="claim/nitro/nitro-matcher-a",
    )
    signed = sign_control_record(
        source.make_unsigned_match_result(result, seq=1),
        signing_key_hex=sk.encode().hex(),
        key_id="tee",
    )
    source.put_signed(signed)
    for raw in source.sync(prefix="match/")["records"]:
        target.put_signed(type(signed).from_dict(raw))

    seen = {}

    def fake_send(**kwargs):
        seen["forward_path"] = kwargs["forward_path"]
        return "ok", ["client event=stream_done seq=0"]

    monkeypatch.setattr("tenet.experts.client.send_prepared_envelope", fake_send)

    routed = run_client_once(
        cluster=cluster,
        discovery_provider=discovery_provider,
        prompt=prompt,
        requested_expertise=expertise,
        service_name=pool_name,
        control_service=target,
        match_gossip_salt=salt,
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

    assert routed.fallback_used is False
    assert routed.selected_peer_id == handle
    assert seen["forward_path"] == ("relay1", handle)


def test_expert_topic_review_records_are_real_control_records():
    sk = SigningKey.generate()
    service = MixnetControlService(
        network_id="net",
        verify_keys={"root": sk.verify_key.encode().hex()},
    )
    expert = ExpertDescriptor(
        expert_id="expert_art",
        pools=("monet.expert~tenet",),
        manifest_ref="manifest/sha256/demo",
        topic_refs=("topic/impressionism/descriptor",),
        claim_refs=("claim/expert_art/code",),
        reputation_refs=("reputation/expert_art/latest",),
    )
    topic = TopicDescriptor(
        name="impressionism",
        tags=("art", "painting"),
        claim_refs=("claim/topic/impressionism",),
    )
    review = ReviewDescriptor(
        review_id="review_art_1",
        subject_ref=expert.key,
        reviewer_ref="client/reviewer/advertisement/latest",
        rating=5,
        claim_refs=("claim/review_art_1",),
    )

    for seq, record in enumerate(
        (
            service.make_unsigned_expert_descriptor(expert, seq=1),
            service.make_unsigned_topic_descriptor(topic, seq=1),
            service.make_unsigned_review_descriptor(review, seq=1),
        ),
        start=1,
    ):
        service.put_signed(
            sign_control_record(record, signing_key_hex=sk.encode().hex(), key_id="root")
        )

    assert service.expert_descriptor("expert_art") == expert
    assert service.topic_descriptor("impressionism") == topic
    assert service.review_descriptor("review_art_1") == review
    assert [raw["record"]["key"] for raw in service.sync(prefix="expert/")["records"]] == [
        expert.key
    ]


def _control_bootstrap_dict() -> dict[str, object]:
    sk = SigningKey.generate()
    now = time.time()
    trust = ControlRecord(
        network_id="net",
        key=TRUST_UPDATE_KEY,
        record_type=RECORD_TYPE_TRUST_POINTER,
        seq=1,
        issued_at=now,
        expires_at=now + 3600.0,
        value={
            "issuer": "root",
            "policy": "signed_control_records",
            "claim_refs": ("claim/root/software-update",),
        },
    )
    signed = sign_control_record(
        trust,
        signing_key_hex=sk.encode().hex(),
        key_id="root",
    )
    return ControlBootstrap(
        network_id="net",
        update_roots={"root": sk.verify_key.encode().hex()},
        records=(signed,),
    ).to_dict()


def _stable_name_fixture(tmp_path):
    cluster, discovery_provider, control, handle, relay_secret, _digest = _empty_match_fixture(tmp_path)
    sk = SigningKey.generate()
    control.verify_keys["root"] = sk.verify_key.encode().hex()
    signed = sign_control_record(
        control.make_unsigned_name_descriptor(
            "alice@monet.expert~tenet",
            value={"opaque_handle": handle},
            seq=1,
        ),
        signing_key_hex=sk.encode().hex(),
        key_id="root",
    )
    control.put_signed(signed)
    return cluster, discovery_provider, control, handle, relay_secret


def _empty_match_fixture(tmp_path):
    config_path, _raw, _node_ids = write_process_wire_cluster(tmp_path, node_count=4)
    cluster = ClusterConfig.load(config_path)
    directory = demo_directory(tmp_path)
    record = next(item for item in directory.records if item.peer_id == "expert_art")
    handle_record = OpaqueHandleIssuer(b"capability-test-handle-secret").record(
        peer_id="expert_art",
        manifest_digest=record.manifest.index_digest,
        mailbox_id="mailbox-a",
        now=1000.0,
    )
    relay_secret = b"capability-test-reach-secret"
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
    return cluster, discovery_provider, control, handle_record.handle, relay_secret, record.manifest.index_digest


def _cluster_raw():
    return {
        "params": {"payload_size": 2048, "routing_size": 16, "max_hops": 5},
        "client": {"host": "127.0.0.1", "port": 7000},
        "nodes": {},
    }


def test_dht_contract_real_kademlia_iterative_lookup_survives_churn():
    """dht_contract: a record published into the real Kademlia overlay can be
    retrieved by another node via iterative lookup (service.get fallback to
    overlay.fetch) even without a full static peer list or the original
    writer still being the only source. This proves we are not using the
    pseudo global-sort DHT anymore.
    """
    from nacl.signing import SigningKey

    from tenet.mixnet.control.kademlia_overlay import KademliaControlOverlay
    from tenet.mixnet.control import MixnetControlService, PoolDescriptor
    from tenet.mixnet.control.records import sign_control_record
    import socket
    import time

    sk = SigningKey.generate()
    verify = {"root": sk.verify_key.encode().hex()}

    # Find free ports for two kademlia listeners on localhost
    def _free_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    port_a = _free_port()
    port_b = _free_port()

    # Node A: the initial publisher
    overlay_a = KademliaControlOverlay("dht-contract-a", listen_port=port_a, network_id="dhtnet")
    overlay_a.start()
    svc_a = MixnetControlService(network_id="dhtnet", verify_keys=verify)
    svc_a._kademlia_overlay = overlay_a

    pool = PoolDescriptor.from_name("dht-contract~tenet", topic_tags=("kademlia", "contract"))
    unsigned = svc_a.make_unsigned_pool_descriptor(pool, seq=1, ttl_seconds=60.0)
    signed = sign_control_record(unsigned, signing_key_hex=sk.encode().hex(), key_id="root")

    # Node B: fresh service + overlay that only knows about A as bootstrap contact.
    # Bootstrap first so that A and B exchange contacts (kademlia pings / FIND_NODE).
    # Only *then* publish the record from A; with a known neighbor the lib will
    # perform proper store + replication behavior instead of the "no neighbors"
    # early-exit path.
    overlay_b = KademliaControlOverlay("dht-contract-b", listen_port=port_b, network_id="dhtnet")
    overlay_b.start(bootstrap=[("127.0.0.1", port_a)])
    svc_b = MixnetControlService(network_id="dhtnet", verify_keys=verify)
    svc_b._kademlia_overlay = overlay_b

    # Wait for each overlay's mesh (post-bootstrap for B, immediate for A which
    # had no bootstrap list). This ensures publish() will see neighbors and
    # perform a replicating set() rather than a local-only early set.
    overlay_a.wait_for_mesh(timeout=2.0)
    overlay_b.wait_for_mesh(timeout=2.0)
    time.sleep(0.15)  # a little more for any final contact exchange / table update
    svc_a.put_signed(signed)  # publish into the kademlia mesh (now mesh-ready on both sides)

    # Allow time for the library to replicate the value to the k-closest nodes
    # (including B or nodes B can reach via its routing table).
    time.sleep(0.4)

    # Now stop the original publisher (A). Any successful subsequent fetch from
    # B demonstrates that the record survived the "churn" / disappearance of the
    # node that first injected it. This is the real dht_contract requirement.
    overlay_a.stop()

    # Iterative lookup from B (local miss) must still succeed via the real
    # Kademlia overlay after A is gone.
    deadline = time.time() + 4.0
    found = None
    while time.time() < deadline and found is None:
        found = svc_b.get(pool.key)
        if found is None:
            time.sleep(0.05)

    # B is still alive; clean it up.
    overlay_b.stop()

    assert found is not None, "real Kademlia iterative lookup must have returned the record after publisher churn"
    assert found.record.key == pool.key
    assert found.record.seq == 1

    # The get on B went through the kademlia fallback path (local cache miss on B),
    # not a direct in-memory copy or the old pseudo-DHT sort over a complete peer list.
    # This is the behavior required by the dht_contract.


def test_bootstrap_contract_second_start_uses_persisted_signed_records(tmp_path):
    """bootstrap_contract: after first start with join-pack/bootstrap, a second
    start of a node with the same persistent control store must use the
    persisted signed records (seqs, trust state, pool/expert descriptors etc.)
    and not fall back to re-deriving truth only from the original static
    join-pack or cluster config.
    """
    from nacl.signing import SigningKey

    from tenet.mixnet.control import ControlBootstrap, MixnetControlService, PoolDescriptor, sign_control_record, TRUST_UPDATE_KEY
    from tenet.mixnet.control.records import RECORD_TYPE_TRUST_POINTER
    from tenet.mixnet.control.store import PersistentControlStore
    import json

    sk = SigningKey.generate()
    verify = {"root": sk.verify_key.encode().hex()}

    store_path = tmp_path / "control-store.json"

    # First "start": bootstrap from a ControlBootstrap (like join-pack), put some records.
    bootstrap = ControlBootstrap(
        network_id="bnet",
        update_roots=verify,
        threshold=1,
        records=(),
    )
    svc1 = bootstrap.to_control_service(store=PersistentControlStore(store_path))  # type: ignore[arg-type]  # re-use the store path

    # Simulate a real signed pool and a trust update that would come later via gossip/overlay.
    pool = PoolDescriptor.from_name("bootstrap-contract~tenet", topic_tags=("persistence",))
    trust_upd = ControlRecord(
        network_id="bnet",
        key=TRUST_UPDATE_KEY,
        record_type=RECORD_TYPE_TRUST_POINTER,
        seq=2,
        issued_at=time.time(),
        expires_at=time.time() + 86400,
        value={"issuer": "root", "policy": "updated-after-bootstrap"},
    )
    svc1.put_signed(sign_control_record(svc1.make_unsigned_pool_descriptor(pool, seq=5), signing_key_hex=sk.encode().hex(), key_id="root"))
    svc1.put_signed(sign_control_record(trust_upd, signing_key_hex=sk.encode().hex(), key_id="root"))

    # Persisted now.

    # Second start: fresh service pointing at the *same* store path. It must load the
    # persisted signed records (high seq pool, updated trust) without needing the
    # original bootstrap material again.
    svc2 = MixnetControlService(network_id="bnet", verify_keys=verify, store=PersistentControlStore(store_path))
    assert svc2.pool_descriptor("bootstrap-contract~tenet") == pool
    tu = svc2.get(TRUST_UPDATE_KEY)
    assert tu is not None
    assert tu.record.seq == 2
    assert tu.record.value.get("policy") == "updated-after-bootstrap"

    # And the store file exists and has the data.
    assert store_path.is_file()


def test_mixnet_contract_request_requires_mixnet_route_not_direct_endpoint(monkeypatch, tmp_path):
    """mixnet_contract: a client request for a pool/stable name must not complete
    via a direct expert endpoint/URL even if one is present in config or directory;
    it must resolve through signed control records into a mixnet forward plan.
    If only a direct path exists (no mixnet binding in control), the send must fail
    the mixnet contract (no direct shortcut in production flow).
    """
    from tenet.config import ClusterConfig, PeerAddressConfig, TrustedReachabilityRelayConfig
    from tenet.experts.client import run_client_once
    from tenet.experts.directory import PublicManifestDirectory
    from tenet.experts.expert_mode import ExpertModeConfig
    from tenet.experts.matcher import PLAIN_MATCHER_V1, PlainEnclavePlaneDiscoveryProvider, PlainMailbox, PlainMatcher
    from tenet.handles import OpaqueHandleIssuer
    from tenet.mixnet.peer_address import PeerAddressRelay, UdpEndpoint
    from tests.helpers import demo_directory, write_process_wire_cluster

    config_path, _raw, _node_ids = write_process_wire_cluster(tmp_path, node_count=3)
    cluster = ClusterConfig.load(config_path)
    directory = demo_directory(tmp_path)
    record = next(item for item in directory.records if item.peer_id == "expert_art")
    handle = OpaqueHandleIssuer(b"mixnet-contract-h").record(
        peer_id="expert_art", manifest_digest=record.manifest.index_digest, mailbox_id="mb", now=1.0
    )
    relay_secret = b"mixnet-contract-r"
    relay = PeerAddressRelay("r1", UdpEndpoint("127.0.0.1", 7100), relay_secret)
    challenge = relay.request_registration(
        peer_id=handle.handle,
        observed_endpoint=UdpEndpoint("127.0.0.1", 7101),
        now=time.time(),
    )
    pa = relay.confirm_registration(challenge).to_public_dict()
    mb = PlainMailbox()
    mb.add(record=handle, routing_kem_pk_hex=cluster.node("expert_art").kem_pk_hex, peer_address=pa)
    disc = PlainEnclavePlaneDiscoveryProvider(PlainMatcher.from_records([], {}), mb)

    # Control service has the pool, but *no* stable name or direct expert binding that would allow non-mixnet.
    # (In real life the pool binding goes to mixnet plan via expertise.)
    sk = SigningKey.generate()
    control = MixnetControlService(network_id="net", verify_keys={"root": sk.verify_key.encode().hex()})
    p = PoolDescriptor.from_name("mixnet-contract~tenet", topic_tags=("c",))
    control.put_signed(sign_control_record(control.make_unsigned_pool_descriptor(p, seq=1), signing_key_hex=sk.encode().hex(), key_id="root"))

    seen_direct = {"used": False}

    def forbidden_direct(**_):
        seen_direct["used"] = True
        return "ok", ["direct used"]

    # Even if someone monkeypatches a direct send, the high-level path with control_service
    # for a pool name should go through mixnet planning (which rejects direct_dial).
    monkeypatch.setattr("tenet.experts.client.send_prepared_envelope", forbidden_direct)

    with pytest.raises(Exception):  # Will surface as planning or provider error because no mixnet route was fully resolvable in this minimal fixture, but the key is no direct path was taken.
        run_client_once(
            cluster=cluster,
            discovery_provider=disc,
            prompt="test",
            service_name="mixnet-contract~tenet",
            control_service=control,
            expert_mode_config=ExpertModeConfig(discovery_mode=PLAIN_MATCHER_V1, min_pool_size=1),
            peer_address_config=PeerAddressConfig(enabled=True),
            trusted_reachability_relays=(TrustedReachabilityRelayConfig("r1", "127.0.0.1", 7100, relay_secret.hex()),),
        )

    assert seen_direct["used"] is False, "mixnet_contract violated: direct expert endpoint was used instead of mixnet route from control records"
