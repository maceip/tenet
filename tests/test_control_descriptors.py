"""Anti-leak tests for control descriptors (Item 5).

The control plane describes *what* exists (matchers, handles, peers, pools)
without exposing *where* it lives. These tests assert that descriptors reject
every attempt to smuggle a routeable endpoint or an expertise->route mapping,
and that legitimate descriptors round-trip through the signed control service.
"""

from __future__ import annotations

import time

import pytest
from nacl.signing import SigningKey

from tenet.mixnet.control.descriptors import (
    ControlDhtPeerDescriptor,
    HandleAddressRecord,
    MatcherCapabilityDescriptor,
    ReachabilityAssistDescriptor,
)
from tenet.mixnet.control.pools import PoolDescriptor
from tenet.mixnet.control.records import ControlRecord, sign_control_record, RECORD_TYPE_NAME_DESCRIPTOR
from tenet.mixnet.control.names import parse_tenet_name
from tenet.mixnet.control.service import MixnetControlService, binding_from_record, RouteBindingError

OPAQUE_HANDLE = "h" + "0123456789abcde"  # 'h' + 15 chars = 16 ASCII bytes
POOL = "monet.expert~tenet"


def _service():
    sk = SigningKey.generate()
    svc = MixnetControlService(network_id="net", verify_keys={"root": sk.verify_key.encode().hex()})
    return svc, sk


def _put(svc, sk, unsigned: ControlRecord, *, now: float | None = None):
    svc.put_signed(
        sign_control_record(unsigned, signing_key_hex=sk.encode().hex(), key_id="root"),
        now=now,
    )


# --------------------------------------------------------------------------- #
# MatcherCapabilityDescriptor
# --------------------------------------------------------------------------- #


def _tee_matcher(**overrides) -> MatcherCapabilityDescriptor:
    base = dict(
        matcher_id="m1",
        pools=(POOL,),
        trust_tier="tee",
        result_signing_key="ff" * 32,
        matcher_handle=OPAQUE_HANDLE,
        attestation_ref="attestation/n1/r1",
    )
    base.update(overrides)
    return MatcherCapabilityDescriptor(**base)


def test_matcher_capability_tee_roundtrips_through_service():
    svc, sk = _service()
    cap = _tee_matcher()
    _put(svc, sk, svc.make_unsigned_matcher_capability(cap, seq=1))
    fetched = svc.matcher_capability("m1")
    assert fetched is not None
    assert fetched.trust_tier == "tee"
    assert svc.matcher_capabilities(pool=POOL) == (fetched,)
    assert svc.matcher_capabilities(pool="other.expert~tenet") == ()


def test_matcher_capability_non_tee_signed_roundtrips_with_evidence():
    cap = MatcherCapabilityDescriptor(
        matcher_id="m2",
        pools=(POOL,),
        trust_tier="non_tee_signed",
        result_signing_key="ab" * 32,
        query_endpoint_ref="matcher/m2/endpoint",
        code_identity="sha256-codeid",
        dataset_commitment="sha256-dataset",
    )
    cap.validate()  # no raise


def test_matcher_capability_cannot_carry_both_handle_and_endpoint():
    with pytest.raises(ValueError, match="exactly one"):
        _tee_matcher(query_endpoint_ref="matcher/m1/endpoint").validate()


def test_matcher_capability_requires_a_reachability_ref():
    with pytest.raises(ValueError, match="exactly one"):
        MatcherCapabilityDescriptor(
            matcher_id="m1",
            pools=(POOL,),
            trust_tier="tee",
            result_signing_key="ff" * 32,
            attestation_ref="attestation/x",
        ).validate()


def test_matcher_capability_query_endpoint_cannot_be_a_url():
    with pytest.raises(ValueError, match="routeable endpoint"):
        MatcherCapabilityDescriptor(
            matcher_id="m1",
            pools=(POOL,),
            trust_tier="authority_pinned",
            result_signing_key="ff" * 32,
            query_endpoint_ref="https://matcher.example.com:8443/q",
        ).validate()


def test_matcher_capability_handle_must_be_opaque():
    with pytest.raises(ValueError, match="opaque handle"):
        _tee_matcher(matcher_handle="not-an-opaque-handle").validate()


def test_matcher_capability_rejects_unknown_trust_tier():
    with pytest.raises(ValueError, match="trust tier"):
        _tee_matcher(trust_tier="totally-trusted").validate()


def test_non_tee_matcher_missing_dataset_commitment_rejected():
    with pytest.raises(ValueError, match="dataset_commitment"):
        MatcherCapabilityDescriptor(
            matcher_id="m2",
            pools=(POOL,),
            trust_tier="non_tee_signed",
            result_signing_key="ab" * 32,
            query_endpoint_ref="matcher/m2/endpoint",
            code_identity="sha256-codeid",
        ).validate()


def test_non_tee_matcher_missing_code_identity_rejected():
    with pytest.raises(ValueError, match="code_identity"):
        MatcherCapabilityDescriptor(
            matcher_id="m2",
            pools=(POOL,),
            trust_tier="non_tee_signed",
            result_signing_key="ab" * 32,
            query_endpoint_ref="matcher/m2/endpoint",
            dataset_commitment="sha256-dataset",
        ).validate()


def test_tee_matcher_missing_attestation_rejected():
    with pytest.raises(ValueError, match="attestation_ref"):
        MatcherCapabilityDescriptor(
            matcher_id="m1",
            pools=(POOL,),
            trust_tier="tee",
            result_signing_key="ff" * 32,
            matcher_handle=OPAQUE_HANDLE,
        ).validate()


def test_matcher_capability_pools_must_be_pool_names():
    with pytest.raises(ValueError, match="pool names"):
        _tee_matcher(pools=("alice@stable.svc~tenet",)).validate()


# --------------------------------------------------------------------------- #
# HandleAddressRecord
# --------------------------------------------------------------------------- #


def _handle_address(**overrides) -> HandleAddressRecord:
    issued = time.time()
    base = dict(
        handle=OPAQUE_HANDLE,
        route_candidates=("assist/a1", "mix/node-7"),
        assist_refs=("assist/a1",),
        issued_at=issued,
        expires_at=issued + 3600.0,
        signer="root",
    )
    base.update(overrides)
    return HandleAddressRecord(**base)


def test_handle_address_roundtrips_through_service():
    svc, sk = _service()
    _put(svc, sk, svc.make_unsigned_handle_address(_handle_address(), seq=1))
    fetched = svc.handle_address(OPAQUE_HANDLE)
    assert fetched is not None
    assert fetched.route_candidates == ("assist/a1", "mix/node-7")


def test_handle_address_requires_opaque_handle():
    with pytest.raises(ValueError, match="opaque handle"):
        _handle_address(handle="bob@stable.svc~tenet").validate()


def test_handle_address_route_candidate_cannot_be_an_endpoint():
    with pytest.raises(ValueError, match="routeable endpoint"):
        _handle_address(route_candidates=("10.0.0.5:9000",)).validate()


def test_handle_address_assist_ref_cannot_carry_expertise_pool():
    with pytest.raises(ValueError, match="expertise pool"):
        _handle_address(assist_refs=(POOL,)).validate()


def test_handle_address_requires_signer():
    with pytest.raises(ValueError, match="signer"):
        _handle_address(signer="").validate()


# --------------------------------------------------------------------------- #
# ControlDhtPeerDescriptor
# --------------------------------------------------------------------------- #


def test_control_dht_peer_roundtrips_through_service():
    svc, sk = _service()
    peer = ControlDhtPeerDescriptor(peer_id="node-7", node_key="cc" * 32, capabilities=("control_dht",))
    _put(svc, sk, svc.make_unsigned_control_dht_peer(peer, seq=1))
    peers = svc.control_dht_peers()
    assert len(peers) == 1 and peers[0].peer_id == "node-7"


def test_control_dht_peer_cannot_embed_endpoint_in_id():
    with pytest.raises(ValueError, match="routeable endpoint"):
        ControlDhtPeerDescriptor(peer_id="127.0.0.1:7001", node_key="cc" * 32).validate()


def test_control_dht_peer_region_hint_cannot_be_endpoint():
    with pytest.raises(ValueError, match="routeable endpoint"):
        ControlDhtPeerDescriptor(
            peer_id="node-7", node_key="cc" * 32, region_hint="https://eu.example.com"
        ).validate()


# --------------------------------------------------------------------------- #
# PoolDescriptor strengthening
# --------------------------------------------------------------------------- #


def test_pool_descriptor_rejects_routeable_member_ref():
    with pytest.raises(ValueError, match="routeable endpoint"):
        PoolDescriptor(
            name=POOL,
            topic_tags=("impressionism",),
            member_capability_refs=("peer@198.51.100.7:9000",),
        ).validate()


def test_pool_descriptor_valid_refs_still_pass():
    PoolDescriptor(
        name=POOL,
        topic_tags=("impressionism",),
        member_capability_refs=("client/abc/advertisement/latest",),
    ).validate()


# --------------------------------------------------------------------------- #
# ReachabilityAssist strengthening
# --------------------------------------------------------------------------- #


def test_reachability_assist_cannot_carry_expertise_pool():
    with pytest.raises(ValueError, match="expertise pool"):
        ReachabilityAssistDescriptor(
            assist_id="a1",
            provider_node_id="node-1",
            policy="nat-relay",
            opaque_refs=(POOL,),
        ).validate()


def test_reachability_assist_cannot_carry_endpoint():
    with pytest.raises(ValueError, match="routeable endpoint"):
        ReachabilityAssistDescriptor(
            assist_id="a1",
            provider_node_id="node-1",
            policy="nat-relay",
            opaque_refs=("turn://1.2.3.4:3478",),
        ).validate()


def test_reachability_assist_valid_still_passes():
    ReachabilityAssistDescriptor(
        assist_id="a1",
        provider_node_id="node-1",
        policy="nat-relay",
        opaque_refs=("assist/token/abc",),
    ).validate()


# --------------------------------------------------------------------------- #
# Name binding strengthening
# --------------------------------------------------------------------------- #


def test_stable_name_binding_requires_opaque_handle():
    name = parse_tenet_name("alice@inbox.svc~tenet")
    record = ControlRecord(
        network_id="net",
        key=name.control_key,
        record_type=RECORD_TYPE_NAME_DESCRIPTOR,
        seq=1,
        issued_at=1000.0,
        expires_at=2000.0,
        value={
            "name": name.normalized,
            "kind": name.kind,
            "transport": "mixnet",
            "direct_dial_allowed": False,
            "opaque_handle": "alice-direct-handle",  # not an opaque token
        },
    )
    with pytest.raises(RouteBindingError, match="opaque handle"):
        binding_from_record(record, name)


def test_stable_name_binding_accepts_opaque_handle():
    name = parse_tenet_name("alice@inbox.svc~tenet")
    record = ControlRecord(
        network_id="net",
        key=name.control_key,
        record_type=RECORD_TYPE_NAME_DESCRIPTOR,
        seq=1,
        issued_at=1000.0,
        expires_at=2000.0,
        value={
            "name": name.normalized,
            "kind": name.kind,
            "transport": "mixnet",
            "direct_dial_allowed": False,
            "opaque_handle": OPAQUE_HANDLE,
        },
    )
    binding = binding_from_record(record, name)
    assert binding.opaque_handle == OPAQUE_HANDLE
