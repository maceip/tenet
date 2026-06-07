"""Adversarial tests for signed control-record policy enforcement (Item 1).

These tests assert that signature validity is necessary but NOT sufficient: a
record is only accepted when its signer is *authorized* for the record type, the
record is fresh, on-network, schema-known, within size bounds, and not revoked.
Every case here is a path an attacker (or a buggy peer) could take to smuggle a
fact into the control plane.
"""

from __future__ import annotations

import time

import pytest
from nacl.signing import SigningKey

from tenet.mixnet.control.policy import (
    DEFAULT_RECORD_POLICY,
    TrustPolicy,
    validate_record_policy,
)
from tenet.mixnet.control.records import (
    ControlRecord,
    ControlRecordError,
    MAX_SIGNED_CONTROL_RECORD_BYTES,
    RECORD_TYPE_EXPERT_DESCRIPTOR,
    RECORD_TYPE_REVOCATION,
    RECORD_TYPE_TRUST_POINTER,
    RECORD_TYPE_TRUST_UPDATE,
    sign_control_record,
)
from tenet.mixnet.control.service import MixnetControlService
from tenet.mixnet.control.descriptors import ExpertDescriptor


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _keypair():
    sk = SigningKey.generate()
    return sk, sk.verify_key.encode().hex()


def _record(
    *,
    network_id: str = "net",
    key: str = "expert/e/descriptor",
    record_type: str = RECORD_TYPE_EXPERT_DESCRIPTOR,
    seq: int = 1,
    now: float | None = None,
    ttl: float = 3600.0,
    value: dict | None = None,
    issuer_id: str = "",
    revokes: str | None = None,
) -> ControlRecord:
    issued = time.time() if now is None else now
    return ControlRecord(
        network_id=network_id,
        key=key,
        record_type=record_type,
        seq=seq,
        issued_at=issued,
        expires_at=issued + ttl,
        value=value if value is not None else {},
        issuer_id=issuer_id,
        revokes=revokes,
    )


def _signed(record: ControlRecord, sk: SigningKey, key_id: str):
    return sign_control_record(record, signing_key_hex=sk.encode().hex(), key_id=key_id)


# --------------------------------------------------------------------------- #
# wrong authority
# --------------------------------------------------------------------------- #


def test_client_key_cannot_issue_trust_update():
    """A correctly-signed record from a client key is rejected for a root-only type."""
    sk, vk = _keypair()
    policy = TrustPolicy(
        verify_keys={"client-key": vk},
        key_authorities={"client-key": "client"},
    )
    service = MixnetControlService(network_id="net", trust_policy=policy)
    record = _record(
        record_type=RECORD_TYPE_TRUST_UPDATE,
        key="trust/update/u1",
        value={
            "update_id": "u1",
            "issuer": "attacker",
            "policy": "rotate",
            "schema": "tenet.trust_update.2026-06",
        },
    )
    signed = _signed(record, sk, "client-key")
    # signature itself is valid...
    assert signed.valid_signer_ids({"client-key": vk})
    # ...but the client authority is not permitted to issue a trust update.
    with pytest.raises(ControlRecordError, match="requires authority"):
        service.put_signed(signed)


def test_non_tee_matcher_key_cannot_forge_attestation_receipt():
    sk, vk = _keypair()
    policy = TrustPolicy(
        verify_keys={"m": vk},
        key_authorities={"m": "non_tee_matcher"},
    )
    record = _record(
        record_type="attestation_receipt",
        key="attestation/n1/r1",
        value={
            "receipt_id": "r1",
            "subject_node_id": "n1",
            "measurement": "deadbeef",
            "schema": "tenet.attestation_receipt.2026-06",
        },
    )
    signed = _signed(record, sk, "m")
    with pytest.raises(ControlRecordError, match="requires authority"):
        validate_record_policy(signed, policy)


def test_tee_key_may_issue_match_result_but_client_may_not():
    sk_tee, vk_tee = _keypair()
    sk_cli, vk_cli = _keypair()
    policy = TrustPolicy(
        verify_keys={"tee": vk_tee, "cli": vk_cli},
        key_authorities={"tee": "tee", "cli": "client"},
    )
    mk_record = lambda: _record(
        record_type="match_result",
        key="match/monet.expert~tenet/qc/m1",
        value={
            "query_commitment": "qc",
            "pool_name": "monet.expert~tenet",
            "matcher_id": "m1",
            "candidates": [],
            "result_nonce": "n",
            "schema": "tenet.match_result.2026-06",
        },
    )
    # tee signer accepted
    validate_record_policy(_signed(mk_record(), sk_tee, "tee"), policy)
    # client signer rejected
    with pytest.raises(ControlRecordError, match="requires authority"):
        validate_record_policy(_signed(mk_record(), sk_cli, "cli"), policy)


def test_root_is_superuser_for_any_record_type():
    sk, vk = _keypair()
    policy = TrustPolicy(verify_keys={"r": vk}, key_authorities={"r": "root"})
    # root signs a match_result whose policy set is {tee, non_tee_matcher} — no root.
    record = _record(
        record_type="match_result",
        key="match/monet.expert~tenet/qc/m1",
        value={
            "query_commitment": "qc",
            "pool_name": "monet.expert~tenet",
            "matcher_id": "m1",
            "candidates": [],
            "result_nonce": "n",
            "schema": "tenet.match_result.2026-06",
        },
    )
    classes = validate_record_policy(_signed(record, sk, "r"), policy)
    assert "root" in classes


def test_issuer_id_impersonation_rejected():
    """A client key may not claim issuer_id of a known higher-authority key."""
    sk_cli, vk_cli = _keypair()
    _sk_root, vk_root = _keypair()
    policy = TrustPolicy(
        verify_keys={"cli": vk_cli, "root": vk_root},
        key_authorities={"cli": "client", "root": "root"},
    )
    record = _record(
        record_type=RECORD_TYPE_EXPERT_DESCRIPTOR,
        value={"expert_id": "e", "pools": ["monet.expert~tenet"], "manifest_ref": "m"},
        issuer_id="root",  # claims to be issued by the root key
    )
    signed = _signed(record, sk_cli, "cli")  # but signed only by the client key
    with pytest.raises(ControlRecordError, match="did not sign"):
        validate_record_policy(signed, policy)


# --------------------------------------------------------------------------- #
# revocation
# --------------------------------------------------------------------------- #


def test_revocation_makes_get_return_none():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    expert = ExpertDescriptor(expert_id="e", pools=("monet.expert~tenet",), manifest_ref="m")
    rec = service.make_unsigned_expert_descriptor(expert, seq=1)
    service.put_signed(_signed(rec, sk, "root"))
    assert service.get(rec.key) is not None

    revocation = service.make_unsigned_revocation(rec.key, seq=1, reason="compromised")
    service.put_signed(_signed(revocation, sk, "root"))
    assert service.get(rec.key) is None
    assert service.is_revoked(rec.key)


def test_revocation_is_terminal_even_against_higher_seq_record():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    expert = ExpertDescriptor(expert_id="e", pools=("monet.expert~tenet",), manifest_ref="m")
    rec1 = service.make_unsigned_expert_descriptor(expert, seq=1)
    service.put_signed(_signed(rec1, sk, "root"))
    service.put_signed(_signed(service.make_unsigned_revocation(rec1.key, seq=1), sk, "root"))
    assert service.get(rec1.key) is None

    # A later, higher-seq record for the same key must NOT resurrect it.
    rec2 = service.make_unsigned_expert_descriptor(expert, seq=5)
    service.put_signed(_signed(rec2, sk, "root"))
    assert service.get(rec1.key) is None


def test_unauthorized_class_cannot_revoke():
    sk_cli, vk_cli = _keypair()
    sk_root, vk_root = _keypair()
    policy = TrustPolicy(
        verify_keys={"cli": vk_cli, "root": vk_root},
        key_authorities={"cli": "client", "root": "root"},
    )
    service = MixnetControlService(network_id="net", trust_policy=policy)
    expert = ExpertDescriptor(expert_id="e", pools=("monet.expert~tenet",), manifest_ref="m")
    rec = service.make_unsigned_expert_descriptor(expert, seq=1)
    service.put_signed(_signed(rec, sk_cli, "cli"))  # client may issue expert descriptor

    # client tries to revoke — revocation requires {root, delegated}
    revocation = service.make_unsigned_revocation(rec.key, seq=1)
    with pytest.raises(ControlRecordError, match="requires authority"):
        service.put_signed(_signed(revocation, sk_cli, "cli"))
    assert service.get(rec.key) is not None  # still live

    # root can revoke
    service.put_signed(_signed(revocation, sk_root, "root"))
    assert service.get(rec.key) is None


def test_revocation_record_requires_target():
    with pytest.raises(ControlRecordError, match="revoked key"):
        ControlRecord(
            network_id="net",
            key="revocation/x",
            record_type=RECORD_TYPE_REVOCATION,
            seq=1,
            issued_at=1000.0,
            expires_at=2000.0,
            value={},
        ).validate()


# --------------------------------------------------------------------------- #
# seq rollback
# --------------------------------------------------------------------------- #


def test_seq_rollback_rejected():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    expert = ExpertDescriptor(expert_id="e", pools=("monet.expert~tenet",), manifest_ref="m")
    service.put_signed(_signed(service.make_unsigned_expert_descriptor(expert, seq=5), sk, "root"))
    with pytest.raises(ControlRecordError, match="seq did not advance"):
        service.put_signed(_signed(service.make_unsigned_expert_descriptor(expert, seq=3), sk, "root"))
    # equal seq also rejected
    with pytest.raises(ControlRecordError, match="seq did not advance"):
        service.put_signed(_signed(service.make_unsigned_expert_descriptor(expert, seq=5), sk, "root"))


# --------------------------------------------------------------------------- #
# expiry
# --------------------------------------------------------------------------- #


def test_expired_record_rejected_on_put():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    record = _record(now=1000.0, ttl=10.0)  # expires at 1010
    signed = _signed(record, sk, "root")
    with pytest.raises(ControlRecordError, match="expired"):
        service.put_signed(signed, now=2000.0)


def test_record_disappears_from_get_after_expiry():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    # trust_pointer is not descriptor-parsed, so this isolates the expiry property.
    record = _record(
        record_type=RECORD_TYPE_TRUST_POINTER,
        key="trust/pointer",
        value={"ok": "1"},
        now=1000.0,
        ttl=100.0,
    )  # expires at 1100
    service.put_signed(_signed(record, sk, "root"), now=1000.0)
    assert service.get(record.key, now=1050.0) is not None
    assert service.get(record.key, now=1200.0) is None


# --------------------------------------------------------------------------- #
# wrong network
# --------------------------------------------------------------------------- #


def test_wrong_network_rejected():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    record = _record(network_id="other-net")
    signed = _signed(record, sk, "root")
    with pytest.raises(ControlRecordError, match="network_id mismatch"):
        service.put_signed(signed)


# --------------------------------------------------------------------------- #
# unknown schema / record type
# --------------------------------------------------------------------------- #


def test_unknown_record_type_has_no_policy_and_is_rejected():
    sk, vk = _keypair()
    policy = TrustPolicy(verify_keys={"root": vk}, key_authorities={"root": "root"})
    record = _record(record_type="totally_made_up_type", key="x/y")
    signed = _signed(record, sk, "root")
    with pytest.raises(ControlRecordError, match="no trust policy"):
        validate_record_policy(signed, policy)


def test_unsupported_control_record_schema_rejected():
    with pytest.raises(ControlRecordError, match="schema"):
        ControlRecord(
            network_id="net",
            key="x/y",
            record_type=RECORD_TYPE_EXPERT_DESCRIPTOR,
            seq=1,
            issued_at=1000.0,
            expires_at=2000.0,
            value={},
            schema="bogus.schema",
        ).validate()


def test_every_known_record_type_has_a_policy_entry():
    """Guard: if a new record type is added without a policy entry it must fail
    closed, not be silently accepted. This proves the default policy covers the
    record types the service indexes."""
    from tenet.mixnet.control import records as rec_mod

    indexed_types = {
        rec_mod.RECORD_TYPE_NAME_DESCRIPTOR,
        rec_mod.RECORD_TYPE_CLIENT_ADVERTISEMENT,
        rec_mod.RECORD_TYPE_POOL_DESCRIPTOR,
        rec_mod.RECORD_TYPE_EXPERT_DESCRIPTOR,
        rec_mod.RECORD_TYPE_TOPIC_DESCRIPTOR,
        rec_mod.RECORD_TYPE_REVIEW_DESCRIPTOR,
        rec_mod.RECORD_TYPE_MIXNODE_DESCRIPTOR,
        rec_mod.RECORD_TYPE_MATCH_RESULT,
        rec_mod.RECORD_TYPE_TRUST_UPDATE,
        rec_mod.RECORD_TYPE_SOFTWARE_IDENTITY,
        rec_mod.RECORD_TYPE_ATTESTATION_RECEIPT,
        rec_mod.RECORD_TYPE_MIXNET_ROUTING,
        rec_mod.RECORD_TYPE_REACHABILITY_ASSIST,
        rec_mod.RECORD_TYPE_REVOCATION,
    }
    missing = indexed_types - set(DEFAULT_RECORD_POLICY)
    assert not missing, f"record types missing a policy entry: {missing}"


# --------------------------------------------------------------------------- #
# oversized DHT payload
# --------------------------------------------------------------------------- #


class _DummyOverlay:
    """Stand-in overlay so the service enforces the DHT size bound on put."""

    def __init__(self):
        self.published = []

    def publish(self, key, signed):
        self.published.append(key)

    def fetch(self, key):
        return None


def test_oversized_record_rejected_when_overlay_attached():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    service._kademlia_overlay = _DummyOverlay()
    # trust_pointer has no descriptor parsing branch, so a big opaque blob is fine
    # structurally but exceeds the DHT byte bound.
    blob = "x" * (MAX_SIGNED_CONTROL_RECORD_BYTES + 1024)
    record = _record(record_type=RECORD_TYPE_TRUST_POINTER, key="trust/pointer", value={"blob": blob})
    signed = _signed(record, sk, "root")
    with pytest.raises(ControlRecordError, match="maximum size"):
        service.put_signed(signed)
    # rejected before publish
    assert service._kademlia_overlay.published == []


def test_normal_sized_record_publishes_to_attached_overlay():
    sk, vk = _keypair()
    service = MixnetControlService(network_id="net", verify_keys={"root": vk})
    overlay = _DummyOverlay()
    service._kademlia_overlay = overlay
    record = _record(record_type=RECORD_TYPE_TRUST_POINTER, key="trust/pointer", value={"ok": "1"})
    service.put_signed(_signed(record, sk, "root"))
    assert overlay.published == ["trust/pointer"]
