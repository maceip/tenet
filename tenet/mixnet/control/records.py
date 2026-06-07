"""Signed control records for mixnet-bonded gossip/DHT storage."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import time
from typing import Literal, Mapping, Sequence

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

CONTROL_RECORD_SCHEMA = "tenet.mixnet.control.record.2026-06"
SIGNED_CONTROL_RECORD_SCHEMA = "tenet.mixnet.control.signed_record.2026-06"

# Authority classes a signing key can hold. Policy (see control/policy.py) maps
# each record_type to the authority classes permitted to issue it, so a client
# key can never mint a trust update and a non-TEE key can never mint a record
# that claims TEE provenance.
AuthorityClass = Literal["root", "tee", "client", "delegated", "non_tee_matcher"]
AUTHORITY_CLASSES: frozenset[str] = frozenset(
    {"root", "tee", "client", "delegated", "non_tee_matcher"}
)

RECORD_TYPE_NAME_DESCRIPTOR = "name_descriptor"
RECORD_TYPE_CLIENT_ADVERTISEMENT = "client_advertisement"
RECORD_TYPE_POOL_DESCRIPTOR = "pool_descriptor"
RECORD_TYPE_EXPERT_DESCRIPTOR = "expert_descriptor"
RECORD_TYPE_TOPIC_DESCRIPTOR = "topic_descriptor"
RECORD_TYPE_REVIEW_DESCRIPTOR = "review_descriptor"
RECORD_TYPE_TRUST_POINTER = "trust_pointer"
RECORD_TYPE_TRUST_UPDATE = "trust_update"
RECORD_TYPE_PEER_MANIFEST = "peer_manifest"
RECORD_TYPE_MIXNODE_DESCRIPTOR = "mixnode_descriptor"
RECORD_TYPE_MIXNET_ROUTING = "mixnet_routing_descriptor"
RECORD_TYPE_REACHABILITY_ASSIST = "reachability_assist_descriptor"
RECORD_TYPE_SOFTWARE_IDENTITY = "software_identity"
RECORD_TYPE_ATTESTATION_RECEIPT = "attestation_receipt"
RECORD_TYPE_REVOCATION = "revocation"
RECORD_TYPE_MATCHER_CAPABILITY = "matcher_capability"
RECORD_TYPE_HANDLE_ADDRESS = "handle_address"
RECORD_TYPE_CONTROL_DHT_PEER = "control_dht_peer"

# Maximum size for a serialized SignedControlRecord when stored/fetched via the
# control DHT (Kademlia). This is a safety bound because the overlay uses UDP
# and we do not want huge records to cause transport or parsing issues.
MAX_SIGNED_CONTROL_RECORD_BYTES = 32 * 1024  # 32 KiB
RECORD_TYPE_MATCH_RESULT = "match_result"


class ControlRecordError(ValueError):
    """Raised when a signed control-plane record is invalid."""


@dataclass(frozen=True)
class ControlRecord:
    """Unsigned canonical control-plane value.

    Values are public metadata for discovery and routing policy. They are not
    transport endpoints; validation rejects fields that would turn control-plane
    names into direct dial instructions.
    """

    network_id: str
    key: str
    record_type: str
    seq: int
    issued_at: float
    expires_at: float
    value: dict[str, object]
    # Identity/lineage fields. ``subject_id`` is the thing the record is *about*
    # (e.g. the matcher/handle/node id); ``issuer_id`` is the principal claiming
    # to issue it; ``supersedes`` and ``revokes`` reference other record keys.
    # They participate in the signed canonical bytes, so they cannot be forged
    # after signing.
    subject_id: str = ""
    issuer_id: str = ""
    supersedes: str | None = None
    revokes: str | None = None
    schema: str = CONTROL_RECORD_SCHEMA

    def validate(self) -> None:
        if self.schema != CONTROL_RECORD_SCHEMA:
            raise ControlRecordError(f"unsupported control record schema: {self.schema}")
        if not self.network_id:
            raise ControlRecordError("network_id is required")
        if not self.key:
            raise ControlRecordError("key is required")
        if self.seq < 0:
            raise ControlRecordError("seq must be non-negative")
        if self.expires_at <= self.issued_at:
            raise ControlRecordError("expires_at must be after issued_at")
        if self.supersedes is not None and not str(self.supersedes):
            raise ControlRecordError("supersedes, if set, must be a non-empty key")
        if self.record_type == RECORD_TYPE_REVOCATION and not self.revokes:
            raise ControlRecordError("revocation records must name the revoked key")
        if self.revokes is not None and not str(self.revokes):
            raise ControlRecordError("revokes, if set, must be a non-empty key")
        _reject_direct_dial_fields(self.value)

    def is_expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at

    def canonical_bytes(self) -> bytes:
        self.validate()
        return _canonical_json(asdict(self))

    def content_hash(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "ControlRecord":
        value = raw.get("value")
        if not isinstance(value, dict):
            raise ControlRecordError("control record value must be an object")
        supersedes = raw.get("supersedes")
        revokes = raw.get("revokes")
        record = cls(
            network_id=str(raw.get("network_id", "")),
            key=str(raw.get("key", "")),
            record_type=str(raw.get("record_type", "")),
            seq=int(raw.get("seq", 0)),
            issued_at=float(raw.get("issued_at", 0.0)),
            expires_at=float(raw.get("expires_at", 0.0)),
            value=dict(value),
            subject_id=str(raw.get("subject_id", "")),
            issuer_id=str(raw.get("issuer_id", "")),
            supersedes=str(supersedes) if supersedes else None,
            revokes=str(revokes) if revokes else None,
            schema=str(raw.get("schema", CONTROL_RECORD_SCHEMA)),
        )
        record.validate()
        return record


@dataclass(frozen=True)
class SignedControlRecord:
    record: ControlRecord
    signatures: tuple[dict[str, str], ...]
    schema: str = SIGNED_CONTROL_RECORD_SCHEMA

    def validate(
        self,
        *,
        verify_keys: Mapping[str, str | bytes],
        threshold: int = 1,
        now: float | None = None,
    ) -> None:
        if self.schema != SIGNED_CONTROL_RECORD_SCHEMA:
            raise ControlRecordError(f"unsupported signed record schema: {self.schema}")
        self.record.validate()
        if self.record.is_expired(now):
            raise ControlRecordError("control record expired")
        if threshold < 1:
            raise ControlRecordError("signature threshold must be positive")
        valid = 0
        seen: set[str] = set()
        payload = self.record.canonical_bytes()
        for sig in self.signatures:
            key_id = sig.get("key_id", "")
            sig_hex = sig.get("signature", "")
            if not key_id or key_id in seen or key_id not in verify_keys:
                continue
            if _verify_ed25519(verify_keys[key_id], payload, sig_hex):
                seen.add(key_id)
                valid += 1
        if valid < threshold:
            raise ControlRecordError("control record signature threshold not met")

    def valid_signer_ids(
        self,
        verify_keys: Mapping[str, str | bytes],
        *,
        now: float | None = None,
    ) -> frozenset[str]:
        """Return the set of key_ids whose signatures over this record verify.

        This is the authority-bearing primitive: policy decides what a record may
        assert based on *which* keys signed it, not merely that the signature
        threshold was met. Expired records yield no valid signers (fail closed).
        """

        if self.record.is_expired(now):
            return frozenset()
        payload = self.record.canonical_bytes()
        signers: set[str] = set()
        for sig in self.signatures:
            key_id = sig.get("key_id", "")
            sig_hex = sig.get("signature", "")
            if not key_id or key_id in signers or key_id not in verify_keys:
                continue
            if _verify_ed25519(verify_keys[key_id], payload, sig_hex):
                signers.add(key_id)
        return frozenset(signers)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "record": self.record.to_dict(),
            "signatures": list(self.signatures),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "SignedControlRecord":
        record_raw = raw.get("record")
        if not isinstance(record_raw, dict):
            raise ControlRecordError("signed control record requires record object")
        sigs = raw.get("signatures") or ()
        if not isinstance(sigs, Sequence):
            raise ControlRecordError("signatures must be a sequence")
        return cls(
            record=ControlRecord.from_dict(record_raw),
            signatures=tuple(dict(item) for item in sigs if isinstance(item, dict)),
            schema=str(raw.get("schema", SIGNED_CONTROL_RECORD_SCHEMA)),
        )


def sign_control_record(
    record: ControlRecord,
    *,
    signing_key_hex: str,
    key_id: str | None = None,
) -> SignedControlRecord:
    signing_key = SigningKey(bytes.fromhex(signing_key_hex))
    signature = signing_key.sign(record.canonical_bytes()).signature.hex()
    verify_hex = signing_key.verify_key.encode().hex()
    return SignedControlRecord(
        record=record,
        signatures=(
            {
                "key_id": key_id or verify_hex,
                "alg": "ed25519",
                "signature": signature,
            },
        ),
    )


def _verify_ed25519(key: str | bytes, payload: bytes, sig_hex: str) -> bool:
    key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
    try:
        VerifyKey(key_bytes).verify(payload, bytes.fromhex(sig_hex))
    except (BadSignatureError, ValueError):
        return False
    return True


def _canonical_json(raw: Mapping[str, object]) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reject_direct_dial_fields(value: Mapping[str, object]) -> None:
    forbidden = {
        "addr",
        "address",
        "addresses",
        "direct_addr",
        "direct_address",
        "endpoint",
        "endpoints",
        "host",
        "ip",
        "ip_address",
        "multiaddr",
        "multiaddrs",
        "port",
        "socket",
        "url",
    }
    found = sorted(key for key in value if key.lower() in forbidden)
    if found:
        raise ControlRecordError(
            "control records must not carry direct dial fields: " + ", ".join(found)
        )
    for item in value.values():
        if isinstance(item, Mapping):
            _reject_direct_dial_fields(item)
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            for nested in item:
                if isinstance(nested, Mapping):
                    _reject_direct_dial_fields(nested)


def signed_record_to_dht_bytes(signed: "SignedControlRecord") -> bytes:
    """Canonical compact JSON used as the value in the control DHT.

    Size of this bytes object is what we bound for Kademlia safety.
    """
    return json.dumps(signed.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
