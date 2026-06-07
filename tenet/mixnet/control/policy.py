"""Trust policy for signed control records.

Every discovered network fact has to be *policy-validated* before product code
acts on it. Signature verification alone proves a key signed the record; policy
decides whether that key was *allowed* to assert that record type. This closes
privilege-escalation gaps: a client key cannot mint a trust update, and a
non-TEE key cannot mint a record that claims TEE provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from tenet.mixnet.control.records import (
    AUTHORITY_CLASSES,
    AuthorityClass,
    ControlRecordError,
    RECORD_TYPE_ATTESTATION_RECEIPT,
    RECORD_TYPE_CLIENT_ADVERTISEMENT,
    RECORD_TYPE_CONTROL_DHT_PEER,
    RECORD_TYPE_EXPERT_DESCRIPTOR,
    RECORD_TYPE_HANDLE_ADDRESS,
    RECORD_TYPE_MATCH_RESULT,
    RECORD_TYPE_MATCHER_CAPABILITY,
    RECORD_TYPE_MIXNET_ROUTING,
    RECORD_TYPE_MIXNODE_DESCRIPTOR,
    RECORD_TYPE_NAME_DESCRIPTOR,
    RECORD_TYPE_PEER_MANIFEST,
    RECORD_TYPE_POOL_DESCRIPTOR,
    RECORD_TYPE_REACHABILITY_ASSIST,
    RECORD_TYPE_REVIEW_DESCRIPTOR,
    RECORD_TYPE_REVOCATION,
    RECORD_TYPE_SOFTWARE_IDENTITY,
    RECORD_TYPE_TOPIC_DESCRIPTOR,
    RECORD_TYPE_TRUST_POINTER,
    RECORD_TYPE_TRUST_UPDATE,
    SignedControlRecord,
)

# A RecordPolicy maps a record_type to the set of authority classes permitted to
# issue it.
RecordPolicy = Mapping[str, frozenset]

# ``root`` is the network's ultimate authority and may issue any record type. The
# per-type policy below therefore enumerates the *non-root* classes allowed for
# each type; a root signer always passes. This keeps the common single-operator
# deployment working (every key defaults to root authority) while letting
# hardened deployments classify keys as ``client``/``tee``/``non_tee_matcher`` and
# constrain exactly what those lower-authority keys can assert.
SUPERUSER_AUTHORITIES: frozenset = frozenset({"root"})

# Default authority assignment. The principle: the more a record can change about
# *trust* or *routing*, the higher the authority required to issue it.
#
#   root             network operator / authority root keys
#   delegated        keys an authority has delegated (e.g. join-pack issuers)
#   tee              keys whose provenance is a TEE attestation
#   non_tee_matcher  matcher keys without TEE backing (degraded trust)
#   client           ordinary client keys advertising themselves
DEFAULT_RECORD_POLICY: dict[str, frozenset] = {
    RECORD_TYPE_NAME_DESCRIPTOR: frozenset({"root", "delegated"}),
    RECORD_TYPE_CLIENT_ADVERTISEMENT: frozenset({"client", "tee", "delegated"}),
    RECORD_TYPE_POOL_DESCRIPTOR: frozenset({"root", "delegated"}),
    RECORD_TYPE_EXPERT_DESCRIPTOR: frozenset({"client", "tee", "delegated"}),
    RECORD_TYPE_TOPIC_DESCRIPTOR: frozenset({"root", "delegated"}),
    RECORD_TYPE_REVIEW_DESCRIPTOR: frozenset({"client", "delegated"}),
    RECORD_TYPE_TRUST_POINTER: frozenset({"root"}),
    RECORD_TYPE_TRUST_UPDATE: frozenset({"root"}),
    RECORD_TYPE_PEER_MANIFEST: frozenset({"root", "delegated"}),
    RECORD_TYPE_MIXNODE_DESCRIPTOR: frozenset({"root", "delegated", "tee"}),
    RECORD_TYPE_MIXNET_ROUTING: frozenset({"root", "delegated", "tee"}),
    RECORD_TYPE_REACHABILITY_ASSIST: frozenset({"root", "delegated", "tee", "client"}),
    RECORD_TYPE_SOFTWARE_IDENTITY: frozenset({"root", "delegated"}),
    RECORD_TYPE_ATTESTATION_RECEIPT: frozenset({"root", "tee"}),
    RECORD_TYPE_MATCH_RESULT: frozenset({"tee", "non_tee_matcher"}),
    RECORD_TYPE_REVOCATION: frozenset({"root", "delegated"}),
    RECORD_TYPE_MATCHER_CAPABILITY: frozenset(
        {"root", "delegated", "tee", "non_tee_matcher"}
    ),
    RECORD_TYPE_HANDLE_ADDRESS: frozenset({"root", "delegated", "tee", "client"}),
    RECORD_TYPE_CONTROL_DHT_PEER: frozenset({"root", "delegated", "tee"}),
}


@dataclass(frozen=True)
class TrustPolicy:
    """Authority map + record policy + resolver trust knobs.

    ``verify_keys`` and ``key_authorities`` share key_ids: the former carries the
    public key bytes used to check signatures, the latter the authority class the
    key holds. A key present in ``verify_keys`` but absent from
    ``key_authorities`` defaults to ``default_authority`` (operator keys are root
    unless classified otherwise) so existing deployments keep working while
    hardened deployments classify their keys explicitly.

    The resolver knobs (``allowed_trust_tiers``, ``allow_non_tee_signed``,
    ``max_staleness_seconds``) are consumed by control/resolvers.py and the
    matcher/reachability resolvers; they live here so there is a single trust
    policy object threaded through the whole control plane.
    """

    verify_keys: Mapping[str, str | bytes] = field(default_factory=dict)
    key_authorities: Mapping[str, AuthorityClass] = field(default_factory=dict)
    record_policy: RecordPolicy = field(default_factory=lambda: dict(DEFAULT_RECORD_POLICY))
    threshold: int = 1
    default_authority: AuthorityClass = "root"
    allowed_trust_tiers: frozenset = frozenset({"tee", "authority_pinned"})
    allow_non_tee_signed: bool = False
    max_staleness_seconds: float | None = None

    def __post_init__(self) -> None:
        for key_id, klass in self.key_authorities.items():
            if klass not in AUTHORITY_CLASSES:
                raise ControlRecordError(
                    f"unknown authority class for {key_id!r}: {klass!r}"
                )
        if self.default_authority not in AUTHORITY_CLASSES:
            raise ControlRecordError(
                f"unknown default authority class: {self.default_authority!r}"
            )

    def authority_of(self, key_id: str) -> AuthorityClass | None:
        """Authority class for a key_id, or None if the key is unknown."""

        if key_id in self.key_authorities:
            return self.key_authorities[key_id]
        if key_id in self.verify_keys:
            return self.default_authority
        return None

    def allowed_authorities(self, record_type: str) -> frozenset | None:
        return self.record_policy.get(record_type)

    @classmethod
    def from_verify_keys(
        cls,
        verify_keys: Mapping[str, str | bytes] | None,
        *,
        key_authorities: Mapping[str, AuthorityClass] | None = None,
        record_policy: RecordPolicy | None = None,
        threshold: int = 1,
        default_authority: AuthorityClass = "root",
        allowed_trust_tiers: frozenset = frozenset({"tee", "authority_pinned"}),
        allow_non_tee_signed: bool = False,
        max_staleness_seconds: float | None = None,
    ) -> "TrustPolicy":
        return cls(
            verify_keys=dict(verify_keys or {}),
            key_authorities=dict(key_authorities or {}),
            record_policy=dict(record_policy) if record_policy is not None else dict(DEFAULT_RECORD_POLICY),
            threshold=threshold,
            default_authority=default_authority,
            allowed_trust_tiers=allowed_trust_tiers,
            allow_non_tee_signed=allow_non_tee_signed,
            max_staleness_seconds=max_staleness_seconds,
        )


def validate_record_policy(
    signed: SignedControlRecord,
    trust_policy: TrustPolicy,
    *,
    now: float | None = None,
) -> frozenset:
    """Reject a signed record whose signer is not authorized for its type.

    Returns the set of authority classes the record's valid signers hold (a
    subset of the allowed set). Raises :class:`ControlRecordError` if:

    * the record type has no policy entry (unknown / unsupported schema), or
    * no valid signature comes from a key authorized for that record type, or
    * the record names an ``issuer_id`` that is a known key which did not sign
      (i.e. someone is impersonating a higher-authority issuer).

    This must run *after* signature/TTL/network/seq validation so that
    ``valid_signer_ids`` already reflects fresh, well-formed signatures.
    """

    record = signed.record
    allowed = trust_policy.allowed_authorities(record.record_type)
    if allowed is None:
        raise ControlRecordError(
            f"no trust policy for record type: {record.record_type!r}"
        )

    valid_signers = signed.valid_signer_ids(trust_policy.verify_keys, now=now)
    if not valid_signers:
        raise ControlRecordError("control record has no valid authorized signer")

    signer_classes = {
        trust_policy.authority_of(key_id) for key_id in valid_signers
    }
    signer_classes.discard(None)
    # Root is a superuser: it may issue any record type.
    permitted = signer_classes & (set(allowed) | SUPERUSER_AUTHORITIES)
    if not permitted:
        raise ControlRecordError(
            f"record type {record.record_type!r} requires authority "
            f"{sorted(allowed)}, signers held {sorted(c for c in signer_classes)}"
        )

    # Anti-impersonation: if the record claims an issuer_id that is itself a
    # known key, that key must be among the valid signers. Stops a client key
    # from claiming issuer_id=<root key> while signing with its own key.
    issuer_id = record.issuer_id
    if issuer_id and issuer_id in trust_policy.verify_keys and issuer_id not in valid_signers:
        raise ControlRecordError(
            f"record claims issuer_id {issuer_id!r} that did not sign it"
        )

    return frozenset(permitted)
