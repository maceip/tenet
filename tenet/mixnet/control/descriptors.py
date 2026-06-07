"""Expert/topic/review descriptors for mixnet-bonded discovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping

from tenet.handles import is_opaque_handle
from tenet.mixnet.control.names import parse_tenet_name
from tenet.mixnet.control.records import (
    ControlRecord,
    RECORD_TYPE_ATTESTATION_RECEIPT,
    RECORD_TYPE_CONTROL_DHT_PEER,
    RECORD_TYPE_EXPERT_DESCRIPTOR,
    RECORD_TYPE_HANDLE_ADDRESS,
    RECORD_TYPE_MATCHER_CAPABILITY,
    RECORD_TYPE_MIXNET_ROUTING,
    RECORD_TYPE_REACHABILITY_ASSIST,
    RECORD_TYPE_REVIEW_DESCRIPTOR,
    RECORD_TYPE_SOFTWARE_IDENTITY,
    RECORD_TYPE_TOPIC_DESCRIPTOR,
    RECORD_TYPE_TRUST_UPDATE,
)
from tenet.protocol_invariants import (
    reject_expertise_pool,
    reject_routeable_string,
)

MATCHER_TRUST_TIERS = frozenset({"tee", "authority_pinned", "non_tee_signed"})

EXPERT_DESCRIPTOR_SCHEMA = "tenet.expert_descriptor.2026-06"
TOPIC_DESCRIPTOR_SCHEMA = "tenet.topic_descriptor.2026-06"
REVIEW_DESCRIPTOR_SCHEMA = "tenet.review_descriptor.2026-06"


@dataclass(frozen=True)
class ExpertDescriptor:
    """Public expert metadata.

    Live reachability is still through mixnet descriptors and opaque handles; this
    record describes what an expert claims to know and which pool records it is
    willing to serve.
    """

    expert_id: str
    pools: tuple[str, ...]
    manifest_ref: str
    topic_refs: tuple[str, ...] = ()
    claim_refs: tuple[str, ...] = ()
    reputation_refs: tuple[str, ...] = ()
    schema: str = EXPERT_DESCRIPTOR_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "ExpertDescriptor":
        return cls(
            expert_id=str(raw.get("expert_id", "")),
            pools=tuple(str(item) for item in raw.get("pools", ()) or ()),
            manifest_ref=str(raw.get("manifest_ref", "")),
            topic_refs=tuple(str(item) for item in raw.get("topic_refs", ()) or ()),
            claim_refs=tuple(str(item) for item in raw.get("claim_refs", ()) or ()),
            reputation_refs=tuple(str(item) for item in raw.get("reputation_refs", ()) or ()),
            schema=str(raw.get("schema", EXPERT_DESCRIPTOR_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"expert/{self.expert_id}/descriptor"

    def validate(self) -> None:
        if self.schema != EXPERT_DESCRIPTOR_SCHEMA:
            raise ValueError(f"unsupported expert descriptor schema: {self.schema}")
        if not self.expert_id:
            raise ValueError("expert_id is required")
        if not self.pools:
            raise ValueError("expert descriptor requires at least one pool")
        if not self.manifest_ref:
            raise ValueError("manifest_ref is required")
        for pool in self.pools:
            parsed = parse_tenet_name(pool)
            if parsed.normalized != pool or parsed.kind != "pool":
                raise ValueError("expert pools must be normalized pool Tenet names")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(
        self,
        *,
        network_id: str,
        seq: int,
        issued_at: float,
        expires_at: float,
    ) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_EXPERT_DESCRIPTOR,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


@dataclass(frozen=True)
class TopicDescriptor:
    name: str
    tags: tuple[str, ...]
    parent_ref: str | None = None
    claim_refs: tuple[str, ...] = ()
    schema: str = TOPIC_DESCRIPTOR_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "TopicDescriptor":
        return cls(
            name=str(raw.get("name", "")),
            tags=tuple(str(item) for item in raw.get("tags", ()) or ()),
            parent_ref=_optional_str(raw.get("parent_ref")),
            claim_refs=tuple(str(item) for item in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", TOPIC_DESCRIPTOR_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"topic/{self.name}/descriptor"

    def validate(self) -> None:
        if self.schema != TOPIC_DESCRIPTOR_SCHEMA:
            raise ValueError(f"unsupported topic descriptor schema: {self.schema}")
        if not self.name:
            raise ValueError("topic name is required")
        if "/" in self.name:
            raise ValueError("topic name must not contain /")
        if not self.tags:
            raise ValueError("topic descriptor requires tags")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(
        self,
        *,
        network_id: str,
        seq: int,
        issued_at: float,
        expires_at: float,
    ) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_TOPIC_DESCRIPTOR,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


@dataclass(frozen=True)
class ReviewDescriptor:
    review_id: str
    subject_ref: str
    reviewer_ref: str
    rating: int | None = None
    claim_refs: tuple[str, ...] = ()
    reputation_refs: tuple[str, ...] = ()
    schema: str = REVIEW_DESCRIPTOR_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "ReviewDescriptor":
        rating = raw.get("rating")
        return cls(
            review_id=str(raw.get("review_id", "")),
            subject_ref=str(raw.get("subject_ref", "")),
            reviewer_ref=str(raw.get("reviewer_ref", "")),
            rating=int(rating) if rating is not None else None,
            claim_refs=tuple(str(item) for item in raw.get("claim_refs", ()) or ()),
            reputation_refs=tuple(str(item) for item in raw.get("reputation_refs", ()) or ()),
            schema=str(raw.get("schema", REVIEW_DESCRIPTOR_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"review/{self.review_id}/descriptor"

    def validate(self) -> None:
        if self.schema != REVIEW_DESCRIPTOR_SCHEMA:
            raise ValueError(f"unsupported review descriptor schema: {self.schema}")
        if not self.review_id:
            raise ValueError("review_id is required")
        if not self.subject_ref:
            raise ValueError("subject_ref is required")
        if not self.reviewer_ref:
            raise ValueError("reviewer_ref is required")
        if self.rating is not None and not 1 <= self.rating <= 5:
            raise ValueError("review rating must be between 1 and 5")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(
        self,
        *,
        network_id: str,
        seq: int,
        issued_at: float,
        expires_at: float,
    ) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_REVIEW_DESCRIPTOR,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


# --- New required record families for real control overlay (per spec) ---

ATTESTATION_RECEIPT_SCHEMA = "tenet.attestation_receipt.2026-06"
SOFTWARE_IDENTITY_SCHEMA = "tenet.software_identity.2026-06"
TRUST_UPDATE_SCHEMA = "tenet.trust_update.2026-06"
MIXNET_ROUTING_SCHEMA = "tenet.mixnet_routing_descriptor.2026-06"
REACHABILITY_ASSIST_SCHEMA = "tenet.reachability_assist_descriptor.2026-06"


@dataclass(frozen=True)
class AttestationReceiptDescriptor:
    """TEE/code attestation receipt as signed control record.

    Proves a measurement (PCR, code hash, etc.) at a point in time for a node/capability.
    TEE proves commitment, not behavioral quality (room for later reputation/claim refs).
    Must not contain direct endpoints.
    """

    receipt_id: str
    subject_node_id: str
    measurement: str  # e.g. PCR0 or code hash or TEE measurement
    code_identity_ref: str | None = None
    issued_by: str | None = None
    claim_refs: tuple[str, ...] = ()
    schema: str = ATTESTATION_RECEIPT_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "AttestationReceiptDescriptor":
        return cls(
            receipt_id=str(raw.get("receipt_id", "")),
            subject_node_id=str(raw.get("subject_node_id", "")),
            measurement=str(raw.get("measurement", "")),
            code_identity_ref=_optional_str(raw.get("code_identity_ref")),
            issued_by=_optional_str(raw.get("issued_by")),
            claim_refs=tuple(str(x) for x in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", ATTESTATION_RECEIPT_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"attestation/{self.subject_node_id}/{self.receipt_id}"

    def validate(self) -> None:
        if self.schema != ATTESTATION_RECEIPT_SCHEMA:
            raise ValueError(f"unsupported attestation receipt schema: {self.schema}")
        if not self.receipt_id or not self.subject_node_id or not self.measurement:
            raise ValueError("attestation receipt requires id, subject, and measurement")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_ATTESTATION_RECEIPT,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


@dataclass(frozen=True)
class SoftwareIdentityDescriptor:
    """Code/software identity record (binary hash, build id, etc.)."""

    identity_id: str
    code_hash: str
    version: str | None = None
    build_ref: str | None = None
    claim_refs: tuple[str, ...] = ()
    schema: str = SOFTWARE_IDENTITY_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "SoftwareIdentityDescriptor":
        return cls(
            identity_id=str(raw.get("identity_id", "")),
            code_hash=str(raw.get("code_hash", "")),
            version=_optional_str(raw.get("version")),
            build_ref=_optional_str(raw.get("build_ref")),
            claim_refs=tuple(str(x) for x in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", SOFTWARE_IDENTITY_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"software/{self.identity_id}"

    def validate(self) -> None:
        if self.schema != SOFTWARE_IDENTITY_SCHEMA:
            raise ValueError(f"unsupported software identity schema: {self.schema}")
        if not self.identity_id or not self.code_hash:
            raise ValueError("software identity requires id and code_hash")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_SOFTWARE_IDENTITY,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


@dataclass(frozen=True)
class TrustUpdateDescriptor:
    """Signed trust/update record for root keys, code measurements, TEE policies.

    After join-pack bootstrap, clients learn current trust state from these gossiped
    signed records (key rotation, new approved code hashes, TEE measurements).
    Clients must fail closed on bad sigs or unrecognized required measurements.
    """

    update_id: str
    issuer: str
    policy: str
    added_roots: tuple[str, ...] = ()
    removed_roots: tuple[str, ...] = ()
    approved_code_hashes: tuple[str, ...] = ()
    approved_tee_measurements: tuple[str, ...] = ()
    claim_refs: tuple[str, ...] = ()
    schema: str = TRUST_UPDATE_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "TrustUpdateDescriptor":
        return cls(
            update_id=str(raw.get("update_id", "")),
            issuer=str(raw.get("issuer", "")),
            policy=str(raw.get("policy", "")),
            added_roots=tuple(str(x) for x in raw.get("added_roots", ()) or ()),
            removed_roots=tuple(str(x) for x in raw.get("removed_roots", ()) or ()),
            approved_code_hashes=tuple(str(x) for x in raw.get("approved_code_hashes", ()) or ()),
            approved_tee_measurements=tuple(str(x) for x in raw.get("approved_tee_measurements", ()) or ()),
            claim_refs=tuple(str(x) for x in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", TRUST_UPDATE_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"trust/update/{self.update_id}"

    def validate(self) -> None:
        if self.schema != TRUST_UPDATE_SCHEMA:
            raise ValueError(f"unsupported trust update schema: {self.schema}")
        if not self.update_id or not self.issuer or not self.policy:
            raise ValueError("trust update requires id, issuer, policy")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_TRUST_UPDATE,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


@dataclass(frozen=True)
class MixnetRoutingDescriptor:
    """Mixnet routing descriptor (for control-plane mixnode participation)."""

    node_id: str
    node_key: str
    capabilities: tuple[str, ...] = ()
    claim_refs: tuple[str, ...] = ()
    schema: str = MIXNET_ROUTING_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "MixnetRoutingDescriptor":
        return cls(
            node_id=str(raw.get("node_id", "")),
            node_key=str(raw.get("node_key", "")),
            capabilities=tuple(str(x) for x in raw.get("capabilities", ()) or ()),
            claim_refs=tuple(str(x) for x in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", MIXNET_ROUTING_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"mixnet/routing/{self.node_id}"

    def validate(self) -> None:
        if self.schema != MIXNET_ROUTING_SCHEMA:
            raise ValueError(f"unsupported mixnet routing schema: {self.schema}")
        if not self.node_id or not self.node_key:
            raise ValueError("mixnet routing descriptor requires node_id and node_key")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_MIXNET_ROUTING,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


@dataclass(frozen=True)
class ReachabilityAssistDescriptor:
    """Reachability assistance (NAT relay, etc.) as a capability any node can offer.

    Policy-scoped and privacy-sensitive. Must not become "everyone talks to one relay".
    Clients use when first joining, behind NAT, or lacking working paths.
    Record carries opaque assist refs / policies, never raw direct dial info.
    """

    assist_id: str
    provider_node_id: str
    policy: str  # e.g. "nat-relay", "first-join-only", "privacy-tier-X"
    privacy_notes: str | None = None
    opaque_refs: tuple[str, ...] = ()
    claim_refs: tuple[str, ...] = ()
    schema: str = REACHABILITY_ASSIST_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "ReachabilityAssistDescriptor":
        return cls(
            assist_id=str(raw.get("assist_id", "")),
            provider_node_id=str(raw.get("provider_node_id", "")),
            policy=str(raw.get("policy", "")),
            privacy_notes=_optional_str(raw.get("privacy_notes")),
            opaque_refs=tuple(str(x) for x in raw.get("opaque_refs", ()) or ()),
            claim_refs=tuple(str(x) for x in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", REACHABILITY_ASSIST_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"reachability/assist/{self.assist_id}"

    def validate(self) -> None:
        if self.schema != REACHABILITY_ASSIST_SCHEMA:
            raise ValueError(f"unsupported reachability assist schema: {self.schema}")
        if not self.assist_id or not self.provider_node_id or not self.policy:
            raise ValueError("reachability assist requires id, provider, policy")
        # A reachability assist is a NAT/relay capability. It must never leak
        # which expertise pool a handle serves, and its opaque refs must not
        # become direct dial instructions.
        for ref in self.opaque_refs:
            reject_routeable_string(ref, field="reachability assist opaque_ref")
            reject_expertise_pool(ref, field="reachability assist opaque_ref")
        reject_expertise_pool(self.policy, field="reachability assist policy")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_REACHABILITY_ASSIST,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
        )


# --- Anti-leak descriptors that bind discovery without exposing routes --- #

MATCHER_CAPABILITY_SCHEMA = "tenet.matcher_capability.2026-06"
HANDLE_ADDRESS_SCHEMA = "tenet.handle_address.2026-06"
CONTROL_DHT_PEER_SCHEMA = "tenet.control_dht_peer.2026-06"


@dataclass(frozen=True)
class MatcherCapabilityDescriptor:
    """What a matcher offers, with the trust evidence needed to use it.

    This is the record a client resolves to choose a matcher. It must let the
    client verify result signatures and trust tier *without* exposing a public
    expertise->route mapping: the matcher is reached via an opaque handle or an
    opaque endpoint ref, never a dialable address.
    """

    matcher_id: str
    pools: tuple[str, ...]
    trust_tier: str  # "tee" | "authority_pinned" | "non_tee_signed"
    result_signing_key: str
    query_endpoint_ref: str | None = None
    matcher_handle: str | None = None
    attestation_ref: str | None = None
    code_identity: str | None = None
    dataset_commitment: str | None = None
    privacy_policy: str | None = None
    expires_at: float | None = None
    schema: str = MATCHER_CAPABILITY_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "MatcherCapabilityDescriptor":
        expires_at = raw.get("expires_at")
        return cls(
            matcher_id=str(raw.get("matcher_id", "")),
            pools=tuple(str(x) for x in raw.get("pools", ()) or ()),
            trust_tier=str(raw.get("trust_tier", "")),
            result_signing_key=str(raw.get("result_signing_key", "")),
            query_endpoint_ref=_optional_str(raw.get("query_endpoint_ref")),
            matcher_handle=_optional_str(raw.get("matcher_handle")),
            attestation_ref=_optional_str(raw.get("attestation_ref")),
            code_identity=_optional_str(raw.get("code_identity")),
            dataset_commitment=_optional_str(raw.get("dataset_commitment")),
            privacy_policy=_optional_str(raw.get("privacy_policy")),
            expires_at=float(expires_at) if expires_at is not None else None,
            schema=str(raw.get("schema", MATCHER_CAPABILITY_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"matcher/{self.matcher_id}/capability"

    def validate(self) -> None:
        if self.schema != MATCHER_CAPABILITY_SCHEMA:
            raise ValueError(f"unsupported matcher capability schema: {self.schema}")
        if not self.matcher_id:
            raise ValueError("matcher capability requires matcher_id")
        if not self.pools:
            raise ValueError("matcher capability requires at least one pool")
        for pool in self.pools:
            parsed = parse_tenet_name(pool)
            if parsed.normalized != pool or parsed.kind != "pool":
                raise ValueError("matcher capability pools must be normalized pool names")
        if self.trust_tier not in MATCHER_TRUST_TIERS:
            raise ValueError(f"unsupported matcher trust tier: {self.trust_tier!r}")
        if not self.result_signing_key:
            raise ValueError("matcher capability requires result_signing_key")
        # Exactly one reachability reference, and it must be opaque.
        if bool(self.query_endpoint_ref) == bool(self.matcher_handle):
            raise ValueError(
                "matcher capability requires exactly one of query_endpoint_ref or matcher_handle"
            )
        if self.matcher_handle is not None and not is_opaque_handle(self.matcher_handle):
            raise ValueError("matcher_handle must be an opaque handle")
        if self.query_endpoint_ref is not None:
            reject_routeable_string(self.query_endpoint_ref, field="matcher query_endpoint_ref")
        # Trust-tier evidence requirements (defense in depth; the matcher resolver
        # enforces the same rules at selection time).
        if self.trust_tier == "tee" and not self.attestation_ref:
            raise ValueError("tee matcher capability requires attestation_ref")
        if self.trust_tier == "non_tee_signed":
            if not self.code_identity:
                raise ValueError("non_tee_signed matcher capability requires code_identity")
            if not self.dataset_commitment:
                raise ValueError("non_tee_signed matcher capability requires dataset_commitment")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_MATCHER_CAPABILITY,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
            subject_id=self.matcher_id,
        )


@dataclass(frozen=True)
class HandleAddressRecord:
    """Binds an opaque handle to a set of opaque route/assist references.

    The whole point of the handle layer is that the asker never learns a dialable
    address for the answerer. This record carries only opaque references (assist
    ids, mix-path node ids); resolving them to a live path is the reachability
    resolver's job and still goes through mailbox/peer-address resolution.
    """

    handle: str
    route_candidates: tuple[str, ...] = ()
    assist_refs: tuple[str, ...] = ()
    direct_allowed: bool = False
    issued_at: float = 0.0
    expires_at: float = 0.0
    signer: str = ""
    schema: str = HANDLE_ADDRESS_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "HandleAddressRecord":
        return cls(
            handle=str(raw.get("handle", "")),
            route_candidates=tuple(str(x) for x in raw.get("route_candidates", ()) or ()),
            assist_refs=tuple(str(x) for x in raw.get("assist_refs", ()) or ()),
            direct_allowed=bool(raw.get("direct_allowed", False)),
            issued_at=float(raw.get("issued_at", 0.0)),
            expires_at=float(raw.get("expires_at", 0.0)),
            signer=str(raw.get("signer", "")),
            schema=str(raw.get("schema", HANDLE_ADDRESS_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"handle/{self.handle}/address"

    def validate(self) -> None:
        if self.schema != HANDLE_ADDRESS_SCHEMA:
            raise ValueError(f"unsupported handle address schema: {self.schema}")
        if not is_opaque_handle(self.handle):
            raise ValueError("handle address record requires an opaque handle")
        if not self.signer:
            raise ValueError("handle address record requires a signer")
        if self.expires_at <= self.issued_at:
            raise ValueError("handle address expires_at must be after issued_at")
        for ref in self.route_candidates:
            if not ref:
                raise ValueError("handle address route_candidate must be non-empty")
            reject_routeable_string(ref, field="handle address route_candidate")
            reject_expertise_pool(ref, field="handle address route_candidate")
        for ref in self.assist_refs:
            reject_routeable_string(ref, field="handle address assist_ref")
            reject_expertise_pool(ref, field="handle address assist_ref")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_HANDLE_ADDRESS,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
            subject_id=self.handle,
        )


@dataclass(frozen=True)
class ControlDhtPeerDescriptor:
    """Names a control-DHT peer for sync/discovery — without a dialable address.

    Item 4 syncs from DHT-discovered control peers; this is the record it
    discovers. It carries the peer identity and capabilities so reachability can
    be resolved separately (peer-address/mixnet), never a raw endpoint.
    """

    peer_id: str
    node_key: str
    capabilities: tuple[str, ...] = ()
    region_hint: str | None = None
    claim_refs: tuple[str, ...] = ()
    schema: str = CONTROL_DHT_PEER_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "ControlDhtPeerDescriptor":
        return cls(
            peer_id=str(raw.get("peer_id", "")),
            node_key=str(raw.get("node_key", "")),
            capabilities=tuple(str(x) for x in raw.get("capabilities", ()) or ()),
            region_hint=_optional_str(raw.get("region_hint")),
            claim_refs=tuple(str(x) for x in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", CONTROL_DHT_PEER_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"control_dht/peer/{self.peer_id}"

    def validate(self) -> None:
        if self.schema != CONTROL_DHT_PEER_SCHEMA:
            raise ValueError(f"unsupported control dht peer schema: {self.schema}")
        if not self.peer_id or not self.node_key:
            raise ValueError("control dht peer requires peer_id and node_key")
        reject_routeable_string(self.peer_id, field="control dht peer_id")
        if self.region_hint is not None:
            reject_routeable_string(self.region_hint, field="control dht region_hint")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    def to_record(self, *, network_id: str, seq: int, issued_at: float, expires_at: float) -> ControlRecord:
        return ControlRecord(
            network_id=network_id,
            key=self.key,
            record_type=RECORD_TYPE_CONTROL_DHT_PEER,
            seq=seq,
            issued_at=issued_at,
            expires_at=expires_at,
            value=self.to_dict(),
            subject_id=self.peer_id,
        )
