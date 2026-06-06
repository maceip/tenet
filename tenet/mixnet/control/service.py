"""In-memory service for mixnet control-plane records."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Mapping, Sequence

from tenet.mixnet.control.advertisement import CapabilityDescriptor, ClientAdvertisement
from tenet.mixnet.control.dht import ControlDhtPeer, ControlDhtPlan, replication_plan
from tenet.mixnet.control.descriptors import (
    AttestationReceiptDescriptor,
    ExpertDescriptor,
    MixnetRoutingDescriptor,
    ReachabilityAssistDescriptor,
    ReviewDescriptor,
    SoftwareIdentityDescriptor,
    TopicDescriptor,
    TrustUpdateDescriptor,
)
from tenet.mixnet.control.match_result import MatchResultDescriptor
from tenet.mixnet.control.mixnode import MixnodeDescriptor
from tenet.mixnet.control.names import NAME_KIND_POOL, NAME_KIND_STABLE, TenetName, parse_tenet_name
from tenet.mixnet.control.pools import PoolDescriptor
from tenet.mixnet.control.records import (
    ControlRecord,
    ControlRecordError,
    RECORD_TYPE_ATTESTATION_RECEIPT,
    RECORD_TYPE_CLIENT_ADVERTISEMENT,
    RECORD_TYPE_EXPERT_DESCRIPTOR,
    RECORD_TYPE_MATCH_RESULT,
    RECORD_TYPE_MIXNET_ROUTING,
    RECORD_TYPE_MIXNODE_DESCRIPTOR,
    RECORD_TYPE_NAME_DESCRIPTOR,
    RECORD_TYPE_POOL_DESCRIPTOR,
    RECORD_TYPE_REACHABILITY_ASSIST,
    RECORD_TYPE_REVIEW_DESCRIPTOR,
    RECORD_TYPE_SOFTWARE_IDENTITY,
    RECORD_TYPE_TOPIC_DESCRIPTOR,
    RECORD_TYPE_TRUST_UPDATE,
    SignedControlRecord,
)
from tenet.mixnet.control.store import PersistentControlStore


class RouteBindingError(ValueError):
    """Raised when a control-plane name cannot produce a mixnet route binding."""


@dataclass(frozen=True)
class MixnetRouteBinding:
    """Control-plane output consumed by the existing mixnet route planner.

    This deliberately has no host, port, URL, or multiaddr fields.
    """

    name: str
    name_kind: str
    transport: str
    requested_expertise: str | None = None
    pool_name: str | None = None
    opaque_handle: str | None = None
    mix_path: tuple[str, ...] = ()
    descriptor_hash: str | None = None
    direct_dial_allowed: bool = False

    @property
    def relay_path(self) -> tuple[str, ...]:
        """Compatibility alias for legacy descriptors."""

        return self.mix_path

    def validate(self) -> None:
        if self.transport != "mixnet":
            raise RouteBindingError("route bindings must use mixnet transport")
        if self.direct_dial_allowed:
            raise RouteBindingError("direct dial route bindings are not allowed")
        _validate_binding_mix_path(self.mix_path, exit_handle=self.opaque_handle)
        if self.name_kind == NAME_KIND_POOL and not self.requested_expertise:
            raise RouteBindingError("pool route bindings require requested_expertise")
        if self.name_kind == NAME_KIND_STABLE and not self.opaque_handle:
            raise RouteBindingError("stable route bindings require an opaque handle")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "name": self.name,
            "name_kind": self.name_kind,
            "transport": self.transport,
            "requested_expertise": self.requested_expertise,
            "pool_name": self.pool_name,
            "opaque_handle": self.opaque_handle,
            "mix_path": list(self.mix_path),
            "descriptor_hash": self.descriptor_hash,
            "direct_dial_allowed": self.direct_dial_allowed,
        }


class MixnetControlService:
    """Validated record cache for names and future DHT/gossip replication."""

    def __init__(
        self,
        *,
        network_id: str,
        verify_keys: Mapping[str, str | bytes] | None = None,
        threshold: int = 1,
        store: PersistentControlStore | None = None,
    ) -> None:
        self.network_id = network_id
        self.verify_keys = dict(verify_keys or {})
        self.threshold = threshold
        self.store = store
        self._records: dict[str, SignedControlRecord] = {}
        self._advertisements: dict[str, ClientAdvertisement] = {}
        self._pools: dict[str, PoolDescriptor] = {}
        self._experts: dict[str, ExpertDescriptor] = {}
        self._topics: dict[str, TopicDescriptor] = {}
        self._reviews: dict[str, ReviewDescriptor] = {}
        self._mixnodes: dict[str, MixnodeDescriptor] = {}
        self._match_results: dict[str, MatchResultDescriptor] = {}
        self._trust_updates: dict[str, TrustUpdateDescriptor] = {}
        self._software_identities: dict[str, SoftwareIdentityDescriptor] = {}
        self._attestation_receipts: dict[str, AttestationReceiptDescriptor] = {}
        self._mixnet_routings: dict[str, MixnetRoutingDescriptor] = {}
        self._reachability_assists: dict[str, ReachabilityAssistDescriptor] = {}
        self._kademlia_overlay = None  # set by runtime or tests when real overlay is active
        if self.store is not None:
            for signed in self.store.load():
                self.put_signed(signed)

    def put_signed(self, signed: SignedControlRecord, *, now: float | None = None) -> None:
        signed.validate(verify_keys=self.verify_keys, threshold=self.threshold, now=now)
        record = signed.record
        if record.network_id != self.network_id:
            raise ControlRecordError("control record network_id mismatch")
        old = self._records.get(record.key)
        if old is not None and record.seq <= old.record.seq:
            raise ControlRecordError("control record seq did not advance")

        # Enforce DHT payload size bound when a real overlay is attached (or always
        # for consistency when the control plane may ever be replicated). This
        # rejects before we index or publish (fix 7).
        if getattr(self, "_kademlia_overlay", None) is not None:
            try:
                from .records import MAX_SIGNED_CONTROL_RECORD_BYTES, signed_record_to_dht_bytes
                if len(signed_record_to_dht_bytes(signed)) > MAX_SIGNED_CONTROL_RECORD_BYTES:
                    raise ControlRecordError("signed control record exceeds maximum size for control DHT")
            except ControlRecordError:
                raise
            except Exception:
                pass  # defensive; overlay will also enforce at publish time

        self._records[record.key] = signed
        if record.record_type == RECORD_TYPE_CLIENT_ADVERTISEMENT:
            advertisement = ClientAdvertisement.from_dict(record.value)
            advertisement.validate()
            self._advertisements[advertisement.client_id] = advertisement
        if record.record_type == RECORD_TYPE_POOL_DESCRIPTOR:
            pool = PoolDescriptor.from_dict(record.value)
            pool.validate()
            self._pools[pool.name] = pool
        if record.record_type == RECORD_TYPE_EXPERT_DESCRIPTOR:
            expert = ExpertDescriptor.from_dict(record.value)
            expert.validate()
            self._experts[expert.expert_id] = expert
        if record.record_type == RECORD_TYPE_TOPIC_DESCRIPTOR:
            topic = TopicDescriptor.from_dict(record.value)
            topic.validate()
            self._topics[topic.name] = topic
        if record.record_type == RECORD_TYPE_REVIEW_DESCRIPTOR:
            review = ReviewDescriptor.from_dict(record.value)
            review.validate()
            self._reviews[review.review_id] = review
        if record.record_type == RECORD_TYPE_MIXNODE_DESCRIPTOR:
            mixnode = MixnodeDescriptor.from_dict(record.value)
            mixnode.validate()
            self._mixnodes[mixnode.node_id] = mixnode
        if record.record_type == RECORD_TYPE_MATCH_RESULT:
            result = MatchResultDescriptor.from_dict(record.value)
            result.validate()
            self._match_results[result.key] = result
        if record.record_type == RECORD_TYPE_TRUST_UPDATE:
            upd = TrustUpdateDescriptor.from_dict(record.value)
            upd.validate()
            self._trust_updates[upd.update_id] = upd
        if record.record_type == RECORD_TYPE_SOFTWARE_IDENTITY:
            sw = SoftwareIdentityDescriptor.from_dict(record.value)
            sw.validate()
            self._software_identities[sw.identity_id] = sw
        if record.record_type == RECORD_TYPE_ATTESTATION_RECEIPT:
            ar = AttestationReceiptDescriptor.from_dict(record.value)
            ar.validate()
            self._attestation_receipts[ar.receipt_id] = ar
        if record.record_type == RECORD_TYPE_MIXNET_ROUTING:
            mr = MixnetRoutingDescriptor.from_dict(record.value)
            mr.validate()
            self._mixnet_routings[mr.node_id] = mr
        if record.record_type == RECORD_TYPE_REACHABILITY_ASSIST:
            ra = ReachabilityAssistDescriptor.from_dict(record.value)
            ra.validate()
            self._reachability_assists[ra.assist_id] = ra
        if self.store is not None:
            self.store.save_all(self._records.values())
        # Also publish into the real Kademlia overlay (if attached by a
        # CAPABILITY_CONTROL_DHT runtime). This gives iterative lookup,
        # proper replication to k-closest nodes, and survival after the
        # original bootstrap peers disappear.
        if getattr(self, "_kademlia_overlay", None) is not None:
            try:
                self._kademlia_overlay.publish(record.key, signed)
            except Exception:
                pass

    def get(self, key: str, *, now: float | None = None) -> SignedControlRecord | None:
        signed = self._records.get(key)
        if signed is not None and not signed.record.is_expired(now):
            return signed
        # Miss in local cache: try the real Kademlia overlay (if present).
        # fetch() performs an *iterative* lookup using the library's routing
        # table and kademlia protocol. The candidate is fed through
        # put_signed so that signature threshold, seq, network, expiry and
        # direct-dial rules are enforced exactly as for wire/bootstrap records.
        if getattr(self, "_kademlia_overlay", None) is not None:
            candidate = self._kademlia_overlay.fetch(key)
            if candidate is not None:
                try:
                    self.put_signed(candidate, now=now)
                    return self._records.get(key)
                except ControlRecordError:
                    pass
        return None

    def have(self, key: str, *, now: float | None = None) -> dict[str, object] | None:
        signed = self.get(key, now=now)
        if signed is None:
            return None
        return {
            "key": signed.record.key,
            "seq": signed.record.seq,
            "hash": signed.record.content_hash(),
            "expires_at": signed.record.expires_at,
        }

    def sync(
        self,
        *,
        prefix: str = "",
        cursor: str = "",
        limit: int = 100,
        now: float | None = None,
    ) -> dict[str, object]:
        keys = sorted(key for key in self._records if key.startswith(prefix))
        if cursor:
            keys = [key for key in keys if key > cursor]
        selected = keys[: max(0, limit)]
        records = [
            self._records[key].to_dict()
            for key in selected
            if self.get(key, now=now) is not None
        ]
        next_cursor = selected[-1] if len(selected) == limit and selected else ""
        return {"records": records, "next_cursor": next_cursor}

    def replication_plan(
        self,
        signed: SignedControlRecord,
        peers: Sequence[ControlDhtPeer],
        *,
        replication_factor: int = 5,
    ) -> ControlDhtPlan:
        return replication_plan(signed, peers, replication_factor=replication_factor)

    def bind_name(self, name: str | TenetName) -> MixnetRouteBinding:
        parsed = parse_tenet_name(name) if isinstance(name, str) else name
        if parsed.kind == NAME_KIND_POOL:
            pool = self._pools.get(parsed.normalized)
            expertise = " ".join(pool.topic_tags) if pool is not None else parsed.pool_query()
            return MixnetRouteBinding(
                name=parsed.normalized,
                name_kind=parsed.kind,
                transport="mixnet",
                requested_expertise=expertise,
                pool_name=parsed.normalized,
                descriptor_hash=(
                    self._records[pool.key].record.content_hash() if pool is not None else None
                ),
            )

        signed = self.get(parsed.control_key)
        if signed is None:
            raise RouteBindingError(f"no signed descriptor for {parsed.normalized}")
        return binding_from_record(signed.record, parsed)

    def client_advertisement(self, client_id: str) -> ClientAdvertisement | None:
        return self._advertisements.get(client_id)

    def pool_descriptor(self, name: str | TenetName) -> PoolDescriptor | None:
        parsed = parse_tenet_name(name) if isinstance(name, str) else name
        return self._pools.get(parsed.normalized)

    def expert_descriptor(self, expert_id: str) -> ExpertDescriptor | None:
        return self._experts.get(expert_id)

    def topic_descriptor(self, name: str) -> TopicDescriptor | None:
        return self._topics.get(name)

    def review_descriptor(self, review_id: str) -> ReviewDescriptor | None:
        return self._reviews.get(review_id)

    def mixnode_descriptor(self, node_id: str) -> MixnodeDescriptor | None:
        return self._mixnodes.get(node_id)

    def mixnode_dht_peers(self) -> tuple[ControlDhtPeer, ...]:
        return tuple(
            ControlDhtPeer(node_id, descriptor.node_key)
            for node_id, descriptor in sorted(self._mixnodes.items())
        )

    def match_result(self, key: str) -> MatchResultDescriptor | None:
        return self._match_results.get(key)

    def trust_update(self, update_id: str) -> TrustUpdateDescriptor | None:
        return self._trust_updates.get(update_id)

    def software_identity(self, identity_id: str) -> SoftwareIdentityDescriptor | None:
        return self._software_identities.get(identity_id)

    def attestation_receipt(self, receipt_id: str) -> AttestationReceiptDescriptor | None:
        return self._attestation_receipts.get(receipt_id)

    def mixnet_routing_descriptor(self, node_id: str) -> MixnetRoutingDescriptor | None:
        return self._mixnet_routings.get(node_id)

    def reachability_assist(self, assist_id: str) -> ReachabilityAssistDescriptor | None:
        return self._reachability_assists.get(assist_id)

    def match_results(
        self,
        *,
        pool_name: str | None = None,
        query_commitment: str | None = None,
    ) -> tuple[MatchResultDescriptor, ...]:
        results = []
        for result in self._match_results.values():
            if pool_name is not None and result.pool_name != pool_name:
                continue
            if query_commitment is not None and result.query_commitment != query_commitment:
                continue
            if self.get(result.key) is None:
                continue
            results.append(result)
        return tuple(sorted(results, key=lambda item: (item.pool_name, item.query_commitment, item.matcher_id)))

    def capability_matches(
        self,
        *,
        kind: str | None = None,
        pool: str | None = None,
        trust_tier: str | None = None,
    ) -> tuple[tuple[ClientAdvertisement, CapabilityDescriptor], ...]:
        matches: list[tuple[ClientAdvertisement, CapabilityDescriptor]] = []
        for advertisement in self._advertisements.values():
            if trust_tier is not None and not any(
                receipt.tier == trust_tier for receipt in advertisement.trust_receipts
            ):
                continue
            for capability in advertisement.capabilities:
                if kind is not None and capability.kind != kind:
                    continue
                if pool is not None and pool not in capability.pools:
                    continue
                matches.append((advertisement, capability))
        return tuple(matches)

    def make_unsigned_client_advertisement(
        self,
        advertisement: ClientAdvertisement,
        *,
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        advertisement.validate()
        issued = time.time() if now is None else now
        return advertisement.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_pool_descriptor(
        self,
        pool: PoolDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        pool.validate()
        issued = time.time() if now is None else now
        return pool.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_expert_descriptor(
        self,
        expert: ExpertDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        expert.validate()
        issued = time.time() if now is None else now
        return expert.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_topic_descriptor(
        self,
        topic: TopicDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        topic.validate()
        issued = time.time() if now is None else now
        return topic.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_review_descriptor(
        self,
        review: ReviewDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        review.validate()
        issued = time.time() if now is None else now
        return review.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_mixnode_descriptor(
        self,
        descriptor: MixnodeDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        descriptor.validate()
        issued = time.time() if now is None else now
        return descriptor.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_match_result(
        self,
        result: MatchResultDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 300.0,
        now: float | None = None,
    ) -> ControlRecord:
        result.validate()
        issued = time.time() if now is None else now
        return result.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_trust_update(
        self,
        update: TrustUpdateDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0 * 24 * 30,
        now: float | None = None,
    ) -> ControlRecord:
        update.validate()
        issued = time.time() if now is None else now
        return update.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_software_identity(
        self,
        identity: SoftwareIdentityDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0 * 24 * 90,
        now: float | None = None,
    ) -> ControlRecord:
        identity.validate()
        issued = time.time() if now is None else now
        return identity.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_attestation_receipt(
        self,
        receipt: AttestationReceiptDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0 * 24 * 7,
        now: float | None = None,
    ) -> ControlRecord:
        receipt.validate()
        issued = time.time() if now is None else now
        return receipt.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_mixnet_routing(
        self,
        descriptor: MixnetRoutingDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        descriptor.validate()
        issued = time.time() if now is None else now
        return descriptor.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_reachability_assist(
        self,
        assist: ReachabilityAssistDescriptor,
        *,
        seq: int,
        ttl_seconds: float = 3600.0 * 6,
        now: float | None = None,
    ) -> ControlRecord:
        assist.validate()
        issued = time.time() if now is None else now
        return assist.to_record(
            network_id=self.network_id,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
        )

    def make_unsigned_name_descriptor(
        self,
        name: str | TenetName,
        *,
        value: Mapping[str, object],
        seq: int,
        ttl_seconds: float = 3600.0,
        now: float | None = None,
    ) -> ControlRecord:
        parsed = parse_tenet_name(name) if isinstance(name, str) else name
        issued = time.time() if now is None else now
        return ControlRecord(
            network_id=self.network_id,
            key=parsed.control_key,
            record_type=RECORD_TYPE_NAME_DESCRIPTOR,
            seq=seq,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
            value={
                "name": parsed.normalized,
                "kind": parsed.kind,
                "transport": "mixnet",
                "direct_dial_allowed": False,
                **dict(value),
            },
        )


def binding_from_record(record: ControlRecord, name: TenetName) -> MixnetRouteBinding:
    if record.record_type != RECORD_TYPE_NAME_DESCRIPTOR:
        raise RouteBindingError("record is not a name descriptor")
    value = record.value
    if str(value.get("transport", "")) != "mixnet":
        raise RouteBindingError("name descriptor does not bind to mixnet")
    if bool(value.get("direct_dial_allowed", False)):
        raise RouteBindingError("name descriptor attempted to allow direct dial")
    if str(value.get("name", "")) != name.normalized:
        raise RouteBindingError("name descriptor mismatch")

    if name.kind == NAME_KIND_STABLE:
        handle = str(value.get("opaque_handle", ""))
        if not handle:
            raise RouteBindingError("stable name descriptor requires opaque_handle")
        raw_path = value.get("mix_path", value.get("relay_path", ())) or ()
        mix_path = tuple(str(item) for item in raw_path)
        binding = MixnetRouteBinding(
            name=name.normalized,
            name_kind=name.kind,
            transport="mixnet",
            opaque_handle=handle,
            mix_path=mix_path,
            descriptor_hash=record.content_hash(),
        )
        binding.validate()
        return binding

    raise RouteBindingError(f"{name.kind} descriptors are not route-bindable yet")


def _validate_binding_mix_path(
    mix_path: Sequence[str],
    *,
    exit_handle: str | None,
) -> None:
    normalized = tuple(str(node_id).strip() for node_id in mix_path)
    if any(not node_id for node_id in normalized):
        raise RouteBindingError("route binding mix_path contains an empty hop")
    if len(set(normalized)) != len(normalized):
        raise RouteBindingError("route binding mix_path contains a repeated hop")
    if exit_handle and str(exit_handle).strip() in normalized:
        raise RouteBindingError("route binding mix_path repeats the opaque handle")
