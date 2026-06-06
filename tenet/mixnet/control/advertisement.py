"""Client advertisements for the mixnet control plane."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping, Sequence

from tenet.protocol_invariants import (
    CAPABILITY_ANSWER,
    CAPABILITY_CONTROL_DHT,
    CAPABILITY_FORWARD,
    CAPABILITY_MAILBOX,
    CAPABILITY_MATCHER,
    CAPABILITY_REACHABILITY_ASSIST,
    CAPABILITY_TEE,
    ProtocolInvariantError,
    validate_advertised_capability,
)
from tenet.mixnet.control.records import ControlRecord, RECORD_TYPE_CLIENT_ADVERTISEMENT

CLIENT_ADVERTISEMENT_SCHEMA = "tenet.client_advertisement.2026-06"


@dataclass(frozen=True)
class CapabilityDescriptor:
    kind: str
    capability_id: str
    commitments: dict[str, str] = field(default_factory=dict)
    pools: tuple[str, ...] = ()
    policy: dict[str, object] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.kind:
            raise ValueError("capability kind is required")
        if not self.capability_id:
            raise ValueError("capability_id is required")
        try:
            validate_advertised_capability(kind=self.kind, pools=self.pools)
        except ProtocolInvariantError as exc:
            raise ValueError(str(exc)) from exc

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "CapabilityDescriptor":
        return cls(
            kind=str(raw.get("kind", "")),
            capability_id=str(raw.get("capability_id", "")),
            commitments={str(k): str(v) for k, v in dict(raw.get("commitments", {}) or {}).items()},
            pools=tuple(str(item) for item in raw.get("pools", ()) or ()),
            policy=dict(raw.get("policy", {}) or {}),
        )


@dataclass(frozen=True)
class TrustReceipt:
    tier: str
    receipt_hash: str
    code_identity: str | None = None
    data_commitment: str | None = None
    valid_until: str | None = None

    def validate(self) -> None:
        if not self.tier:
            raise ValueError("trust receipt tier is required")
        if not self.receipt_hash:
            raise ValueError("trust receipt hash is required")

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "TrustReceipt":
        return cls(
            tier=str(raw.get("tier", "")),
            receipt_hash=str(raw.get("receipt_hash", "")),
            code_identity=_optional_str(raw.get("code_identity")),
            data_commitment=_optional_str(raw.get("data_commitment")),
            valid_until=_optional_str(raw.get("valid_until")),
        )


@dataclass(frozen=True)
class ClientAdvertisement:
    """One Tenet client advertising capabilities and trust receipts.

    Reputation is intentionally reference-only here. Scoring, payments, disputes,
    and weighting remain future policy; this schema just leaves a place for signed
    reputation/claim records to attach without changing advertisement shape.
    Software/update authority belongs in trust metadata, not in behavior scoring.
    """

    client_id: str
    code_identity: dict[str, str]
    capabilities: tuple[CapabilityDescriptor, ...]
    trust_receipts: tuple[TrustReceipt, ...] = ()
    reachability: dict[str, object] = field(default_factory=lambda: {"transport": "mixnet"})
    reputation_refs: tuple[str, ...] = ()
    claim_refs: tuple[str, ...] = ()
    schema: str = CLIENT_ADVERTISEMENT_SCHEMA

    def to_dict(self) -> dict[str, object]:
        self.validate()
        raw = asdict(self)
        raw["capabilities"] = [asdict(item) for item in self.capabilities]
        raw["trust_receipts"] = [asdict(item) for item in self.trust_receipts]
        return raw

    def validate(self) -> None:
        if self.schema != CLIENT_ADVERTISEMENT_SCHEMA:
            raise ValueError(f"unsupported client advertisement schema: {self.schema}")
        if not self.client_id:
            raise ValueError("client_id is required")
        if not self.code_identity:
            raise ValueError("code_identity is required")
        if self.reachability.get("transport") != "mixnet":
            raise ValueError("client advertisement reachability must be mixnet")
        for capability in self.capabilities:
            capability.validate()
        for receipt in self.trust_receipts:
            receipt.validate()

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "ClientAdvertisement":
        return cls(
            client_id=str(raw.get("client_id", "")),
            code_identity={str(k): str(v) for k, v in dict(raw.get("code_identity", {}) or {}).items()},
            capabilities=tuple(
                CapabilityDescriptor.from_dict(item)
                for item in raw.get("capabilities", ()) or ()
                if isinstance(item, Mapping)
            ),
            trust_receipts=tuple(
                TrustReceipt.from_dict(item)
                for item in raw.get("trust_receipts", ()) or ()
                if isinstance(item, Mapping)
            ),
            reachability=dict(raw.get("reachability", {}) or {"transport": "mixnet"}),
            reputation_refs=tuple(str(item) for item in raw.get("reputation_refs", ()) or ()),
            claim_refs=tuple(
                str(item)
                for item in (raw.get("claim_refs") or raw.get("blessing_refs") or ())
            ),
            schema=str(raw.get("schema", CLIENT_ADVERTISEMENT_SCHEMA)),
        )

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
            key=f"client/{self.client_id}/advertisement/latest",
            record_type=RECORD_TYPE_CLIENT_ADVERTISEMENT,
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
