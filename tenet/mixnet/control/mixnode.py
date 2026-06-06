"""Mixnode membership descriptors for the mixnet control DHT."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping

from tenet.mixnet.control.names import TENET_NAME_SUFFIX, parse_tenet_name
from tenet.mixnet.control.records import ControlRecord, RECORD_TYPE_MIXNODE_DESCRIPTOR

MIXNODE_DESCRIPTOR_SCHEMA = "tenet.mixnode_descriptor.2026-06"


@dataclass(frozen=True)
class MixnodeDescriptor:
    """Signed mixnet/DHT membership, separate from NAT relay semantics.

    `relay` is reserved for NAT/reachability assistance. This descriptor names a
    mixnet/control-DHT participant and does not carry host/port/url fields.
    """

    node_id: str
    node_key: str
    name: str | None = None
    contact_refs: tuple[str, ...] = ()
    claim_refs: tuple[str, ...] = ()
    schema: str = MIXNODE_DESCRIPTOR_SCHEMA

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> "MixnodeDescriptor":
        return cls(
            node_id=str(raw.get("node_id", raw.get("relay_id", ""))),
            node_key=str(raw.get("node_key", "")),
            name=_optional_str(raw.get("name")),
            contact_refs=tuple(str(item) for item in raw.get("contact_refs", ()) or ()),
            claim_refs=tuple(str(item) for item in raw.get("claim_refs", ()) or ()),
            schema=str(raw.get("schema", MIXNODE_DESCRIPTOR_SCHEMA)),
        )

    @property
    def key(self) -> str:
        return f"mixnode/{self.node_id}/descriptor"

    def validate(self) -> None:
        if self.schema != MIXNODE_DESCRIPTOR_SCHEMA:
            raise ValueError(f"unsupported mixnode descriptor schema: {self.schema}")
        if not self.node_id:
            raise ValueError("mixnode node_id is required")
        if not self.node_key:
            raise ValueError("mixnode node_key is required")
        if self.name:
            parsed = parse_tenet_name(self.name)
            if parsed.normalized != self.name or not self.name.endswith(TENET_NAME_SUFFIX):
                raise ValueError("mixnode descriptor name is not normalized")

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
            record_type=RECORD_TYPE_MIXNODE_DESCRIPTOR,
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
