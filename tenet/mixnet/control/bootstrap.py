"""Bootstrap material for signed mixnet control records."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from tenet.mixnet.control.records import (
    RECORD_TYPE_TRUST_POINTER,
    SignedControlRecord,
)
from tenet.mixnet.control.service import MixnetControlService
from tenet.mixnet.control.store import PersistentControlStore

BOOTSTRAP_SCHEMA = "tenet.bootstrap.2026-06"
TRUST_UPDATE_KEY = "trust/update/latest"


@dataclass(frozen=True)
class ControlBootstrap:
    """Signed control-record bootstrap, replacing static network truth.

    Update roots are the current issuer keys for software/trust metadata. The
    records they sign can later point to federated issuers without changing this
    file shape.
    """

    network_id: str
    update_roots: dict[str, str]
    threshold: int = 1
    records: tuple[SignedControlRecord, ...] = ()
    bootstrap_relays: tuple[str, ...] = ()
    schema: str = BOOTSTRAP_SCHEMA
    source_path: Path | None = field(default=None, compare=False)

    @classmethod
    def from_dict(
        cls,
        raw: Mapping[str, object],
        *,
        source_path: str | Path | None = None,
    ) -> "ControlBootstrap":
        records = raw.get("records") or raw.get("cached_records") or ()
        if not isinstance(records, list):
            raise ValueError("bootstrap records must be a list")
        roots = raw.get("update_roots") or raw.get("verify_keys") or {}
        if not isinstance(roots, Mapping):
            raise ValueError("bootstrap update_roots must be an object")
        relays = raw.get("bootstrap_relays") or ()
        return cls(
            network_id=str(raw.get("network_id", "")),
            update_roots={str(key): str(value) for key, value in roots.items()},
            threshold=int(raw.get("threshold", 1)),
            records=tuple(
                SignedControlRecord.from_dict(item)
                for item in records
                if isinstance(item, Mapping)
            ),
            bootstrap_relays=tuple(str(item) for item in relays),
            schema=str(raw.get("schema", BOOTSTRAP_SCHEMA)),
            source_path=Path(source_path) if source_path is not None else None,
        ).validate()

    @classmethod
    def load(cls, path: str | Path) -> "ControlBootstrap":
        bootstrap_path = Path(path).resolve()
        raw = json.loads(bootstrap_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("bootstrap file must be a JSON object")
        return cls.from_dict(raw, source_path=bootstrap_path)

    def validate(self) -> "ControlBootstrap":
        if self.schema != BOOTSTRAP_SCHEMA:
            raise ValueError(f"unsupported bootstrap schema: {self.schema!r}")
        if not self.network_id:
            raise ValueError("bootstrap network_id is required")
        if self.threshold < 1:
            raise ValueError("bootstrap threshold must be positive")
        if len(self.update_roots) < self.threshold:
            raise ValueError("bootstrap update roots do not satisfy threshold")
        for key_id, key_hex in self.update_roots.items():
            if not key_id:
                raise ValueError("bootstrap update root key id is required")
            try:
                bytes.fromhex(key_hex)
            except ValueError as exc:
                raise ValueError("bootstrap update roots must be hex") from exc
        for signed in self.records:
            signed.validate(verify_keys=self.update_roots, threshold=self.threshold)
            if signed.record.network_id != self.network_id:
                raise ValueError("bootstrap record network_id mismatch")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema": self.schema,
            "network_id": self.network_id,
            "update_roots": dict(self.update_roots),
            "threshold": self.threshold,
            "bootstrap_relays": list(self.bootstrap_relays),
            "records": [record.to_dict() for record in self.records],
        }

    def trust_update(self) -> SignedControlRecord | None:
        for signed in self.records:
            if (
                signed.record.key == TRUST_UPDATE_KEY
                and signed.record.record_type == RECORD_TYPE_TRUST_POINTER
            ):
                return signed
        return None

    def to_control_service(
        self,
        *,
        store: PersistentControlStore | None = None,
    ) -> MixnetControlService:
        service = MixnetControlService(
            network_id=self.network_id,
            verify_keys=self.update_roots,
            threshold=self.threshold,
            store=store,
        )
        for signed in self.records:
            old = service.get(signed.record.key)
            if old is None or signed.record.seq > old.record.seq:
                service.put_signed(signed)
        return service
