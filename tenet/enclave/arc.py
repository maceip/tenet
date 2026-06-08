"""Anonymous rate-limit credential wire placeholder.

This is the committed no-op box: it carries an unlinkable-looking presentation
through the enclave-plane API and performs only structural validation. Real ARC
verification replaces this module without changing the API payload shape.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Mapping
from uuid import uuid4

from tenet.schema import legacy_schema_name, normalize_schema, supports_schema


NOOP_ARC_CREDENTIAL_VERSION = "tenet.arc.noop_credential.2026-06"
# Live Nitro EIF (deployed 2026-06-04) predates the tenet rename and only accepts
# the legacy por.* wire name. Outbound requests must emit this until EIF is redeployed.
WIRE_ARC_CREDENTIAL_VERSION = legacy_schema_name(NOOP_ARC_CREDENTIAL_VERSION)


@dataclass(frozen=True)
class NoopArcCredential:
    version: str
    presentation_id: str
    epoch: str
    issued_at: float

    @classmethod
    def issue(
        cls,
        *,
        epoch: str = "plain-dev",
        now: float | None = None,
    ) -> "NoopArcCredential":
        return cls(
            version=WIRE_ARC_CREDENTIAL_VERSION,
            presentation_id=uuid4().hex,
            epoch=epoch,
            issued_at=time.time() if now is None else now,
        )

    def to_public_dict(self) -> dict[str, object]:
        return asdict(self)


def noop_arc_credential_from_dict(raw: Mapping[str, object]) -> NoopArcCredential:
    version = str(raw.get("version", ""))
    if not supports_schema(version, NOOP_ARC_CREDENTIAL_VERSION):
        raise ValueError(f"unsupported ARC credential version: {version!r}")
    version = normalize_schema(version, NOOP_ARC_CREDENTIAL_VERSION)
    presentation_id = str(raw.get("presentation_id", ""))
    if not presentation_id:
        raise ValueError("ARC credential presentation_id is required")
    epoch = str(raw.get("epoch", ""))
    if not epoch:
        raise ValueError("ARC credential epoch is required")
    return NoopArcCredential(
        version=version,
        presentation_id=presentation_id,
        epoch=epoch,
        issued_at=float(raw.get("issued_at", 0.0)),
    )
