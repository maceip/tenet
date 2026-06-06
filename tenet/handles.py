"""Opaque handle primitives for mailbox-resolvable expert routing."""

from __future__ import annotations

import hmac
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Mapping


OPAQUE_HANDLE_VERSION = "por.opaque_handle.v1"
OPAQUE_HANDLE_RECORD_VERSION = "por.opaque_handle_record.v1"
OPAQUE_HANDLE_SIZE = 16
DEFAULT_HANDLE_TTL_SECONDS = 270


@dataclass(frozen=True)
class OpaqueHandle:
    """A fixed-width opaque route token.

    The current Outfox routing field is 16 bytes in the production profile, so
    the token is exactly 16 ASCII bytes. It is not a `(relay, peer_id)` tuple.
    """

    token: str
    version: str = OPAQUE_HANDLE_VERSION

    def __post_init__(self) -> None:
        try:
            raw = self.token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("opaque handle token must be ASCII") from exc
        if len(raw) != OPAQUE_HANDLE_SIZE:
            raise ValueError("opaque handle token must be exactly 16 ASCII bytes")


@dataclass(frozen=True)
class OpaqueHandleRecord:
    """Asker-facing directory material for a selected expert.

    This record intentionally contains no relay endpoint, peer id, KEM key, or
    peer-address record. Those are mailbox-resolution data.
    """

    version: str
    handle: str
    mailbox_id: str
    issued_at: float
    expires_at: float
    signature: str

    def is_expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at

    def to_public_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HandleResolution:
    """Mailbox-only resolution result for a handle."""

    handle: str
    routing_kem_pk_hex: str
    peer_address: dict[str, object]


class OpaqueHandleIssuer:
    """Deterministically mints opaque handles for a mailbox epoch."""

    def __init__(self, secret: bytes, *, epoch: str = "default") -> None:
        if len(secret) < 16:
            raise ValueError("handle issuer secret must be at least 16 bytes")
        if not epoch:
            raise ValueError("handle issuer epoch is required")
        self.secret = secret
        self.epoch = epoch

    def issue(self, *, peer_id: str, manifest_digest: str) -> OpaqueHandle:
        msg = f"{self.epoch}|{peer_id}|{manifest_digest}".encode("utf-8")
        digest = hmac.new(self.secret, msg, sha256).hexdigest()
        return OpaqueHandle("h" + digest[: OPAQUE_HANDLE_SIZE - 1])

    def record(
        self,
        *,
        peer_id: str,
        manifest_digest: str,
        mailbox_id: str,
        now: float | None = None,
        ttl_seconds: int = DEFAULT_HANDLE_TTL_SECONDS,
    ) -> OpaqueHandleRecord:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if not mailbox_id:
            raise ValueError("mailbox_id is required")
        issued_at = time.time() if now is None else now
        handle = self.issue(peer_id=peer_id, manifest_digest=manifest_digest)
        unsigned = OpaqueHandleRecord(
            version=OPAQUE_HANDLE_RECORD_VERSION,
            handle=handle.token,
            mailbox_id=mailbox_id,
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
            signature="",
        )
        return OpaqueHandleRecord(
            **{**asdict(unsigned), "signature": self._record_signature(unsigned)}
        )

    def verify_record(self, record: OpaqueHandleRecord) -> bool:
        if not record.signature:
            return False
        expected = self._record_signature(
            OpaqueHandleRecord(**{**asdict(record), "signature": ""})
        )
        return hmac.compare_digest(record.signature, expected)

    def _record_signature(self, record: OpaqueHandleRecord) -> str:
        return hmac.new(self.secret, _record_signature_payload(record), sha256).hexdigest()


def opaque_handle_record_from_dict(raw: Mapping[str, object]) -> OpaqueHandleRecord:
    version = str(raw.get("version", ""))
    if version != OPAQUE_HANDLE_RECORD_VERSION:
        raise ValueError(f"unsupported opaque handle record version: {version!r}")
    return OpaqueHandleRecord(
        version=version,
        handle=str(raw.get("handle", "")),
        mailbox_id=str(raw.get("mailbox_id", "")),
        issued_at=float(raw.get("issued_at", 0.0)),
        expires_at=float(raw.get("expires_at", 0.0)),
        signature=str(raw.get("signature", "")),
    )


def _record_signature_payload(record: OpaqueHandleRecord) -> bytes:
    return "|".join(
        (
            record.version,
            record.handle,
            record.mailbox_id,
            str(int(record.issued_at)),
            str(int(record.expires_at)),
        )
    ).encode("utf-8")
