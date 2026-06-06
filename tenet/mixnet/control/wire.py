"""Wire messages for mixnode control-record exchange."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from tenet.mixnet.control.records import SignedControlRecord

CONTROL_MAGIC = b"TCTL-2026-06\n"

MSG_GET = "get"
MSG_GET_RESPONSE = "get_response"
MSG_PUT = "put"
MSG_HAVE = "have"
MSG_SYNC = "sync"
MSG_SYNC_RESPONSE = "sync_response"
MSG_ERROR = "error"


@dataclass(frozen=True)
class ControlWireMessage:
    kind: str
    body: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "body": self.body}


def is_control_datagram(data: bytes) -> bool:
    return data.startswith(CONTROL_MAGIC)


def encode_control_message(message: ControlWireMessage) -> bytes:
    return CONTROL_MAGIC + json.dumps(
        message.to_dict(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def decode_control_message(data: bytes) -> ControlWireMessage:
    if not is_control_datagram(data):
        raise ValueError("not a Tenet control datagram")
    raw = json.loads(data[len(CONTROL_MAGIC):].decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("control message root must be an object")
    body = raw.get("body") or {}
    if not isinstance(body, dict):
        raise ValueError("control message body must be an object")
    return ControlWireMessage(kind=str(raw.get("kind", "")), body=dict(body))


def control_get(key: str) -> ControlWireMessage:
    return ControlWireMessage(MSG_GET, {"key": key})


def control_put(record: SignedControlRecord) -> ControlWireMessage:
    return ControlWireMessage(MSG_PUT, {"record": record.to_dict()})


def control_have(record: SignedControlRecord) -> ControlWireMessage:
    return ControlWireMessage(
        MSG_HAVE,
        {
            "key": record.record.key,
            "seq": record.record.seq,
            "hash": record.record.content_hash(),
            "expires_at": record.record.expires_at,
        },
    )


def signed_record_from_body(body: Mapping[str, object]) -> SignedControlRecord | None:
    record = body.get("record")
    if not isinstance(record, dict):
        return None
    return SignedControlRecord.from_dict(record)
