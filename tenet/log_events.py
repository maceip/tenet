"""Structured log event helpers for tenet daemons and tests."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TextIO


LOG_SCHEMA_VERSION = "tenet.log.2026-06"
DEFAULT_REDACT_FIELDS = frozenset(
    {
        "api_key",
        "authorization",
        "bearer",
        "prompt",
        "prompt_payload",
        "secret",
        "token",
    }
)


@dataclass(frozen=True)
class PorLogEvent:
    event: str
    component: str
    node_id: str | None = None
    role: str | None = None
    level: str = "info"
    request_id: str | None = None
    peer_id: str | None = None
    link_cid: str | None = None
    fields: dict[str, object] = field(default_factory=dict)
    schema: str = LOG_SCHEMA_VERSION
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self, *, redact_fields: set[str] | frozenset[str] = DEFAULT_REDACT_FIELDS) -> dict[str, object]:
        raw = asdict(self)
        raw["fields"] = _redact_mapping(raw["fields"], redact_fields)
        return {key: value for key, value in raw.items() if value is not None}


def format_log_event(
    event: PorLogEvent,
    *,
    fmt: str = "json",
    redact_fields: set[str] | frozenset[str] = DEFAULT_REDACT_FIELDS,
) -> str:
    data = event.to_dict(redact_fields=redact_fields)
    if fmt == "json":
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    if fmt == "plain":
        parts = [
            f"ts={data['timestamp']}",
            f"level={data['level']}",
            f"component={data['component']}",
            f"event={data['event']}",
        ]
        for key in ("node_id", "role", "request_id", "peer_id", "link_cid"):
            if key in data:
                parts.append(f"{key}={data[key]}")
        for key, value in data.get("fields", {}).items():
            parts.append(f"{key}={value}")
        return " ".join(parts)
    raise ValueError(f"unsupported log format: {fmt}")


def emit_log_event(
    event: PorLogEvent,
    *,
    stream: TextIO | None = None,
    fmt: str = "json",
    redact_fields: set[str] | frozenset[str] = DEFAULT_REDACT_FIELDS,
) -> None:
    if fmt == "silent":
        return  # embedded runtimes (e.g. relay inside the interactive client) stay quiet
    output = sys.stdout if stream is None else stream
    output.write(format_log_event(event, fmt=fmt, redact_fields=redact_fields) + "\n")
    output.flush()


def _redact_mapping(value: dict[str, object], redact_fields: set[str] | frozenset[str]) -> dict[str, object]:
    redacted = {}
    normalized = {field.lower() for field in redact_fields}
    for key, item in value.items():
        if key.lower() in normalized:
            redacted[key] = "[redacted]"
        elif isinstance(item, dict):
            redacted[key] = _redact_mapping(item, normalized)
        else:
            redacted[key] = item
    return redacted
