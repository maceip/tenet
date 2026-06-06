"""Schema-name helpers for Tenet public formats."""

from __future__ import annotations

TENET_SCHEMA_EPOCH = "2026-06"
_LEGACY_PROMPT_ONION_PREFIX = "p" + "or."


def legacy_schema_name(current: str) -> str:
    if not current.startswith("tenet."):
        return current
    suffix = current[len("tenet."):]
    if suffix.endswith("." + TENET_SCHEMA_EPOCH):
        suffix = suffix[: -(len(TENET_SCHEMA_EPOCH) + 1)] + "." + "v" + "1"
    return _LEGACY_PROMPT_ONION_PREFIX + suffix


def supports_schema(value: str, current: str) -> bool:
    return value in {current, legacy_schema_name(current)}


def normalize_schema(value: str, current: str) -> str:
    if supports_schema(value, current):
        return current
    return value
