"""Tenet names for mixnet control-plane discovery.

A Tenet name is intentionally not DNS and not a multiaddr. It names a pool,
stable service, or infrastructure object that must resolve into mixnet control
metadata, not an IP endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

TENET_NAME_SUFFIX = "~tenet"

NAME_KIND_POOL = "pool"
NAME_KIND_STABLE = "stable"
NAME_KIND_SESSION = "session"
NAME_KIND_RELAY = "relay"
NAME_KIND_MATCHER = "matcher"

_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class TenetNameError(ValueError):
    """Raised when a Tenet name is malformed or ambiguous."""


@dataclass(frozen=True)
class TenetName:
    """Parsed Tenet name.

    `pool` names are the default. Stable names require an explicit `@` owner so
    direct expert targeting cannot happen by accident.
    """

    raw: str
    labels: tuple[str, ...]
    kind: str = NAME_KIND_POOL
    owner: str | None = None

    @property
    def normalized(self) -> str:
        prefix = ".".join(self.labels)
        if self.kind == NAME_KIND_STABLE and self.owner:
            prefix = f"{self.owner}@{prefix}"
        return f"{prefix}{TENET_NAME_SUFFIX}"

    @property
    def control_key(self) -> str:
        return f"name/{self.kind}/{self.normalized}"

    def pool_query(self) -> str:
        """Return a human expertise query for pool matching."""

        if self.kind != NAME_KIND_POOL:
            raise TenetNameError(f"{self.kind} names do not define a pool query")
        return " ".join(self.labels)

    def to_descriptor(self) -> dict[str, object]:
        raw = {
            "name": self.normalized,
            "kind": self.kind,
            "labels": list(self.labels),
            "control_key": self.control_key,
            "transport": "mixnet",
            "direct_dial_allowed": False,
        }
        if self.owner:
            raw["owner"] = self.owner
        return raw


def parse_tenet_name(value: str) -> TenetName:
    text = value.strip().lower()
    if not text.endswith(TENET_NAME_SUFFIX):
        raise TenetNameError(f"Tenet names must end with {TENET_NAME_SUFFIX}")
    body = text[: -len(TENET_NAME_SUFFIX)]
    if not body:
        raise TenetNameError("Tenet name body is empty")
    if "/" in body or ":" in body:
        raise TenetNameError("Tenet names are not URLs or multiaddrs")

    owner = None
    if "@" in body:
        owner, body = body.split("@", 1)
        _validate_label(owner, label_name="owner")

    labels = tuple(part for part in body.split(".") if part)
    if not labels:
        raise TenetNameError("Tenet name has no labels")
    for label in labels:
        _validate_label(label)

    kind = _kind_for(labels, owner)
    return TenetName(raw=value, labels=labels, kind=kind, owner=owner)


def _kind_for(labels: tuple[str, ...], owner: str | None) -> str:
    if owner is not None:
        return NAME_KIND_STABLE
    if labels[-1] == "relay":
        return NAME_KIND_RELAY
    if labels[-1] == "matcher":
        return NAME_KIND_MATCHER
    if labels[-1] == "session":
        return NAME_KIND_SESSION
    return NAME_KIND_POOL


def _validate_label(label: str, *, label_name: str = "label") -> None:
    if not _LABEL_RE.fullmatch(label):
        raise TenetNameError(f"invalid Tenet name {label_name}: {label!r}")
