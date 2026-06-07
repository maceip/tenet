"""Protocol invariants that prevent identity/routing/privacy drift."""

from __future__ import annotations

import re
from typing import Sequence

from tenet.handles import is_opaque_handle


CAPABILITY_ANSWER = "answer"
CAPABILITY_CONTROL_DHT = "control_dht"
CAPABILITY_FORWARD = "forward"
CAPABILITY_MAILBOX = "mailbox"
CAPABILITY_MATCHER = "matcher"
CAPABILITY_REACHABILITY_ASSIST = "reachability_assist"
CAPABILITY_TEE = "tee"

SUBSTRATE_CAPABILITIES = frozenset(
    {
        CAPABILITY_ANSWER,
        CAPABILITY_CONTROL_DHT,
        CAPABILITY_FORWARD,
        CAPABILITY_MAILBOX,
        CAPABILITY_MATCHER,
        CAPABILITY_REACHABILITY_ASSIST,
        CAPABILITY_TEE,
    }
)
POOL_SCOPED_CAPABILITIES = frozenset({CAPABILITY_MATCHER})


def require_route_handle(value: object, *, field: str = "route target") -> str:
    handle = str(value or "")
    if not is_opaque_handle(handle):
        raise ProtocolInvariantError(f"{field} must be an opaque handle")
    return handle


# A string in a control descriptor that looks like a dialable endpoint is a
# layer violation: control records name things, they do not address them. This
# catches values that ``_reject_direct_dial_fields`` (which only inspects keys)
# would miss, e.g. an endpoint smuggled into a list of "opaque refs".
_ROUTEABLE_RE = re.compile(
    r"://"  # scheme://
    r"|(?:\d{1,3}\.){3}\d{1,3}"  # bare IPv4 (optionally with :port)
    r"|\b(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)+):\d{2,5}\b"  # host.with.dots:port
    r"|\[[0-9a-f:]+\]"  # bracketed IPv6
)


def looks_routeable(value: object) -> bool:
    return bool(_ROUTEABLE_RE.search(str(value).lower()))


def reject_routeable_string(value: object, *, field: str) -> str:
    text = str(value)
    if looks_routeable(text):
        raise ProtocolInvariantError(
            f"{field} must be an opaque control ref, not a routeable endpoint: {text!r}"
        )
    return text


def reject_expertise_pool(value: object, *, field: str) -> None:
    """Reject a value that encodes an expertise pool name.

    Reachability/address records must not leak which expertise a handle serves;
    only the matcher/control layer may bind expertise to pools.
    """

    text = str(value)
    # Imported lazily to avoid a control<->invariants import cycle.
    from tenet.mixnet.control.names import TenetNameError, parse_tenet_name

    try:
        parsed = parse_tenet_name(text)
    except TenetNameError:
        return
    if parsed.kind == "pool":
        raise ProtocolInvariantError(
            f"{field} must not carry an expertise pool name: {text!r}"
        )


def validate_advertised_capability(
    *,
    kind: str,
    pools: Sequence[str] = (),
) -> None:
    if kind not in SUBSTRATE_CAPABILITIES:
        raise ProtocolInvariantError(f"unsupported substrate capability: {kind}")
    if tuple(pools) and kind not in POOL_SCOPED_CAPABILITIES:
        raise ProtocolInvariantError(
            "clients advertise substrate capabilities, not routeable expertise"
        )


class ProtocolInvariantError(ValueError):
    """Raised when code tries to collapse name, identity, and route layers."""
