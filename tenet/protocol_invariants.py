"""Protocol invariants that prevent identity/routing/privacy drift."""

from __future__ import annotations

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
