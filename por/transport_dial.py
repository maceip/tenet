"""Dial-target resolution for peer-address records.

This module stops at target selection. Transport code owns socket creation,
QUIC clients, and supernode forwarding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from .config import TrustedReachabilityRelayConfig
from .envelope import PromptRequestEnvelope
from .peer_address import DialPlan, DialRoute, ROUTE_DIRECT, ROUTE_RELAY


@dataclass(frozen=True)
class DialTarget:
    peer_id: str
    route_kind: str
    transport: str
    host: str
    port: int
    relay_id: str | None = None
    inline_required: bool = True


def resolve_dial_target(
    plan: DialPlan,
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig],
    *,
    dev_allow_untrusted_reachability_relays: bool = False,
) -> DialTarget | None:
    """Resolve a verified dial plan into the first transport target.

    Relay routes dial the trusted relay endpoint from local config, not the
    endpoint embedded in the record. Direct routes use the expert endpoint only
    when the already-verified plan explicitly chose a direct route.
    """

    for route in _candidate_routes(plan):
        if route.kind == ROUTE_RELAY:
            target = _relay_dial_target(
                plan,
                route,
                trusted_reachability_relays,
                dev_allow_untrusted_reachability_relays=(
                    dev_allow_untrusted_reachability_relays
                ),
            )
            if target is not None:
                return target
            continue
        if route.kind == ROUTE_DIRECT and route.endpoint is not None:
            return DialTarget(
                peer_id=plan.peer_id,
                route_kind=ROUTE_DIRECT,
                transport=route.transport,
                host=route.endpoint.host,
                port=route.endpoint.port,
                relay_id=None,
                inline_required=False,
            )
    return None


def _candidate_routes(plan: DialPlan) -> tuple[DialRoute, ...]:
    if plan.primary is None:
        return ()
    return (plan.primary,) + plan.fallbacks


def _relay_dial_target(
    plan: DialPlan,
    route: DialRoute,
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig],
    *,
    dev_allow_untrusted_reachability_relays: bool,
) -> DialTarget | None:
    if not route.relay_id:
        return None
    trusted = _trusted_by_id(trusted_reachability_relays).get(route.relay_id)
    if trusted is None:
        if not dev_allow_untrusted_reachability_relays or route.endpoint is None:
            return None
        return DialTarget(
            peer_id=plan.peer_id,
            route_kind=ROUTE_RELAY,
            transport=route.transport,
            host=route.endpoint.host,
            port=route.endpoint.port,
            relay_id=route.relay_id,
            inline_required=route.inline_required,
        )
    return DialTarget(
        peer_id=plan.peer_id,
        route_kind=ROUTE_RELAY,
        transport=route.transport,
        host=trusted.host,
        port=trusted.port,
        relay_id=trusted.relay_id,
        inline_required=route.inline_required,
    )


def send_prepared_envelope_via_plan(
    *,
    envelope: PromptRequestEnvelope,
    plan: DialPlan,
    trusted_reachability_relays: Sequence[TrustedReachabilityRelayConfig],
    sender: Callable[[DialTarget, PromptRequestEnvelope], object],
    dev_allow_untrusted_reachability_relays: bool = False,
) -> DialTarget | None:
    """Resolve then hand off to transport-owned socket IO."""

    target = resolve_dial_target(
        plan,
        trusted_reachability_relays,
        dev_allow_untrusted_reachability_relays=dev_allow_untrusted_reachability_relays,
    )
    if target is None:
        return None
    sender(target, envelope)
    return target


def _trusted_by_id(
    relays: Sequence[TrustedReachabilityRelayConfig],
) -> dict[str, TrustedReachabilityRelayConfig]:
    return {relay.relay_id: relay for relay in relays}
