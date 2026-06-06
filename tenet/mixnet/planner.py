"""Sealed-route planner boundary.

The invariant is deliberately narrow:

Control resolves names and signed records. This planner turns those resolved
values plus local policy into an opaque sealed path. Packet construction and
socket IO remain in the transport send path. This planner validates routing
shape; it does not claim mixnet-grade anonymity by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from tenet.mixnet.control.names import parse_tenet_name
from tenet.mixnet.control.service import MixnetControlService, MixnetRouteBinding, RouteBindingError
from tenet.mixnet.transport_dial import DialTarget


class MixnetPlanningError(ValueError):
    """Raised when control metadata cannot become a mixnet route plan."""


@dataclass(frozen=True)
class MixnetForwardPlan:
    """A transport-agnostic sealed route selected by the planner.

    ``mix_path`` contains intermediate mix/control/reachability-assist nodes.
    ``exit_handle`` is the selected opaque recipient handle or cluster node id.
    The plan intentionally contains no host, port, URL, or multiaddr fields.
    """

    exit_handle: str
    mix_path: tuple[str, ...] = ()
    dial_target: DialTarget | None = None
    source: str = "local-policy"
    min_mix_hops: int = 0
    known_mixnodes: frozenset[str] = frozenset()

    @property
    def forward_path(self) -> tuple[str, ...]:
        return self.mix_path + (self.exit_handle,)

    @property
    def relay_path(self) -> tuple[str, ...]:
        """Compatibility alias for old call sites; do not use in new code."""

        return self.mix_path

    def validate(self) -> None:
        if not self.exit_handle:
            raise MixnetPlanningError("mixnet forward plans require an exit handle")
        if (
            self.dial_target is not None
            and self.dial_target.route_kind == "direct"
            and self.mix_path
        ):
            raise MixnetPlanningError("direct dial targets cannot be combined with mix hops")
        validate_mix_path(
            self.mix_path,
            exit_handle=self.exit_handle,
            min_mix_hops=self.min_mix_hops,
            known_mixnodes=self.known_mixnodes,
        )

    def log_line(self) -> str:
        self.validate()
        return (
            "client event=mixnet_forward_plan source={source} exit={exit} "
            "mix_path={path} ta_claim=sealed_transport"
        ).format(
            source=self.source,
            exit=self.exit_handle,
            path="/".join(self.mix_path),
        )


def resolve_name_binding(
    service_name: str,
    *,
    control_service: MixnetControlService | None,
) -> MixnetRouteBinding:
    """Resolve a Tenet name through a real control-record service.

    Creating an empty ad hoc control service here would silently downgrade the
    overlay into local guesswork. Callers must inject the bootstrapped or
    replicated control service they actually trust.
    """

    parsed = parse_tenet_name(service_name)
    if control_service is None:
        raise MixnetPlanningError("control_service_required")
    try:
        binding = control_service.bind_name(parsed)
    except RouteBindingError as exc:
        raise MixnetPlanningError(str(exc)) from exc
    binding.validate()
    return binding


def build_forward_plan(
    *,
    exit_handle: str | None,
    mix_path: Sequence[str] = (),
    dial_target: DialTarget | None = None,
    source: str = "local-policy",
    min_mix_hops: int = 0,
    known_mixnodes: Sequence[str] = (),
) -> MixnetForwardPlan:
    plan = MixnetForwardPlan(
        exit_handle=str(exit_handle or ""),
        mix_path=tuple(str(node_id) for node_id in mix_path),
        dial_target=dial_target,
        source=source,
        min_mix_hops=max(0, int(min_mix_hops)),
        known_mixnodes=frozenset(str(node_id) for node_id in known_mixnodes),
    )
    plan.validate()
    return plan


def validate_mix_path(
    mix_path: Sequence[str],
    *,
    exit_handle: str | None = None,
    min_mix_hops: int = 0,
    known_mixnodes: Sequence[str] | frozenset[str] = (),
) -> tuple[str, ...]:
    """Validate the non-secret shape of a sealed forwarding path.

    The caller supplies the signed/locally trusted mixnode universe. When that
    universe is available, every intermediate hop must be in it. The exit handle
    is intentionally validated separately because opaque expert handles are not
    necessarily mixnode ids.
    """

    normalized = tuple(str(node_id).strip() for node_id in mix_path)
    if len(normalized) < max(0, int(min_mix_hops)):
        raise MixnetPlanningError("mix path does not meet minimum hop count")
    if any(not node_id for node_id in normalized):
        raise MixnetPlanningError("mix path contains an empty hop")
    if len(set(normalized)) != len(normalized):
        raise MixnetPlanningError("mix path contains a repeated hop")
    exit_id = str(exit_handle or "").strip()
    if exit_id and exit_id in normalized:
        raise MixnetPlanningError("mix path repeats the exit handle")
    known = frozenset(str(node_id) for node_id in known_mixnodes if str(node_id))
    if known:
        unknown = tuple(node_id for node_id in normalized if node_id not in known)
        if unknown:
            raise MixnetPlanningError(
                "mix path contains unsigned or unknown hops: " + ", ".join(unknown)
            )
    return normalized
