"""High-level Expert Mode orchestration for the tenet MVP."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone

from tenet.experts.directory import (
    DiscoveryProvider,
    DiscoveryRequest,
    DiscoveryResult,
    PUBLIC_SNAPSHOT_V1,
    PrivateDiscoveryUnavailable,
)
from tenet.envelope import HYBRID_RETURN_PATH_V2, PromptRequestEnvelope
from tenet.experts.expert_route import CandidatePool, ExpertRoutePlan, RouteIntent, plan_expert_route


STABLE_NAME_DISCOVERY = "stable_name"
MATCH_RESULT_GOSSIP_DISCOVERY = "match_result_gossip"


@dataclass(frozen=True)
class ExpertModeConfig:
    min_pool_size: int = 3
    allow_degraded_pool: bool = True
    fallback_provider: str = "frontier"
    discovery_mode: str = PUBLIC_SNAPSHOT_V1
    allow_public_discovery_fallback: bool = True
    require_hybrid_return: bool = True
    discovery_max_records: int | None = None

    @classmethod
    def from_routing(cls, routing) -> "ExpertModeConfig":
        """Build from an ``ExpertRoutingConfig`` (Seam C).

        The capability reads the base routing config; base ``config`` no longer
        needs to know this expert type exists. Duck-typed so ``expert_mode`` need
        not import ``config``.
        """
        return cls(
            min_pool_size=routing.min_pool_size,
            allow_degraded_pool=routing.allow_degraded_pool,
            fallback_provider=routing.fallback_provider,
            discovery_mode=routing.discovery_mode,
            allow_public_discovery_fallback=routing.allow_public_discovery_fallback,
            require_hybrid_return=routing.require_hybrid_return,
            discovery_max_records=routing.discovery_max_records,
        )


@dataclass(frozen=True)
class ExpertModeTrace:
    use_expert: bool
    discovery_mode: str
    pool_tier: str
    candidate_count: int
    selected_handle: str | None
    fallback_reason: str | None
    exact_query_sent: bool
    private_query_used: bool
    warnings: tuple[str, ...]

    @property
    def selected_peer_id(self) -> str | None:
        """Compatibility alias for callers not yet renamed to selected_handle."""

        return self.selected_handle


@dataclass(frozen=True)
class ExpertModePreparedRequest:
    plan: ExpertRoutePlan
    discovery: DiscoveryResult
    envelope: PromptRequestEnvelope | None
    warnings: tuple[str, ...]
    trace: ExpertModeTrace

    @property
    def use_expert(self) -> bool:
        return self.plan.use_expert


def prepare_expert_mode_request(
    intent: RouteIntent,
    discovery_provider: DiscoveryProvider,
    config: ExpertModeConfig | None = None,
    provider_request: dict[str, object] | None = None,
    return_descriptor: dict[str, object] | None = None,
) -> ExpertModePreparedRequest:
    """Plan Expert Mode and build the Layer 7 envelope for the selected peer."""

    config = config or ExpertModeConfig()
    effective_intent = replace(
        intent,
        min_pool_size=config.min_pool_size,
        allow_degraded_pool=config.allow_degraded_pool,
        fallback_provider=config.fallback_provider,
    )

    warnings: list[str] = []
    discovery_max_records = config.discovery_max_records
    if config.discovery_mode == PUBLIC_SNAPSHOT_V1 and discovery_max_records is not None:
        warnings.append("ignored discovery_max_records for public snapshot; rank before limiting")
        discovery_max_records = None

    try:
        discovery = discovery_provider.discover(
            DiscoveryRequest(
                intent=effective_intent,
                mode=config.discovery_mode,
                max_records=discovery_max_records,
            )
        )
    except PrivateDiscoveryUnavailable:
        if not config.allow_public_discovery_fallback or config.discovery_mode == PUBLIC_SNAPSHOT_V1:
            raise
        warnings.append(f"{config.discovery_mode} unavailable; used {PUBLIC_SNAPSHOT_V1}")
        discovery = discovery_provider.discover(
            DiscoveryRequest(intent=effective_intent, mode=PUBLIC_SNAPSHOT_V1)
        )

    plan = plan_expert_route(effective_intent, discovery.candidates)
    if plan.pool.degraded_anonymity:
        warnings.append("candidate pool below privacy target; destination anonymity degraded")

    descriptor = return_descriptor or _default_return_descriptor()
    if config.require_hybrid_return and descriptor.get("mode") != HYBRID_RETURN_PATH_V2:
        warnings.append("hybrid return path required by platform but not present in descriptor")

    trace = _build_trace(plan, discovery, tuple(warnings))
    if not plan.use_expert:
        return ExpertModePreparedRequest(
            plan=plan,
            discovery=discovery,
            envelope=None,
            warnings=tuple(warnings),
            trace=trace,
        )

    envelope = PromptRequestEnvelope.visible_prompt(
        prompt=effective_intent.prompt,
        selected_handle=plan.selected_handle,
        requested_expertise=effective_intent.requested_expertise,
        provider_request=provider_request or _default_expert_provider_request(plan, config.fallback_provider),
        return_descriptor=descriptor,
        privacy_warnings=tuple(warnings),
        client_extensions=_negotiated_extensions(discovery, descriptor),
        extra_intent={
            "discovery_mode": discovery.mode,
            "candidate_pool_size": len(plan.pool.candidates),
            "degraded_anonymity": plan.pool.degraded_anonymity,
            "pool_tier": plan.pool.pool_tier,
            "match_source": (
                "live_private_discovery"
                if discovery.private_query_used
                else "public_snapshot_discovery"
            ),
            "live_tee_match": bool(discovery.private_query_used),
        },
    )
    return ExpertModePreparedRequest(
        plan=plan,
        discovery=discovery,
        envelope=envelope,
        warnings=tuple(warnings),
        trace=trace,
    )


def prepare_stable_name_request(
    intent: RouteIntent,
    *,
    selected_handle: str,
    config: ExpertModeConfig | None = None,
    provider_request: dict[str, object] | None = None,
    return_descriptor: dict[str, object] | None = None,
    descriptor_hash: str | None = None,
) -> ExpertModePreparedRequest:
    """Build an Expert Mode envelope from a signed stable-name descriptor.

    The descriptor has already resolved to an opaque handle. This path avoids
    live matching while preserving the Layer 7 envelope contract used by the
    normal expert-mode planner.
    """

    config = config or ExpertModeConfig()
    effective_intent = replace(
        intent,
        min_pool_size=config.min_pool_size,
        allow_degraded_pool=config.allow_degraded_pool,
        fallback_provider=config.fallback_provider,
    )
    discovery = DiscoveryResult(
        candidates=tuple(),
        mode=STABLE_NAME_DISCOVERY,
        snapshot_size=0,
        exact_query_sent=False,
        private_query_used=False,
        generated_at=datetime.now(timezone.utc).isoformat(),
        note="stable Tenet name resolved from a signed mixnet control descriptor",
    )
    pool = CandidatePool(
        candidates=tuple(),
        min_pool_size=effective_intent.min_pool_size,
        pool_tier=STABLE_NAME_DISCOVERY,
        healthy=True,
        degraded_anonymity=False,
        reason="stable Tenet name descriptor selected opaque handle",
    )
    plan = ExpertRoutePlan(
        use_expert=True,
        selected_handle=selected_handle,
        fallback_provider=effective_intent.fallback_provider,
        pool=pool,
        reason=pool.reason,
    )
    descriptor = return_descriptor or _default_return_descriptor()
    warnings: tuple[str, ...] = ()
    envelope = PromptRequestEnvelope.visible_prompt(
        prompt=effective_intent.prompt,
        selected_handle=selected_handle,
        requested_expertise=effective_intent.requested_expertise,
        provider_request=provider_request or _default_expert_provider_request(plan, config.fallback_provider),
        return_descriptor=descriptor,
        privacy_warnings=warnings,
        client_extensions=_negotiated_extensions(discovery, descriptor),
        extra_intent={
            "discovery_mode": discovery.mode,
            "candidate_pool_size": 0,
            "degraded_anonymity": False,
            "pool_tier": pool.pool_tier,
            "descriptor_hash": descriptor_hash,
        },
    )
    return ExpertModePreparedRequest(
        plan=plan,
        discovery=discovery,
        envelope=envelope,
        warnings=warnings,
        trace=_build_trace(plan, discovery, warnings),
    )


def prepare_match_result_gossip_request(
    intent: RouteIntent,
    *,
    selected_handle: str,
    matcher_id: str,
    result_key: str,
    attestation_ref: str | None = None,
    record_issued_at: float | None = None,
    record_expires_at: float | None = None,
    config: ExpertModeConfig | None = None,
    provider_request: dict[str, object] | None = None,
    return_descriptor: dict[str, object] | None = None,
) -> ExpertModePreparedRequest:
    """Build an Expert Mode envelope from a signed, gossiped match result.

    This is an allowed cached-TEE route source: it is not a live matcher call,
    but the control service has already validated the signed record and TTL.
    """

    config = config or ExpertModeConfig()
    effective_intent = replace(
        intent,
        min_pool_size=config.min_pool_size,
        allow_degraded_pool=config.allow_degraded_pool,
        fallback_provider=config.fallback_provider,
    )
    discovery = DiscoveryResult(
        candidates=tuple(),
        mode=MATCH_RESULT_GOSSIP_DISCOVERY,
        snapshot_size=0,
        exact_query_sent=False,
        private_query_used=True,
        generated_at=datetime.now(timezone.utc).isoformat(),
        note="signed match-result gossip selected opaque handle",
    )
    pool = CandidatePool(
        candidates=tuple(),
        min_pool_size=effective_intent.min_pool_size,
        pool_tier=MATCH_RESULT_GOSSIP_DISCOVERY,
        healthy=True,
        degraded_anonymity=False,
        reason="signed match-result gossip selected opaque handle",
    )
    plan = ExpertRoutePlan(
        use_expert=True,
        selected_handle=selected_handle,
        fallback_provider=effective_intent.fallback_provider,
        pool=pool,
        reason=pool.reason,
    )
    descriptor = return_descriptor or _default_return_descriptor()
    warnings: tuple[str, ...] = ("match_result_from_signed_gossip_cache",)
    envelope = PromptRequestEnvelope.visible_prompt(
        prompt=effective_intent.prompt,
        selected_handle=selected_handle,
        requested_expertise=effective_intent.requested_expertise,
        provider_request=provider_request or _default_expert_provider_request(plan, config.fallback_provider),
        return_descriptor=descriptor,
        privacy_warnings=warnings,
        client_extensions=_negotiated_extensions(discovery, descriptor),
        extra_intent={
            "discovery_mode": discovery.mode,
            "candidate_pool_size": 0,
            "degraded_anonymity": False,
            "pool_tier": pool.pool_tier,
            "matcher_id": matcher_id,
            "match_result_key": result_key,
            "match_source": "cached_tee_signed_gossip",
            "live_tee_match": False,
            "attestation_ref": attestation_ref,
            "match_record_issued_at": record_issued_at,
            "match_record_expires_at": record_expires_at,
        },
    )
    return ExpertModePreparedRequest(
        plan=plan,
        discovery=discovery,
        envelope=envelope,
        warnings=warnings,
        trace=_build_trace(plan, discovery, warnings),
    )


def _build_trace(
    plan: ExpertRoutePlan,
    discovery: DiscoveryResult,
    warnings: tuple[str, ...],
) -> ExpertModeTrace:
    return ExpertModeTrace(
        use_expert=plan.use_expert,
        discovery_mode=discovery.mode,
        pool_tier=plan.pool.pool_tier,
        candidate_count=len(plan.pool.candidates),
        selected_handle=plan.selected_handle,
        fallback_reason=None if plan.use_expert else plan.reason,
        exact_query_sent=discovery.exact_query_sent,
        private_query_used=discovery.private_query_used,
        warnings=warnings,
    )


def _default_return_descriptor() -> dict[str, object]:
    from tenet.packet.ta_claims import streaming_return_descriptor

    return streaming_return_descriptor(mode=HYBRID_RETURN_PATH_V2, paced=False)


def _default_expert_provider_request(plan: ExpertRoutePlan, fallback_provider: str) -> dict[str, object]:
    return {
        "provider": "expert_peer",
        "fallback_provider": fallback_provider,
        "stream": True,
    }


def _negotiated_extensions(
    discovery: DiscoveryResult,
    return_descriptor: dict[str, object],
) -> tuple[str, ...]:
    extensions: list[str] = []
    if discovery.mode:
        extensions.append(discovery.mode)
    return_mode = return_descriptor.get("mode")
    if isinstance(return_mode, str):
        extensions.append(return_mode)
    return tuple(extensions)
