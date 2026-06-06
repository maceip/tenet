"""Expert-mode planning against the live attested enclave matcher."""

from __future__ import annotations

from tenet.experts.expert_mode import ExpertModeConfig, prepare_expert_mode_request
from tenet.experts.expert_route import RouteIntent
from tenet.experts.live_enclave import LiveEnclaveConfig, build_attested_client
from tenet.experts.matcher import PLAIN_MATCHER_V1


def plan_live_expert(
    config: LiveEnclaveConfig,
    *,
    prompt: str,
    requested_expertise: str | None = None,
    min_pool_size: int = 1,
) -> dict[str, object]:
    """Attest to the enclave, run expert-mode discovery via `/v1/match`, return plan."""
    client = build_attested_client(config)
    client.establish()
    prepared = prepare_expert_mode_request(
        RouteIntent(
            prompt=prompt,
            requested_expertise=requested_expertise,
            min_pool_size=min_pool_size,
            allow_degraded_pool=True,
        ),
        client,
        ExpertModeConfig(
            discovery_mode=PLAIN_MATCHER_V1,
            min_pool_size=min_pool_size,
            allow_degraded_pool=True,
            allow_public_discovery_fallback=False,
        ),
    )
    trace = prepared.trace
    att = client.attestation
    return {
        "ok": True,
        "url": config.url,
        "use_expert": prepared.use_expert,
        "selected_handle": trace.selected_handle,
        "selected_peer_id": trace.selected_peer_id,
        "pool_tier": trace.pool_tier,
        "candidate_count": trace.candidate_count,
        "discovery_mode": trace.discovery_mode,
        "fallback_reason": trace.fallback_reason,
        "warnings": list(trace.warnings),
        "attestation": {
            "platform": att.platform if att else None,
            "value_x_prefix": f"{att.value_x[:16]}..." if att else None,
        },
        "candidates": [
            {"peer_id": candidate.manifest.peer_id}
            for candidate in prepared.discovery.candidates[:8]
        ],
    }
