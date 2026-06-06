"""Expert Mode planning detached from packet routing.

This module turns a prompt plus public memory manifests into a route decision:
use a memory peer, or fall back to a normal frontier model. It does not know how
to build onion packets and it does not contact peers.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from tenet.experts.memory_index import COVER_MARKER, MemoryManifest, score_manifest


POOL_STRONG = "strong"
POOL_WEAK = "weak"
POOL_DEGRADED = "degraded"
POOL_FALLBACK = "fallback"
WEAK_POOL_SCORE_THRESHOLD = 0.15


@dataclass(frozen=True)
class PeerObservation:
    """Deterministic operational facts observed outside the manifest."""

    peer_id: str
    p50_latency_ms: float = 500.0
    p95_latency_ms: float = 1500.0
    uptime: float = 1.0
    completion_rate: float = 1.0
    price_units: float = 0.0


@dataclass(frozen=True)
class PeerCandidate:
    manifest: MemoryManifest
    observation: PeerObservation | None = None


@dataclass(frozen=True)
class RouteIntent:
    prompt: str
    requested_expertise: str | None = None
    min_pool_size: int = 3
    allow_degraded_pool: bool = True
    fallback_provider: str = "frontier"
    max_price_units: float | None = None
    random_seed: int | None = None

    def query_text(self) -> str:
        if self.requested_expertise:
            return f"{self.requested_expertise}\n{self.prompt}"
        return self.prompt


@dataclass(frozen=True)
class CandidateScore:
    peer_id: str
    total_score: float
    memory_score: float
    operational_score: float
    price_penalty: float
    p50_latency_ms: float
    price_units: float
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CandidatePool:
    """Scored candidate pool for Expert Mode.

    `pool_tier` is the source of truth for ops/product behavior. `healthy` is
    retained for compatibility and means strong-only; weak and degraded pools
    can still route when policy allows it.
    """

    candidates: tuple[CandidateScore, ...]
    min_pool_size: int
    pool_tier: str
    healthy: bool
    degraded_anonymity: bool
    reason: str


@dataclass(frozen=True)
class ExpertRoutePlan:
    use_expert: bool
    selected_peer_id: str | None
    fallback_provider: str
    pool: CandidatePool
    reason: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2)


def plan_expert_route(
    intent: RouteIntent,
    candidates: Sequence[PeerCandidate],
    limit: int = 20,
) -> ExpertRoutePlan:
    scored = _score_candidates(intent, candidates)
    scored = tuple(scored[:limit])

    if not scored:
        pool = CandidatePool(
            candidates=tuple(),
            min_pool_size=intent.min_pool_size,
            pool_tier=POOL_FALLBACK,
            healthy=False,
            degraded_anonymity=False,
            reason="no candidate had measurable memory fit",
        )
        return ExpertRoutePlan(False, None, intent.fallback_provider, pool, pool.reason)

    degraded = len(scored) < intent.min_pool_size
    if degraded and not intent.allow_degraded_pool:
        pool = CandidatePool(
            candidates=scored,
            min_pool_size=intent.min_pool_size,
            pool_tier=POOL_FALLBACK,
            healthy=False,
            degraded_anonymity=True,
            reason="candidate pool below minimum privacy threshold",
        )
        return ExpertRoutePlan(False, None, intent.fallback_provider, pool, pool.reason)

    pool_tier = _pool_tier(scored, intent.min_pool_size)
    pool = CandidatePool(
        candidates=scored,
        min_pool_size=intent.min_pool_size,
        pool_tier=pool_tier,
        healthy=pool_tier == POOL_STRONG,
        degraded_anonymity=degraded,
        reason=_pool_reason(pool_tier),
    )
    selected = _weighted_choice(scored, intent.random_seed)
    return ExpertRoutePlan(True, selected.peer_id, intent.fallback_provider, pool, pool.reason)


def _score_candidates(
    intent: RouteIntent,
    candidates: Sequence[PeerCandidate],
) -> list[CandidateScore]:
    query = intent.query_text()
    scored = []

    for candidate in candidates:
        # Cover (decoy) candidates pad the matcher response to a constant size to
        # hide the real-match count from the oblivious operator (item 6). They are
        # never routing targets, so drop them before scoring. The operator could
        # not read this marker; the asker can.
        if candidate.manifest.privacy.get(COVER_MARKER):
            continue
        observation = candidate.observation or PeerObservation(peer_id=candidate.manifest.peer_id)
        price = observation.price_units
        if intent.max_price_units is not None and price > intent.max_price_units:
            continue

        memory = score_manifest(candidate.manifest, query)
        if memory <= 0:
            continue

        operational = _operational_score(observation)
        price_penalty = min(0.4, price / 100.0)
        total = max(0.0, memory * (0.7 + 0.3 * operational) - price_penalty)
        if total <= 0:
            continue

        reasons = (
            f"memory_score={memory:.3f}",
            f"operational_score={operational:.3f}",
            f"p50_latency_ms={observation.p50_latency_ms:.0f}",
            f"price_units={price:.3f}",
        )
        scored.append(
            CandidateScore(
                peer_id=candidate.manifest.peer_id,
                total_score=total,
                memory_score=memory,
                operational_score=operational,
                price_penalty=price_penalty,
                p50_latency_ms=observation.p50_latency_ms,
                price_units=price,
                reasons=reasons,
            )
        )

    scored.sort(key=lambda item: (-item.total_score, item.peer_id))
    return scored


def _operational_score(observation: PeerObservation) -> float:
    uptime = _clamp01(observation.uptime)
    completion = _clamp01(observation.completion_rate)
    latency = 1.0 / (1.0 + max(0.0, observation.p50_latency_ms) / 1000.0)
    tail = 1.0 / (1.0 + max(0.0, observation.p95_latency_ms) / 3000.0)
    return (0.35 * uptime) + (0.35 * completion) + (0.2 * latency) + (0.1 * tail)


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _pool_tier(scored: Sequence[CandidateScore], min_pool_size: int) -> str:
    if not scored:
        return POOL_FALLBACK
    if len(scored) < min_pool_size:
        return POOL_DEGRADED
    if scored[0].total_score < WEAK_POOL_SCORE_THRESHOLD:
        return POOL_WEAK
    return POOL_STRONG


def _pool_reason(pool_tier: str) -> str:
    if pool_tier == POOL_STRONG:
        return "candidate pool ready"
    if pool_tier == POOL_WEAK:
        return "candidate pool has enough peers but weak memory fit"
    if pool_tier == POOL_DEGRADED:
        return "candidate pool is small; destination anonymity degraded"
    return "no expert route available"


def _weighted_choice(candidates: Sequence[CandidateScore], seed: int | None) -> CandidateScore:
    rng = random.Random(seed)
    total = sum(candidate.total_score for candidate in candidates)
    if total <= 0:
        return candidates[0]
    pick = rng.random() * total
    upto = 0.0
    for candidate in candidates:
        upto += candidate.total_score
        if upto >= pick:
            return candidate
    return candidates[-1]


def load_manifest(path: str | Path) -> MemoryManifest:
    return MemoryManifest.from_json(Path(path).read_text(encoding="utf-8"))


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plan an Expert Mode route from memory manifests.")
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--expertise")
    parser.add_argument("--manifest", action="append", required=True, help="Manifest JSON file. Can be repeated.")
    parser.add_argument("--min-pool-size", type=int, default=3)
    parser.add_argument("--strict-pool", action="store_true", help="Fallback if pool is below min-pool-size.")
    parser.add_argument("--fallback-provider", default="frontier")
    parser.add_argument("--seed", type=int)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    manifests = [load_manifest(path) for path in args.manifest]
    intent = RouteIntent(
        prompt=args.prompt,
        requested_expertise=args.expertise,
        min_pool_size=args.min_pool_size,
        allow_degraded_pool=not args.strict_pool,
        fallback_provider=args.fallback_provider,
        random_seed=args.seed,
    )
    plan = plan_expert_route(intent, [PeerCandidate(manifest) for manifest in manifests])
    print(plan.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
