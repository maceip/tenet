from por.expert_route import (
    PeerCandidate,
    PeerObservation,
    RouteIntent,
    plan_expert_route,
)
from por.memory_index import IndexConfig, build_memory_index


def _manifest(tmp_path, peer_id, filename, text):
    root = tmp_path / peer_id
    root.mkdir()
    (root / filename).write_text(text, encoding="utf-8")
    return build_memory_index(IndexConfig(peer_id=peer_id, roots=(str(root),))).manifest


def test_expert_route_selects_matching_memory_peer(tmp_path):
    art = _manifest(
        tmp_path,
        "peer-art",
        "art.md",
        "Monet Degas Impressionism Paris salon painting color light.",
    )
    systems = _manifest(
        tmp_path,
        "peer-systems",
        "systems.md",
        "kernel scheduler tcp congestion packet retransmission.",
    )

    plan = plan_expert_route(
        RouteIntent(
            prompt="What did Monet contribute to Impressionism?",
            requested_expertise="Impressionist art history",
            random_seed=1,
        ),
        [PeerCandidate(art), PeerCandidate(systems)],
    )

    assert plan.use_expert
    assert plan.selected_peer_id == "peer-art"
    assert [c.peer_id for c in plan.pool.candidates] == ["peer-art"]
    assert plan.pool.pool_tier == "degraded"


def test_expert_route_falls_back_without_memory_fit(tmp_path):
    systems = _manifest(
        tmp_path,
        "peer-systems",
        "systems.md",
        "kernel scheduler tcp congestion packet retransmission.",
    )

    plan = plan_expert_route(
        RouteIntent(prompt="Explain Renoir and Degas", fallback_provider="anthropic"),
        [PeerCandidate(systems)],
    )

    assert not plan.use_expert
    assert plan.selected_peer_id is None
    assert plan.fallback_provider == "anthropic"
    assert plan.pool.pool_tier == "fallback"


def test_small_pool_can_be_used_with_degraded_anonymity(tmp_path):
    art = _manifest(
        tmp_path,
        "peer-art",
        "art.md",
        "Monet Impressionism Impressionism painting.",
    )

    plan = plan_expert_route(
        RouteIntent(
            prompt="Monet?",
            min_pool_size=3,
            allow_degraded_pool=True,
            random_seed=7,
        ),
        [PeerCandidate(art)],
    )

    assert plan.use_expert
    assert plan.pool.degraded_anonymity
    assert plan.pool.healthy is False
    assert plan.pool.pool_tier == "degraded"


def test_small_pool_can_fail_closed(tmp_path):
    art = _manifest(
        tmp_path,
        "peer-art",
        "art.md",
        "Monet Impressionism Impressionism painting.",
    )

    plan = plan_expert_route(
        RouteIntent(prompt="Monet?", min_pool_size=3, allow_degraded_pool=False),
        [PeerCandidate(art)],
    )

    assert not plan.use_expert
    assert plan.pool.degraded_anonymity
    assert plan.pool.pool_tier == "fallback"
    assert "below minimum" in plan.reason


def test_price_filter_removes_candidate(tmp_path):
    art = _manifest(
        tmp_path,
        "peer-art",
        "art.md",
        "Monet Impressionism Impressionism painting.",
    )
    expensive = PeerCandidate(
        art,
        PeerObservation(peer_id="peer-art", price_units=99),
    )

    plan = plan_expert_route(
        RouteIntent(prompt="Monet?", max_price_units=5),
        [expensive],
    )

    assert not plan.use_expert


def test_large_low_fit_pool_is_weak_not_degraded(tmp_path):
    manifests = [
        _manifest(tmp_path, f"peer-{idx}", "notes.md", "Monet painting.")
        for idx in range(3)
    ]
    noisy_prompt = "Monet " + " ".join(f"unrelated{idx}" for idx in range(30))

    plan = plan_expert_route(
        RouteIntent(prompt=noisy_prompt, min_pool_size=3, random_seed=2),
        [PeerCandidate(manifest) for manifest in manifests],
    )

    assert plan.use_expert
    assert plan.pool.pool_tier == "weak"
    assert not plan.pool.degraded_anonymity


def test_large_good_fit_pool_is_strong_and_healthy(tmp_path):
    manifests = [
        _manifest(
            tmp_path,
            f"peer-art-{idx}",
            "art.md",
            "Monet Degas Renoir Impressionism painting Paris color light.",
        )
        for idx in range(3)
    ]

    plan = plan_expert_route(
        RouteIntent(
            prompt="What did Monet contribute to Impressionism?",
            requested_expertise="Impressionist art history",
            min_pool_size=3,
            random_seed=4,
        ),
        [PeerCandidate(manifest) for manifest in manifests],
    )

    assert plan.use_expert
    assert plan.pool.pool_tier == "strong"
    assert plan.pool.healthy is True
    assert not plan.pool.degraded_anonymity
