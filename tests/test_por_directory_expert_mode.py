import pytest

from tenet.experts.directory import (
    PRIVATE_DISCOVERY_V1,
    PUBLIC_SNAPSHOT_V1,
    DiscoveryRequest,
    PrivateDiscoveryUnavailable,
    PublicManifestDirectory,
)
from tenet.envelope import HYBRID_RETURN_PATH_V2, PromptRequestEnvelope
from tenet.packet.ta_claims import streaming_return_descriptor
from tenet.experts.expert_mode import ExpertModeConfig, prepare_expert_mode_request
from tenet.experts.expert_route import PeerObservation, RouteIntent
from tenet.experts.memory_index import IndexConfig, build_memory_index


def _manifest(tmp_path, peer_id, text):
    root = tmp_path / peer_id
    root.mkdir()
    (root / "notes.md").write_text(text, encoding="utf-8")
    return build_memory_index(IndexConfig(peer_id=peer_id, roots=(str(root),))).manifest


def test_public_directory_returns_snapshot_without_exact_query(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    other = _manifest(tmp_path, "peer-systems", "QUIC UDP transport packets.")
    directory = PublicManifestDirectory.from_manifests(
        [manifest, other],
        [PeerObservation(peer_id="peer-art", p50_latency_ms=90)],
    )

    result = directory.discover(
        DiscoveryRequest(
            RouteIntent(prompt="private Monet question"),
            mode=PUBLIC_SNAPSHOT_V1,
            max_records=1,
        )
    )

    assert result.snapshot_size == 2
    assert result.exact_query_sent is False
    assert result.private_query_used is False
    assert result.candidates[0].manifest.peer_id == "peer-art"
    assert "max_records ignored" in result.note


def test_private_discovery_request_fails_cleanly_without_provider(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism color light.")
    directory = PublicManifestDirectory.from_manifests([manifest])

    with pytest.raises(PrivateDiscoveryUnavailable):
        directory.discover(
            DiscoveryRequest(RouteIntent(prompt="Monet?"), mode=PRIVATE_DISCOVERY_V1)
        )


def test_expert_mode_prepares_visible_envelope_and_warnings(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism painting Paris.")
    directory = PublicManifestDirectory.from_manifests([manifest])

    prepared = prepare_expert_mode_request(
        RouteIntent(prompt="What did Monet change?", requested_expertise="Impressionist art history"),
        directory,
        ExpertModeConfig(min_pool_size=3, allow_degraded_pool=True),
        provider_request={"provider": "demo", "model": "frontier", "stream": True},
    )

    assert prepared.use_expert
    assert prepared.envelope is not None
    assert prepared.envelope.selected_peer_id == "peer-art"
    assert prepared.envelope.prompt_text() == "What did Monet change?"
    assert prepared.envelope.return_descriptor["mode"] == HYBRID_RETURN_PATH_V2
    assert prepared.envelope.provider_request["provider"] == "demo"
    assert "destination anonymity degraded" in " ".join(prepared.warnings)
    assert prepared.trace.discovery_mode == PUBLIC_SNAPSHOT_V1
    assert prepared.trace.use_expert is True
    assert prepared.trace.pool_tier == "degraded"
    assert prepared.trace.candidate_count == 1
    assert prepared.trace.selected_peer_id == "peer-art"


def test_expert_mode_falls_back_when_no_memory_fit(tmp_path):
    manifest = _manifest(tmp_path, "peer-systems", "QUIC congestion packets.")
    directory = PublicManifestDirectory.from_manifests([manifest])

    prepared = prepare_expert_mode_request(
        RouteIntent(prompt="What did Monet change?", requested_expertise="Impressionist art history"),
        directory,
    )

    assert not prepared.use_expert
    assert prepared.envelope is None
    assert prepared.plan.fallback_provider == "frontier"
    assert prepared.trace.use_expert is False
    assert prepared.trace.pool_tier == "fallback"
    assert prepared.trace.fallback_reason == "no candidate had measurable memory fit"


def test_private_discovery_can_fall_back_to_public_snapshot(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism painting Paris.")
    directory = PublicManifestDirectory.from_manifests([manifest])

    prepared = prepare_expert_mode_request(
        RouteIntent(prompt="Monet?", requested_expertise="Impressionism"),
        directory,
        ExpertModeConfig(discovery_mode=PRIVATE_DISCOVERY_V1, allow_public_discovery_fallback=True),
    )

    assert prepared.discovery.mode == PUBLIC_SNAPSHOT_V1
    assert prepared.use_expert
    assert "used public_snapshot_v1" in " ".join(prepared.warnings)
    assert prepared.envelope is not None
    assert prepared.envelope.client_extensions == (PUBLIC_SNAPSHOT_V1, HYBRID_RETURN_PATH_V2)


def test_expert_mode_default_provider_request_is_expert_oriented(tmp_path):
    manifest = _manifest(tmp_path, "peer-art", "Monet Impressionism painting Paris.")
    directory = PublicManifestDirectory.from_manifests([manifest])

    prepared = prepare_expert_mode_request(
        RouteIntent(prompt="Monet?", requested_expertise="Impressionism"),
        directory,
    )

    assert prepared.envelope is not None
    assert prepared.envelope.provider_request == {
        "provider": "expert_peer",
        "fallback_provider": "frontier",
        "stream": True,
    }
    assert "mptls_prompt_hiding_future" not in prepared.envelope.client_extensions


def test_orchestrator_ignores_public_max_records_before_scoring(tmp_path):
    weak = _manifest(tmp_path, "peer-systems", "QUIC UDP transport packets.")
    strong = _manifest(tmp_path, "peer-art", "Monet Impressionism painting Paris color light.")
    directory = PublicManifestDirectory.from_manifests([weak, strong])

    prepared = prepare_expert_mode_request(
        RouteIntent(prompt="Monet?", requested_expertise="Impressionism"),
        directory,
        ExpertModeConfig(discovery_max_records=1),
    )

    assert prepared.envelope is not None
    assert prepared.envelope.selected_peer_id == "peer-art"
    assert "rank before limiting" in " ".join(prepared.warnings)


def test_envelope_round_trip_visible_prompt():
    envelope = PromptRequestEnvelope.visible_prompt(
        prompt="hello",
        selected_peer_id="peer-a",
        requested_expertise="test",
        return_descriptor=streaming_return_descriptor(mode=HYBRID_RETURN_PATH_V2),
    )

    loaded = PromptRequestEnvelope.from_json(envelope.to_json())

    assert loaded.prompt_text() == "hello"
    assert loaded.intent_descriptor["requested_expertise"] == "test"
