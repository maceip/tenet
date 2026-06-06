"""Tests for TA-3 honest streaming claims."""

import pytest
from pathlib import Path

from sphinxmix.ta_claims import (
    CLAIM_ENCRYPTED_RELAY_CHAIN,
    NOT_GPA_RESISTANT,
    assert_honest_streaming_copy,
    find_forbidden_streaming_claims,
    response_claim_headers,
    scan_files_for_forbidden_claims,
    streaming_return_descriptor,
)
from por.envelope import HYBRID_RETURN_PATH_V2, PromptRequestEnvelope
from por.expert_mode import ExpertModeConfig, prepare_expert_mode_request
from por.expert_route import RouteIntent
from por.directory import PublicManifestDirectory
from por.memory_index import IndexConfig, build_memory_index


def test_streaming_return_descriptor_includes_ta_claim():
    desc = streaming_return_descriptor(mode=HYBRID_RETURN_PATH_V2, paced=True)
    assert desc["ta_claim"] == CLAIM_ENCRYPTED_RELAY_CHAIN
    assert NOT_GPA_RESISTANT in desc["ta_not"]
    assert "exit_paced_only" in desc["ta_not"]


def test_forbidden_streaming_copy_detected():
    bad = "Our mixnet-grade GPA-resistant streaming return path"
    found = find_forbidden_streaming_claims(bad)
    assert "mixnet-grade" in found
    assert "gpa-resistant" in found

    with pytest.raises(ValueError):
        assert_honest_streaming_copy(bad)


def test_envelope_requires_ta_claim_when_streaming():
    envelope = PromptRequestEnvelope.visible_prompt(
        prompt="x",
        selected_peer_id="p",
        return_descriptor={"mode": HYBRID_RETURN_PATH_V2, "stream": True},
    )
    with pytest.raises(ValueError):
        envelope.validate()


def test_expert_mode_default_envelope_has_ta_claim(tmp_path):
    root = tmp_path / "peer"
    root.mkdir()
    (root / "notes.md").write_text("Monet Impressionism painting.", encoding="utf-8")
    manifest = build_memory_index(IndexConfig(peer_id="peer", roots=(str(root),))).manifest
    directory = PublicManifestDirectory.from_manifests([manifest])

    prepared = prepare_expert_mode_request(
        RouteIntent(prompt="Monet?", requested_expertise="art"),
        directory,
        ExpertModeConfig(min_pool_size=1),
    )

    assert prepared.envelope is not None
    assert prepared.envelope.return_descriptor["ta_claim"] == CLAIM_ENCRYPTED_RELAY_CHAIN


def test_scan_tracked_docs_are_honest():
    root = Path(__file__).resolve().parent
    violations = scan_files_for_forbidden_claims(root)
    assert violations == []


def test_response_claim_headers():
    headers = response_claim_headers(paced=True)
    assert headers["X-Return-Path-Claim"] == CLAIM_ENCRYPTED_RELAY_CHAIN
    assert NOT_GPA_RESISTANT in headers["X-Return-Path-Not"]
