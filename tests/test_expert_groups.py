import inspect

import pytest

from tenet.experts.directory import PeerRecord
from tenet.experts.expert_groups import (
    GROUP_DEGRADED,
    GROUP_READY,
    ROOT_GROUP_ID,
    assign_expert_group,
    build_expert_population_index,
)
from tenet.experts.memory_index import IndexConfig, build_memory_index


def _record(tmp_path, peer_id, text, *, descriptor=None, publish_terms=True):
    root = tmp_path / peer_id
    root.mkdir()
    (root / "notes.md").write_text(text, encoding="utf-8")
    manifest = build_memory_index(
        IndexConfig(peer_id=peer_id, roots=(str(root),), publish_terms=publish_terms)
    ).manifest
    return PeerRecord(manifest=manifest, descriptor=descriptor)


def test_population_index_groups_existing_manifests_without_query_matching(tmp_path):
    records = [
        _record(tmp_path, "peer-art", "Monet Degas Impressionism painting color light."),
        _record(tmp_path, "peer-sys", "QUIC UDP congestion packet transport scheduler."),
        _record(tmp_path, "peer-sec", "Sphinx Outfox mixnet privacy adversary threat model."),
    ]

    signature = inspect.signature(build_expert_population_index)
    assert "prompt" not in signature.parameters
    assert "query" not in signature.parameters

    index = build_expert_population_index(records, min_group_size=1)

    assert index.group_for_peer("peer-art").group_id == "art_culture"
    assert index.group_for_peer("peer-sys").group_id == "systems_networking"
    assert index.group_for_peer("peer-sec").group_id == "security_privacy"
    assert index.group(ROOT_GROUP_ID).peer_ids == ("peer-art", "peer-sec", "peer-sys")


def test_undersized_domain_group_is_degraded_and_can_broaden_to_root(tmp_path):
    records = [
        _record(tmp_path, "peer-art", "Monet Impressionism painting."),
        _record(tmp_path, "peer-sys-a", "QUIC UDP transport packet."),
        _record(tmp_path, "peer-sys-b", "TCP scheduler congestion packet."),
    ]

    index = build_expert_population_index(records, min_group_size=3)

    art = index.group("art_culture")
    root = index.group(ROOT_GROUP_ID)
    assert root.status == GROUP_READY
    assert art.status == GROUP_DEGRADED
    assert art.broaden_to == ROOT_GROUP_ID
    assert art.peer_ids == ("peer-art",)


def test_descriptor_tags_assign_group_when_manifest_terms_are_private(tmp_path):
    record = _record(
        tmp_path,
        "peer-private-art",
        "Monet Degas Impressionism painting.",
        publish_terms=False,
        descriptor={"expertise_tags": ["Impressionism", "painting"]},
    )

    assignment = assign_expert_group(record)

    assert assignment.group_id == "art_culture"
    assert "impressionism" in assignment.evidence_terms


def test_population_index_does_not_publish_peer_address_endpoints(tmp_path):
    record = _record(
        tmp_path,
        "peer-art",
        "Monet Impressionism painting.",
    )
    with pytest.raises(TypeError, match="peer_address"):
        PeerRecord(
            manifest=record.manifest,
            descriptor=record.descriptor,
            peer_address={
                "relay_candidates": [
                    {
                        "relay_id": "bootstrap-1",
                        "endpoint": {"host": "203.0.113.99", "port": 4433},
                    }
                ]
            },
        )

    data = build_expert_population_index([record], min_group_size=1).to_json()

    assert "203.0.113.99" not in data
    assert "4433" not in data
    assert "peer-art" in data
