import json

from tenet.experts.memory_index import (
    IndexConfig,
    MemoryManifest,
    build_memory_index,
    score_manifest,
    verify_chunk_proof,
)


def test_build_manifest_without_raw_text(tmp_path):
    (tmp_path / "art.md").write_text(
        "Monet and Degas were central figures in Impressionism. "
        "Paris salons, plein air painting, and color theory matter here.",
        encoding="utf-8",
    )
    (tmp_path / "private.md").write_text(
        "private question about a sensitive medical concern should not be copied raw",
        encoding="utf-8",
    )

    index = build_memory_index(IndexConfig(peer_id="peer-a", roots=(str(tmp_path),)))
    manifest = index.manifest
    data = manifest.to_json()

    assert manifest.version == "por.memory_manifest.v1"
    assert manifest.file_count == 2
    assert manifest.chunk_count >= 2
    assert manifest.corpus_root
    assert str(tmp_path) not in data
    assert "private question about a sensitive medical concern" not in data
    assert manifest.privacy["raw_text_published"] is False

    loaded = MemoryManifest.from_json(data)
    assert loaded.index_digest == manifest.index_digest


def test_manifest_score_prefers_matching_corpus(tmp_path):
    (tmp_path / "art.md").write_text(
        "Monet Degas Renoir Impressionism Impressionism painting Paris color.",
        encoding="utf-8",
    )
    index = build_memory_index(IndexConfig(peer_id="peer-a", roots=(str(tmp_path),)))

    art_score = score_manifest(index.manifest, "question about Monet and Impressionism")
    unrelated_score = score_manifest(index.manifest, "kernel scheduler packet retransmission")

    assert art_score > unrelated_score


def test_local_query_can_hide_or_reveal_sources(tmp_path):
    (tmp_path / "art.md").write_text(
        "Monet studied light and color in impressionist landscape painting.",
        encoding="utf-8",
    )
    index = build_memory_index(IndexConfig(peer_id="peer-a", roots=(str(tmp_path),)))

    hidden = index.query("Monet color", limit=1)
    revealed = index.query("Monet color", limit=1, reveal=True)

    assert hidden[0].score > 0
    assert hidden[0].source is None
    assert hidden[0].excerpt is None
    assert revealed[0].source is not None
    assert "Monet" in revealed[0].excerpt


def test_chunk_proof_verifies_and_tamper_fails(tmp_path):
    (tmp_path / "notes.md").write_text(
        "Impressionism memory cache about Monet and Degas.",
        encoding="utf-8",
    )
    index = build_memory_index(IndexConfig(peer_id="peer-a", roots=(str(tmp_path),)))
    hit = index.query("Degas", limit=1)[0]

    proof = index.chunk_proof(hit.chunk_id)
    assert verify_chunk_proof(proof)

    tampered = proof.__class__(
        chunk_id=proof.chunk_id,
        commitment=proof.commitment,
        chunk_hash="00" * 32,
        nonce=proof.nonce,
        leaf_index=proof.leaf_index,
        siblings=proof.siblings,
        root=proof.root,
    )
    assert not verify_chunk_proof(tampered)


def test_private_terms_mode_removes_public_terms(tmp_path):
    (tmp_path / "notes.md").write_text(
        "Monet Impressionism private local topic words.",
        encoding="utf-8",
    )
    index = build_memory_index(
        IndexConfig(peer_id="peer-a", roots=(str(tmp_path),), publish_terms=False)
    )

    manifest_json = json.loads(index.manifest.to_json())
    assert manifest_json["top_terms"] == []
    assert index.manifest.privacy["public_terms"] is False
    assert score_manifest(index.manifest, "Monet Impressionism") == 0
