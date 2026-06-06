import json
from pathlib import Path

from tenet.experts.alpha_experts import (
    build_corpus_from_transcript,
    materialize_alpha_population,
    write_alpha_population,
)


def test_build_corpus_from_transcript(tmp_path):
    transcript = tmp_path / "sess.jsonl"
    transcript.write_text(
        json.dumps(
            {
                "role": "user",
                "message": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "Explain QUIC congestion control, UDP NAT traversal, "
                                "reachability relays, and mixnet routing for home experts "
                                "behind CGNAT. Include packet scheduling, supernode forward "
                                "semantics, and why the asker must never learn the expert IP."
                            ),
                        }
                    ],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    spec = build_corpus_from_transcript(transcript, tmp_path / "corpus")
    assert spec is not None
    assert spec.group_id == "systems_networking"
    assert (spec.corpus_dir / "session.md").is_file()


def test_materialize_includes_synthetic_when_no_logs(tmp_path):
    pop = materialize_alpha_population(
        log_roots=[tmp_path / "empty"],
        corpus_out=tmp_path / "corpus",
        min_experts=1,
        include_synthetic=True,
        max_transcripts=0,
    )
    assert len(pop.experts) >= 4
    path = write_alpha_population(pop, tmp_path / "pop.json")
    loaded = json.loads(path.read_text())
    assert loaded["version"] == "por.alpha_population.v1"
