"""Alpha network (STATUS.md item 15) — required expert population.

Materialize expert peers from agent session logs (Cursor, Codex, Claude,
Antigravity, etc.). Each peer gets a corpus directory and public manifest;
live deploy runs ``tenet run`` on real nodes. Synthetic seeds only pad node count
when there are fewer sessions than VMs — the population file is still mandatory
for item 15 scale-out.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from tenet.experts.directory import DIRECTORY_SNAPSHOT_VERSION, PeerRecord
from tenet.experts.expert_groups import assign_expert_group, build_expert_population_index
from tenet.experts.memory_index import IndexConfig, build_memory_index
from tenet.schema import supports_schema

ALPHA_POPULATION_VERSION = "tenet.alpha_population.2026-06"
DEFAULT_LOG_ROOTS = (
    Path.home() / ".cursor" / "projects",
)
TRANSCRIPT_GLOB = "**/agent-transcripts/**/*.jsonl"
MIN_CORPUS_CHARS = 200
SYNTHETIC_SEEDS: Mapping[str, str] = {
    "alpha-seed-art": (
        "Monet, Degas, and Renoir developed Impressionism in Paris. "
        "Brushwork, light, and color on canvas defined the movement."
    ),
    "alpha-seed-systems": (
        "QUIC over UDP, TCP congestion control, NAT traversal, and reachability "
        "relays for home experts behind CGNAT."
    ),
    "alpha-seed-security": (
        "Sphinx mixnet, Outfox sealed transport, opaque handles, attested Nitro "
        "matcher, and privacy-preserving expert routing."
    ),
    "alpha-seed-software": (
        "LLM agents, RAG retrieval, prompt routing, tool use, and expert networks "
        "that never expose home IP addresses."
    ),
}


@dataclass(frozen=True)
class AlphaExpertSpec:
    """One Alpha expert: corpus on disk + public directory fields."""

    expert_id: str
    corpus_dir: Path
    source: str  # cursor_transcript | synthetic_seed | merged
    session_id: str | None
    descriptor: dict[str, object]
    group_id: str
    byte_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "expert_id": self.expert_id,
            "corpus_dir": str(self.corpus_dir),
            "source": self.source,
            "session_id": self.session_id,
            "descriptor": self.descriptor,
            "group_id": self.group_id,
            "byte_count": self.byte_count,
        }


@dataclass(frozen=True)
class AlphaPopulation:
    version: str
    experts: tuple[AlphaExpertSpec, ...]
    generated_from: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "generated_from": list(self.generated_from),
            "experts": [e.to_dict() for e in self.experts],
        }

    def peer_records(self, *, created_at_iso: str | None = None) -> tuple[PeerRecord, ...]:
        records: list[PeerRecord] = []
        for spec in self.experts:
            built = build_memory_index(
                IndexConfig(
                    peer_id=spec.expert_id,
                    roots=(str(spec.corpus_dir),),
                    created_at_iso=created_at_iso,
                )
            )
            records.append(
                PeerRecord(manifest=built.manifest, descriptor=dict(spec.descriptor))
            )
        return tuple(records)

    def population_index(self, *, min_group_size: int = 1):
        return build_expert_population_index(self.peer_records(), min_group_size=min_group_size)


def default_log_roots() -> tuple[Path, ...]:
    return DEFAULT_LOG_ROOTS


def discover_transcript_files(roots: Sequence[Path | str] | None = None) -> list[Path]:
    paths: list[Path] = []
    for root in roots or default_log_roots():
        base = Path(root).expanduser()
        if not base.is_dir():
            continue
        paths.extend(sorted(base.glob(TRANSCRIPT_GLOB)))
    return paths


def _extract_message_text(message: object) -> str:
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and block.get("text"):
            parts.append(str(block["text"]))
    return "\n".join(parts)


def iter_transcript_text(path: Path) -> Iterator[tuple[str, str]]:
    """Yield (role, text) for each non-empty line in a JSONL transcript."""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        role = str(row.get("role", "unknown"))
        text = _extract_message_text(row.get("message"))
        text = text.strip()
        if len(text) < 20:
            continue
        yield role, text


def session_id_from_path(path: Path) -> str:
    stem = path.stem
    if stem.endswith(".jsonl"):
        stem = path.stem
    return stem[:32]


def expert_id_from_session(session_id: str) -> str:
    digest = sha256(session_id.encode("utf-8")).hexdigest()[:10]
    return f"alpha-{digest}"


def build_corpus_from_transcript(
    path: Path,
    out_dir: Path,
    *,
    expert_id: str | None = None,
) -> AlphaExpertSpec | None:
    session = session_id_from_path(path)
    eid = expert_id or expert_id_from_session(session)
    out_dir = out_dir / eid
    out_dir.mkdir(parents=True, exist_ok=True)

    chunks: list[str] = []
    for role, text in iter_transcript_text(path):
        chunks.append(f"## {role}\n\n{text}\n")

    body = "\n".join(chunks).strip()
    if len(body) < MIN_CORPUS_CHARS:
        return None

    corpus_file = out_dir / "session.md"
    corpus_file.write_text(body, encoding="utf-8")

    record = PeerRecord(
        manifest=build_memory_index(
            IndexConfig(peer_id=eid, roots=(str(out_dir),))
        ).manifest,
        descriptor={
            "source": "cursor_agent_transcript",
            "session_id": session,
            "transcript_path": str(path),
            "agent_surface": _agent_surface_from_path(path),
        },
    )
    assignment = assign_expert_group(record)
    tags = list(assignment.evidence_terms[:12]) or [assignment.label]
    descriptor = dict(record.descriptor or {})
    descriptor["expertise_tags"] = tags
    descriptor["alpha_group"] = assignment.group_id

    return AlphaExpertSpec(
        expert_id=eid,
        corpus_dir=out_dir,
        source="cursor_transcript",
        session_id=session,
        descriptor=descriptor,
        group_id=assignment.group_id,
        byte_count=len(body.encode("utf-8")),
    )


def _agent_surface_from_path(path: Path) -> str:
    parts = [p.lower() for p in path.parts]
    if "cursor" in parts:
        return "cursor"
    if "codex" in parts:
        return "codex"
    if "antigravity" in parts:
        return "antigravity"
    if "claude" in parts:
        return "claude"
    return "unknown"


def build_synthetic_expert(
    seed_id: str,
    text: str,
    out_root: Path,
) -> AlphaExpertSpec:
    out_dir = out_root / seed_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "seed.md").write_text(text, encoding="utf-8")
    record = PeerRecord(
        manifest=build_memory_index(IndexConfig(peer_id=seed_id, roots=(str(out_dir),))).manifest,
        descriptor={
            "source": "synthetic_seed",
            "expertise_tags": [seed_id.replace("alpha-seed-", "").replace("-", " ")],
        },
    )
    assignment = assign_expert_group(record)
    descriptor = dict(record.descriptor or {})
    descriptor["alpha_group"] = assignment.group_id
    return AlphaExpertSpec(
        expert_id=seed_id,
        corpus_dir=out_dir,
        source="synthetic_seed",
        session_id=None,
        descriptor=descriptor,
        group_id=assignment.group_id,
        byte_count=len(text.encode("utf-8")),
    )


def materialize_alpha_population(
    *,
    log_roots: Sequence[Path | str] | None = None,
    corpus_out: Path | str = "data/alpha/corpus",
    min_experts: int = 1,
    max_transcripts: int | None = 50,
    include_synthetic: bool = True,
    extra_transcript_paths: Sequence[Path | str] = (),
) -> AlphaPopulation:
    """Build Alpha experts from agent logs; pad with synthetic seeds if needed."""

    out_root = Path(corpus_out)
    out_root.mkdir(parents=True, exist_ok=True)
    sources: list[str] = []
    experts: list[AlphaExpertSpec] = []

    transcripts: list[Path] = [Path(p).expanduser() for p in extra_transcript_paths]
    for path in discover_transcript_files(log_roots):
        transcripts.append(path)

    seen_sessions: set[str] = set()
    for path in transcripts:
        if max_transcripts is not None and len(experts) >= max_transcripts:
            break
        path = Path(path).expanduser()
        if not path.is_file():
            continue
        session = session_id_from_path(path)
        if session in seen_sessions:
            continue
        seen_sessions.add(session)
        spec = build_corpus_from_transcript(path, out_root)
        if spec is None:
            continue
        experts.append(spec)
        sources.append(str(path))

    if include_synthetic:
        for seed_id, text in SYNTHETIC_SEEDS.items():
            if any(e.expert_id == seed_id for e in experts):
                continue
            experts.append(build_synthetic_expert(seed_id, text, out_root))
            sources.append(f"synthetic:{seed_id}")

    if len(experts) < min_experts:
        raise RuntimeError(
            f"Alpha population has {len(experts)} experts (need {min_experts}). "
            "Add transcripts under ~/.cursor/projects/.../agent-transcripts/ "
            "or lower min_experts."
        )

    experts.sort(key=lambda e: e.expert_id)
    return AlphaPopulation(
        version=ALPHA_POPULATION_VERSION,
        experts=tuple(experts),
        generated_from=tuple(sources),
    )


def write_alpha_population(population: AlphaPopulation, path: Path | str) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(population.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def load_alpha_population(path: Path | str) -> AlphaPopulation:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not supports_schema(str(raw.get("version", "")), ALPHA_POPULATION_VERSION):
        raise ValueError(f"unsupported alpha population version: {raw.get('version')!r}")
    experts = []
    for item in raw.get("experts", []):
        experts.append(
            AlphaExpertSpec(
                expert_id=str(item["expert_id"]),
                corpus_dir=Path(str(item["corpus_dir"])),
                source=str(item["source"]),
                session_id=item.get("session_id"),
                descriptor=dict(item.get("descriptor") or {}),
                group_id=str(item.get("group_id", "general")),
                byte_count=int(item.get("byte_count", 0)),
            )
        )
    return AlphaPopulation(
        version=ALPHA_POPULATION_VERSION,
        experts=tuple(experts),
        generated_from=tuple(str(s) for s in raw.get("generated_from", [])),
    )


def attach_topology_experts(
    population: AlphaPopulation,
    topology_experts: Sequence[Mapping[str, object]],
) -> list[tuple[AlphaExpertSpec, Mapping[str, object]]]:
    """Pair population experts with topology node entries (by index)."""
    if len(topology_experts) > len(population.experts):
        raise ValueError(
            f"topology has {len(topology_experts)} expert nodes but population has "
            f"{len(population.experts)} experts"
        )
    pairs: list[tuple[AlphaExpertSpec, Mapping[str, object]]] = []
    for index, node in enumerate(topology_experts):
        pairs.append((population.experts[index], node))
    return pairs
