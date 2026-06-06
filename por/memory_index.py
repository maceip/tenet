"""Deterministic local memory indexing for P-OR Layer 7 matching.

This module intentionally does not certify "expertise." It builds a read-only
sidecar index over local text and publishes a small manifest that can be used
for deterministic routing signals:

* rough corpus fit for a prompt
* corpus size and freshness
* file type coverage
* Merkle commitment root for later challenge/proof flows

The raw chunks stay local. A peer can keep using any agent memory system it
already has; this index is only a neutral routing artifact beside it.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Iterator, Sequence


MANIFEST_VERSION = "por.memory_manifest.v1"
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_'-]{2,}")
DEFAULT_TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".markdown",
    ".rst",
    ".log",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".csv",
    ".tsv",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".rs",
    ".go",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
}

STOPWORDS = {
    "about",
    "after",
    "again",
    "also",
    "and",
    "any",
    "are",
    "because",
    "been",
    "before",
    "being",
    "between",
    "both",
    "but",
    "can",
    "could",
    "did",
    "does",
    "doing",
    "done",
    "for",
    "from",
    "had",
    "has",
    "have",
    "here",
    "how",
    "into",
    "its",
    "just",
    "like",
    "more",
    "not",
    "now",
    "one",
    "only",
    "our",
    "out",
    "over",
    "same",
    "she",
    "should",
    "some",
    "than",
    "that",
    "the",
    "their",
    "them",
    "then",
    "there",
    "these",
    "they",
    "this",
    "through",
    "too",
    "use",
    "was",
    "way",
    "were",
    "what",
    "when",
    "where",
    "which",
    "while",
    "who",
    "why",
    "with",
    "would",
    "you",
    "your",
}


@dataclass(frozen=True)
class IndexConfig:
    """Configuration for building a local memory sidecar index."""

    peer_id: str
    roots: tuple[str, ...]
    include_globs: tuple[str, ...] = ("**/*",)
    exclude_globs: tuple[str, ...] = (
        "**/.git/**",
        "**/__pycache__/**",
        "**/.pytest_cache/**",
        "**/node_modules/**",
    )
    text_extensions: tuple[str, ...] = tuple(sorted(DEFAULT_TEXT_EXTENSIONS))
    chunk_tokens: int = 220
    chunk_overlap: int = 40
    max_public_terms: int = 64
    publish_terms: bool = True


@dataclass(frozen=True)
class ChunkRecord:
    chunk_id: str
    source: str
    start_token: int
    token_count: int
    byte_count: int
    chunk_hash: str
    nonce: str
    commitment: str
    terms: dict[str, int]
    text: str = field(repr=False)


@dataclass(frozen=True)
class MemoryManifest:
    version: str
    peer_id: str
    created_at: str
    roots: tuple[str, ...]
    file_count: int
    byte_count: int
    chunk_count: int
    token_count: int
    file_types: dict[str, int]
    top_terms: tuple[tuple[str, int], ...]
    corpus_root: str
    index_digest: str
    privacy: dict[str, object]

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2)

    @classmethod
    def from_json(cls, data: str) -> "MemoryManifest":
        raw = json.loads(data)
        return cls(
            version=raw["version"],
            peer_id=raw["peer_id"],
            created_at=raw["created_at"],
            roots=tuple(raw["roots"]),
            file_count=raw["file_count"],
            byte_count=raw["byte_count"],
            chunk_count=raw["chunk_count"],
            token_count=raw["token_count"],
            file_types=dict(raw["file_types"]),
            top_terms=tuple((term, int(count)) for term, count in raw["top_terms"]),
            corpus_root=raw["corpus_root"],
            index_digest=raw["index_digest"],
            privacy=dict(raw["privacy"]),
        )


@dataclass(frozen=True)
class RetrievalHit:
    chunk_id: str
    score: float
    token_count: int
    source: str | None = None
    excerpt: str | None = None


@dataclass(frozen=True)
class ChunkProof:
    """Merkle inclusion proof for a chunk commitment.

    This proves that the peer committed to a chunk hash at index-build time. It
    does not prove semantic quality, and without revealing chunk text it does
    not prove that the chunk hash corresponds to useful content.
    """

    chunk_id: str
    commitment: str
    chunk_hash: str
    nonce: str
    leaf_index: int
    siblings: tuple[tuple[str, str], ...]
    root: str


@dataclass
class LocalMemoryIndex:
    """Local-only index plus public manifest."""

    manifest: MemoryManifest
    chunks: tuple[ChunkRecord, ...]

    def query(self, query_text: str, limit: int = 5, reveal: bool = False) -> list[RetrievalHit]:
        q_terms = _count_terms(query_text)
        if not q_terms:
            return []

        hits = []
        for chunk in self.chunks:
            score = _cosine_score(q_terms, chunk.terms)
            if score <= 0:
                continue
            hits.append(
                RetrievalHit(
                    chunk_id=chunk.chunk_id,
                    score=score,
                    token_count=chunk.token_count,
                    source=chunk.source if reveal else None,
                    excerpt=_excerpt(chunk.text, q_terms) if reveal else None,
                )
            )

        hits.sort(key=lambda hit: (-hit.score, hit.chunk_id))
        return hits[:limit]

    def chunk_proof(self, chunk_id: str) -> ChunkProof:
        for index, chunk in enumerate(self.chunks):
            if chunk.chunk_id == chunk_id:
                return ChunkProof(
                    chunk_id=chunk.chunk_id,
                    commitment=chunk.commitment,
                    chunk_hash=chunk.chunk_hash,
                    nonce=chunk.nonce,
                    leaf_index=index,
                    siblings=_merkle_proof([c.commitment for c in self.chunks], index),
                    root=self.manifest.corpus_root,
                )
        raise KeyError(f"unknown chunk_id: {chunk_id}")


def build_memory_index(config: IndexConfig) -> LocalMemoryIndex:
    files = list(_iter_text_files(config))
    chunks: list[ChunkRecord] = []
    aggregate_terms: Counter[str] = Counter()
    file_types: Counter[str] = Counter()
    byte_count = 0
    token_count = 0

    for path in files:
        text = _read_text(path)
        if not text.strip():
            continue

        source = _stable_source(path)
        file_types[path.suffix.lower() or "<none>"] += 1
        byte_count += path.stat().st_size

        for start_token, chunk_text in _chunk_text(text, config.chunk_tokens, config.chunk_overlap):
            terms = _count_terms(chunk_text)
            if not terms:
                continue

            chunk_token_count = sum(terms.values())
            chunk_hash = _hex_hash(b"por.chunk.text.v1", chunk_text.encode("utf-8"))
            chunk_number = len(chunks)
            nonce = _hex_hash(
                b"por.chunk.nonce.v1",
                config.peer_id.encode("utf-8"),
                source.encode("utf-8"),
                str(start_token).encode("ascii"),
                chunk_hash.encode("ascii"),
            )
            commitment = _hex_hash(
                b"por.chunk.commitment.v1",
                bytes.fromhex(nonce),
                bytes.fromhex(chunk_hash),
            )
            chunk_id = _hex_hash(
                b"por.chunk.id.v1",
                config.peer_id.encode("utf-8"),
                str(chunk_number).encode("ascii"),
                commitment.encode("ascii"),
            )[:24]

            chunks.append(
                ChunkRecord(
                    chunk_id=chunk_id,
                    source=source,
                    start_token=start_token,
                    token_count=chunk_token_count,
                    byte_count=len(chunk_text.encode("utf-8")),
                    chunk_hash=chunk_hash,
                    nonce=nonce,
                    commitment=commitment,
                    terms=dict(terms),
                    text=chunk_text,
                )
            )
            aggregate_terms.update(terms)
            token_count += chunk_token_count

    top_terms = tuple(aggregate_terms.most_common(config.max_public_terms))
    if not config.publish_terms:
        top_terms = tuple()

    manifest = MemoryManifest(
        version=MANIFEST_VERSION,
        peer_id=config.peer_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        roots=tuple(_root_id(root) for root in config.roots),
        file_count=len(files),
        byte_count=byte_count,
        chunk_count=len(chunks),
        token_count=token_count,
        file_types=dict(sorted(file_types.items())),
        top_terms=top_terms,
        corpus_root=_merkle_root([chunk.commitment for chunk in chunks]),
        index_digest="",
        privacy={
            "raw_text_published": False,
            "sources_in_manifest": False,
            "public_terms": config.publish_terms,
            "commitment_note": (
                "Merkle root commits to salted chunk hashes. Proofs show index "
                "commitment, not expertise or answer quality."
            ),
        },
    )
    manifest = replace(manifest, index_digest=_manifest_digest(manifest))
    return LocalMemoryIndex(manifest=manifest, chunks=tuple(chunks))


def score_manifest(manifest: MemoryManifest, query_text: str) -> float:
    """Score a public manifest against a query using only public top terms."""
    q_terms = _count_terms(query_text)
    manifest_terms = dict(manifest.top_terms)
    if not q_terms or not manifest_terms:
        return 0.0
    lexical = _cosine_score(q_terms, manifest_terms)
    coverage = math.log1p(manifest.chunk_count) / 10.0
    return lexical * (1.0 + coverage)


def verify_chunk_proof(proof: ChunkProof) -> bool:
    commitment = _hex_hash(
        b"por.chunk.commitment.v1",
        bytes.fromhex(proof.nonce),
        bytes.fromhex(proof.chunk_hash),
    )
    if commitment != proof.commitment:
        return False

    node = bytes.fromhex(proof.commitment)
    index = proof.leaf_index
    for side, sibling_hex in proof.siblings:
        sibling = bytes.fromhex(sibling_hex)
        if side == "left":
            node = _hash_pair(sibling, node)
        elif side == "right":
            node = _hash_pair(node, sibling)
        else:
            return False
        index //= 2
    return node.hex() == proof.root


def _iter_text_files(config: IndexConfig) -> Iterator[Path]:
    extensions = {ext.lower() for ext in config.text_extensions}
    seen: set[Path] = set()
    for root in config.roots:
        root_path = Path(root).resolve()
        if root_path.is_file():
            candidates = [root_path]
        else:
            candidates = [path for pattern in config.include_globs for path in root_path.glob(pattern)]

        for path in candidates:
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            if resolved.suffix.lower() not in extensions:
                continue
            rel = _relative_for_glob(root_path, resolved)
            if any(fnmatch.fnmatch(rel, pattern) for pattern in config.exclude_globs):
                continue
            seen.add(resolved)
            yield resolved


def _relative_for_glob(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    return data.decode("utf-8", errors="replace")


def _stable_source(path: Path) -> str:
    return str(path.resolve())


def _root_id(root: str) -> str:
    resolved = str(Path(root).resolve()).encode("utf-8")
    return _hex_hash(b"por.root.id.v1", resolved)[:24]


def _chunk_text(text: str, chunk_tokens: int, overlap: int) -> Iterator[tuple[int, str]]:
    tokens = TOKEN_RE.findall(text)
    if not tokens:
        return
    step = max(1, chunk_tokens - overlap)
    for start in range(0, len(tokens), step):
        part = tokens[start:start + chunk_tokens]
        if not part:
            break
        yield start, " ".join(part)
        if start + chunk_tokens >= len(tokens):
            break


def _count_terms(text: str) -> Counter[str]:
    terms = Counter()
    for token in TOKEN_RE.findall(text.lower()):
        token = token.strip("_-'")
        if len(token) < 3 or token in STOPWORDS:
            continue
        terms[token] += 1
    return terms


def _cosine_score(left: dict[str, int] | Counter[str], right: dict[str, int] | Counter[str]) -> float:
    shared = set(left) & set(right)
    if not shared:
        return 0.0
    dot = sum(left[term] * right[term] for term in shared)
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


def _excerpt(text: str, q_terms: Counter[str], max_chars: int = 220) -> str:
    lower = text.lower()
    positions = [lower.find(term) for term in q_terms if lower.find(term) >= 0]
    start = min(positions) if positions else 0
    start = max(0, start - 40)
    return text[start:start + max_chars]


def _hex_hash(*parts: bytes) -> str:
    h = sha256()
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.hexdigest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return sha256(b"por.merkle.node.v1" + left + right).digest()


def _merkle_root(commitments: Sequence[str]) -> str:
    if not commitments:
        return _hex_hash(b"por.merkle.empty.v1")
    level = [bytes.fromhex(commitment) for commitment in commitments]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def _merkle_proof(commitments: Sequence[str], index: int) -> tuple[tuple[str, str], ...]:
    if index < 0 or index >= len(commitments):
        raise IndexError(index)
    level = [bytes.fromhex(commitment) for commitment in commitments]
    proof = []
    current = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling_index = current ^ 1
        side = "left" if sibling_index < current else "right"
        proof.append((side, level[sibling_index].hex()))
        current //= 2
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return tuple(proof)


def _manifest_digest(manifest: MemoryManifest) -> str:
    data = asdict(replace(manifest, index_digest=""))
    return _hex_hash(b"por.manifest.digest.v1", json.dumps(data, sort_keys=True).encode("utf-8"))


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a P-OR memory manifest.")
    parser.add_argument("roots", nargs="+", help="Files or directories to index")
    parser.add_argument("--peer-id", required=True, help="Peer identifier to place in the manifest")
    parser.add_argument("--out", help="Write manifest JSON to this file instead of stdout")
    parser.add_argument("--private-terms", action="store_true", help="Do not publish top terms")
    parser.add_argument("--chunk-tokens", type=int, default=220)
    parser.add_argument("--chunk-overlap", type=int, default=40)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    config = IndexConfig(
        peer_id=args.peer_id,
        roots=tuple(args.roots),
        publish_terms=not args.private_terms,
        chunk_tokens=args.chunk_tokens,
        chunk_overlap=args.chunk_overlap,
    )
    index = build_memory_index(config)
    output = index.manifest.to_json() + "\n"
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
