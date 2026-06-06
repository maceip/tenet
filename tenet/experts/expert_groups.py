"""Population grouping for expert peers.

This module organizes public expert records into coarse groups. It deliberately
does not accept a prompt, rank peers, or choose an expert.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence

from tenet.experts.directory import PeerRecord
from tenet.experts.memory_index import STOPWORDS, TOKEN_RE


GROUP_TAXONOMY_VERSION = "por.expert_groups.v1"
ROOT_GROUP_ID = "root"
GENERAL_GROUP_ID = "general"

GROUP_READY = "ready"
GROUP_DEGRADED = "degraded"


GROUP_LABELS: Mapping[str, str] = {
    ROOT_GROUP_ID: "All experts",
    GENERAL_GROUP_ID: "General",
    "art_culture": "Art and culture",
    "systems_networking": "Systems and networking",
    "security_privacy": "Security and privacy",
    "medicine_health": "Medicine and health",
    "law_policy": "Law and policy",
    "finance_economics": "Finance and economics",
    "science_engineering": "Science and engineering",
    "software_ai": "Software and AI",
}

GROUP_KEYWORDS: Mapping[str, tuple[str, ...]] = {
    "art_culture": (
        "art",
        "brushwork",
        "color",
        "degas",
        "history",
        "impressionism",
        "impressionist",
        "monet",
        "museum",
        "painting",
        "paris",
        "renoir",
        "salon",
        "wine",
    ),
    "systems_networking": (
        "cgnat",
        "congestion",
        "kernel",
        "nat",
        "network",
        "packet",
        "quic",
        "relay",
        "runtime",
        "scheduler",
        "socket",
        "stream",
        "tcp",
        "transport",
        "udp",
    ),
    "security_privacy": (
        "adversary",
        "anonymity",
        "crypto",
        "cryptography",
        "kem",
        "mixnet",
        "outfox",
        "privacy",
        "signature",
        "sphinx",
        "sybil",
        "threat",
    ),
    "medicine_health": (
        "cardiology",
        "clinical",
        "diagnosis",
        "disease",
        "health",
        "medical",
        "medicine",
        "oncology",
        "patient",
        "symptom",
        "treatment",
    ),
    "law_policy": (
        "compliance",
        "contract",
        "court",
        "law",
        "legal",
        "policy",
        "regulation",
        "statute",
    ),
    "finance_economics": (
        "debt",
        "economics",
        "equity",
        "finance",
        "market",
        "portfolio",
        "price",
        "revenue",
        "trading",
    ),
    "science_engineering": (
        "bearing",
        "biology",
        "chemistry",
        "civil",
        "engineering",
        "load",
        "material",
        "mechanical",
        "physics",
        "structural",
    ),
    "software_ai": (
        "agent",
        "embedding",
        "inference",
        "llm",
        "model",
        "prompt",
        "rag",
        "retrieval",
        "software",
        "tool",
    ),
}


@dataclass(frozen=True)
class ExpertGroup:
    group_id: str
    label: str
    parent_id: str | None
    peer_ids: tuple[str, ...]
    status: str
    min_group_size: int
    broaden_to: str | None
    evidence_terms: tuple[str, ...]

    @property
    def size(self) -> int:
        return len(self.peer_ids)

    @property
    def degraded(self) -> bool:
        return self.status == GROUP_DEGRADED


@dataclass(frozen=True)
class ExpertPopulationIndex:
    version: str
    min_group_size: int
    groups: tuple[ExpertGroup, ...]
    peer_group_ids: dict[str, str]

    def group(self, group_id: str) -> ExpertGroup | None:
        for group in self.groups:
            if group.group_id == group_id:
                return group
        return None

    def group_for_peer(self, peer_id: str) -> ExpertGroup | None:
        group_id = self.peer_group_ids.get(peer_id)
        if group_id is None:
            return None
        return self.group(group_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "min_group_size": self.min_group_size,
            "groups": [asdict(group) for group in self.groups],
            "peer_group_ids": dict(sorted(self.peer_group_ids.items())),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def build_expert_population_index(
    records: Sequence[PeerRecord],
    *,
    min_group_size: int = 3,
) -> ExpertPopulationIndex:
    """Group a public expert population without performing request matching."""

    if min_group_size <= 0:
        raise ValueError("min_group_size must be positive")

    by_group: dict[str, list[str]] = defaultdict(list)
    evidence_by_group: dict[str, set[str]] = defaultdict(set)
    peer_group_ids: dict[str, str] = {}

    for record in records:
        assignment = assign_expert_group(record)
        by_group[assignment.group_id].append(record.peer_id)
        evidence_by_group[assignment.group_id].update(assignment.evidence_terms)
        peer_group_ids[record.peer_id] = assignment.group_id

    all_peer_ids = tuple(sorted(record.peer_id for record in records))
    root_status = GROUP_READY if len(all_peer_ids) >= min_group_size else GROUP_DEGRADED
    groups = [
        ExpertGroup(
            group_id=ROOT_GROUP_ID,
            label=GROUP_LABELS[ROOT_GROUP_ID],
            parent_id=None,
            peer_ids=all_peer_ids,
            status=root_status,
            min_group_size=min_group_size,
            broaden_to=None,
            evidence_terms=(),
        )
    ]

    for group_id in sorted(by_group):
        peer_ids = tuple(sorted(by_group[group_id]))
        status = GROUP_READY if len(peer_ids) >= min_group_size else GROUP_DEGRADED
        groups.append(
            ExpertGroup(
                group_id=group_id,
                label=GROUP_LABELS.get(group_id, group_id),
                parent_id=ROOT_GROUP_ID,
                peer_ids=peer_ids,
                status=status,
                min_group_size=min_group_size,
                broaden_to=(
                    ROOT_GROUP_ID
                    if status == GROUP_DEGRADED and root_status == GROUP_READY
                    else None
                ),
                evidence_terms=tuple(sorted(evidence_by_group[group_id])),
            )
        )

    return ExpertPopulationIndex(
        version=GROUP_TAXONOMY_VERSION,
        min_group_size=min_group_size,
        groups=tuple(groups),
        peer_group_ids=dict(sorted(peer_group_ids.items())),
    )


@dataclass(frozen=True)
class ExpertGroupAssignment:
    group_id: str
    label: str
    score: int
    evidence_terms: tuple[str, ...]


def assign_expert_group(record: PeerRecord) -> ExpertGroupAssignment:
    """Assign one coarse group using public descriptor tags and manifest terms."""

    terms = _record_terms(record)
    scores: dict[str, int] = {}
    evidence: dict[str, set[str]] = defaultdict(set)
    for group_id, keywords in GROUP_KEYWORDS.items():
        keyword_set = set(keywords)
        score = 0
        for term, count in terms.items():
            if term in keyword_set:
                score += max(1, int(count))
                evidence[group_id].add(term)
        if score:
            scores[group_id] = score

    if not scores:
        return ExpertGroupAssignment(
            group_id=GENERAL_GROUP_ID,
            label=GROUP_LABELS[GENERAL_GROUP_ID],
            score=0,
            evidence_terms=(),
        )

    group_id = sorted(scores, key=lambda item: (-scores[item], item))[0]
    return ExpertGroupAssignment(
        group_id=group_id,
        label=GROUP_LABELS[group_id],
        score=scores[group_id],
        evidence_terms=tuple(sorted(evidence[group_id])),
    )


def _record_terms(record: PeerRecord) -> Counter[str]:
    terms = Counter(dict(record.manifest.top_terms))
    terms.update(_descriptor_terms(record.descriptor))
    return terms


def _descriptor_terms(descriptor: Mapping[str, object] | None) -> Counter[str]:
    if not descriptor:
        return Counter()
    values: list[str] = []
    for key in ("expertise_tags", "domain_tags", "domains", "capabilities"):
        raw = descriptor.get(key)
        if raw is None:
            continue
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray)):
            values.extend(str(item) for item in raw)
    return _count_terms(" ".join(values))


def _count_terms(text: str) -> Counter[str]:
    terms = Counter()
    for token in TOKEN_RE.findall(text.lower()):
        token = token.strip("_-'")
        if len(token) < 3 or token in STOPWORDS:
            continue
        terms[token] += 1
    return terms
