"""Honest traffic-analysis claims for circuit streaming (TA-3).

Streaming return is an encrypted relay chain, not mixnet-grade anonymity.
Callers attach these fields to envelopes/headers so overselling is harder
to accidentally delete.
"""

from __future__ import annotations

from pathlib import Path

# What this path IS (use in docs, headers, return_descriptor.ta_claim)
CLAIM_ENCRYPTED_RELAY_CHAIN = "encrypted_relay_chain"
CLAIM_CIRCUIT_RETURN_PATH = "circuit_return_path"

# What streaming return is NOT (use in ta_not lists)
NOT_GPA_RESISTANT = "not_gpa_resistant"
NOT_MIXNET_STREAMING = "not_mixnet_streaming"
NOT_PATH_WIDE_COVER = "not_path_wide_cover"

# Substrings that must not appear in user-facing streaming descriptions
_FORBIDDEN_IN_STREAMING_COPY = (
    "mixnet-grade",
    "gpa-resistant",
    "gpa resistant",
    "global passive adversary resistant",
    "unlinkable streaming",
    "anonymous streaming",
)


def streaming_ta_not(paced: bool = False) -> tuple[str, ...]:
    notes = (NOT_GPA_RESISTANT, NOT_MIXNET_STREAMING, NOT_PATH_WIDE_COVER)
    if not paced:
        return notes
    return notes + ("exit_paced_only",)


def streaming_return_descriptor(
    *,
    mode: str = "hybrid_return_path_v2",
    stream: bool = True,
    paced: bool = False,
    extra: dict | None = None,
) -> dict[str, object]:
    """Default honest return_descriptor fields for circuit streaming."""
    descriptor: dict[str, object] = {
        "mode": mode,
        "stream": stream,
        "ta_claim": CLAIM_ENCRYPTED_RELAY_CHAIN,
        "ta_claim_detail": CLAIM_CIRCUIT_RETURN_PATH,
        "ta_not": list(streaming_ta_not(paced=paced)),
    }
    if extra:
        descriptor.update(extra)
    return descriptor


def response_claim_headers(*, paced: bool = False) -> dict[str, str]:
    """HTTP-style headers for proxy/API responses."""
    return {
        "X-Return-Path-Claim": CLAIM_ENCRYPTED_RELAY_CHAIN,
        "X-Return-Path-Not": ",".join(streaming_ta_not(paced=paced)),
    }


_SKIP_LINE_MARKERS = (
    " not ",
    "not_",
    "don't",
    "do not",
    "forbidden",
    "ta_not",
    "oversell",
    "must not",
    "`",
    "claims:",
)


def find_forbidden_streaming_claims(text: str) -> tuple[str, ...]:
    """Return forbidden substrings found in marketing/docs copy."""
    found: set[str] = set()
    for line in text.splitlines():
        lower = line.lower()
        if any(marker in lower for marker in _SKIP_LINE_MARKERS):
            continue
        for phrase in _FORBIDDEN_IN_STREAMING_COPY:
            if phrase in lower:
                found.add(phrase)
    return tuple(sorted(found))


def assert_honest_streaming_copy(text: str) -> None:
    """Raise ValueError if text oversells streaming return privacy."""
    bad = find_forbidden_streaming_claims(text)
    if bad:
        raise ValueError(f"overselling streaming return path: {bad}")


# Docs scanned by scripts/check_ta_claims.py (TA-3 regression guard)
TA_CLAIM_SCAN_PATHS = (
    "notes/hybrid_return_ta_requirements.md",
    "STATUS.md",
    "notes/HYBRID_RETURN_PATH_SPEC.txt",
    "tests/mixnet_test_network.py",
    "tenet/packet/OutfoxNode.py",
)


def missing_scan_paths(
    root: Path,
    relative_paths: tuple[str, ...] = TA_CLAIM_SCAN_PATHS,
) -> tuple[str, ...]:
    """Return configured scan paths that do not exist under ``root``."""
    missing = []
    for rel in relative_paths:
        if not (root / rel).is_file():
            missing.append(rel)
    return tuple(missing)


def scan_files_for_forbidden_claims(
    root: Path,
    relative_paths: tuple[str, ...] = TA_CLAIM_SCAN_PATHS,
) -> list[tuple[str, tuple[str, ...]]]:
    """Return (path, forbidden_substrings) for files that oversell streaming."""
    violations: list[tuple[str, tuple[str, ...]]] = []
    for rel in relative_paths:
        path = root / rel
        if not path.is_file():
            continue
        bad = find_forbidden_streaming_claims(path.read_text(encoding="utf-8"))
        if bad:
            violations.append((rel, bad))
    return violations
