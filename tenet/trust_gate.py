"""Client-side trust gate — the *consume* half of the unified trust-update rail.

The same rail (join-pack-root keys → signed ``trust_update`` records) governs two
artifacts under one anchor:

  - **client binary**  — its sha256 must be in ``approved_code_hashes``
  - **matcher TEE**    — its Value X must be in ``approved_tee_measurements``

This module does the client-binary half: self-hash the running executable and
check it against the latest *signed* trust update. Soft by default (surface
"update available"); a bundle may mark itself ``required`` to fail closed. It
never raises and never blocks the prompt — any fetch/verify failure degrades to
UNKNOWN. The contract lives here + in tests/test_trust_gate.py (not a doc).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request
from dataclasses import dataclass

from tenet.mixnet.control.descriptors import (
    SoftwareIdentityDescriptor,
    TrustUpdateDescriptor,
)
from tenet.mixnet.control.records import SignedControlRecord

UP_TO_DATE = "up_to_date"
UPDATE_AVAILABLE = "update_available"
UNKNOWN = "unknown"

TRUST_BUNDLE_SCHEMA = "tenet.trust_update_bundle.2026-06"

# Where the signed bundle ships by default (CI attaches it to each release).
# Override with TENET_TRUST_UPDATE_URL or a join-pack ``trust_update_url`` pin.
DEFAULT_TRUST_UPDATE_URL = (
    "https://github.com/maceip/tenet/releases/latest/download/trust-update.json"
)


@dataclass(frozen=True)
class TrustState:
    """Resolved trust state for the running client binary."""

    state: str                      # UP_TO_DATE | UPDATE_AVAILABLE | UNKNOWN
    self_hash: str
    latest_version: str | None
    detail: str
    required: bool = False          # hard fail-closed if set and not up-to-date

    @property
    def ok(self) -> bool:
        """May the client proceed? Soft states proceed; required+not-up-to-date blocks."""
        return self.state == UP_TO_DATE or not self.required


def self_code_hash(path: str | None = None) -> str:
    """sha256 of the running executable — matches CI ``SHA256SUMS`` for a release.

    For a frozen PyInstaller binary that's ``sys.executable``. Returns "" when
    the running artifact can't be hashed (e.g. a bare ``python -m`` source run).
    """
    target = path
    if target is None:
        if getattr(sys, "frozen", False):
            target = sys.executable
        elif sys.argv and os.path.isfile(sys.argv[0]):
            target = sys.argv[0]
    if not target or not os.path.isfile(target):
        return ""
    digest = hashlib.sha256()
    with open(target, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate(
    self_hash: str,
    trust_update: TrustUpdateDescriptor,
    latest: SoftwareIdentityDescriptor | None = None,
    *,
    required: bool = False,
) -> TrustState:
    """Pure decision: where does this binary stand against the approved set?"""
    approved = set(trust_update.approved_code_hashes)
    version = latest.version if latest else None
    if not self_hash:
        return TrustState(UNKNOWN, self_hash, version, "cannot hash own executable", required)
    if not approved:
        return TrustState(UNKNOWN, self_hash, version, "no approved code hashes published", required)
    if self_hash in approved:
        return TrustState(UP_TO_DATE, self_hash, version, "running an approved build", required)
    if latest and latest.code_hash in approved and latest.code_hash != self_hash:
        suffix = f" ({version})" if version else ""
        return TrustState(UPDATE_AVAILABLE, self_hash, version,
                          f"newer approved build available{suffix}", required)
    return TrustState(UNKNOWN, self_hash, version, "running an unrecognized build", required)


def _verified_descriptor(raw: object, roots, threshold: int):
    """Verify a SignedControlRecord against the join-pack roots; return its value dict."""
    if not isinstance(raw, dict):
        raise ValueError("signed record must be an object")
    signed = SignedControlRecord.from_dict(raw)
    signed.validate(verify_keys=roots, threshold=threshold)
    return signed.record.value


def load_trust_state(
    pack,
    *,
    url: str | None = None,
    timeout: float = 4.0,
    self_hash: str | None = None,
) -> TrustState:
    """Fetch + verify the latest signed trust-update bundle, then evaluate self.

    Best-effort, fail-soft: any network/parse/signature failure returns UNKNOWN.
    Source order for the bundle URL: explicit ``url`` → ``TENET_TRUST_UPDATE_URL``
    → a ``trust_update_url`` pinned in the join-pack.
    """
    resolved_hash = self_code_hash() if self_hash is None else self_hash
    src = (url or os.environ.get("TENET_TRUST_UPDATE_URL")
           or getattr(pack, "trust_update_url", None) or DEFAULT_TRUST_UPDATE_URL)
    if not src:
        return TrustState(UNKNOWN, resolved_hash, None, "no trust-update source pinned")

    roots = dict(getattr(pack.control_bootstrap, "update_roots", {}) or {})
    threshold = int(getattr(pack.control_bootstrap, "threshold", 1) or 1)
    try:
        with urllib.request.urlopen(str(src), timeout=timeout) as resp:  # noqa: S310 - pinned src
            bundle = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # pragma: no cover - network guard
        return TrustState(UNKNOWN, resolved_hash, None, f"trust-update fetch failed: {exc}")

    try:
        tu = TrustUpdateDescriptor.from_dict(
            _verified_descriptor(bundle.get("trust_update"), roots, threshold))
        latest = None
        si_raw = bundle.get("software_identity")
        if si_raw:
            latest = SoftwareIdentityDescriptor.from_dict(
                _verified_descriptor(si_raw, roots, threshold))
        return evaluate(resolved_hash, tu, latest, required=bool(bundle.get("required")))
    except Exception as exc:
        return TrustState(UNKNOWN, resolved_hash, None, f"trust-update invalid: {exc}")
