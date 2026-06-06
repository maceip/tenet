"""Cover handles for output-count hiding (STATUS.md item 6 — output layer).

Oblivious *selection* (``tenet.experts.oblivious``) hides *which* expert matched by making
the access pattern data-independent. But the matcher's response still leaked
*how many* experts matched: it returned one candidate per real match, so the
operator could read the match count off the response cardinality (and size).

Cover handles close that: the matcher always returns exactly ``K`` candidates,
padding the empty slots with covers. A cover is wire-indistinguishable from a
real candidate to the operator — the operator runs the matcher inside the TEE and
cannot read content, only sizes/access — because a cover is a full-size manifest
carrying a real-looking expert summary. The only difference is a
``privacy["cover"]`` marker in the (TLS-encrypted, TEE-sealed) content, which the
asker reads to drop covers before routing (``tenet.experts.expert_route`` skips them). The
operator can read neither the marker nor the count.

Honest scope: this closes the *cardinality* leak (always K objects) and, by
size-matching covers to a real manifest, approximately the *size* leak. Exact
byte-length normalisation of the whole response, and the hardware-CT/ORAM port of
the assembly step, remain the in-TEE (Rust) hardening. See
STATUS.md architecture rules.
"""

from __future__ import annotations

import hmac
from dataclasses import replace
from hashlib import sha256

from tenet.experts.expert_route import PeerCandidate
from tenet.handles import OPAQUE_HANDLE_SIZE, OpaqueHandle
from tenet.experts.memory_index import COVER_MARKER, MemoryManifest


def cover_handle(cover_key: bytes, nonce: bytes, slot: int) -> OpaqueHandle:
    """A cover route token, shaped exactly like a real opaque handle.

    Derived from a keyed PRF over a per-response ``nonce`` and the ``slot`` index,
    so covers are unlinkable across responses and do not (save for negligible
    collision probability) coincide with any real issued handle. Same ``"h"`` +
    15-hex-char shape as ``OpaqueHandleIssuer.issue``.
    """
    digest = hmac.new(cover_key, nonce + slot.to_bytes(4, "big"), sha256).hexdigest()
    return OpaqueHandle("h" + digest[: OPAQUE_HANDLE_SIZE - 1])


def cover_candidate(
    template: MemoryManifest, cover_key: bytes, nonce: bytes, slot: int
) -> PeerCandidate:
    """A cover candidate: the template manifest, re-keyed to a cover handle.

    Using a real manifest as the template makes the cover the same size/shape as
    a real candidate (so response size barely moves with the real-match count).
    The ``cover`` marker lets the asker filter it; the operator cannot see it.
    """
    handle = cover_handle(cover_key, nonce, slot)
    manifest = replace(
        template,
        peer_id=handle.token,
        privacy={**template.privacy, COVER_MARKER: True},
    )
    return PeerCandidate(manifest, None, route_handle=handle.token)


def is_cover(candidate: PeerCandidate) -> bool:
    """True if this candidate is a cover (decoy) and must not be routed to."""
    return bool(candidate.manifest.privacy.get(COVER_MARKER))
