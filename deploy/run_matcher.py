"""In-enclave matcher workload: the REAL PlainMatcher behind the app-proxy.

Builds a small demo expert population and serves the real enclave-plane handler
(matcher + mailbox: oblivious top-K selection + cover-handle padding) on
127.0.0.1:8080, which bountynet's app-proxy fronts over attested TLS. This is the
genuine matcher, not a stub — a query is scored, selected obliviously, and padded
with cover handles before the response leaves the enclave.
"""

from __future__ import annotations

import os

from tenet.experts.enclave_plane_server import serve_enclave_plane
from tenet.experts.expert_route import PeerCandidate
from tenet.handles import OPAQUE_HANDLE_SIZE, OpaqueHandle
from tenet.experts.matcher import MatcherEntry, PlainEnclavePlaneDiscoveryProvider, PlainMailbox, PlainMatcher
from tenet.experts.memory_index import MemoryManifest
from tenet.experts.oblivious import rust_backend_available


def _manifest(peer_id: str, terms: dict[str, int]) -> MemoryManifest:
    return MemoryManifest(
        version="por.memory_manifest.v1",
        peer_id=peer_id,
        created_at="2026-06-02T00:00:00+00:00",
        roots=("/corpus",),
        file_count=12,
        byte_count=48000,
        chunk_count=40,
        token_count=9000,
        file_types={".md": 8, ".py": 4},
        top_terms=tuple(sorted(terms.items())),
        corpus_root="demo",
        index_digest="d" * 64,
        privacy={"publish_terms": True},
    )


def _entry(peer_id: str, terms: dict[str, int]) -> MatcherEntry:
    token = ("h" + peer_id).ljust(OPAQUE_HANDLE_SIZE, "0")[:OPAQUE_HANDLE_SIZE]
    handle = OpaqueHandle(token)
    return MatcherEntry(handle=handle, candidate=PeerCandidate(_manifest(handle.token, terms)))


def build_provider() -> PlainEnclavePlaneDiscoveryProvider:
    experts = [
        _entry("monet", {"monet": 6, "impressionism": 5, "painting": 4}),
        _entry("rustlang", {"borrow": 6, "lifetime": 5, "ownership": 4}),
        _entry("biology", {"cell": 6, "enzyme": 5, "protein": 4}),
        _entry("history", {"rome": 6, "empire": 5, "senate": 4}),
    ]
    matcher = PlainMatcher(experts, top_k=4, cover_key=b"demo-cover-key!!" * 2)
    return PlainEnclavePlaneDiscoveryProvider(matcher, PlainMailbox())


def main() -> None:
    host = os.environ.get("MATCHER_HOST", "127.0.0.1")
    port = int(os.environ.get("MATCHER_PORT", "8080"))
    server = serve_enclave_plane(build_provider(), host=host, port=port)
    backend = "rust" if rust_backend_available() else "python"
    print(
        f"real matcher workload serving on http://{host}:{port} "
        f"(oblivious selector: {backend})",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
