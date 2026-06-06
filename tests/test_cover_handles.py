"""STATUS.md item 6: cover-handle padding hides the real-match count.

The matcher returns a constant K candidates regardless of how many experts
actually matched; the extras are covers (decoys). Covers are wire-indistinguishable
to the oblivious operator but carry a marker the asker uses to drop them before
routing.
"""

from tenet.experts.cover import COVER_MARKER, cover_handle, is_cover
from tenet.experts.directory import DiscoveryRequest
from tenet.experts.expert_route import PeerCandidate, RouteIntent, plan_expert_route
from tenet.handles import OPAQUE_HANDLE_SIZE, OpaqueHandle
from tenet.experts.matcher import PLAIN_MATCHER_V1, MatcherEntry, PlainMatcher
from tenet.experts.memory_index import MemoryManifest


def _manifest(peer_id: str, terms: dict[str, int]) -> MemoryManifest:
    return MemoryManifest(
        version="por.memory_manifest.v1",
        peer_id=peer_id,
        created_at="2026-01-01T00:00:00+00:00",
        roots=("/x",),
        file_count=3,
        byte_count=1000,
        chunk_count=10,
        token_count=500,
        file_types={".py": 3},
        top_terms=tuple(sorted(terms.items())),
        corpus_root="root",
        index_digest="d" * 64,
        privacy={"publish_terms": True},
    )


def _entry(peer_id: str, terms: dict[str, int]) -> MatcherEntry:
    handle = OpaqueHandle("h" + peer_id.rjust(15, "0")[:15])
    return MatcherEntry(handle=handle, candidate=PeerCandidate(_manifest(handle.token, terms)))


def _matcher(top_k=4, **kw):
    entries = [
        _entry("monet", {"monet": 5, "impressionism": 4}),  # matches "monet"
        _entry("rustlang", {"borrow": 5, "lifetime": 4}),
        _entry("biology", {"cell": 5, "enzyme": 4}),
    ]
    return PlainMatcher(entries, top_k=top_k, cover_key=b"k" * 32, **kw)


def _discover(matcher, query="monet impressionism", max_records=None):
    return matcher.discover(
        DiscoveryRequest(
            RouteIntent(prompt=query, requested_expertise=query),
            mode=PLAIN_MATCHER_V1,
            max_records=max_records,
        )
    )


# --- constant-K output --------------------------------------------------------

def test_output_is_constant_k_with_one_real_match():
    result = _discover(_matcher(top_k=4), query="monet impressionism")
    assert len(result.candidates) == 4               # padded to K
    reals = [c for c in result.candidates if not is_cover(c)]
    covers = [c for c in result.candidates if is_cover(c)]
    assert len(reals) == 1 and len(covers) == 3


def test_output_is_constant_k_with_zero_real_matches():
    result = _discover(_matcher(top_k=4), query="zzz nonmatching query")
    assert len(result.candidates) == 4
    assert all(is_cover(c) for c in result.candidates)  # all covers, count hidden


def test_real_match_count_not_readable_from_response_length():
    one = _discover(_matcher(top_k=4), query="monet")
    none = _discover(_matcher(top_k=4), query="zzz")
    # The operator sees the same number of candidates whether 1 or 0 matched.
    assert len(one.candidates) == len(none.candidates) == 4


def test_real_candidates_come_before_covers():
    result = _discover(_matcher(top_k=4), query="monet impressionism")
    assert not is_cover(result.candidates[0])         # the real match leads
    assert all(is_cover(c) for c in result.candidates[1:])


# --- covers are well-formed and unlinkable ------------------------------------

def test_cover_handles_have_real_handle_shape():
    result = _discover(_matcher(top_k=4))
    for c in result.candidates:
        if is_cover(c):
            OpaqueHandle(c.manifest.peer_id)          # 16-ASCII shape or raises
            assert c.manifest.peer_id.startswith("h")
            assert c.manifest.privacy[COVER_MARKER] is True


def test_cover_handles_unlinkable_across_responses():
    a = {c.manifest.peer_id for c in _discover(_matcher(top_k=4)).candidates if is_cover(c)}
    b = {c.manifest.peer_id for c in _discover(_matcher(top_k=4)).candidates if is_cover(c)}
    assert a and b and a.isdisjoint(b)                # fresh nonce per response


def test_cover_handle_prf_is_deterministic_for_fixed_inputs():
    h1 = cover_handle(b"k" * 32, b"n" * 16, 3)
    h2 = cover_handle(b"k" * 32, b"n" * 16, 3)
    assert h1.token == h2.token
    assert len(h1.token.encode("ascii")) == OPAQUE_HANDLE_SIZE


# --- the asker drops covers before routing ------------------------------------

def test_routing_ignores_cover_candidates():
    result = _discover(_matcher(top_k=4), query="monet impressionism")
    plan = plan_expert_route(
        RouteIntent(prompt="monet impressionism", min_pool_size=1),
        result.candidates,
    )
    # Only the single real expert is in the pool; the 3 covers were filtered.
    assert len(plan.pool.candidates) == 1
    assert plan.selected_peer_id == result.candidates[0].manifest.peer_id
    cover_ids = {c.manifest.peer_id for c in result.candidates if is_cover(c)}
    assert plan.selected_peer_id not in cover_ids


# --- legacy (un-padded) wire still available ----------------------------------

def test_pad_with_covers_false_drops_dummies():
    result = _discover(_matcher(top_k=4, pad_with_covers=False), query="monet")
    assert all(not is_cover(c) for c in result.candidates)
    assert len(result.candidates) == 1                 # only the real match
