"""Oblivious top-K: correctness + the access-pattern-invariance property."""

import pytest

from tenet.experts.oblivious import DUMMY_INDEX, oblivious_top_k


def _reference_top_k(scores, k):
    """Plain (non-oblivious) top-K over positive scores, padded with dummies."""
    ranked = sorted(
        (i for i in range(len(scores)) if scores[i] > 0.0),
        key=lambda i: (-scores[i], i),
    )[:k]
    return list(ranked) + [DUMMY_INDEX] * (k - len(ranked))


@pytest.mark.parametrize(
    "scores,k",
    [
        ([5.0, 1.0, 9.0, 2.0, 0.0, 7.0, 3.0, 4.0], 3),
        ([5.0, 1.0, 9.0, 2.0, 0.0, 7.0, 3.0, 4.0], 1),
        ([1.0, 2.0, 3.0], 5),          # k > number of positives -> dummies
        ([0.0, 0.0, 0.0, 0.0], 3),     # no positives -> all dummies
        ([4.0, 4.0, 4.0, 4.0], 2),     # ties -> lower index first
        ([-1.0, 8.0, -3.0, 6.0], 4),   # negatives excluded
    ],
)
def test_matches_reference_top_k(scores, k):
    assert oblivious_top_k(scores, k) == _reference_top_k(scores, k)


def test_output_length_is_constant_k():
    assert len(oblivious_top_k([9.0, 1.0], 5)) == 5
    assert len(oblivious_top_k([0.0], 5)) == 5


def test_missing_positions_are_dummies():
    out = oblivious_top_k([7.0], 3)
    assert out[0] == 0
    assert out[1] == DUMMY_INDEX
    assert out[2] == DUMMY_INDEX


def test_rejects_non_positive_k():
    with pytest.raises(ValueError):
        oblivious_top_k([1.0, 2.0], 0)


def test_access_pattern_is_independent_of_scores():
    """The obliviousness property: identical access trace for any score vector."""
    n, k = 8, 3

    def trace(scores):
        acc: list[int] = []
        oblivious_top_k(scores, k, on_access=acc.append)
        return acc

    high_spread = trace([5.0, 1.0, 9.0, 2.0, 0.0, 7.0, 3.0, 4.0])
    low_spread = trace([0.11, 0.22, 0.33, 0.44, 0.55, 0.66, 0.77, 0.88])
    all_zero = trace([0.0] * n)            # every result a dummy
    reversed_winner = trace([9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0])

    assert high_spread == low_spread == all_zero == reversed_winner
    # and the trace is exactly k select-scans + k mark-scans, each a full 0..n-1.
    assert high_spread == list(range(n)) * (2 * k)
