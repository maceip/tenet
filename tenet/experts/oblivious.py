"""Oblivious top-K selection for the matcher (STATUS.md item 6 — algorithm layer).

Inside the TEE, the operator cannot *read* content — but it can watch *access
patterns*. If the matcher's memory accesses depend on which expert matched, the
operator learns the match from the access trace even though the data is sealed.
Obliviousness closes that: every query touches every entry in the same order,
the output length is constant, and every data-dependent choice is a constant-time
select rather than a branch or early exit.

Production path: when the ``oblivious_core`` PyO3 extension is installed
(``./scripts/build-oblivious-core.sh``), ``oblivious_top_k`` delegates to the
Rust CMOV implementation. Tests that record ``on_access`` traces always use the
Python reference implementation.
"""

from __future__ import annotations

from typing import Callable, Sequence


DUMMY_INDEX = -1

try:
    from oblivious_core import DUMMY_INDEX as _RUST_DUMMY
    from oblivious_core import oblivious_top_k_py as _rust_oblivious_top_k

    DUMMY_INDEX = int(_RUST_DUMMY)
    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False


def rust_backend_available() -> bool:
    return _RUST_AVAILABLE


def ct_select(cond: bool, a, b):
    """Select ``a`` if ``cond`` else ``b`` without a data-dependent access."""
    return a if (1 if cond else 0) else b


def _python_oblivious_top_k(
    scores: Sequence[float],
    k: int,
    *,
    on_access: Callable[[int], None] | None = None,
) -> list[int]:
    if k <= 0:
        raise ValueError("k must be positive")
    n = len(scores)
    taken = [False] * n
    out: list[int] = []
    for _ in range(k):
        best_idx = DUMMY_INDEX
        best_score = float("-inf")
        best_is_real = False
        for i in range(n):
            if on_access is not None:
                on_access(i)
            eligible = (not taken[i]) and (scores[i] > 0.0)
            better = scores[i] > best_score
            sel = eligible and better
            best_score = ct_select(sel, scores[i], best_score)
            best_idx = ct_select(sel, i, best_idx)
            best_is_real = ct_select(sel, True, best_is_real)
        for i in range(n):
            if on_access is not None:
                on_access(i)
            taken[i] = ct_select(i == best_idx and best_is_real, True, taken[i])
        out.append(best_idx)
    return out


def oblivious_top_k(
    scores: Sequence[float],
    k: int,
    *,
    on_access: Callable[[int], None] | None = None,
) -> list[int]:
    """Return ``k`` entry indices in descending score order, data-obliviously."""
    if on_access is not None:
        return _python_oblivious_top_k(scores, k, on_access=on_access)
    if _RUST_AVAILABLE:
        return [int(i) for i in _rust_oblivious_top_k(list(scores), k)]
    return _python_oblivious_top_k(scores, k)
