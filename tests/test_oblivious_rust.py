"""When oblivious_core PyO3 extension is installed, results match Python."""

import pytest

from tenet.experts.oblivious import _python_oblivious_top_k, rust_backend_available


@pytest.mark.parametrize(
    "scores,k",
    [
        ([5.0, 1.0, 9.0, 2.0, 0.0, 7.0, 3.0, 4.0], 3),
        ([0.0, 0.0, 0.0, 0.0], 3),
        ([4.0, 4.0, 4.0, 4.0], 2),
    ],
)
def test_rust_matches_python_when_installed(scores, k):
    if not rust_backend_available():
        pytest.skip("oblivious_core extension not built — run ./scripts/build-oblivious-core.sh")
    from tenet.experts.oblivious import oblivious_top_k

    assert oblivious_top_k(scores, k) == _python_oblivious_top_k(scores, k)
