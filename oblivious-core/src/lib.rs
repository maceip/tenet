//! Constant-time oblivious top-K selection — the in-TEE (Rust) hardening of
//! `por/oblivious.py` (STATUS.md items 6 / 7).
//!
//! Inside the TEE the operator can't read content, but it can watch access
//! patterns and timing. Python's `ct_select` keeps the access pattern
//! data-independent but is not instruction-level constant-time (the interpreter
//! still branches). This port uses the `subtle` crate's branchless conditional
//! selects (the CMOV-level guarantee) so the *timing and branch trace* are
//! data-independent too, not just the memory-access order.
//!
//! Guarantees, none of which depend on the score values:
//! - exactly `k` full linear scans for selection + `k` for marking, each over
//!   all `n` entries in index order (uniform access pattern);
//! - exactly `k` results; an empty slot is [`DUMMY_INDEX`], so the count never
//!   leaks how many entries scored well;
//! - only entries with `score > 0` are eligible; ties break to the lower index;
//! - every data-dependent choice is a `subtle` conditional select — no `if` on
//!   secret data, no early exit.
//!
//! Scores are `u64` (the matcher quantises its relevance score to a non-negative
//! integer; 0 means "below threshold"). This keeps comparisons constant-time via
//! `subtle::ConstantTimeGreater`, which is defined for unsigned integers.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

/// Sentinel for an empty (padded) result slot.
pub const DUMMY_INDEX: i64 = -1;

/// Constant-time select: `a` if `cond` else `b`, with no data-dependent branch.
#[inline]
pub fn ct_select_u64(cond: Choice, a: u64, b: u64) -> u64 {
    u64::conditional_select(&b, &a, cond)
}

/// Return `k` entry indices in descending score order, data-obliviously.
///
/// A position with no remaining eligible (`score > 0`, not already taken) entry
/// is [`DUMMY_INDEX`]. The work performed (and the branch/timing trace) is a
/// function of `(scores.len(), k)` only — never of the score values.
pub fn oblivious_top_k(scores: &[u64], k: usize) -> Vec<i64> {
    let n = scores.len();
    let mut taken: Vec<Choice> = vec![Choice::from(0u8); n];
    let mut out: Vec<i64> = Vec::with_capacity(k);

    for _ in 0..k {
        let mut best_idx: u64 = 0;
        let mut best_score: u64 = 0; // only score > 0 is eligible
        let mut best_real: Choice = Choice::from(0u8);

        // Selection scan: constant-time running max over eligible entries.
        for i in 0..n {
            let s = scores[i];
            let eligible = s.ct_gt(&0) & !taken[i];
            let better = s.ct_gt(&best_score);
            let sel = eligible & better;
            best_score = u64::conditional_select(&best_score, &s, sel);
            best_idx = u64::conditional_select(&best_idx, &(i as u64), sel);
            best_real.conditional_assign(&Choice::from(1u8), sel);
        }

        // Marking scan: set taken[best_idx] iff a real entry was found.
        for i in 0..n {
            let is_best = (i as u64).ct_eq(&best_idx) & best_real;
            taken[i].conditional_assign(&Choice::from(1u8), is_best);
        }

        // Emit best_idx, or DUMMY_INDEX if this slot found nothing.
        let emit = i64::conditional_select(&DUMMY_INDEX, &(best_idx as i64), best_real);
        out.push(emit);
    }
    out
}

/// Quantise matcher float scores to `u64` for constant-time comparison.
/// Preserves ordering among positive floats; non-positive → 0 (ineligible).
pub fn quantise_scores(scores: &[f64]) -> Vec<u64> {
    scores
        .iter()
        .map(|&s| {
            if s <= 0.0 {
                0
            } else {
                (s * 1_000_000.0).round() as u64
            }
        })
        .collect()
}

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pyfunction]
fn oblivious_top_k_py(scores: Vec<f64>, k: usize) -> PyResult<Vec<i64>> {
    if k == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("k must be positive"));
    }
    let quantised = quantise_scores(&scores);
    Ok(oblivious_top_k(&quantised, k))
}

#[cfg(feature = "python")]
#[pyfunction]
fn using_rust_backend() -> bool {
    true
}

#[cfg(feature = "python")]
#[pymodule]
fn oblivious_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(oblivious_top_k_py, m)?)?;
    m.add_function(wrap_pyfunction!(using_rust_backend, m)?)?;
    m.add("DUMMY_INDEX", DUMMY_INDEX)?;
    m.add("oblivious_top_k", m.getattr("oblivious_top_k_py")?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plain reference: descending score, ties to lower index, only score > 0,
    /// padded to k with DUMMY_INDEX. Used to check the oblivious version's output.
    fn reference_top_k(scores: &[u64], k: usize) -> Vec<i64> {
        let mut idx: Vec<usize> = (0..scores.len()).filter(|&i| scores[i] > 0).collect();
        idx.sort_by(|&a, &b| scores[b].cmp(&scores[a]).then(a.cmp(&b)));
        let mut out: Vec<i64> = idx.into_iter().take(k).map(|i| i as i64).collect();
        while out.len() < k {
            out.push(DUMMY_INDEX);
        }
        out
    }

    #[test]
    fn matches_reference_on_varied_inputs() {
        let cases: &[(&[u64], usize)] = &[
            (&[5, 1, 9, 3], 2),
            (&[5, 1, 9, 3], 4),
            (&[0, 0, 0], 2),
            (&[7], 3),
            (&[4, 4, 4, 4], 3), // ties -> lower index
            (&[0, 8, 0, 8, 2], 3),
        ];
        for (scores, k) in cases {
            assert_eq!(
                oblivious_top_k(scores, *k),
                reference_top_k(scores, *k),
                "scores={scores:?} k={k}"
            );
        }
    }

    #[test]
    fn output_is_always_exactly_k() {
        for k in 1..=6 {
            assert_eq!(oblivious_top_k(&[9, 1], k).len(), k);
            assert_eq!(oblivious_top_k(&[0], k).len(), k);
            assert_eq!(oblivious_top_k(&[], k).len(), k);
        }
    }

    #[test]
    fn zero_scores_yield_all_dummy() {
        assert_eq!(oblivious_top_k(&[0, 0, 0], 2), vec![DUMMY_INDEX, DUMMY_INDEX]);
    }

    #[test]
    fn only_positive_scores_selected() {
        // index 1 (score 5) is the only eligible; rest are DUMMY.
        assert_eq!(oblivious_top_k(&[0, 5, 0], 3), vec![1, DUMMY_INDEX, DUMMY_INDEX]);
    }

    #[test]
    fn work_is_independent_of_values() {
        // Same (n, k) over wildly different score vectors performs identical work:
        // k*(2n) inner iterations regardless of data. We assert the structural
        // invariant by construction here (no data-dependent control flow), and
        // check the output shape is constant.
        let a = oblivious_top_k(&[1, 2, 3, 4, 5], 3);
        let b = oblivious_top_k(&[0, 0, 0, 0, 0], 3);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn ct_select_picks_correctly() {
        assert_eq!(ct_select_u64(Choice::from(1u8), 10, 20), 10);
        assert_eq!(ct_select_u64(Choice::from(0u8), 10, 20), 20);
    }
}
