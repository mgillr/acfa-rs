// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Acceptance test for the raw-value range guard, designed so it cannot go partially green.
//!
//! WHAT WENT WRONG. `encode()` bounds values to `[fixed::MIN, fixed::MAX]` (`+/-2^31`) on the
//! float path, but a `Contribution` can be constructed directly from raw `i64` -- which is
//! what decoding a wire receipt does -- and `check()` validated emptiness, dimensions and tie
//! keys while never looking at magnitudes. Unbounded values reached every `i128` accumulator
//! on the selection path.
//!
//! THE TWO-STAGE FAILURE, which is why the obvious fix was the wrong one. At `+/-2^62` each
//! squared coordinate difference is `2^125` and fits comfortably, so `sq_dist` returns
//! cleanly; the SCORE accumulator then sums four of them to `2^127` and overflows. Measured
//! before the fix: `sq_dist` Ok, `multi_krum` PANIC, `bulyan_select` PANIC. Guarding
//! `sq_dist` would have moved the fault one line down and made it look like a different bug.
//!
//! WHY EVERY CASE RUNS THROUGH BULYAN AS WELL AS KRUM. The score-summing block was duplicated
//! byte-for-byte in both selection paths. A hand patch to one copy yields a guard covering
//! Krum and not Bulyan, with the whole suite still green because nothing exercised the second
//! copy at an overflowing magnitude. That false green is worse than no fix, so Bulyan is in
//! the matrix here by construction, and the duplicated block itself has been extracted into a
//! single `krum_scores` so there is only one place left for it to be wrong.
//!
//! THE CONTRACT IS REFUSAL, NOT PANIC. A panic is a denial-of-service reachable from
//! untrusted wire bytes; a typed error is a decision the caller can act on. Every case below
//! asserts `Err(AggError::ValueOutOfRange)` specifically -- not merely "did not panic",
//! which a saturating implementation would also satisfy while silently changing the result.

use acfa_aggregate::rules::{
    bulyan_aggregate, bulyan_select, coord_median_trim, krum_aggregate, mean, multi_krum,
    trimmed_mean, AggError, Contribution,
};

fn onehot(i: usize, d: usize, mag: i64) -> Vec<i64> {
    let mut v = vec![0i64; d];
    v[i] = mag;
    v
}

/// Mutually distant contributions: each sits on its own axis, so no pairwise distance is
/// zero and the `m` smallest distances are all large. A set that clusters by sign leaves
/// zeros in every score and does not reach the accumulator bound.
fn spread(n: usize, mag: i64) -> Vec<Contribution> {
    (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i}").into_bytes(),
            v: onehot(i, n, mag),
        })
        .collect()
}

/// The four measured magnitudes. `2^62` is the case that separates the two accumulators;
/// `i64::MAX` is the extreme; `MAX + 1` and `MIN - 1` pin the boundary exactly.
fn cases() -> Vec<(&'static str, i64)> {
    vec![
        ("2^62", 1i64 << 62),
        ("i64::MAX", i64::MAX),
        ("fixed::MAX + 1", 1i64 << 31),
        ("fixed::MIN - 1", -(1i64 << 31) - 1),
    ]
}

#[test]
fn out_of_range_is_refused_by_krum_and_bulyan_alike() {
    for (label, mag) in cases() {
        // n = 11 satisfies Bulyan's n >= 4f+3 at f = 2, so a refusal here is the range
        // guard firing and not the population bound.
        let cs = spread(11, mag);

        assert_eq!(
            multi_krum(&cs, 2),
            Err(AggError::ValueOutOfRange),
            "multi_krum accepted an out-of-range value at {label}"
        );
        assert_eq!(
            bulyan_select(&cs, 2),
            Err(AggError::ValueOutOfRange),
            "bulyan_select accepted an out-of-range value at {label} \
             -- the duplicated score block is unguarded"
        );
        assert_eq!(
            krum_aggregate(&cs, 2),
            Err(AggError::ValueOutOfRange),
            "krum_aggregate accepted an out-of-range value at {label}"
        );
        assert_eq!(
            bulyan_aggregate(&cs, 2),
            Err(AggError::ValueOutOfRange),
            "bulyan_aggregate accepted an out-of-range value at {label}"
        );
    }
}

#[test]
fn every_coordinate_wise_rule_refuses_too() {
    // The three coordinate-wise sums are also unguarded i128 accumulators. They bind later
    // than the score sum, but "later" is not "never".
    for (label, mag) in cases() {
        let cs = spread(11, mag);
        assert_eq!(mean(&cs), Err(AggError::ValueOutOfRange), "mean at {label}");
        assert_eq!(
            trimmed_mean(&cs, 1, 4),
            Err(AggError::ValueOutOfRange),
            "trimmed_mean at {label}"
        );
        assert_eq!(
            coord_median_trim(&cs, 2),
            Err(AggError::ValueOutOfRange),
            "coord_median_trim at {label}"
        );
    }
}

#[test]
fn a_single_out_of_range_coordinate_anywhere_is_enough() {
    // The guard must be per-value, not per-contribution-norm: one bad coordinate buried in
    // an otherwise ordinary contribution is the realistic wire case.
    let mut cs = spread(11, 1000);
    cs[7].v[3] = i64::MAX;
    assert_eq!(multi_krum(&cs, 2), Err(AggError::ValueOutOfRange));
    assert_eq!(bulyan_select(&cs, 2), Err(AggError::ValueOutOfRange));
}

#[test]
fn in_range_extremes_still_compute() {
    // The guard must not be a blunt instrument: the full representable range has to keep
    // working, including both boundary values, or the fix has broken the product to protect
    // it. This is the direction a too-tight bound would fail in.
    let n = 11;
    let cs: Vec<Contribution> = (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i}").into_bytes(),
            v: {
                let mut v = onehot(i, n, acfa_aggregate::fixed::MAX);
                v[(i + 1) % n] = acfa_aggregate::fixed::MIN;
                v
            },
        })
        .collect();

    assert!(
        multi_krum(&cs, 2).is_ok(),
        "full-range values must still aggregate"
    );
    assert!(
        bulyan_select(&cs, 2).is_ok(),
        "full-range values must still select"
    );
    assert!(mean(&cs).is_ok());
    assert!(coord_median_trim(&cs, 2).is_ok());
}

// ---------------------------------------------------------------- cost guards

/// rust-02: the decoder bounds `n` LINEARLY against the bytes present, but the distance
/// matrix is QUADRATIC in `n`. Hardening the decoder moved the amplification one layer up
/// rather than removing it: a receipt small enough to pass the wire check can still ask a
/// verifier to allocate gigabytes.
#[test]
fn the_quadratic_matrix_is_bounded() {
    use acfa_aggregate::rules::MAX_CONTRIBUTIONS;
    let n = MAX_CONTRIBUTIONS + 1;
    let cs: Vec<Contribution> = (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i}").into_bytes(),
            v: vec![(i as i64 % 1000) << 8, 0],
        })
        .collect();

    assert_eq!(
        multi_krum(&cs, 2),
        Err(AggError::TooManyContributions {
            n,
            max: MAX_CONTRIBUTIONS
        }),
        "multi_krum accepted a set large enough to make the n x n matrix a DoS vector"
    );
}

/// rust-03: one attacker-chosen wire byte selects Bulyan, whose cost is CUBIC. The guard
/// inside the quadratic selection is not enough, because Bulyan buys `theta` of them.
#[test]
fn the_cubic_rule_has_its_own_lower_bound() {
    use acfa_aggregate::rules::MAX_CONTRIBUTIONS_BULYAN;
    // A const-vs-const assert is a compile-time tautology to clippy, so the relationship
    // is stated where it is enforced -- in the guard itself -- and exercised below instead.
    let n = MAX_CONTRIBUTIONS_BULYAN + 1;
    let cs: Vec<Contribution> = (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i}").into_bytes(),
            v: vec![(i as i64 % 1000) << 8, 0],
        })
        .collect();

    assert_eq!(
        bulyan_select(&cs, 2),
        Err(AggError::TooManyContributions {
            n,
            max: MAX_CONTRIBUTIONS_BULYAN
        }),
        "bulyan accepted a set whose cubic cost is unbounded from one wire byte"
    );
}

/// The guards must not have become a blunt instrument: ordinary deployment sizes still run.
#[test]
fn realistic_sizes_are_unaffected() {
    let cs: Vec<Contribution> = (0..64)
        .map(|i| Contribution {
            tie_key: format!("k{i}").into_bytes(),
            v: vec![(i as i64) << 10, 1 << 12],
        })
        .collect();
    assert!(multi_krum(&cs, 2).is_ok());
    assert!(bulyan_select(&cs, 2).is_ok());
}
