// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Q16.16 fixed-point encoding.
//!
//! Fixed-point is not an implementation detail here, it is the whole point. Float
//! aggregation is order-dependent: the same multiset of contributions summed in a
//! different order yields different bytes, so two honest replicas disagree and no
//! downstream proof can distinguish that from misbehaviour. Integers on a common
//! dyadic grid sum exactly and commute, so the aggregate is a function of the SET.
//!
//! DEPLOYMENT PARAMETER, NOT A UNIVERSAL CHOICE. Q16.16 fixes the dynamic range at
//! +/-2^15 with 2^-16 resolution. Components far below that resolution quantise to
//! zero. Any per-tensor scaling introduced to widen the range must itself be a
//! deterministic function of data both parties already hold; a scale chosen by one
//! party at runtime reopens exactly the non-determinism this module exists to close.

/// Number of fractional bits. Q16.16.
pub const FRAC_BITS: u32 = 16;
/// Scale factor, 2^FRAC_BITS.
pub const SCALE: i64 = 1 << FRAC_BITS;

/// Largest representable value, exclusive of the sign bit's extra step.
pub const MAX: i64 = (1 << 31) - 1;
/// Smallest representable value.
pub const MIN: i64 = -(1 << 31);

/// Errors that are worth refusing rather than silently absorbing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FixedError {
    /// The value is outside Q16.16 dynamic range. Saturating here would make the
    /// aggregate depend on WHICH replica saturated first; refusing keeps it total.
    OutOfRange,
    /// NaN or infinity has no fixed-point image and no sensible default.
    NotFinite,
}

/// Encode a float to Q16.16, refusing anything it cannot represent exactly-enough.
///
/// Rounds half away from zero. The rounding rule is part of the wire contract: two
/// implementations that round differently produce different aggregates from the same
/// inputs, which is indistinguishable from one of them being faulty.
pub fn encode(x: f64) -> Result<i64, FixedError> {
    if !x.is_finite() {
        return Err(FixedError::NotFinite);
    }
    let scaled = x * (SCALE as f64);
    if scaled > MAX as f64 || scaled < MIN as f64 {
        return Err(FixedError::OutOfRange);
    }
    // Round half away from zero. `f64::round` IS half-away-from-zero and is correctly
    // rounded, so it is a single operation with no intermediate value to misround.
    //
    // The previous form, `(scaled + 0.5).floor()`, was NOT equivalent: the addition is
    // itself a rounded operation. At the largest double strictly below 0.5, the true sum
    // `1 - 2^-54` is a binary64 midpoint, ties-to-even carries it to exactly `1.0`, and
    // the floor then returned 1 where half-away requires 0. Exactly one double per sign
    // in the whole Q16.16 range hit it, which is why a boundary test probing 0.5 itself
    // never caught it. See `encode_is_half_away_from_zero_at_the_largest_double_below_a_half`.
    Ok(scaled.round() as i64)
}

/// Decode Q16.16 back to a float. Exact: every Q16.16 value is a dyadic rational
/// with a numerator well below 2^53, so this conversion loses nothing.
pub fn decode(v: i64) -> f64 {
    (v as f64) / (SCALE as f64)
}

/// Encode a whole vector, reporting the index of the first element that fails.
pub fn encode_vec(xs: &[f64]) -> Result<Vec<i64>, (usize, FixedError)> {
    let mut out = Vec::with_capacity(xs.len());
    for (i, &x) in xs.iter().enumerate() {
        out.push(encode(x).map_err(|e| (i, e))?);
    }
    Ok(out)
}

/// Decode a whole vector.
pub fn decode_vec(vs: &[i64]) -> Vec<f64> {
    vs.iter().map(|&v| decode(v)).collect()
}

/// Squared Euclidean distance between two fixed-point vectors, in RAW UNITS.
///
/// `pub(crate)`, and fallible, for one measured reason. While this was `pub` inside a
/// `pub mod`, it was reachable by any dependent crate, and `acc += d * d` is only safe
/// under the Q16.16 range invariant that `rules::check` and `wire::decode` enforce at
/// their doors -- an invariant a direct caller bypasses entirely. A consumer crate
/// depending on this one from git, calling `acfa_aggregate::fixed::sq_dist` on raw
/// `i64::MAX`/`i64::MIN` vectors, got a panic in a debug build and, in a RELEASE build,
/// `-110680464442257309693`: a NEGATIVE squared distance, silently, exit 0. Release is
/// the dangerous half because `[profile.release] overflow-checks = true` in this manifest
/// governs only builds rooted HERE; a dependent's own profile governs their build of this
/// code, and release defaults to overflow-checks off. The wrapped value is worse than a
/// wrong number: a squared distance is non-negative by definition, `multi_krum` ranks by
/// ASCENDING score, so a negative distance sorts FIRST and the overflowing contribution is
/// preferentially SELECTED -- a selection inversion, which is the exact failure this crate
/// exists to exclude.
///
/// `None` on overflow rather than a saturated value: a saturated distance is a wrong but
/// plausible number, and a plausible wrong answer is worse than a refusal in a kernel whose
/// product is meant to be re-executable. Callers map it to `AggError::ValueOutOfRange`.
///
/// Returns i128 and never rescales. Two reasons, both load-bearing:
///   1. A Q16.16 difference squared is Q32.32, and summing d of those overflows i64
///      for realistic d. i128 holds it exactly for any d that fits in memory.
///   2. Rescaling back to Q16.16 would round, and a rounded distance can reorder
///      two near-tied scores -- which is precisely the selection flip the whole
///      determinism argument is built to exclude. Comparisons are done on exact
///      raw-unit values and the scale is never needed, because ranking is
///      invariant under the positive scale factor.
pub(crate) fn sq_dist(a: &[i64], b: &[i64]) -> Option<i128> {
    debug_assert_eq!(a.len(), b.len(), "dimension mismatch");
    let mut acc: i128 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        // The difference of two i64 always fits i128; the SQUARE of it does not.
        let d = (*x as i128) - (*y as i128);
        acc = acc.checked_add(d.checked_mul(d)?)?;
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    /// num-06. `(scaled + 0.5).floor()` is NOT half-away-from-zero: when `scaled` is the
    /// largest double strictly below 0.5, the addition itself rounds to exactly 1.0
    /// (the true sum 1 - 2^-54 is a binary64 midpoint and ties-to-even picks 1.0), so
    /// the floor returns 1 where half-away must return 0.
    ///
    /// An exhaustive scan of the 3 doubles below and 3 at/above every half-integer
    /// boundary across the whole Q16.16 range finds exactly ONE such double per sign,
    /// so this is a single-point defect -- which is precisely why no existing test
    /// caught it: `rounds_half_away_from_zero_symmetrically` probes exactly 0.5 LSB.
    ///
    /// It reaches the wire: acfa-agg on this value emits `ok 1` where `ok 0` is correct.
    #[test]
    fn encode_is_half_away_from_zero_at_the_largest_double_below_a_half() {
        // x * SCALE == 0.49999999999999994, the largest double < 0.5.
        let x = f64::from_bits(0x3EDF_FFFF_FFFF_FFFF);
        assert_eq!(
            x * (SCALE as f64),
            0.499_999_999_999_999_94_f64,
            "precondition"
        );
        assert_eq!(
            encode(x),
            Ok(0),
            "positive side must round toward zero, not up"
        );
        assert_eq!(encode(-x), Ok(0), "negative side likewise");
    }

    /// Guard the guard: agreement with `f64::round`, which IS correctly-rounded
    /// half-away-from-zero, at every half-integer boundary and its neighbours.
    #[test]
    fn encode_agrees_with_correctly_rounded_half_away_at_every_boundary() {
        let mut checked = 0u32;
        for n in 0..2048i64 {
            let mid = n as f64 + 0.5;
            for step in -2i64..=2 {
                let scaled = if step == 0 {
                    mid
                } else if step < 0 {
                    (0..-step).fold(mid, |a, _| f64::from_bits(a.to_bits() - 1))
                } else {
                    (0..step).fold(mid, |a, _| f64::from_bits(a.to_bits() + 1))
                };
                let x = scaled / (SCALE as f64);
                if let Ok(got) = encode(x) {
                    assert_eq!(
                        got as f64,
                        (x * (SCALE as f64)).round(),
                        "encode disagreed with half-away at scaled={scaled:?}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked > 8000,
            "scan too small to be meaningful ({checked})"
        );
    }

    use super::*;

    #[test]
    fn round_trip_is_exact_on_representable_values() {
        for &v in &[0i64, 1, -1, SCALE, -SCALE, 12345, -99999] {
            assert_eq!(encode(decode(v)).unwrap(), v, "round trip failed for {v}");
        }
    }

    #[test]
    fn refuses_rather_than_saturates() {
        assert_eq!(encode(f64::NAN), Err(FixedError::NotFinite));
        assert_eq!(encode(f64::INFINITY), Err(FixedError::NotFinite));
        assert_eq!(encode(40000.0), Err(FixedError::OutOfRange));
        assert_eq!(encode(-40000.0), Err(FixedError::OutOfRange));
    }

    #[test]
    fn rounds_half_away_from_zero_symmetrically() {
        // The asymmetric case is the one that bites: banker's rounding would send
        // these two to different magnitudes and break sign symmetry of the encoder.
        let half = 0.5 / (SCALE as f64);
        assert_eq!(encode(half).unwrap(), 1);
        assert_eq!(encode(-half).unwrap(), -1);
    }

    #[test]
    fn sq_dist_is_order_independent_and_exact() {
        let a = vec![1000i64, -2000, 3000];
        let b = vec![-500i64, 700, 900];
        let fwd = sq_dist(&a, &b).unwrap();
        let rev: i128 = {
            let mut ra = a.clone();
            let mut rb = b.clone();
            ra.reverse();
            rb.reverse();
            sq_dist(&ra, &rb).unwrap()
        };
        assert_eq!(fwd, rev, "distance must not depend on coordinate order");
        assert_eq!(fwd, 1500i128 * 1500 + 2700 * 2700 + 2100 * 2100);
    }

    #[test]
    fn sq_dist_refuses_rather_than_wrapping_outside_the_range() {
        // The measured regression. Before this was fallible, a dependent crate calling
        // `acfa_aggregate::fixed::sq_dist` on raw i64 extremes got `-110680464442257309693`
        // in a release build: a NEGATIVE squared distance, which sorts FIRST under Krum's
        // ascending rank and selects the offender. Assert refusal SPECIFICALLY, not merely
        // "did not panic" -- a saturating implementation would pass the weaker assertion
        // while silently changing which contribution wins.
        assert_eq!(
            sq_dist(&[i64::MAX], &[i64::MIN]),
            None,
            "one coordinate, opposite extremes"
        );
        assert_eq!(
            sq_dist(&[i64::MAX, i64::MAX], &[MIN, MIN]),
            None,
            "two coordinates"
        );
        // Non-negativity is the invariant Krum's ranking depends on: whatever it returns,
        // it is never negative.
        for (a, b) in [(i64::MAX, i64::MIN), (i64::MIN, i64::MAX), (MAX, MIN)] {
            if let Some(v) = sq_dist(&[a], &[b]) {
                assert!(
                    v >= 0,
                    "sq_dist({a}, {b}) returned a negative squared distance"
                );
            }
        }
    }

    #[test]
    fn sq_dist_does_not_overflow_at_extremes() {
        // Worst case: full-range opposite extremes across a large dimension.
        let d = 100_000;
        let a = vec![MAX; d];
        let b = vec![MIN; d];
        let got = sq_dist(&a, &b).unwrap();
        let per = (MAX as i128 - MIN as i128).pow(2);
        assert_eq!(got, per * d as i128);
    }
}
