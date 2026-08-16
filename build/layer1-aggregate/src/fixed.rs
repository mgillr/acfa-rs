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
    // Round half away from zero, explicitly, rather than inheriting a platform default.
    let v = if scaled >= 0.0 {
        (scaled + 0.5).floor() as i64
    } else {
        (scaled - 0.5).ceil() as i64
    };
    Ok(v)
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
/// Returns i128 and never rescales. Two reasons, both load-bearing:
///   1. A Q16.16 difference squared is Q32.32, and summing d of those overflows i64
///      for realistic d. i128 holds it exactly for any d that fits in memory.
///   2. Rescaling back to Q16.16 would round, and a rounded distance can reorder
///      two near-tied scores -- which is precisely the selection flip the whole
///      determinism argument is built to exclude. Comparisons are done on exact
///      raw-unit values and the scale is never needed, because ranking is
///      invariant under the positive scale factor.
pub fn sq_dist(a: &[i64], b: &[i64]) -> i128 {
    debug_assert_eq!(a.len(), b.len(), "dimension mismatch");
    let mut acc: i128 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        let d = (*x as i128) - (*y as i128);
        acc += d * d;
    }
    acc
}

#[cfg(test)]
mod tests {
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
        let fwd = sq_dist(&a, &b);
        let rev: i128 = {
            let mut ra = a.clone();
            let mut rb = b.clone();
            ra.reverse();
            rb.reverse();
            sq_dist(&ra, &rb)
        };
        assert_eq!(fwd, rev, "distance must not depend on coordinate order");
        assert_eq!(fwd, 1500i128 * 1500 + 2700 * 2700 + 2100 * 2100);
    }

    #[test]
    fn sq_dist_does_not_overflow_at_extremes() {
        // Worst case: full-range opposite extremes across a large dimension.
        let d = 100_000;
        let a = vec![MAX; d];
        let b = vec![MIN; d];
        let got = sq_dist(&a, &b);
        let per = (MAX as i128 - MIN as i128).pow(2);
        assert_eq!(got, per * d as i128);
    }
}
