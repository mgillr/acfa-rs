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

/// `Display` and `Error`. See the note on `rules::AggError`: a refusal the caller cannot
/// print or propagate with `?` is a refusal that reaches the operator as a type name.
///
/// `core::error::Error`, not `std::`, so these impls need nothing if the no-std question
/// recorded on `encode` is ever resolved. CORRECTING A CLAIM MADE IN THE COMMIT THAT
/// INTRODUCED THEM: that message said "layer1's production code now contains zero explicit
/// `std::` paths". That is true of the LIBRARY and false of the CRATE -- `src/bin/acfa-agg.rs`
/// is a bin target of this same package and carries six (`io::Read`, `process::ExitCode`,
/// `io::IsTerminal`, `env::args`, `io::stdin` twice), all outside its test module. The probe
/// behind the claim scanned three library files; the claim was stated over the crate.
///
/// The underlying reasoning is unaffected, which is why this is a scope correction and not a
/// retraction: a bin is a separate crate root, so a no-std LIBRARY can ship a std BINARY, and
/// a CLI that reads stdin necessarily has std. The library's single blocker remains
/// `f64::round`.
impl core::fmt::Display for FixedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FixedError::OutOfRange => write!(
                f,
                "value is outside the Q16.16 range [{}, {}] in raw units; saturating would \
                 make the aggregate depend on WHICH replica saturated first",
                MIN, MAX
            ),
            FixedError::NotFinite => {
                write!(
                    f,
                    "NaN or infinity has no fixed-point image and no sensible default"
                )
            }
        }
    }
}

impl core::error::Error for FixedError {}

/// Encode a float to Q16.16, refusing anything it cannot represent exactly-enough.
///
/// Rounds half away from zero. The rounding rule is part of the wire contract: two
/// implementations that round differently produce different aggregates from the same
/// inputs, which is indistinguishable from one of them being faulty.
///
/// # THE CONTRACT A PORT MUST MEET, AND WHY IT IS STATED HERE RATHER THAN ASSUMED
///
/// Write `s = x * 2^16`. A conforming encoder returns the integer nearest `s`, with exact
/// halves going AWAY FROM ZERO. Equivalently, and this is the single number every known
/// non-conforming implementation has got wrong:
///
/// > **The annihilation threshold is HALF a raw unit, not one.** `|s| < 0.5` encodes to 0;
/// > `0.5 <= |s| < 1.5` encodes to `+/-1`. Nothing in `[0.5, 1)` may vanish.
///
/// FIVE INDEPENDENT IMPLEMENTATIONS HAVE GOT THIS WRONG, in three distinct ways, which is
/// why it is now pinned by `a_conforming_encoder_rounds_half_away_from_zero` and its sibling
/// rather than described in prose that only a Rust reader ever opens. Three of the five were
/// written by ONE author inside a single afternoon, twice while reviewing this very rule with
/// the contract open on screen. The idiom survives repeated exposure to its own refutation,
/// and that -- not the count -- is the argument for pinning it:
///
///   - **Truncation toward zero** (`np.trunc`, `int(s)`, a C-style cast to `long`). Annihilates the
///     whole band up to one raw unit, so its threshold is exactly TWICE the contract's.
///     This is not a tie-breaking difference -- it disagrees on every non-integer `s`, and
///     it fails 9 of the 12 conformance rows. Measured consequence when it appeared in the
///     Flower adapter's annihilation guard: at sigma 2.0e-5 it predicted 55.5% of
///     coordinates lost where the kernel loses 29.7%, over-refusing by 25.7 points, and the
///     over-report PEAKS exactly in the band where the guard is consulted.
///   - **Ties-to-even** (Python's `round`, IEEE roundTiesToEven, Rust's
///     `format!("{:.0}")`). Agrees everywhere except at exact halves whose floor is even --
///     `0.5 -> 0` and `2.5 -> 2` where the contract requires 1 and 3. Half the ties, and it
///     fails 4 of the 12 rows. This is what the vendored reference's `fp_encode` does; see
///     `reference/README.md`, where it is recorded as a deliberate, asserted divergence.
///   - **`(s + 0.5).floor()`**, the usual hand-rolled "half away" idiom, which this crate
///     itself shipped. The addition is a rounded operation, so at the largest double below
///     0.5 it carries to exactly 1.0 and returns 1 where 0 is required. One double per
///     sign in the whole range -- see the note on the implementation below.
///
/// `f64::round` is the contract; prefer your language's correctly-rounded half-away
/// primitive over composing one.
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
/// product is meant to be re-executable. Callers map it to `AggError::ArithmeticOverflow`.
///
/// # rust-01 IS HELD BY A CONJUNCTION, AND THIS IS ONLY HALF OF IT
///
/// The critical finding -- *"the Q16.16 range invariant is documented everywhere and
/// enforced nowhere on the i64 path"* -- is closed by TWO independent guards, and removing
/// either reopens it in a regime the other does not cover:
///
/// 1. **The entry bound**, `rules::check`, which refuses any raw value outside
///    `[MIN, MAX]`. It makes overflow here UNREACHABLE for every path through the public
///    rules, because bounded at `+/-2^31` a difference is at most `2^32`, its square at
///    most `2^64`, and a sum of `m` of those cannot approach `i128::MAX`.
/// 2. **This function's own totality**, the `checked_mul`/`checked_add` below. It is what
///    stands if the entry bound is ever relaxed, and it is the only thing that would.
///
/// MEASURED, guard-deletion matrix on a fresh clone at `2b26b76`, 73 tests green at
/// baseline:
///
/// ```text
///     delete the entry bound only        5 tests red   (all entry-refusal tests)
///     delete this checked arithmetic     1 test  red   (sq_dist_refuses_...)
///     delete BOTH                        6 tests red   -- exactly the union
/// ```
///
/// The union being clean is the point: each guard is caught by its OWN tests and neither
/// certifies the other, so a maintainer who deletes one sees a real failure rather than a
/// green suite. That is the property `crypto-03` did NOT have, where two guards in two
/// files jointly held one security claim and neither named the other, and three reviewers
/// each held half of it.
///
/// So: **do not relax `rules::check`'s range validation on the assumption that this
/// function is total, and do not make this function infallible on the assumption that
/// `rules::check` bounds its inputs.** Each of those is individually true and jointly
/// fatal.
///
/// Reachability, verified rather than assumed: both call sites (`multi_krum`,
/// `multi_krum_ranked`) run `check` first, this function is `pub(crate)`, and it is not
/// re-exported from `lib.rs` -- so there is no path in or out of this crate that reaches it
/// without passing guard 1.
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

/// Squared L2 distance AND L1 distance in one pass, both exact in raw Q16.16 units.
///
/// Lemma 12's observable perturbation bound needs the largest pairwise L1 distance
/// alongside the score, and the score needs the squared L2. Walking the pair once and
/// returning both costs one traversal instead of two; the caller that does not need the
/// L1 keeps using `sq_dist` and pays nothing (see `krum_scores_inner`'s const generic).
///
/// L1 cannot overflow where the square does not: each `|d|` is at most the Q16.16 span
/// (2^32 - 1) and there are at most `d` of them, so the sum is far below the `d * span^2`
/// the squared accumulator already tolerates. It is still `checked_add`, because a bound
/// argued in a comment is not a bound the compiler enforces.
pub(crate) fn sq_and_l1(a: &[i64], b: &[i64]) -> Option<(i128, i128)> {
    debug_assert_eq!(a.len(), b.len(), "dimension mismatch");
    let mut sq: i128 = 0;
    let mut l1: i128 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        let d = (*x as i128) - (*y as i128);
        sq = sq.checked_add(d.checked_mul(d)?)?;
        l1 = l1.checked_add(d.abs())?;
    }
    Some((sq, l1))
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

    /// THE RANGE EDGE ITSELF, which nothing pinned.
    ///
    /// `refuses_rather_than_saturates` above probes 40000, roughly 2.6 billion raw units
    /// past the limit. That says the check exists; it says nothing about WHERE it is.
    /// Found by mutation, not by reading: widening the lower bound by a single raw unit
    /// (`scaled < MIN as f64` becomes `scaled < MIN as f64 - 1.0`) SURVIVES THE ENTIRE
    /// SUITE. A port whose bound is off by one, in either direction, was undetectable.
    ///
    /// Both edges are inclusive and the first excluded value on each side is half a raw
    /// unit out, because the comparison happens on the SCALED value before rounding.
    #[test]
    fn the_range_edge_is_inclusive_and_the_next_value_out_is_refused() {
        let q = SCALE as f64;
        // The edges themselves must ENCODE, not refuse.
        assert_eq!(
            encode(MIN as f64 / q),
            Ok(MIN),
            "MIN itself is representable"
        );
        assert_eq!(
            encode(MAX as f64 / q),
            Ok(MAX),
            "MAX itself is representable"
        );
        // And half a raw unit beyond each must refuse. This is the assertion the
        // off-by-one mutant fails; `-40000.0` cannot see it.
        assert_eq!(
            encode((MIN as f64 - 0.5) / q),
            Err(FixedError::OutOfRange),
            "half a raw unit below MIN must be refused, not rounded back into range"
        );
        assert_eq!(
            encode((MAX as f64 + 0.5) / q),
            Err(FixedError::OutOfRange),
            "half a raw unit above MAX must be refused"
        );
    }

    #[test]
    fn rounds_half_away_from_zero_symmetrically() {
        // The asymmetric case is the one that bites: banker's rounding would send
        // these two to different magnitudes and break sign symmetry of the encoder.
        let half = 0.5 / (SCALE as f64);
        assert_eq!(encode(half).unwrap(), 1);
        assert_eq!(encode(-half).unwrap(), -1);
    }

    /// THE CONFORMANCE TABLE FOR A PORT. Executable form of the contract documented on
    /// `encode`, kept as a table because prose has now been misread three times.
    ///
    /// IT IS PROVEN TO DISCRIMINATE, which is the only thing that makes it worth having:
    /// the same twelve rows were run against the two non-conforming rules seen in the
    /// wild, and each is rejected, by different rows.
    ///
    ///   half-away (the contract)  PASSES 12/12
    ///   truncation toward zero    FAILS 9/12 -- first at s=0.5 (gives 0, needs 1) and
    ///                             s=0.9 (gives 0, needs 1); it loses the whole [0.5,1) band
    ///   ties-to-even              FAILS 4/12 -- only at halves with an even floor,
    ///                             s=0.5 (gives 0, needs 1) and s=2.5 (gives 2, needs 3)
    ///
    /// So a port that passes this cannot be doing either, and a port that fails it is told
    /// by WHICH rows which mistake it made. Note the rows are chosen so that `s` is exactly
    /// representable wherever it sits on a boundary (halves and integers are dyadic, and
    /// dividing by `SCALE` is exact), so no row depends on float round-trip luck.
    ///
    /// # NEITHER THIS TEST NOR ITS SIBLING IS SUFFICIENT ALONE. MEASURED, BOTH DIRECTIONS.
    ///
    /// Each of the two catches a wrong rule the other certifies, so deleting either loses
    /// coverage. Every cell below was produced by mutating `encode` and running both tests:
    ///
    /// ```text
    ///   wrong rule                     this table      sibling (annihilation boundary)
    ///   truncation toward zero            FAIL              FAIL
    ///   ties-to-even                      FAIL              pass     <- only this test
    ///   floor(s+0.5), naive               FAIL              FAIL
    ///   floor(s+0.5)/ceil(s-0.5)          pass              FAIL     <- only the sibling
    /// ```
    ///
    /// The rows here catch rules that differ AT a midpoint. They cannot see a rule that
    /// differs BESIDE one: a sign-symmetric `(s + 0.5).floor()` port passes all twelve,
    /// including every midpoint, and is wrong on exactly one double per sign. Conversely the
    /// sibling cannot see ties-to-even, which is correct at that boundary.
    ///
    /// So they are not one test split for tidiness, they are two different questions.
    /// Do not fold them together, and do not treat these rows as the conformance suite on
    /// their own -- see the sibling for why a conformance table can CERTIFY a wrong port.
    #[test]
    fn a_conforming_encoder_rounds_half_away_from_zero() {
        // (scaled value `s`, the only admissible output)
        const TABLE: [(f64, i64); 12] = [
            (0.5, 1),
            (-0.5, -1),
            (0.9, 1),
            (-0.9, -1),
            (1.5, 2),
            (-1.5, -2),
            (2.5, 3),
            (-2.5, -3),
            (0.49, 0),
            (-0.49, 0),
            (1.0, 1),
            (3.5, 4),
        ];
        for (s, want) in TABLE {
            let x = s / (SCALE as f64);
            assert_eq!(
                encode(x),
                Ok(want),
                "conformance: s={s} must encode to {want} (half away from zero)"
            );
        }
    }

    /// THE CASE `a_conforming_encoder_rounds_half_away_from_zero` CANNOT CATCH.
    ///
    /// Deliberately a SEPARATE test rather than two more assertions inside the table
    /// above, because the note warning against deleting it would otherwise be a comment,
    /// and a comment cannot fail. As its own named test the protection is structural: the
    /// name states the role, removing it is a visible deletion of a test rather than a
    /// tidy-up of a line that looks redundant, and `grep half_away_from_zero` surfaces
    /// both halves from either end.
    ///
    /// WHAT IT CATCHES THAT THE TABLE DOES NOT. The textbook `(s + 0.5).floor()` idiom
    /// written with sign symmetry -- `floor(s+0.5)` for positives, `ceil(s-0.5)` for
    /// negatives -- returns the CONTRACT'S ANSWER on all twelve rows, including every
    /// midpoint. It is wrong on exactly one double per sign: at the largest double below
    /// half a unit, `s + 0.5` rounds up to exactly `1.0` and the floor yields 1.
    ///
    /// So the table certifies it and this test does not. Sign asymmetry is the first thing
    /// anyone notices about that idiom, so the author who thinks about it at all writes the
    /// form the table cannot see -- CARE REMOVES THE COARSE ERRORS AND LEAVES THE SUBTLE
    /// ONE. Measured: naive `floor(s+0.5)` everywhere fails the table 3/12 (all negatives)
    /// and fails here; the symmetric form passes the table 12/12 and fails here.
    ///
    /// AND THE DEPENDENCE RUNS BOTH WAYS, which is why neither test absorbs the other: this
    /// one CANNOT see ties-to-even. That rule rounds `0.49999999999999994` to 0 correctly and
    /// passes here, and is caught only by the table's midpoint rows. Two different questions,
    /// two tests; the full matrix is in the sibling's doc.
    ///
    /// Five implementations have now got this rule wrong -- three of them by one author
    /// inside a single afternoon, twice while reviewing this very rule with the contract
    /// open. The idiom survives repeated exposure to its own refutation, which is the whole
    /// argument for pinning it rather than describing it.
    #[test]
    fn a_conforming_encoder_annihilates_below_half_a_unit_and_not_above() {
        // The one number ports get wrong: the threshold is HALF a raw unit, not one.
        let below = f64::from_bits((0.5f64 / (SCALE as f64)).to_bits() - 1);
        assert_eq!(
            encode(below),
            Ok(0),
            "the double just below half a unit must annihilate. THE CONFORMANCE TABLE IN \
             `a_conforming_encoder_rounds_half_away_from_zero` CANNOT CATCH THIS: a \
             sign-symmetric `(s + 0.5).floor()` port passes all twelve of its rows and \
             fails only here. Do not fold this test into that one."
        );
        assert_eq!(
            encode(0.999 / (SCALE as f64)),
            Ok(1),
            "0.999 of a raw unit must NOT annihilate -- truncation loses this whole band"
        );
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

    /// THIS IS THE ONLY TEST THAT GUARDS `sq_dist`'S TOTALITY. DO NOT DELETE IT AS
    /// REDUNDANT.
    ///
    /// Measured: deleting the `checked_mul`/`checked_add` turns exactly ONE test red, and
    /// it is this one. Every other test in the crate stays green, because the entry bound
    /// in `rules::check` keeps the overflow unreachable through the public rules -- so from
    /// inside the suite this function's fallibility looks like dead weight, and it is not.
    /// It is guard 2 of the `rust-01` conjunction and the only thing standing if the entry
    /// bound is ever relaxed. See the note on `sq_dist` itself.
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
