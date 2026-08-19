// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Deterministic robust-aggregation rules over Q16.16 vectors.
//!
//! Every rule here is a pure function of the SET of contributions. Feed the same
//! contributions in any order, on any target, and the output bytes are identical.
//! That property is the product; the robustness is inherited from the literature.
//!
//! LAYER BOUNDARY. This module never hashes, signs, verifies, or times anything.
//! Where the reference implementation passes commitment leaf hashes for canonical
//! tie-breaking, this takes an OPAQUE `tie_key: &[u8]` supplied by the caller and
//! never interprets it. The aggregator's requirement is only that some deterministic
//! total order over contributions exists; what supplies that order is not this
//! layer's business, and keeping it out means publishing this layer discloses no
//! commitment scheme.

use crate::fixed::sq_dist;

/// A single contribution: an opaque ordering key plus its fixed-point vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    /// Opaque, caller-supplied, used ONLY to break exact ties. Never interpreted.
    pub tie_key: Vec<u8>,
    /// Q16.16 values.
    pub v: Vec<i64>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AggError {
    Empty,
    /// Vectors of differing length cannot be aggregated coordinate-wise, and
    /// padding one silently would let a short contribution shift the result.
    ///
    /// crdt-08, ACCOUNTABILITY HALF. This variant used to be a bare unit with no payload,
    /// so a single in-budget adversary sending a short vector nullified the round for
    /// everyone and NOBODY WAS ATTRIBUTABLE for it. The refusal named no node, no index and
    /// no tie key, which left an operator with a dead round and no one to exclude.
    ///
    /// `expected` IS THE LOAD-BEARING FIELD, not `offender`. It is the PLURALITY length --
    /// the length held by strictly more contributions than any other -- so a caller
    /// recovers the whole offender set with one filter (`c.v.len() != expected`) and
    /// attributes each by its own `tie_key`. `offender` is the first such index, a witness
    /// for the log. The slice is the caller's, so an index is a sufficient handle and this
    /// variant stays `Copy`.
    ///
    /// PLURALITY, NOT `cs[0]`, AND THAT IS THE WHOLE SECURITY ARGUMENT. Attribution is an
    /// accusation, so the obvious rule is the dangerous one. Taking `cs[0].v.len()` as
    /// correct -- which is exactly what this function computed before -- lets the ADVERSARY
    /// PICK THE ACCUSED simply by arriving first: measured on six honest dim-4 and one
    /// adversarial dim-2, that rule names the adversary when it arrives last and names ALL
    /// SIX HONEST NODES when the same adversary arrives at index 0. Naive attribution is
    /// therefore strictly worse than none, converting a denial of service into a framing
    /// vector. Plurality names the adversary in both orders, and in the two-adversary case
    /// names both. Same shape as the `crdt-07` framing vector in `layer2-finality`, where
    /// attribution had to be read from verified signatures rather than map membership.
    ///
    /// Soundness rests on the fault budget, and it is the budget this crate already
    /// assumes: with `f < n/2` the honest nodes are the strict plurality by counting, so
    /// the plurality length is honest. Outside that budget there is no strict plurality to
    /// find and the refusal degrades to `DimensionMismatchUnattributable` rather than
    /// guessing -- see there.
    ///
    /// WHAT THIS DOES NOT FIX: the AVAILABILITY half of crdt-08. One short vector still
    /// nullifies the round -- every rule still returns `Err` and no aggregate is produced.
    /// Whether to refuse the set or drop the offenders and proceed is a protocol policy
    /// decision that does not belong in this module, and `expected` is what makes that
    /// decision a one-line filter at the layer that owns it.
    DimensionMismatch {
        /// Index of the first contribution not at `expected`. A witness; the full set is
        /// recovered by filtering on `expected`.
        offender: usize,
        /// The plurality vector length -- what strictly more contributions agreed on than
        /// any other length, and under the fault budget the honest length.
        expected: usize,
        /// The offending contribution's length.
        got: usize,
    },
    /// Vector lengths disagree and NO STRICT PLURALITY EXISTS, so there is no honest
    /// majority to attribute against and naming anyone would be a guess.
    ///
    /// crdt-08 again, and this variant exists so that the fix cannot become the defect.
    /// Refusing to accuse is the correct answer here: an even split (`n = 4` as `2/2`) or a
    /// two-node round means the fault budget is already exceeded, and the rule that names
    /// an offender anyway would be naming one of two indistinguishable groups. Measured:
    /// the `cs[0]` rule accuses the second group in both cases with no evidence whatsoever.
    ///
    /// This is a strictly worse position for the operator than `DimensionMismatch` and the
    /// message says so, because the remedy is different -- there is no one to exclude, and
    /// the round cannot be repaired by dropping a minority.
    DimensionMismatchUnattributable {
        /// How many distinct lengths were present. Always `>= 2`.
        lengths: usize,
    },
    /// Every contribution agrees on a length of ZERO, so there are no coordinates to
    /// aggregate.
    ///
    /// Split out of `DimensionMismatch` while fixing crdt-08. It was reported as a
    /// mismatch, which was a second unattributable refusal hiding inside the first: nothing
    /// mismatches here, everyone agrees, and there is no offender to name because there is
    /// no offender. It had no test at all -- the `d == 0` branch was the only arm of this
    /// function no case in the suite entered.
    EmptyVectors,
    /// Two contributions carry the same tie key, so no total order exists and the
    /// output would depend on input order. Refusing is the only deterministic answer.
    DuplicateTieKey,
    /// Bulyan requires `n >= 4f + 3`. Below that its selection stage cannot draw the
    /// `theta = n - 2f` candidates its guarantee is stated over, so running anyway
    /// would return a plausible-looking aggregate with no Byzantine guarantee behind
    /// it. Refusing is the only honest answer -- the same discipline as refusing an
    /// out-of-range encode rather than saturating it.
    BulyanTooFewContributions,
    /// A raw value lies outside the Q16.16 representable range `[fixed::MIN, fixed::MAX]`
    /// (`+/-2^31`).
    ///
    /// THIS IS THE LOAD-BEARING VALIDATION, NOT A COURTESY CHECK. `encode()` enforces the
    /// range on the float path, but a `Contribution` can be built directly from raw `i64`
    /// -- which is exactly what decoding a wire receipt does -- and that path reached the
    /// distance and score accumulators unbounded.
    ///
    /// The arithmetic is why this is the only structurally sufficient place to check.
    /// Bounded at `+/-2^31`: a coordinate difference is at most `2^32`, its square at most
    /// `2^64`, and a score summing `m` of those is at most `m * 2^64`, which cannot reach
    /// `i128::MAX = 2^127 - 1` for any realistic `m`. Every accumulator on the path is then
    /// safe BY CONSTRUCTION, and no internal audit is needed to keep it that way.
    ///
    /// Unbounded, the same arithmetic breaks in two stages: at `+/-2^62` each squared
    /// difference is `2^125` and still fits, so `sq_dist` returns cleanly, and then the
    /// SCORE accumulator sums four of them to `2^127` and overflows. Measured: `sq_dist`
    /// returned Ok while `multi_krum` and `bulyan_select` both panicked. Guarding
    /// `sq_dist` alone would have moved the fault one line down and left it looking like a
    /// different bug.
    ValueOutOfRange {
        /// Index of the first contribution carrying an out-of-range value. A witness, as in
        /// `DimensionMismatch`: the full offender set is recovered by re-scanning, and
        /// UNLIKE the length case no plurality rule is needed -- out of range is a property
        /// of the value against a constant bound, so the adversary cannot choose who is
        /// accused by choosing where it arrives.
        offender: usize,
        /// Which coordinate of that contribution.
        coord: usize,
        /// The offending raw value.
        value: i64,
    },
    /// Internal accumulator arithmetic exceeded its width.
    ///
    /// fl-01 split this out of `ValueOutOfRange`, which had been doing two jobs: the ENTRY
    /// refusal above, which names an offender, and these totality arms, which cannot --
    /// an overflow in a score sum has no single offending contribution. Conflating them
    /// forced the attributable case to stay anonymous. On every path inside this module
    /// this variant is UNREACHABLE by construction (`check` bounds every value at entry,
    /// which is what makes the five i128 accumulators safe); it exists because the type
    /// system cannot see that proof, exactly as documented at the `floor_div` call sites.
    ArithmeticOverflow,
    /// `beta_den` is zero, so the trim fraction `beta_num / beta_den` is undefined.
    ///
    /// This was an `assert!` in library code, which aborts the process. A library reached
    /// from a CLI that reads untrusted directives must not abort on a value the caller
    /// supplied -- `acfa-agg` exited 101 on `beta <num> 0` where its own contract promises
    /// a typed refusal.
    BetaDenominatorZero,
    /// adv-05. A `beta` that trims NOTHING, so `trimmed_mean` would return the plain mean.
    ///
    /// The trim is `t = min(floor(n * num / den), n)` and trimming happens only when
    /// `n > 2t`, so there are TWO no-trim regions, one at EACH end: `t == 0`, and `t` large
    /// enough that nothing survives. In both the rule labelled "trimmed" returns exactly the
    /// untrimmed mean -- INCLUDING the outliers it was configured to remove -- at exit 0
    /// with no diagnostic. Measured at n=7 with six honest values near 1.0 and one adversary
    /// at 500.0, where the plain mean is 72.29 and any trimming run gives 1.01:
    /// beta 1/8 -> 72.29, 1/4 -> 1.01, 1/2 -> 1.01, 3/4 -> 72.29, 9/4 -> 72.29.
    ///
    /// REFUSED rather than silently degraded, per the coordinator's ruling: returning the
    /// poisoned aggregate at exit 0 is the worst available failure mode, and it is the same
    /// defect as a rule directive being substituted without complaint. The band is
    /// n-DEPENDENT, so `t` is reported rather than a fixed range: `beta >= 1/2` does NOT
    /// always fail -- 1/2 trims correctly at n=7 (t=3, 7 > 6).
    BetaTrimsNothing {
        /// The trim count the configured beta produces at this `n`.
        t: usize,
        /// The contribution count the trim was computed against.
        n: usize,
    },
    /// More contributions than the rule will process. See `MAX_CONTRIBUTIONS` and
    /// `MAX_CONTRIBUTIONS_BULYAN` for the arithmetic behind each bound.
    ///
    /// This is a REFUSAL, not a truncation. Silently aggregating a prefix would produce a
    /// plausible-looking result over a set the caller never chose, which is the same class
    /// of error as saturating an out-of-range value.
    /// The requested aggregation would cost more coordinate-operations than
    /// `MAX_COORDINATE_OPS` allows. See that constant for the arithmetic and for why the
    /// participant caps do not subsume this one: the cost is a PRODUCT of `n` and `d`, and
    /// capping `n` alone leaves `d` free.
    ///
    /// `work` is an upper bound computed BEFORE any of it is done.
    TooMuchWork {
        work: u128,
        max: u128,
    },
    TooManyContributions {
        n: usize,
        max: usize,
    },
}

/// `Display` and `Error`, because THIS CRATE'S PRODUCT IS ITS REFUSALS.
///
/// Every variant above exists so a rule can decline rather than return a plausible wrong
/// answer -- that is the design argument made throughout this module. A refusal a caller
/// cannot print, and cannot carry with `?` into `Box<dyn Error>` or `anyhow`, is a refusal
/// that arrives as `AggError` in a log and tells the operator nothing. The messages carry
/// the VALUES where a variant has them: "4097 contributions, max 4096" is actionable and
/// `TooManyContributions` alone is not.
impl core::fmt::Display for AggError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AggError::Empty => write!(f, "no contributions to aggregate"),
            AggError::DimensionMismatch {
                offender,
                expected,
                got,
            } => write!(
                f,
                "contribution {offender} has vector length {got}, but {expected} is the \
                 plurality length; exclude every contribution not at {expected} and retry"
            ),
            AggError::DimensionMismatchUnattributable { lengths } => write!(
                f,
                "contributions carry {lengths} different vector lengths with no strict \
                 plurality among them, so no offender can be named without guessing; the \
                 fault budget is already exceeded and the round cannot be repaired by \
                 dropping a minority"
            ),
            AggError::EmptyVectors => write!(
                f,
                "every contribution agrees on a vector length of 0, so there are no \
                 coordinates to aggregate"
            ),
            AggError::DuplicateTieKey => write!(
                f,
                "two contributions share a tie key, so no total order exists and the output \
                 would depend on arrival order"
            ),
            AggError::BulyanTooFewContributions => write!(
                f,
                "too few contributions for Bulyan's precondition n >= 4f + 3; running anyway \
                 would return an aggregate with no Byzantine guarantee behind it"
            ),
            AggError::ValueOutOfRange {
                offender,
                coord,
                value,
            } => write!(
                f,
                "contribution {offender} coordinate {coord} is {value}, outside the Q16.16 \
                 range [{}, {}]; drop that contribution and the round can proceed",
                crate::fixed::MIN,
                crate::fixed::MAX
            ),
            AggError::ArithmeticOverflow => write!(
                f,
                "internal accumulator arithmetic exceeded its width; unreachable when every \
                 input passed the entry range check"
            ),
            AggError::BetaDenominatorZero => {
                write!(
                    f,
                    "beta denominator is zero, so the trim fraction is undefined"
                )
            }
            AggError::BetaTrimsNothing { t, n } => write!(
                f,
                "beta trims {t} from each end of {n}, which trims nothing (needs 1 <= t \
                 and n > 2t), so the result would be the plain mean including any outliers"
            ),
            AggError::TooMuchWork { work, max } => write!(
                f,
                "this aggregation would cost about {work} coordinate operations, over the \
                 limit of {max}; the cost is quadratic or cubic in the contribution count \
                 AND linear in the vector dimension, so reduce either"
            ),
            AggError::TooManyContributions { n, max } => write!(
                f,
                "{n} contributions exceeds the limit of {max}; the distance matrix is \
                 quadratic in n and a prefix would aggregate a set the caller never chose"
            ),
        }
    }
}

impl core::error::Error for AggError {}

/// Largest contribution count the distance-matrix rules will accept.
///
/// WHY A CAP EXISTS AT ALL. `multi_krum` and `bulyan_select` allocate an `n x n` matrix of
/// `i128`, so memory grows QUADRATICALLY in `n` while a receipt carrying those
/// contributions grows only LINEARLY. The wire decoder bounds `n` against the bytes
/// actually present, which stops a length prefix inventing elements -- but a linear bound
/// does not bound quadratic work. A ~1 MB receipt can legitimately carry thousands of
/// small contributions, and the matrix for those is gigabytes. The decoder was hardened
/// and the amplification simply moved one layer up.
///
/// 4096^2 * 16 bytes = 268 MB, which is the point past which this stops being a
/// computation and becomes a denial-of-service vector against anyone who verifies an
/// untrusted receipt.
pub const MAX_CONTRIBUTIONS: usize = 4096;

/// Bulyan's cap is lower because its cost is CUBIC, not quadratic: it re-runs the Krum
/// selection `theta = n - 2f` times over a shrinking pool, so the work is `O(n^3 * d)`.
///
/// Measured on the reference host (see `build/LOAD-AND-STRESS.md`): n=256, d=1024 takes
/// 11.55 s -- a PRE-`MAX_COORDINATE_OPS` measurement; that cell (`bulyan_work = 1.76e10`)
/// is REFUSED by the work bound today. The cube law puts n=512 near 90 s and n=1024 beyond
/// ten minutes, but the work bound now refuses those long before the count cap binds. A single wire
/// byte selects this rule, so an attacker picks the exponent; the cap is what stops one
/// byte buying an unbounded amount of a verifier's time.
pub const MAX_CONTRIBUTIONS_BULYAN: usize = 512;

/// THE CEILING THAT ACTUALLY BINDS: WORK, NOT PARTICIPANT COUNT.
///
/// rust-02 and rust-03 both cap `n`. The cost of both rules is a PRODUCT -- `n^2 * d` for
/// the Krum path, `n^3 * d` for Bulyan -- and `d` was capped by nothing at all. Bounding one
/// factor of a product bounds nothing, and the doc on `MAX_CONTRIBUTIONS_BULYAN` above names
/// the product while the constant addresses only its first term.
///
/// MEASURED ON THE SHIPPED BINARY, `n` PINNED AT THE BULYAN CAP OF 512, ONLY `d` VARYING:
///
/// ```text
///     d=2      21 KB      0.64 s     d=256    2.2 MB    48.02 s
///     d=16    143 KB      3.33 s     d=512    4.5 MB   133 s
///     d=64    561 KB     12.29 s     d=1024   8.9 MB   255 s
/// ```
///
/// Every row was `ok` BEFORE the work bound existed -- these measurements are WHY it does.
/// Under the shipped `MAX_COORDINATE_OPS`, `bulyan_work(512, d) = 1.34e8 * d` crosses `1e9`
/// at `d >= 8`, so every row in the table above except `d = 2` now returns `TooMuchWork`:
/// it is the evidence for the bound, not a menu of what the binary will run. `f` is not the
/// variable either: at `n=512, d=64`, every `f` from 0 to 126 lands between 10.35 s and 11.93 s
/// (also pre-bound; that `(n, d)` is refused now).
///
/// THE ARITHMETIC BEHIND THE NUMBER. Coordinate-operations were timed against wall clock on
/// the calibration host, and the model was checked at two different `(n, d)` with the SAME
/// product rather than only along one axis:
///
/// ```text
///     krum    n=4096 d=16   and  n=2048 d=64   both 2.7e8 units   1.44 s / 1.24 s
///     krum                                     ~5 ns per unit
///     bulyan  n=512 d=16 and d=64              1.80 / 1.78 ns per unit
/// ```
///
/// One billion units is therefore about **5 s of Krum or 1.8 s of Bulyan** on that host --
/// a defensible ceiling for work done on behalf of a file from a stranger, and it is stated
/// here in seconds precisely because a constant whose unit is "contributions" cannot be
/// argued about operationally.
///
/// THIS WILL REFUSE SOME LEGITIMATE WORK AND THAT IS THE TRADE, NOT AN OVERSIGHT. Real
/// federated learning has large `d` -- a model dimension in the millions puts any useful `n`
/// far over this bound. Such deployments are already impractical through this crate's
/// ASCII-over-stdin path (see `fl-08`), and an operator who wants more should raise this
/// deliberately rather than discover the ceiling as a timeout. The refusal names the work it
/// declined and the limit, so the number to raise is in the error itself.
pub const MAX_COORDINATE_OPS: u128 = 1_000_000_000;

/// Work the Krum path will do for `n` contributions of dimension `d`: the `n^2` distance
/// matrix, each entry costing `d` coordinate operations.
fn krum_work(n: usize, d: usize) -> u128 {
    (n as u128)
        .saturating_mul(n as u128)
        .saturating_mul(d as u128)
}

/// Work Bulyan will do: it re-runs the Krum selection `theta = n - 2f` times over a
/// shrinking pool, so `n^3 * d` is the upper bound the cap is stated against.
fn bulyan_work(n: usize, d: usize) -> u128 {
    krum_work(n, d).saturating_mul(n as u128)
}

/// Floor division by a POSITIVE denominator: rounds toward NEGATIVE INFINITY,
/// matching the reference kernel. Refuses anything outside that domain.
///
/// THIS IS NOT COSMETIC. Python's `//` floors; Rust's `/` truncates toward zero.
/// They agree on non-negative values and DISAGREE on every negative non-exact
/// quotient (`-7 // 2 == -4` but `-7 / 2 == -3`). Gradient components are routinely
/// negative, so a port that used `/` would produce a different aggregate from the
/// reference on ordinary inputs -- and two conforming implementations disagreeing is
/// indistinguishable from one of them being faulty, which is the exact failure the
/// determinism property exists to exclude. The rounding rule is wire contract.
///
/// WHAT THIS COVERS AND WHAT IT DOES NOT. The domain is `denom > 0` and a quotient that
/// fits `i64`; every other input is refused, not approximated. It does NOT implement
/// Python's `//` for negative denominators, because no caller here has one and a branch
/// that is dead by construction is a branch no test can keep honest. If a caller ever
/// needs `denom < 0`, that is new behaviour to be written and tested, not assumed present.
///
/// `pub(crate)` and fallible, for the reason `fixed::sq_dist` is. While this was `pub`
/// inside a `pub mod`, the only guard on the denominator was a `debug_assert`, which is
/// COMPILED OUT of a release build, so a dependent crate reached the raw arithmetic. Three
/// measured results, all from a release build of a consumer crate: `floor_div(-7, -2)`
/// returned 4 where the floor is 3 (`div_euclid` floors only for a positive divisor --
/// Euclidean division forces a non-negative remainder, so a negative divisor rounds toward
/// POSITIVE infinity, contradicting the sentence above on all four sign combinations);
/// `floor_div(i128::MAX, 1)` returned -1, the `as i64` cast truncating silently; and
/// `floor_div(1, 0)` panicked, a division-by-zero abort reachable from safe code.
///
/// FLOORING IS DIRECTIONAL, SO IT IS BIASED, AND THE BIAS ACCUMULATES ACROSS ROUNDS.
/// This is a design consequence with no admissible fix, not an open bug, and it is
/// recorded here so a deployment can price it. The remainder of a sum over `n` is uniform
/// on `0..n-1` and the discarded part is `r/n`, so the expected error is
/// `-(n-1)/2n` LSB per round, ALWAYS DOWNWARD -- never cancelling, unlike round-to-nearest.
/// Measured independently twice, 200k trials per configuration, agreeing with the closed
/// form to within 0.001 LSB: n=2 -0.250, n=3 -0.333, n=5 -0.400, n=8 -0.438, n=16 -0.469.
/// Over 600 rounds at n=5 with N(0, 1e-3) updates it is a real drift, not rounding noise.
///
/// THE TWO STANDARD REMEDIES ARE BOTH BARRED, and by the same property:
///   - ERROR FEEDBACK (carry the discarded remainder into the next round) cancels it
///     completely and is the textbook fix. It makes the aggregate a function of HISTORY,
///     so two replicas given the same set in a different sequence produce different bytes.
///     That is exactly the property this module exists to provide -- see the first line of
///     the module doc. It does not trade determinism at the margin, it destroys it.
///   - STOCHASTIC or DITHERED rounding is out for the same reason, unless the dither is a
///     deterministic function of data both parties already hold. That is the identical
///     caveat `fixed.rs` records for per-tensor scaling.
///
/// Round-half-to-even WOULD be both deterministic and unbiased, but the rounding rule is
/// WIRE CONTRACT: the vendored reference floors (Python `//`), and
/// `cross_impl::rust_matches_the_python_reference_on_every_rule` is one of only four tests
/// that detect a change to this function. Changing it costs the reference pin and an
/// erratum against a published artifact. Not paid.
///
/// `None` rather than a saturated or truncated value: this function's product is an
/// aggregate coordinate that goes on the wire, and a plausible wrong coordinate is worse
/// than a refusal in a kernel whose whole claim is that the result is re-executable.
///
/// Callers map `None` to `AggError::ArithmeticOverflow`. On every path inside this module
/// that arm is UNREACHABLE and is a totality requirement, not a live check: `check`
/// rejects the empty set, so `n >= 1` at each call site and each `kept` slice is
/// non-empty; and `check` bounds every raw value to `+/-2^31`, so a coordinate sum over
/// at most `MAX_CONTRIBUTIONS` terms is at most `2^43` and its quotient always fits.
/// The refusals are exercised directly in this module's tests instead.
#[inline]
pub(crate) fn floor_div(numer: i128, denom: i128) -> Option<i64> {
    if denom <= 0 {
        return None;
    }
    // `div_euclid` IS the floor for a positive divisor, and cannot overflow here:
    // the sole overflowing case, `i128::MIN / -1`, needs a negative divisor.
    i64::try_from(numer.div_euclid(denom)).ok()
}

fn check(cs: &[Contribution]) -> Result<usize, AggError> {
    if cs.is_empty() {
        return Err(AggError::Empty);
    }
    // crdt-08, accountability half. The plurality length -- NOT `cs[0].v.len()`, which
    // hands the adversary the choice of who gets accused. See `AggError::DimensionMismatch`
    // for the measurement behind that sentence and for why naive attribution is worse than
    // none.
    //
    // THE SCAN IS SORT-BASED, O(n log n), AND THE FIRST VERSION OF IT WAS QUADRATIC. That
    // version counted each length by filtering the whole slice per contribution, and
    // carried a comment claiming `n` was bounded by `MAX_CONTRIBUTIONS` "above". IT IS NOT:
    // that cap is enforced inside the Krum/Bulyan pool guard, not in `check`, so `mean`
    // takes any `n` the caller can send. Measured on the shipped binary with one short
    // vector among n: 0.024s at n=4000 rising ~4x per doubling to 1.394s at n=32000 --
    // linear input, quadratic work, chosen by the attacker. That is rust-02's shape, and it
    // was introduced HERE, today, by a bound asserted in a comment and enforced nowhere.
    //
    // Unanimity -- every accepted round -- is still settled by the linear `all` below and
    // returns before reaching the scan at all, so the happy path is untouched either way.
    let d = cs[0].v.len();
    if !cs.iter().all(|c| c.v.len() == d) {
        let mut lens: Vec<usize> = cs.iter().map(|c| c.v.len()).collect();
        lens.sort_unstable();
        let (mut best_len, mut best_count, mut distinct, mut tied) =
            (lens[0], 0usize, 0usize, false);
        let mut i = 0;
        while i < lens.len() {
            let mut j = i;
            while j < lens.len() && lens[j] == lens[i] {
                j += 1;
            }
            let count = j - i;
            distinct += 1;
            if count > best_count {
                // A tie recorded below the new maximum was never a tie FOR the maximum.
                (best_len, best_count, tied) = (lens[i], count, false);
            } else if count == best_count {
                tied = true;
            }
            i = j;
        }
        if tied {
            return Err(AggError::DimensionMismatchUnattributable { lengths: distinct });
        }
        // `best_count < cs.len()` here because the lengths are not unanimous, so a
        // contribution off the plurality exists and this cannot be `None`.
        let offender = cs
            .iter()
            .position(|c| c.v.len() != best_len)
            .expect("lengths are not unanimous, so one is off the plurality");
        return Err(AggError::DimensionMismatch {
            offender,
            expected: best_len,
            got: cs[offender].v.len(),
        });
    }
    // Reached only when every contribution agrees, so a zero here is unanimous and is not
    // a mismatch by anyone. It was reported as one until crdt-08.
    if d == 0 {
        return Err(AggError::EmptyVectors);
    }
    let mut keys: Vec<&[u8]> = cs.iter().map(|c| c.tie_key.as_slice()).collect();
    keys.sort_unstable();
    if keys.windows(2).any(|w| w[0] == w[1]) {
        return Err(AggError::DuplicateTieKey);
    }
    // Range validation, and it belongs HERE rather than deeper in the arithmetic. Every
    // rule in this module funnels through `check`, so bounding raw values once at entry
    // makes all five i128 accumulators on the path -- the three coordinate-wise sums, the
    // squared-distance accumulator, and the score sum -- safe by construction. See
    // `AggError::ValueOutOfRange` for the arithmetic.
    for (i, c) in cs.iter().enumerate() {
        for (k, &x) in c.v.iter().enumerate() {
            if !(crate::fixed::MIN..=crate::fixed::MAX).contains(&x) {
                // fl-01. One client's one coordinate denies the round for everyone, and the
                // refusal used to name NOBODY -- an operator could not exclude the offender
                // and retry. The refusal itself is correct (SECURITY.md: never saturate);
                // what was missing was attribution, and range is OBJECTIVE so the first
                // offender is named directly with no framing vector to defend against.
                return Err(AggError::ValueOutOfRange {
                    offender: i,
                    coord: k,
                    value: x,
                });
            }
        }
    }
    Ok(d)
}

/// Coordinate-wise mean, floor rounding. The averaging step of multi-Krum.
pub fn mean(cs: &[Contribution]) -> Result<Vec<i64>, AggError> {
    let d = check(cs)?;
    let n = cs.len() as i128;
    (0..d)
        .map(|k| {
            let s: i128 = cs.iter().map(|c| c.v[k] as i128).sum();
            floor_div(s, n)
        })
        .collect::<Option<Vec<i64>>>()
        .ok_or(AggError::ArithmeticOverflow)
}

/// Coordinate-wise trimmed mean. Drops `t = floor(n * beta_num / beta_den)` values
/// from each end of each coordinate's sorted column, then floor-averages the rest.
/// If trimming would empty the column, nothing is trimmed -- a rule that returns no
/// value is worse than one that returns a value the bound does not actually protect.
pub fn trimmed_mean(
    cs: &[Contribution],
    beta_num: u32,
    beta_den: u32,
) -> Result<Vec<i64>, AggError> {
    let d = check(cs)?;
    let n = cs.len();
    if beta_den == 0 {
        return Err(AggError::BetaDenominatorZero);
    }
    // In `u128`, and clamped, because `n * beta_num` in `usize` OVERFLOWS on a 32-bit
    // target for ordinary values: beta = 1048576/4194304 is just 1/4, and at n = 4096
    // the product is exactly 2^32. With `overflow-checks = true` that panicked on
    // 32-bit while returning a value on 64-bit -- identical inputs, different outcome
    // per target width, which is the divergence this crate exists to exclude.
    //
    // The clamp is behaviour-preserving, not a second guess: trimming happens only
    // when `n > 2 * t`, so every `t >= n` already meant "trim nothing", and pinning it
    // at `n` keeps that while making the narrowing cast total.
    let t = ((n as u128 * beta_num as u128) / beta_den as u128).min(n as u128) as usize;
    // adv-05. REFUSE A BETA THAT TRIMS NOTHING rather than returning the plain mean.
    // Computed exactly as the trim below computes it, not declared as a range: the band is
    // n-dependent and `beta >= 1/2` is NOT the boundary -- 1/2 trims correctly at n=7.
    if t == 0 || n <= 2 * t {
        return Err(AggError::BetaTrimsNothing { t, n });
    }
    (0..d)
        .map(|k| {
            let mut col: Vec<i64> = cs.iter().map(|c| c.v[k]).collect();
            col.sort_unstable();
            // `n > 2 * t` is `n >= 2t + 1` over the integers: at least one element
            // survives the trim. Written in the `>` form because clippy's
            // int_plus_one denies the other one and the lint gate runs -D warnings.
            let kept: &[i64] = if n > 2 * t { &col[t..n - t] } else { &col[..] };
            let s: i128 = kept.iter().map(|&x| x as i128).sum();
            floor_div(s, kept.len() as i128)
        })
        .collect::<Option<Vec<i64>>>()
        .ok_or(AggError::ArithmeticOverflow)
}

/// Coordinate-wise median-trim: per coordinate keep the `theta - 2f` values closest
/// to that coordinate's median, then floor-average them. This is what a plain mean
/// lacks -- it discards coordinate-concentrated outliers that a distance-based rule
/// admits, because a vector can sit inside the honest Euclidean spread while putting
/// its whole budget on one axis.
///
/// The median of an even-sized column is the UPPER middle element (`col[n/2]`),
/// matching the reference. Closeness ties break by value, so the kept set is a
/// function of the multiset alone.
pub fn coord_median_trim(cs: &[Contribution], f: usize) -> Result<Vec<i64>, AggError> {
    let d = check(cs)?;
    let theta = cs.len();
    // `2 * f` wrapped for large `f`, turning a saturating subtraction into an arbitrary
    // one. `saturating_mul` makes the whole expression monotone in `f` at every width.
    let keep = (theta.saturating_sub(f.saturating_mul(2))).max(1);
    (0..d)
        .map(|k| {
            let mut col: Vec<i64> = cs.iter().map(|c| c.v[k]).collect();
            col.sort_unstable();
            let med = col[theta / 2];
            let mut by_close = col.clone();
            by_close.sort_unstable_by_key(|&x| ((x as i128 - med as i128).abs(), x as i128));
            let kept = &by_close[..keep.min(by_close.len())];
            let s: i128 = kept.iter().map(|&x| x as i128).sum();
            floor_div(s, kept.len() as i128)
        })
        .collect::<Option<Vec<i64>>>()
        .ok_or(AggError::ArithmeticOverflow)
}

/// A scored contribution: (score, tie_key, index), ordered lexicographically so the
/// outcome depends on the contribution set and not on arrival order.
type Scored<'a> = (i128, &'a [u8], usize);

/// Krum scores, shared by `multi_krum` and `bulyan_select`.
///
/// EXTRACTED BECAUSE IT WAS DUPLICATED BYTE-FOR-BYTE. This block previously appeared twice,
/// once in each selection path. Both copies summed into an unguarded `i128`, so a hand
/// patch to one of them produced a guard covering Krum and not Bulyan -- with every test
/// still green, because no test exercised the second copy at the overflowing magnitude.
/// A false green is worse than no fix, so the duplicate is removed rather than patched
/// twice: there is now one place for this arithmetic to be wrong.
///
/// `checked_add` is DEFENCE IN DEPTH, not the fix. `check()` bounds raw values so the sum
/// cannot reach `i128::MAX`; this makes the guarantee independent of whether the crate that
/// compiles us has `overflow-checks` on, which is a downstream caller's choice and not ours.
fn krum_scores<'a>(
    cs: &'a [Contribution],
    n: usize,
    m: usize,
) -> Result<Vec<Scored<'a>>, AggError> {
    Ok(krum_scores_inner::<false>(cs, n, m)?.0)
}

/// Scoring, optionally also tracking the largest pairwise L1 distance for Lemma 12.
///
/// `TRACK_L1` is a CONST generic, not a runtime flag, so the plain selection path
/// monomorphises to exactly the code it had before this function existed: no branch in the
/// inner loop, no extra traversal, no measurable cost to `multi_krum`. The certified path
/// pays one extra `abs` and `checked_add` per coordinate and nothing else -- it reuses the
/// same single pass rather than walking every pair a second time.
///
/// Returning the L1 max from HERE rather than recomputing it is what keeps the certificate
/// inside the work bound already checked by the caller: no new asymptotics, same O(n^2 * d).
fn krum_scores_inner<'a, const TRACK_L1: bool>(
    cs: &'a [Contribution],
    n: usize,
    m: usize,
) -> Result<(Vec<Scored<'a>>, i128), AggError> {
    let mut scored: Vec<Scored<'a>> = Vec::with_capacity(n);
    // rust-02. ONE ROW AT A TIME, NEVER THE WHOLE MATRIX.
    //
    // This used to be handed a materialised `n x n` of `i128`: at MAX_CONTRIBUTIONS that
    // is 4096^2 * 16 bytes = 268 MB, reachable by anyone who can hand a verifier a
    // half-megabyte file. Measured on the shipped binary at n=4096, d=2: 258.6 MB max RSS
    // before, 1.8 MB after -- and FLAT in n rather than quadratic (1.1 MB at n=1000).
    //
    // Scoring never needed the matrix. It reads one row at a time and keeps only the `m`
    // smallest of it, so the row is computed here and discarded. The buffer is reused
    // across rows, so this is one allocation of `n` rather than `n` allocations of `n`.
    //
    // IT IS ALSO FASTER, WHICH I DID NOT EXPECT AND SHOULD NOT BE READ AS FREE. It
    // recomputes each pair twice -- `sq_dist(i,j)` and `sq_dist(j,i)` -- where the matrix
    // computed each once, so it does 2x the distance work. Measured n=4096: 1.19s before,
    // 0.63s after. Allocating and scattering 16.7M `i128` writes across 4096 separate
    // `Vec`s cost more than recomputing a cheap distance in cache. The asymptotics are
    // unchanged, O(n^2 * d) either way; only the constant and the memory moved.
    let mut ds: Vec<i128> = Vec::with_capacity(n);
    let mut l1_max: i128 = 0;
    for i in 0..n {
        ds.clear();
        for j in 0..n {
            if j != i {
                if TRACK_L1 {
                    let (sq, l1) = crate::fixed::sq_and_l1(&cs[i].v, &cs[j].v)
                        .ok_or(AggError::ArithmeticOverflow)?;
                    if l1 > l1_max {
                        l1_max = l1;
                    }
                    ds.push(sq);
                } else {
                    ds.push(sq_dist(&cs[i].v, &cs[j].v).ok_or(AggError::ArithmeticOverflow)?);
                }
            }
        }
        ds.sort_unstable();
        let mut score: i128 = 0;
        for &x in &ds[..m.min(ds.len())] {
            score = score.checked_add(x).ok_or(AggError::ArithmeticOverflow)?;
        }
        scored.push((score, cs[i].tie_key.as_slice(), i));
    }
    scored.sort_unstable();
    Ok((scored, l1_max))
}

/// Multi-Krum selection. Score of i is the sum of the `m = n-f-2` smallest squared
/// distances from i to the others; the `m` lowest-scoring indices are selected.
///
/// Returns indices into `cs`, sorted ascending, so the result is a canonical set
/// rather than a ranked list -- a ranking would leak the comparison order into
/// anything that consumed it positionally.
///
/// Distances are compared in exact raw units (i128, never rescaled), because a
/// rounded distance can reorder two near-tied scores, and that reordering is the
/// selection flip the quantisation-margin argument exists to bound.
///
/// If `m < 1` the rule is undefined and every contribution is selected -- the
/// documented select-all convention. It fires exactly when `n <= f + 2`, i.e. when
/// there are too few contributions to defend, and the caller is expected to have
/// checked `n >= 2f + 3` before relying on any robustness claim.
pub fn multi_krum(cs: &[Contribution], f: usize) -> Result<Vec<usize>, AggError> {
    let d = check(cs)?;
    let n = cs.len();
    // `u128`: `f` comes from an untrusted directive, and `f + 3` in `usize` WRAPPED for
    // large `f`, so the select-all convention silently failed to fire. As a dependency
    // built in release this returned six of seven indices with no error; in a build with
    // overflow-checks it aborted with exit 101. Neither is the documented behaviour.
    if (n as u128) < f as u128 + 3 {
        return Ok((0..n).collect());
    }
    // Safe: the guard above establishes `n >= f + 3`, so this cannot underflow.
    let m = n - f - 2;

    // Refuse before allocating: the matrix is the amplification, so the check has to
    // precede it rather than follow it.
    if n > MAX_CONTRIBUTIONS {
        return Err(AggError::TooManyContributions {
            n,
            max: MAX_CONTRIBUTIONS,
        });
    }
    // rust-02/rust-03: the participant cap above bounds `n` and NOTHING bounds `d`, so it
    // does not bound the product that is actually paid for. Refused before any of it is done.
    let work = krum_work(n, d);
    if work > MAX_COORDINATE_OPS {
        return Err(AggError::TooMuchWork {
            work,
            max: MAX_COORDINATE_OPS,
        });
    }

    // (score, tie_key, index) ordered lexicographically, exactly as the reference.
    // tie_key precedes index so the outcome depends on the contribution set and not
    // on the order it happened to arrive in.
    let scored = krum_scores(cs, n, m)?;

    let mut out: Vec<usize> = scored[..m].iter().map(|&(_, _, i)| i).collect();
    out.sort_unstable();
    Ok(out)
}

/// Multi-Krum select, then floor-average the selected. The composed rule.
pub fn krum_aggregate(cs: &[Contribution], f: usize) -> Result<Vec<i64>, AggError> {
    let sel = multi_krum(cs, f)?;
    let picked: Vec<Contribution> = sel.iter().map(|&i| cs[i].clone()).collect();
    mean(&picked)
}

/// A checkable certificate that the fixed-point selection equals the real-valued one.
///
/// **This is Lemma 12 of the paper (quantisation margin, a checkable no-flip condition),
/// in its observable form -- the form a replica can evaluate on the quantised values it
/// actually holds, without access to the real-valued originals.**
///
/// WHY IT EXISTS, AND WHAT IT ADDS OVER DETERMINISM. Byte-identity says every replica
/// computes the SAME selection. It says nothing about whether that selection is the one
/// the un-quantised gradients would have produced. By Lemma 3(b) multi-Krum is
/// discontinuous: arbitrarily near a score tie, a bounded perturbation flips the selection
/// by Theta(1), and Q16.16 rounding IS such a perturbation. So determinism alone leaves
/// open the question a reviewer actually asks -- "did discretising the inputs change who
/// was selected?" This certificate answers it per round, and answers it soundly.
///
/// THE ARITHMETIC IS EXACT AND INTEGER. In raw Q16.16 units the grid step is `delta = 1`,
/// so the lemma's `Delta* = 2*delta*L1max + 3*d*delta^2` becomes exactly
/// `2*l1_max + 3*d` in raw units, and scores are already raw `i128`. There is no float
/// anywhere in the certificate and no scaling step: it is the same kind of exact integer
/// comparison as the selection itself, so two replicas that agree on the selection agree
/// on the certificate, bit for bit.
///
/// SOUND, NOT COMPLETE, AND DELIBERATELY SO. The observable threshold is `4*beta` rather
/// than the real-value `2*beta`, because a replica measures `g_hat` on quantised data and
/// `|g - g_hat| <= 2*beta`. It can therefore DECLINE to certify a configuration that is in
/// fact stable -- but it can never certify one that is not. An adversary who inflates a
/// contribution enlarges `l1_max`, and so enlarges `beta`, and so makes certification
/// HARDER: the failure mode of a hostile input is a withheld certificate, never a false one.
///
/// WHAT IT DOES NOT COVER. It certifies the SELECTION, not robustness: a certified round
/// whose admitted population is below the rule's bound is still undefended, which is why
/// `population_bound_met` is reported separately and neither implies the other. It says
/// nothing about the `<= delta/2` per-coordinate value quantisation of the selected vectors
/// themselves, nor the one unit of floor rounding in the fixed-point mean. And by Remark 13
/// there is an irreducible exact-tie residual (`g -> 0`) that NO margin condition can cover;
/// those rounds are reported `certified: false`, which is the honest answer, not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarginCertificate {
    /// The observable boundary margin `g_hat = s_(m+1) - s_(m)`: the exact raw gap between
    /// the last SELECTED score and the first REJECTED one. Zero means an exact tie.
    pub margin: i128,
    /// `beta_hat = (n - f - 2) * delta_star`: the most any single score can move under
    /// per-coordinate quantisation error.
    pub beta: i128,
    /// `4 * beta_hat` -- the value `margin` must exceed. Stored so a reader never has to
    /// reproduce the factor, and so a change to it is visible in any recorded certificate.
    pub threshold: i128,
    /// `delta_star = 2*l1_max + 3*d` in raw units: the per-squared-distance perturbation bound.
    pub delta_star: i128,
    /// The largest pairwise L1 distance in the scored set, raw units. Adversary-influenceable
    /// upward only, which is why inflating it can deny a certificate but not forge one.
    pub l1_max: i128,
    /// Krum's nearest-neighbour count `n - f - 2`, the number of squared distances summed
    /// into each score -- the multiplier in `beta`.
    pub nn_count: usize,
    /// Dimension of the contributions.
    pub d: usize,
    /// **The verdict.** `margin > threshold`: the quantised selection provably equals the
    /// real-valued selection. False means "not certified", which spans both a genuine
    /// near-tie and a merely conservative decline -- it is never evidence of a flip.
    pub certified: bool,
}

/// Multi-Krum selection together with its Lemma 12 no-flip certificate.
///
/// Returns the SAME selection `multi_krum` returns -- this is an additive observable, not a
/// different rule, and a test asserts the two agree. `None` for the certificate means the
/// select-all band (`n < f + 3`) fired: nothing is excluded, so no selection boundary exists
/// and the no-flip question is vacuous. That band is undefended for the reasons documented on
/// `multi_krum`, and a vacuous certificate must not be read as a safety claim.
///
/// COST: one pass, the same `O(n^2 * d)` the selection already pays, plus an `abs` and an
/// add per coordinate. The work bound is checked before any of it, exactly as in `multi_krum`.
pub fn multi_krum_certified(
    cs: &[Contribution],
    f: usize,
) -> Result<(Vec<usize>, Option<MarginCertificate>), AggError> {
    let d = check(cs)?;
    let n = cs.len();
    if (n as u128) < f as u128 + 3 {
        // Select-all: no boundary, so no certificate. See the doc above.
        return Ok(((0..n).collect(), None));
    }
    let m = n - f - 2;

    if n > MAX_CONTRIBUTIONS {
        return Err(AggError::TooManyContributions {
            n,
            max: MAX_CONTRIBUTIONS,
        });
    }
    let work = krum_work(n, d);
    if work > MAX_COORDINATE_OPS {
        return Err(AggError::TooMuchWork {
            work,
            max: MAX_COORDINATE_OPS,
        });
    }

    let (scored, l1_max) = krum_scores_inner::<true>(cs, n, m)?;

    // Lemma 12 in raw Q16.16 units, where the grid step delta is exactly 1:
    //   delta_star = 2*delta*L1max + 3*d*delta^2  ->  2*l1_max + 3*d
    //   beta       = (n - f - 2) * delta_star
    //   certified  <=> g_hat > 4*beta
    // Every term is i128 and checked: a certificate that overflowed into a wrong answer
    // would be worse than no certificate at all.
    let delta_star = (2i128)
        .checked_mul(l1_max)
        .and_then(|x| x.checked_add(3i128.checked_mul(d as i128)?))
        .ok_or(AggError::ArithmeticOverflow)?;
    let beta = (m as i128)
        .checked_mul(delta_star)
        .ok_or(AggError::ArithmeticOverflow)?;
    let threshold = 4i128
        .checked_mul(beta)
        .ok_or(AggError::ArithmeticOverflow)?;

    // `scored` is sorted ascending, so index m-1 is the m-th smallest (last selected) and
    // index m is the (m+1)-th (first rejected). `m >= 1` and `m <= n - 2` both follow from
    // `n >= f + 3`, so neither index can be out of range.
    let margin = scored[m]
        .0
        .checked_sub(scored[m - 1].0)
        .ok_or(AggError::ArithmeticOverflow)?;

    let mut out: Vec<usize> = scored[..m].iter().map(|&(_, _, i)| i).collect();
    out.sort_unstable();

    Ok((
        out,
        Some(MarginCertificate {
            margin,
            beta,
            threshold,
            delta_star,
            l1_max,
            nn_count: m,
            d,
            certified: margin > threshold,
        }),
    ))
}

/// Multi-Krum selection **in score order**, best first.
///
/// `multi_krum` deliberately returns a canonical ascending SET, because a ranking
/// leaks the comparison order into anything that consumes it positionally. Bulyan,
/// however, genuinely needs the ranking: its first stage repeatedly takes Krum's
/// single best candidate and removes it from the pool. Taking `multi_krum(..)[0]`
/// there would select the lowest INDEX rather than the best score -- a silent and
/// entirely plausible mis-port.
///
/// So the ranked form is exposed separately and named for what it is. Ties break on
/// `tie_key` then index, identically to `multi_krum`, so the ranking is still a
/// function of the contribution set and not of arrival order.
pub fn multi_krum_ranked(cs: &[Contribution], f: usize) -> Result<Vec<usize>, AggError> {
    let d = check(cs)?;
    let n = cs.len();
    // The small-pool case must still come back in SCORE order. `multi_krum` may
    // return `0..n` there because its contract is an unordered canonical set, but
    // this function's contract is the ranking, and handing back index order under a
    // name that promises score order is the very mis-port the split exists to
    // prevent. Bulyan drives the pool down into exactly this regime.
    // `u128` for the same reason as `multi_krum`: `f` is untrusted and `f + 3` in `usize`
    // wraps. I fixed the sibling in num-03 and MISSED THIS ONE, in the same file, in the
    // same commit that documents the hazard -- found later by grepping the whole tree for
    // arithmetic on `f` instead of trusting that the class was closed.
    //
    // NO TEST FAILS ON THE UNFIXED FORM HERE, and that is a claim rather than an excuse.
    // The wrapped branch computes `m = (n - f - 2) mod 2^64`, and for every `f` whose
    // wrap lets the comparison through, that value is provably `>= n - 1 == ds.len()`
    // (checked exhaustively over the reachable range). `krum_scores` slices
    // `&ds[..m.min(ds.len())]`, so an oversized `m` is always clamped and the ranking is
    // unchanged -- verified: `f = usize::MAX - 2` and `f = 100` return the identical
    // ranking. So this is corrected for consistency, not because a hole was open.
    //
    // It is worth correcting anyway: unfixed, this function's safety rests on a clamp in
    // a DIFFERENT function that is not documented as load-bearing, which is exactly the
    // two-guards-and-neither-names-the-other shape found in `crypto-03`.
    let m = if (n as u128) >= f as u128 + 3 {
        n - f - 2
    } else {
        n.saturating_sub(1).max(1)
    };

    // Refuse before allocating: the matrix is the amplification, so the check has to
    // precede it rather than follow it.
    if n > MAX_CONTRIBUTIONS {
        return Err(AggError::TooManyContributions {
            n,
            max: MAX_CONTRIBUTIONS,
        });
    }
    // rust-02/rust-03: the participant cap above bounds `n` and NOTHING bounds `d`, so it
    // does not bound the product that is actually paid for. Refused before any of it is done.
    let work = krum_work(n, d);
    if work > MAX_COORDINATE_OPS {
        return Err(AggError::TooMuchWork {
            work,
            max: MAX_COORDINATE_OPS,
        });
    }
    let scored = krum_scores(cs, n, m)?;
    Ok(scored.into_iter().map(|(_, _, i)| i).collect())
}

/// Bulyan stage 1 (El Mhamdi et al. 2018): iteratively take Krum's single best
/// candidate and remove it from the pool, until `theta = n - 2f` are selected.
///
/// Krum's robustness is Euclidean, so it admits an attacker who stays close in overall
/// distance while pushing hard on ONE coordinate. Bulyan answers that by pairing this
/// selection with a coordinate-wise second stage (`coord_median_trim`). The precondition
/// is `n >= 4f + 3`, stricter than Krum's `n >= 2f + 3`. Unlike the reference, which
/// documents the bound and then does not enforce it, this refuses below it.
///
/// Returns indices sorted ascending: a canonical set, because the second stage consumes
/// it as a set and must not depend on selection order.
///
/// # DELIBERATE DIVERGENCE FROM THE PUBLISHED REFERENCE -- read before "fixing" this
///
/// The reference `bulyan_select` (arXiv:2607.10305 kernel, `reference/acfa.py` l.205) loops on
/// `while len(selected) < theta and len(pool) >= f + 3`. That second condition fires
/// before `theta` candidates have been drawn whenever `f < 2`, so the reference
/// returns FEWER than `theta` with no error. Measured against the reference directly:
///
/// ```text
///   n=7  f=0  theta=7   reference selected 5   short 2
///   n=7  f=1  theta=5   reference selected 4   short 1
///   n=23 f=0  theta=23  reference selected 21  short 2
///   n=23 f=1  theta=21  reference selected 20  short 1
///   f >= 2: reference agrees with theta at every n tested
/// ```
///
/// The shortfall is independent of `n` and sits INSIDE Bulyan's own precondition
/// (`f = 0` is valid for any `n >= 3`), so it is not a degenerate-input guard doing
/// its job -- it is a short selection, which is a quietly different estimator.
///
/// This implementation draws exactly `theta`. It therefore DISAGREES with the
/// reference at `f in {0, 1}`, and that disagreement is intentional and pinned by
/// `bulyan_draws_exactly_theta_and_never_silently_short`. It is called out here
/// because everywhere else in this crate a disagreement with the reference is a bug
/// in this crate -- this is the one place it is not, and a future reader who "restores
/// parity" would be reintroducing the defect.
pub fn bulyan_select(cs: &[Contribution], f: usize) -> Result<Vec<usize>, AggError> {
    let d = check(cs)?;
    // Bulyan gets its OWN, lower cap: it drives the quadratic selection `theta` times, so
    // the cost is cubic and the per-call guard inside `multi_krum_ranked` would let a
    // caller buy `n` of them. One wire byte chooses this rule, so the bound has to be here.
    if cs.len() > MAX_CONTRIBUTIONS_BULYAN {
        return Err(AggError::TooManyContributions {
            n: cs.len(),
            max: MAX_CONTRIBUTIONS_BULYAN,
        });
    }

    // The cubic in the unit that varies. The cap above bounds `n`; `d` is bounded by
    // nothing, and the doc on MAX_CONTRIBUTIONS_BULYAN names `O(n^3 * d)` while capping
    // only the first term. Measured at n=512: d=64 is 12.29 s and d=1024 is 255 s, both
    // accepted. Refused before any of the work.
    let work = bulyan_work(cs.len(), d);
    if work > MAX_COORDINATE_OPS {
        return Err(AggError::TooMuchWork {
            work,
            max: MAX_COORDINATE_OPS,
        });
    }
    let n = cs.len();
    // Refuse below Bulyan's precondition rather than returning a plausible aggregate
    // with no guarantee behind it.
    // `u128`, because this is the guard with the worst failure mode. `4 * f` in `usize`
    // wraps to 0 at f = 2^62, so the comparison became `n < 3` and Bulyan ran with its
    // precondition bypassed, returning a full-population selection carrying no Byzantine
    // guarantee at all -- the exact outcome this refusal exists to prevent.
    if (n as u128) < 4 * f as u128 + 3 {
        return Err(AggError::BulyanTooFewContributions);
    }
    // Safe: `n >= 4f + 3 > 2f` from the guard above.
    let theta = n - 2 * f;

    // rust-03, HALF TWO. `theta == n` EXACTLY WHEN `f == 0`, and stage 1 then drains the
    // whole pool: `selected` ends up holding every index, and the function sorts before
    // returning, so THE ANSWER IS `(0..n)` NO MATTER WHAT THE SCORES SAY. The loop below
    // would spend the full `O(n^3 * d)` computing a result that is determined before it
    // starts. Measured at n=400: 5.11 s of work for an answer known in advance.
    //
    // Skipping is behaviour-preserving rather than a shortcut with a caveat: the loop has
    // no reachable error path here -- `check` has already bounded every value, the pool is
    // never empty, and every sub-call is smaller than the bulyan work bound already
    // cleared above -- so it cannot turn an `Err` into an `Ok`.
    if theta >= n {
        return Ok((0..n).collect());
    }

    let mut pool: Vec<usize> = (0..n).collect();
    // rust-03, HALF ONE. `sub` used to be REBUILT BY CLONING THE WHOLE POOL on every
    // iteration -- `theta` clones of up to `n` contributions of `d` coordinates each, so
    // `O(theta * n * d)` of pure copying on top of the cubic. At n=512, d=1024 that is
    // about 4 MB copied per iteration across ~510 iterations. Clone ONCE and shrink it in
    // lockstep with `pool` instead: same indices removed, same order, one copy total.
    let mut sub: Vec<Contribution> = cs.to_vec();
    let mut selected: Vec<usize> = Vec::new();

    // No `pool.len() >= f + 3` guard here. That guard existed because
    // `multi_krum_ranked` used to degenerate to index order on a small pool; it now
    // ranks by score at every size. With the guard in place this loop exited EARLY
    // for f < 2 and returned FEWER than theta candidates with no error at all --
    // measured shortfall of 2 at f=0 and 1 at f=1, at every n tested.
    while selected.len() < theta {
        let best_local = multi_krum_ranked(&sub, f)?[0];
        selected.push(pool.remove(best_local));
        sub.remove(best_local);
    }
    debug_assert_eq!(
        selected.len(),
        theta,
        "bulyan stage 1 must draw exactly theta"
    );
    selected.sort_unstable();
    Ok(selected)
}

/// Bulyan: stage-1 selection, then the coordinate-wise trimmed stage.
pub fn bulyan_aggregate(cs: &[Contribution], f: usize) -> Result<Vec<i64>, AggError> {
    let sel = bulyan_select(cs, f)?;
    let picked: Vec<Contribution> = sel.iter().map(|&i| cs[i].clone()).collect();
    coord_median_trim(&picked, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Relocated from `tests/determinism.rs`, which reached this helper through the
    /// crate's PUBLIC surface -- the very reachability that made the defects below
    /// exploitable. An integration test is an external consumer; keeping the assertions
    /// here is what lets the helper be `pub(crate)`. The rule-level half of that test
    /// stays where it was, because it goes through the public API on purpose.
    #[test]
    fn floors_toward_negative_infinity_rather_than_truncating_toward_zero() {
        // The regression this crate is most likely to suffer from a well-meaning port.
        assert_eq!(
            floor_div(-7, 2),
            Some(-4),
            "must floor, not truncate toward zero"
        );
        assert_eq!(floor_div(7, 2), Some(3));
        assert_eq!(floor_div(-1, 2), Some(-1));
        assert_eq!(floor_div(-8, 2), Some(-4));
    }

    /// rust-11, first of three. `debug_assert!(denom > 0)` is COMPILED OUT of a release
    /// build, so this was not a guard on any path a dependent crate could take. Measured
    /// in release from a consumer crate before the fix: `floor_div(-7, -2)` returned 4,
    /// where the floor is 3, and `floor_div(1, 0)` panicked with "attempt to divide by
    /// zero". `div_euclid` floors only for a POSITIVE divisor -- Euclidean division
    /// forces a non-negative remainder -- so the doc comment's flat claim was false on
    /// all four negative-denominator sign combinations, not merely unenforced.
    #[test]
    fn refuses_a_denominator_it_cannot_floor_by() {
        assert_eq!(floor_div(1, 0), None, "no quotient exists");
        assert_eq!(floor_div(0, 0), None);
        // Each of these returned a wrong number before the fix, not an error.
        assert_eq!(floor_div(-7, -2), None, "returned 4; the floor is 3");
        assert_eq!(floor_div(-1, -2), None, "returned 1; the floor is 0");
        assert_eq!(floor_div(7, -2), None, "returned -3; the floor is -4");
        assert_eq!(floor_div(1, -2), None, "returned 0; the floor is -1");
    }

    /// rust-11, second. The old body ended `q as i64`, an unchecked narrowing cast on a
    /// value the signature invites to be as wide as `i128`. Measured in release before
    /// the fix: `floor_div(i128::MAX, 1)` returned **-1**, and `i64::MAX as i128 + 1`
    /// returned `i64::MIN`. Wrapping to a NEGATIVE aggregate coordinate is the same shape
    /// of defect as the negative squared distance in `fixed::sq_dist`: not a large error,
    /// a sign error, and one that goes on the wire looking ordinary.
    #[test]
    fn refuses_a_quotient_that_does_not_fit_the_return_type() {
        assert_eq!(floor_div(i128::MAX, 1), None, "returned -1 before the fix");
        assert_eq!(floor_div(i128::MIN, 1), None);
        assert_eq!(
            floor_div(i64::MAX as i128 + 1, 1),
            None,
            "returned i64::MIN before the fix"
        );
        assert_eq!(floor_div(i64::MIN as i128 - 1, 1), None);
    }

    /// GUARD THE GUARD, in the other direction. Every assertion above is satisfied
    /// perfectly by a function that refuses unconditionally, so refusal tests alone
    /// cannot distinguish this fix from a broken one. These pin the accepting side,
    /// including both exact edges of the representable quotient.
    #[test]
    fn accepts_and_is_exact_across_the_whole_domain_it_claims() {
        assert_eq!(
            floor_div(i64::MAX as i128, 1),
            Some(i64::MAX),
            "upper edge must PASS"
        );
        assert_eq!(
            floor_div(i64::MIN as i128, 1),
            Some(i64::MIN),
            "lower edge must PASS"
        );
        // A quotient that fits even though the numerator does not.
        assert_eq!(floor_div(i128::MAX, i128::MAX), Some(1));

        // Exhaustive agreement with the floor, computed independently, over both signs
        // of the numerator and a range of positive denominators.
        let mut checked = 0u32;
        for numer in -400i128..=400 {
            for denom in 1i128..=40 {
                let mut expect = numer / denom;
                if numer % denom != 0 && numer < 0 {
                    expect -= 1;
                }
                assert_eq!(
                    floor_div(numer, denom),
                    Some(expect as i64),
                    "floor_div({numer}, {denom})"
                );
                checked += 1;
            }
        }
        assert!(
            checked > 30_000,
            "scan too small to be meaningful ({checked})"
        );
    }

    /// num-03. `f` arrives from an untrusted directive on stdin, and every guard that
    /// bounds it did unchecked `usize` arithmetic, so a large `f` WRAPPED the guard
    /// instead of tripping it. Measured before the fix, all with n=7:
    ///
    /// - `f = usize::MAX`: `f + 3` wraps to 2, so `n < f + 3` is false and the select-all
    ///   convention never fires. As a dependency built in release (overflow-checks off,
    ///   which is the default a consumer gets) `multi_krum` returned `Ok` with SIX of
    ///   seven indices -- a silent, plausible, wrong selection.
    /// - `f = usize::MAX - 2`: `f + 3` wraps to 0, and `m = n - f - 2` then indexed a
    ///   slice out of bounds: "range end index 8 out of range for slice of length 7".
    /// - `f = 2^63`: `4 * f` wraps to 0, so `n < 4 * f + 3` compares against 3 and
    ///   `bulyan_select` returned `Ok` with all seven -- its precondition bypassed
    ///   entirely. `BulyanTooFewContributions` exists precisely so the rule never
    ///   returns a plausible aggregate with no Byzantine guarantee behind it.
    ///
    /// Through the shipped binary, where this crate's own `overflow-checks = true`
    /// applies, the same inputs abort with exit 101 -- outside the documented 0/1/2
    /// contract. Both regimes are wrong; only one is loud.
    ///
    /// The guards are now evaluated in `u128`, which cannot overflow at any target
    /// width, so each returns the answer the arithmetic actually implies.
    #[test]
    fn a_huge_f_trips_the_guards_rather_than_wrapping_them() {
        let cs: Vec<Contribution> = (0..7u8)
            .map(|i| Contribution {
                tie_key: vec![i],
                v: vec![1, 2, 3, 4],
            })
            .collect();

        // n < f + 3 holds for every f this large, so the select-all convention fires.
        // Written width-independently ON PURPOSE, and the first draft was not: it used
        // `1usize << 62`, which does not even COMPILE on a 32-bit target. A test for
        // width independence that is itself width-dependent is worth nothing, and the
        // 32-bit CI leg is what caught it. `usize::MAX / 4 + 1` is 2^(BITS-2) at every
        // width, which is exactly the value where `4 * f` wraps to zero.
        for f in [
            usize::MAX,
            usize::MAX - 2,
            usize::MAX / 2 + 1,
            usize::MAX / 4 + 1,
        ] {
            assert_eq!(
                multi_krum(&cs, f).map(|s| s.len()),
                Ok(7),
                "multi_krum must select all when it cannot defend (f={f})"
            );
            assert!(
                coord_median_trim(&cs, f).is_ok(),
                "coord_median_trim must not wrap (f={f})"
            );
            // n = 7 is far below 4f + 3 for any of these, so Bulyan must refuse.
            assert_eq!(
                bulyan_select(&cs, f),
                Err(AggError::BulyanTooFewContributions),
                "bulyan must refuse rather than bypass its precondition (f={f})"
            );
        }
    }

    /// num-03, fifth site. `multi_krum_ranked` kept `n >= f + 3` in raw `usize` after the
    /// sibling twelve lines above was hardened.
    ///
    /// FAILS ON THE UNFIXED CODE, and my first account of this was WRONG. I measured only
    /// from a consumer crate -- release, overflow-checks OFF, which is a dependent's
    /// default -- saw the ranking unchanged because `krum_scores` clamps with
    /// `m.min(ds.len())`, and published "no test fails on the unfixed form". In THIS
    /// crate's own profile, where `overflow-checks = true`, the unfixed form does not
    /// return a clamped answer at all: it PANICS, "attempt to add with overflow".
    ///
    /// That is the same two-regime split already documented for `fixed::sq_dist` and in
    /// the num-03 commit -- checks ON for builds rooted here, OFF for dependents -- and I
    /// generalised from one regime after writing down that there were two. Both halves
    /// are real: a dependent gets a silently oversized `m` that the clamp happens to
    /// absorb, and anything built here aborts.
    #[test]
    fn ranked_does_not_wrap_its_pool_guard_on_a_huge_f() {
        let cs: Vec<Contribution> = (0..7u8)
            .map(|i| Contribution {
                tie_key: vec![i],
                v: vec![(i as i64) * (i as i64), 13 - i as i64, 3, 4],
            })
            .collect();
        // Every `f` here is far above `n`, so the small-pool branch is the correct one
        // and all three must agree. Unfixed, the last two panic before returning.
        let small = multi_krum_ranked(&cs, 5).expect("f=5");
        for f in [100usize, usize::MAX - 2, usize::MAX] {
            assert_eq!(
                multi_krum_ranked(&cs, f).as_deref(),
                Ok(small.as_slice()),
                "ranking must not depend on `f` wrapping (f={f})"
            );
        }
    }

    /// rust-10. Every refusal must be PRINTABLE, DISTINCT, and CARRY ITS VALUES.
    ///
    /// "It compiles" is not much of a proof for a `Display` impl, so this pins the three
    /// properties that actually rot: a variant added later with no arm (caught by the
    /// exhaustive match in the impl itself), two variants copy-pasted to the same message,
    /// and a value-carrying variant whose message drops the values. The last is the one that
    /// matters in a log: `TooManyContributions` alone tells an operator nothing, and
    /// "4097 contributions exceeds the limit of 4096" tells them what to change.
    #[test]
    fn every_refusal_is_printable_distinct_and_carries_its_values() {
        let all = [
            AggError::Empty,
            AggError::DimensionMismatch {
                offender: 6,
                expected: 4,
                got: 2,
            },
            AggError::DimensionMismatchUnattributable { lengths: 2 },
            AggError::EmptyVectors,
            AggError::DuplicateTieKey,
            AggError::BulyanTooFewContributions,
            AggError::ValueOutOfRange {
                offender: 0,
                coord: 0,
                value: i64::MAX,
            },
            AggError::ArithmeticOverflow,
            AggError::BetaDenominatorZero,
            AggError::TooManyContributions { n: 4097, max: 4096 },
        ];
        let msgs: Vec<String> = all.iter().map(|e| e.to_string()).collect();

        for (e, m) in all.iter().zip(&msgs) {
            assert!(!m.is_empty(), "{e:?} has an empty message");
            assert!(
                m.len() > 15,
                "{e:?} message is too short to be useful: {m:?}"
            );
        }

        // Distinct, so a copy-pasted arm cannot hide.
        let mut sorted = msgs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            msgs.len(),
            "two refusals share a message; a caller cannot tell them apart"
        );

        // The value-carrying variant must actually carry them.
        let m = AggError::TooManyContributions { n: 4097, max: 4096 }.to_string();
        assert!(
            m.contains("4097") && m.contains("4096"),
            "values dropped: {m:?}"
        );

        // And the range refusal names the range rather than asserting one exists.
        let r = AggError::ValueOutOfRange {
            offender: 3,
            coord: 1,
            value: 1i64 << 31,
        }
        .to_string();
        assert!(
            r.contains(&crate::fixed::MAX.to_string()),
            "range refusal should name the bound: {r:?}"
        );
    }

    /// The `Error` impl, proven by USE rather than by existence: a refusal must travel
    /// through `?` into a boxed trait object, which is what a caller with `anyhow` or a
    /// `Box<dyn Error>` signature actually does. Without the impl this does not compile.
    #[test]
    fn a_refusal_propagates_through_the_std_error_trait() {
        fn caller() -> Result<Vec<i64>, Box<dyn std::error::Error>> {
            let empty: Vec<Contribution> = Vec::new();
            Ok(mean(&empty)?)
        }
        let e = caller().expect_err("empty set must refuse");
        assert_eq!(e.to_string(), AggError::Empty.to_string());
        assert!(e.source().is_none(), "leaf error should report no source");
    }

    /// THE `.max(1)` FLOOR IN `coord_median_trim`, WHICH NOTHING EXERCISED.
    ///
    /// `keep = (theta - 2f).max(1)`. The clamp only does anything when `theta <= 2f + 1`,
    /// and every existing test keeps at least three, so the floor was dead. Found by
    /// mutation rather than by reading: changing `.max(1)` to `.max(2)` SURVIVES THE
    /// ENTIRE SUITE.
    ///
    /// It matters because at `theta == 2f` the rule keeps exactly ONE value -- the
    /// coordinate median -- and that is the strongest form of the rule, not a degenerate
    /// case to be rounded up. Keeping two instead averages the median with its nearest
    /// neighbour and moves the result.
    #[test]
    fn median_trim_keeps_exactly_the_median_when_theta_equals_two_f() {
        let cs: Vec<Contribution> = [10i64, 20, 30, 40, 5000]
            .iter()
            .enumerate()
            .map(|(i, &v)| Contribution {
                tie_key: vec![i as u8],
                v: vec![v],
            })
            .collect();

        // n = 5, f = 2 -> theta - 2f = 1, so the floor is what supplies `keep`.
        assert_eq!(
            (5usize).saturating_sub(2 * 2).max(1),
            1,
            "precondition: this n and f must drive keep to the floor"
        );

        // Sorted column is [10, 20, 30, 40, 5000]; the median is col[5/2] = 30. Keeping
        // exactly one leaves the median alone. Keeping two would average 30 with its
        // nearest neighbour 20 and floor to 25, which is what the `.max(2)` mutant does.
        assert_eq!(
            coord_median_trim(&cs, 2),
            Ok(vec![30]),
            "at theta == 2f the rule must keep exactly the median, not widen to two"
        );
    }

    /// THE OTHER SILENT NO-TRIM REGION, AND MY OWN COVERAGE MISSED IT.
    ///
    /// `trimmed_mean` declines to trim in TWO disjoint regions, not one. The sibling test
    /// below covers `n <= 2t`, at the LARGE-beta end. This one covers `t == 0`, at the
    /// SMALL-beta end, where `floor(n * num / den)` rounds down to zero and the rule trims
    /// nothing while taking the `n > 2t` branch normally.
    ///
    /// I documented the first region, pinned it, and wrote that the trim "would empty the
    /// column" -- true, and a description of only one of the two ways this rule silently
    /// does not trim. MEASURED: breaking the `t == 0` path outright, so it returns a single
    /// element, leaves ALL 56 TESTS PASSING. It was dead to the whole suite.
    ///
    /// WHY IT MATTERS MORE THAN THE OTHER ONE. In both regions the rule returns exactly the
    /// plain mean it exists to replace, so the Byzantine guarantee simply leaves, with no
    /// error, no warning and no metric. Measured downstream at n=7 with six honest values
    /// near 1.0 and ONE ADVERSARY AT 500.0: any trimming beta gives 1.01, and both no-trim
    /// regions give 72.29 -- the adversary passes through in full.
    ///
    /// SETTLED, AND THIS TEST IS NOW INVERTED. Its previous form pinned the silent plain
    /// mean and said in this comment that it did not endorse it: whether a rule that cannot
    /// honour its bound should refuse was an open specification question (adv-05, fl-10),
    /// left with a witness in BOTH regions "so whichever way it is decided, the change is
    /// visible rather than silent". The coordinator has ruled REFUSE -- returning the
    /// poisoned aggregate at exit 0 is the worst available failure mode. The witness did
    /// its job: the ruling landed as a visible inversion of two named tests rather than as
    /// a quiet edit, which is the whole reason a characterisation test is worth writing.
    #[test]
    fn a_trim_fraction_that_floors_to_zero_trims_nothing_and_says_nothing() {
        // n = 7, beta = 1/8 -> floor(7/8) = 0. The small-beta end.
        let vals = [1i64, 1, 1, 1, 1, 1, 500];
        let cs: Vec<Contribution> = vals
            .iter()
            .enumerate()
            .map(|(i, &v)| Contribution {
                tie_key: vec![i as u8],
                v: vec![v],
            })
            .collect();

        // Precondition, so a change to `t` cannot make this test quietly stop testing
        // the region it exists for.
        let (n, num, den) = (7usize, 1usize, 8usize);
        let t = (n * num) / den;
        assert_eq!(t, 0, "precondition: this beta must floor to a zero trim");

        // Was `Ok(vec![72])` -- the plain mean, outlier included, at exit 0. Now refused.
        assert_eq!(
            trimmed_mean(&cs, 1, 8),
            Err(AggError::BetaTrimsNothing { t: 0, n: 7 }),
            "t == 0 trims nothing, so it must refuse rather than return the plain mean"
        );

        // And a beta that does trim excludes it, which is the contrast that shows the
        // first result is the rule declining rather than the data being harmless.
        assert_eq!(
            trimmed_mean(&cs, 1, 4),
            Ok(vec![1]),
            "beta = 1/4 gives t = 1 and the outlier is trimmed away"
        );
    }

    /// THE UNTRIMMED BRANCH OF `trimmed_mean`, WHICH NOTHING EXERCISED.
    ///
    /// When `n <= 2t` the trim would empty the column, so the rule keeps the WHOLE column
    /// instead. Every call site in this crate and every one of the nine golden vectors uses
    /// beta of 1/4 or 1/5, and reaching this branch needs beta >= 1/2 -- so it was dead to
    /// the entire suite. MEASURED, not assumed: replacing `&col[..]` with `&col[..1]`, which
    /// makes the branch return a single element instead of the column, leaves ALL 51 TESTS
    /// PASSING at exit 0. A port could omit this branch entirely, or get it arbitrarily
    /// wrong, and be certified by everything we had.
    ///
    /// THIS TEST PINS THE BEHAVIOUR; IT DOES NOT ENDORSE IT. Returning the untrimmed mean
    /// means the result includes the outliers the caller asked to trim -- an open finding
    /// (adv-05) argues that a rule which cannot honour its bound should refuse rather than
    /// silently return a value the bound does not protect. That is a specification question
    /// and it is not settled here. What is settled is that the branch now has a witness, so
    /// whichever way it is decided the change is VISIBLE rather than silent.
    #[test]
    fn the_untrimmable_column_is_kept_whole_rather_than_emptied() {
        // n = 5, beta = 3/5 -> t = 3, and 2t = 6 > 5, so the trim would empty the column.
        let cs: Vec<Contribution> = [1i64, 2, 3, 4, 1000]
            .iter()
            .enumerate()
            .map(|(i, &v)| Contribution {
                tie_key: vec![i as u8],
                v: vec![v],
            })
            .collect();

        // Precondition, so a future change to `t` cannot make this test silently stop
        // testing the branch it exists for.
        let t = (5 * 3) / 5;
        assert!(
            5 <= 2 * t,
            "precondition: this beta must reach the untrimmed branch"
        );

        // Was `Ok(vec![202])` -- the whole column including the 1000, at exit 0. The
        // large-beta end of the same defect, and refused for the same reason.
        assert_eq!(
            trimmed_mean(&cs, 3, 5),
            Err(AggError::BetaTrimsNothing { t: 3, n: 5 }),
            "an untrimmable beta must refuse, not return the untrimmed mean"
        );

        // And the outlier is still in there, which is the substance of adv-05: the caller
        // asked to trim and got a mean the trim bound does not protect. Asserted against a
        // COMPUTED value rather than a literal -- `assert!(202 > 4)` compares two constants
        // and clippy is right that it can never fail, which is this repository's own
        // gates-that-cannot-fail defect appearing inside a test about coverage gaps.
        // The contrast that gives the refusal meaning: a beta that DOES trim excludes the
        // outlier, so the refusal above is not the rule simply failing on this fixture.
        let trimmed = trimmed_mean(&cs, 1, 5).expect("beta 1/5 trims at n=5");
        assert!(
            trimmed[0] < 100,
            "a trimming beta must exclude the 1000 (got {}) -- otherwise the refusal \
             above proves nothing about adv-05",
            trimmed[0]
        );
    }

    /// num-03, the target-width half, and the reason this is a determinism finding and
    /// not merely a robustness one. `beta_num / beta_den` here is exactly 1/4, written
    /// with large numerals -- an ordinary way to express a fraction, not an attack.
    ///
    /// `n * beta_num` was computed in `usize`. On a 64-bit target that is 2^32 and fine;
    /// on a 32-bit target it overflows, and this crate sets `overflow-checks = true` even
    /// in release, so it PANICS. Verified in CI's own `--platform linux/386
    /// rust:1-slim-bookworm` container, where `usize::BITS` is 32: before the fix this
    /// test panicked at `rules.rs:208` with "attempt to multiply with overflow" while
    /// passing on the host.
    ///
    /// HONEST LIMIT: this test does NOT fail on unfixed code on a 64-bit host. Its
    /// failing witness is the 32-bit CI leg, which is exactly the leg the byte-identity
    /// claim rests on -- identical inputs must not crash on one target and succeed on
    /// another.
    #[test]
    fn the_trim_fraction_does_not_depend_on_target_pointer_width() {
        let cs: Vec<Contribution> = (0..4096u32)
            .map(|i| Contribution {
                tie_key: i.to_be_bytes().to_vec(),
                v: vec![7],
            })
            .collect();
        assert_eq!(
            trimmed_mean(&cs, 1_048_576, 4_194_304),
            Ok(vec![7]),
            "beta = 1/4 written with large numerals must behave identically everywhere"
        );
        // The same fraction written small must give the same answer, on every target.
        assert_eq!(trimmed_mean(&cs, 1, 4), Ok(vec![7]));
    }

    /// The refusal must not be reachable through the rules themselves. `check` rejects
    /// the empty set and bounds every raw value, so the `None` arm the three call sites
    /// map to `ValueOutOfRange` is unreachable by construction -- this asserts that the
    /// mapping did not accidentally become live for ordinary input, which would mean the
    /// rules had started refusing work they used to do.
    #[test]
    fn the_new_refusal_path_is_not_reachable_through_any_rule() {
        let cs: Vec<Contribution> = (0..7u8)
            .map(|i| Contribution {
                tie_key: vec![i],
                v: vec![crate::fixed::MIN, crate::fixed::MAX, -1, 0, 1],
            })
            .collect();
        assert!(mean(&cs).is_ok(), "mean refused ordinary bounded input");
        assert!(trimmed_mean(&cs, 1, 4).is_ok(), "trimmed_mean refused it");
        assert!(
            coord_median_trim(&cs, 1).is_ok(),
            "coord_median_trim refused it"
        );
    }

    /// Six honest dim-4 contributions and one adversarial dim-2, with the adversary placed
    /// at each index in turn.
    fn short_vector_round(adversary_at: usize) -> Vec<Contribution> {
        (0..7usize)
            .map(|i| Contribution {
                tie_key: vec![i as u8],
                v: if i == adversary_at {
                    vec![1, 2]
                } else {
                    vec![10, 20, 30, 40]
                },
            })
            .collect()
    }

    /// crdt-08, ACCOUNTABILITY HALF, AND THIS IS THE ONE THAT PINS THE SECURITY ARGUMENT.
    ///
    /// The finding is that one in-budget adversary nullifies the round with a short vector
    /// and NOBODY IS ATTRIBUTABLE. The fix names the offender -- but the obvious way to name
    /// it is worse than not naming it at all, and that is what this test exists to hold.
    ///
    /// `check` used to take `cs[0].v.len()` as the reference length. Attributing against
    /// that reference lets the ADVERSARY CHOOSE THE ACCUSED by choosing where it arrives:
    /// measured over the seven placements below, that rule names the adversary in exactly
    /// ONE of them and names all six HONEST nodes in the other six. Attribution is an
    /// accusation, so a denial of service would have become a framing vector -- the same
    /// shape as `crdt-07` in `layer2-finality`, where attribution had to be read from
    /// verified signatures rather than from map membership.
    ///
    /// IF THIS TEST IS EVER REDUCED TO A SINGLE PLACEMENT IT STOPS DEFENDING ANYTHING: the
    /// `cs[0]` rule passes the adversary-last case perfectly. Sweeping every index is the
    /// whole test.
    #[test]
    fn the_short_vector_offender_is_named_wherever_it_arrives() {
        for adversary_at in 0..7 {
            let cs = short_vector_round(adversary_at);
            assert_eq!(
                mean(&cs),
                Err(AggError::DimensionMismatch {
                    offender: adversary_at,
                    expected: 4,
                    got: 2,
                }),
                "the accused must be the adversary, not whoever it arrived after \
                 (adversary at index {adversary_at})"
            );
            // The message an operator actually reads must carry the same accusation.
            let msg = mean(&cs).unwrap_err().to_string();
            assert!(
                msg.contains(&format!("contribution {adversary_at}")),
                "message does not name the offender: {msg}"
            );
        }
    }

    /// crdt-08. Every rule, not just `mean` -- the finding says the adversary "nullifies
    /// every round", and all five refusals funnel through the same `check`.
    #[test]
    fn every_rule_attributes_the_same_offender() {
        let cs = short_vector_round(0);
        let expected = Err(AggError::DimensionMismatch {
            offender: 0,
            expected: 4,
            got: 2,
        });
        assert_eq!(mean(&cs), expected, "mean");
        assert_eq!(multi_krum(&cs, 1).map(|_| vec![]), expected, "multi_krum");
        assert_eq!(
            coord_median_trim(&cs, 1).map(|_| vec![]),
            expected,
            "coord_median_trim"
        );
        assert_eq!(
            trimmed_mean(&cs, 1, 4).map(|_| vec![]),
            expected,
            "trimmed_mean"
        );
        assert_eq!(
            bulyan_select(&cs, 1).map(|_| vec![]),
            expected,
            "bulyan_select"
        );
    }

    /// crdt-08. `expected` is the field that makes the AVAILABILITY half fixable one layer
    /// up, so this asserts it is sufficient on its own: filtering on it recovers the whole
    /// offender set and leaves a set that aggregates.
    ///
    /// This is NOT a claim that the availability half is fixed here. It is not -- the round
    /// is still refused, by design, because dropping contributions is a protocol policy
    /// decision that does not belong in this module.
    #[test]
    fn the_plurality_length_is_enough_to_repair_the_round_one_layer_up() {
        let cs = short_vector_round(0);
        let Err(AggError::DimensionMismatch { expected, .. }) = mean(&cs) else {
            panic!("expected an attributable dimension mismatch");
        };
        let kept: Vec<Contribution> = cs
            .iter()
            .filter(|c| c.v.len() == expected)
            .cloned()
            .collect();
        assert_eq!(
            kept.len(),
            6,
            "exactly the adversary should have been dropped"
        );
        assert_eq!(
            mean(&kept),
            Ok(vec![10, 20, 30, 40]),
            "the surviving set must aggregate to the honest answer"
        );
    }

    /// crdt-08, AND THIS IS THE GUARD AGAINST THE FIX BECOMING THE DEFECT. With no strict
    /// plurality there is no honest majority to attribute against, so naming anyone is a
    /// guess -- and the `cs[0]` rule guesses confidently in both cases here.
    #[test]
    fn no_strict_plurality_names_nobody() {
        let split: Vec<Contribution> = (0..4usize)
            .map(|i| Contribution {
                tie_key: vec![i as u8],
                v: if i < 2 { vec![1, 2] } else { vec![1, 2, 3, 4] },
            })
            .collect();
        assert_eq!(
            mean(&split),
            Err(AggError::DimensionMismatchUnattributable { lengths: 2 }),
            "an even 2/2 split has no honest majority and must accuse no one"
        );

        let pair = vec![
            Contribution {
                tie_key: vec![0],
                v: vec![1, 2],
            },
            Contribution {
                tie_key: vec![1],
                v: vec![1, 2, 3, 4],
            },
        ];
        assert_eq!(
            mean(&pair),
            Err(AggError::DimensionMismatchUnattributable { lengths: 2 }),
            "two nodes disagreeing are indistinguishable"
        );

        // A tie BELOW the maximum must not spoil attribution: 4 is still the strict
        // plurality here even though 2 and 3 tie each other.
        let mixed: Vec<Contribution> = [4usize, 4, 4, 2, 2, 3, 3]
            .iter()
            .enumerate()
            .map(|(i, &len)| Contribution {
                tie_key: vec![i as u8],
                v: vec![1; len],
            })
            .collect();
        assert_eq!(
            mean(&mixed),
            Err(AggError::DimensionMismatch {
                offender: 3,
                expected: 4,
                got: 2,
            }),
            "a tie among non-winners must not suppress a real plurality"
        );
    }

    /// crdt-08, incidental. The `d == 0` branch was the only arm of `check` no test in the
    /// suite entered, and it reported unanimous agreement on zero as a MISMATCH -- a second
    /// unattributable refusal hiding inside the first, naming an offender that does not
    /// exist because nothing mismatches.
    #[test]
    fn unanimous_zero_length_is_not_a_mismatch_by_anyone() {
        let cs: Vec<Contribution> = (0..3u8)
            .map(|i| Contribution {
                tie_key: vec![i],
                v: vec![],
            })
            .collect();
        assert_eq!(mean(&cs), Err(AggError::EmptyVectors));
    }

    /// crdt-08, AVAILABILITY HALF -- A CHARACTERISATION TEST, NOT A GUARD.
    ///
    /// It pins behaviour that is still WRONG: one in-budget adversary sending a short
    /// vector costs everyone the round. It exists so the fail-closed default cannot change
    /// silently while the policy decision is outstanding.
    ///
    /// WHEN THIS GOES RED, THE FIX ARRIVED -- INVERT OR DELETE IT, DO NOT PATCH IT BACK TO
    /// GREEN. Repairing it to keep the suite green would restore the defect and add a test
    /// that defends it.
    #[test]
    fn one_short_vector_still_nullifies_the_round_for_everyone() {
        let cs = short_vector_round(6);
        assert!(
            mean(&cs).is_err(),
            "if this now succeeds, the exclusion policy landed"
        );
        let honest: Vec<Contribution> = cs[..6].to_vec();
        assert_eq!(
            mean(&honest),
            Ok(vec![10, 20, 30, 40]),
            "positive control: the same six honest contributions aggregate fine alone, so \
             the refusal above is caused by the single adversary and nothing else"
        );
    }
}
