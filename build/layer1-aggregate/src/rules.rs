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
    DimensionMismatch,
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
    ValueOutOfRange,
    /// `beta_den` is zero, so the trim fraction `beta_num / beta_den` is undefined.
    ///
    /// This was an `assert!` in library code, which aborts the process. A library reached
    /// from a CLI that reads untrusted directives must not abort on a value the caller
    /// supplied -- `acfa-agg` exited 101 on `beta <num> 0` where its own contract promises
    /// a typed refusal.
    BetaDenominatorZero,
    /// More contributions than the rule will process. See `MAX_CONTRIBUTIONS` and
    /// `MAX_CONTRIBUTIONS_BULYAN` for the arithmetic behind each bound.
    ///
    /// This is a REFUSAL, not a truncation. Silently aggregating a prefix would produce a
    /// plausible-looking result over a set the caller never chose, which is the same class
    /// of error as saturating an out-of-range value.
    TooManyContributions {
        n: usize,
        max: usize,
    },
}

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
/// 11.55 s. The cube law puts n=512 near 90 s and n=1024 beyond ten minutes. A single wire
/// byte selects this rule, so an attacker picks the exponent; the cap is what stops one
/// byte buying an unbounded amount of a verifier's time.
pub const MAX_CONTRIBUTIONS_BULYAN: usize = 512;

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
/// Callers map `None` to `AggError::ValueOutOfRange`. On every path inside this module
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
    let d = cs[0].v.len();
    if d == 0 || cs.iter().any(|c| c.v.len() != d) {
        return Err(AggError::DimensionMismatch);
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
    if cs.iter().any(|c| {
        c.v.iter()
            .any(|&x| !(crate::fixed::MIN..=crate::fixed::MAX).contains(&x))
    }) {
        return Err(AggError::ValueOutOfRange);
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
        .ok_or(AggError::ValueOutOfRange)
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
        .ok_or(AggError::ValueOutOfRange)
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
        .ok_or(AggError::ValueOutOfRange)
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
    d2: &[Vec<i128>],
    n: usize,
    m: usize,
) -> Result<Vec<Scored<'a>>, AggError> {
    let mut scored: Vec<Scored<'a>> = Vec::with_capacity(n);
    for i in 0..n {
        let mut ds: Vec<i128> = (0..n).filter(|&j| j != i).map(|j| d2[i][j]).collect();
        ds.sort_unstable();
        let mut score: i128 = 0;
        for &x in &ds[..m.min(ds.len())] {
            score = score.checked_add(x).ok_or(AggError::ValueOutOfRange)?;
        }
        scored.push((score, cs[i].tie_key.as_slice(), i));
    }
    scored.sort_unstable();
    Ok(scored)
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
    check(cs)?;
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
    let mut d2 = vec![vec![0i128; n]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let s = sq_dist(&cs[i].v, &cs[j].v).ok_or(AggError::ValueOutOfRange)?;
            d2[i][j] = s;
            d2[j][i] = s;
        }
    }

    // (score, tie_key, index) ordered lexicographically, exactly as the reference.
    // tie_key precedes index so the outcome depends on the contribution set and not
    // on the order it happened to arrive in.
    let scored = krum_scores(cs, &d2, n, m)?;

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
    check(cs)?;
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
    let mut d2 = vec![vec![0i128; n]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let s = sq_dist(&cs[i].v, &cs[j].v).ok_or(AggError::ValueOutOfRange)?;
            d2[i][j] = s;
            d2[j][i] = s;
        }
    }
    let scored = krum_scores(cs, &d2, n, m)?;
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
    check(cs)?;
    // Bulyan gets its OWN, lower cap: it drives the quadratic selection `theta` times, so
    // the cost is cubic and the per-call guard inside `multi_krum_ranked` would let a
    // caller buy `n` of them. One wire byte chooses this rule, so the bound has to be here.
    if cs.len() > MAX_CONTRIBUTIONS_BULYAN {
        return Err(AggError::TooManyContributions {
            n: cs.len(),
            max: MAX_CONTRIBUTIONS_BULYAN,
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
    let mut pool: Vec<usize> = (0..n).collect();
    let mut selected: Vec<usize> = Vec::new();

    // No `pool.len() >= f + 3` guard here. That guard existed because
    // `multi_krum_ranked` used to degenerate to index order on a small pool; it now
    // ranks by score at every size. With the guard in place this loop exited EARLY
    // for f < 2 and returned FEWER than theta candidates with no error at all --
    // measured shortfall of 2 at f=0 and 1 at f=1, at every n tested.
    while selected.len() < theta {
        let sub: Vec<Contribution> = pool.iter().map(|&i| cs[i].clone()).collect();
        let best_local = multi_krum_ranked(&sub, f)?[0];
        selected.push(pool.remove(best_local));
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

        // The whole column, floor-averaged: (1+2+3+4+1000)/5 = 1010/5 = 202.
        assert_eq!(
            trimmed_mean(&cs, 3, 5),
            Ok(vec![202]),
            "an untrimmable column must be kept WHOLE, not emptied or truncated"
        );

        // And the outlier is still in there, which is the substance of adv-05: the caller
        // asked to trim and got a mean the trim bound does not protect. Asserted against a
        // COMPUTED value rather than a literal -- `assert!(202 > 4)` compares two constants
        // and clippy is right that it can never fail, which is this repository's own
        // gates-that-cannot-fail defect appearing inside a test about coverage gaps.
        let got = trimmed_mean(&cs, 3, 5).unwrap()[0];
        assert!(
            got > 100,
            "the 1000 outlier survives into the result (got {got}) -- see adv-05"
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
}
