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

/// Floor division: rounds toward NEGATIVE INFINITY, matching the reference kernel.
///
/// THIS IS NOT COSMETIC. Python's `//` floors; Rust's `/` truncates toward zero.
/// They agree on non-negative values and DISAGREE on every negative non-exact
/// quotient (`-7 // 2 == -4` but `-7 / 2 == -3`). Gradient components are routinely
/// negative, so a port that used `/` would produce a different aggregate from the
/// reference on ordinary inputs -- and two conforming implementations disagreeing is
/// indistinguishable from one of them being faulty, which is the exact failure the
/// determinism property exists to exclude. The rounding rule is wire contract.
#[inline]
pub fn floor_div(numer: i128, denom: i128) -> i64 {
    debug_assert!(denom > 0, "denominator must be positive");
    let q = numer.div_euclid(denom);
    q as i64
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
    Ok((0..d)
        .map(|k| {
            let s: i128 = cs.iter().map(|c| c.v[k] as i128).sum();
            floor_div(s, n)
        })
        .collect())
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
    assert!(beta_den > 0, "beta_den must be positive");
    let t = (n * beta_num as usize) / beta_den as usize;
    Ok((0..d)
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
        .collect())
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
    let keep = (theta.saturating_sub(2 * f)).max(1);
    Ok((0..d)
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
        .collect())
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
    if n < f + 3 {
        return Ok((0..n).collect());
    }
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
    let m = if n >= f + 3 {
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
    if n < 4 * f + 3 {
        return Err(AggError::BulyanTooFewContributions);
    }
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
