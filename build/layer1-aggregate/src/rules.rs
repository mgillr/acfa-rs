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
}

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

    let mut d2 = vec![vec![0i128; n]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let s = sq_dist(&cs[i].v, &cs[j].v);
            d2[i][j] = s;
            d2[j][i] = s;
        }
    }

    // (score, tie_key, index) ordered lexicographically, exactly as the reference.
    // tie_key precedes index so the outcome depends on the contribution set and not
    // on the order it happened to arrive in.
    let mut scored: Vec<(i128, &[u8], usize)> = (0..n)
        .map(|i| {
            let mut ds: Vec<i128> = (0..n).filter(|&j| j != i).map(|j| d2[i][j]).collect();
            ds.sort_unstable();
            let score: i128 = ds[..m.min(ds.len())].iter().sum();
            (score, cs[i].tie_key.as_slice(), i)
        })
        .collect();
    scored.sort_unstable();

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

    let mut d2 = vec![vec![0i128; n]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let s = sq_dist(&cs[i].v, &cs[j].v);
            d2[i][j] = s;
            d2[j][i] = s;
        }
    }
    let mut scored: Vec<(i128, &[u8], usize)> = (0..n)
        .map(|i| {
            let mut ds: Vec<i128> = (0..n).filter(|&j| j != i).map(|j| d2[i][j]).collect();
            ds.sort_unstable();
            let score: i128 = ds[..m.min(ds.len())].iter().sum();
            (score, cs[i].tie_key.as_slice(), i)
        })
        .collect();
    scored.sort_unstable();
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
