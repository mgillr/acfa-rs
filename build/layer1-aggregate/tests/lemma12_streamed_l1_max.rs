// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Issue #120 -- how `l1_max` may and may not be CHUNKED over the dimension.
//!
//! Lemma 12's observable threshold is built out of exactly one adversary-facing quantity:
//!
//! ```text
//!   delta_star = 2*l1_max + 3*d      beta = (|A| - f - 2) * delta_star      threshold = 4*beta
//! ```
//!
//! and `l1_max` (`src/rules.rs`, `krum_scores_inner`) is a MAX OVER PAIRS of a SUM OVER
//! COORDINATES. Those two reductions do not commute. Any streaming extension -- and the
//! scale work is already streaming the wire in chunks -- has to pick one of three plausible
//! ways to fold a chunk, and only one of them is the lemma's quantity:
//!
//!   * PER-PAIR ACCUMULATORS -- keep one running `i128` per unordered pair, add each chunk's
//!     contribution into it, take the max only after the LAST chunk. Exact.
//!   * SUM-OF-CHUNK-MAXIMA -- max over pairs inside each chunk, then sum those maxima. This
//!     lets a different pair win in each chunk, so it OVER-estimates.
//!   * MAX-OF-CHUNK-SUMS -- max over pairs inside each chunk, then take the largest chunk.
//!     It sees at most one chunk's worth of a distance spread over all of `d`, so it
//!     UNDER-estimates.
//!
//! DIRECTION IS THE WHOLE FINDING, NOT THE DIFFERENCE. Over-estimating `l1_max` enlarges
//! `threshold` and can only WITHHOLD a certificate, which is Lemma 12's designed failure
//! mode and is documented on `MarginCertificate` ("the failure mode of a hostile input is a
//! withheld certificate, never a false one"). Under-estimating SHRINKS `threshold`, so a
//! round is certified that must not be -- a FALSE CERTIFICATE, i.e. the one artefact a third
//! party trusts INSTEAD of re-deriving the selection. So the negative control below asserts
//! the SIGN of the error, not merely that an error exists.
//!
//! MEASURED HERE, this session, on the 6x5000 pseudo-random set built by `random_set()`
//! (LCG seed `0x5EED_0120`, raw values uniform in [-100000, 100000]); true single-pass
//! `l1_max` = 338 441 553. The two wrong columns are shown as SIGNED ERROR against that
//! truth, because the sign is the finding:
//!
//! ```text
//!   chunk   chunks   per-pair accumulators   sum-of-chunk-maxima   max-of-chunk-sums
//!       1     5000            338441553        +377310496 OVER    -338241861 UNDER
//!       7      715            338441553        +147701107 OVER    -337516125 UNDER
//!      13      385            338441553        +106950854 OVER    -336893353 UNDER
//!     250       20            338441553         +20533617 OVER    -319760951 UNDER
//!     251       20            338441553         +20141842 OVER    -319866168 UNDER
//!     997        6            338441553          +7994197 OVER    -268551347 UNDER
//!    1000        5            338441553          +7925240 OVER    -268245795 UNDER
//!    2500        2            338441553          +3768517 OVER    -166271670 UNDER
//!    4999        2            338441553            +52987 OVER        -22196 UNDER
//!    5000        1            338441553                 0 EXACT             0 EXACT
//!    5001        1            338441553                 0 EXACT             0 EXACT
//!    8192        1            338441553                 0 EXACT             0 EXACT
//! ```
//!
//! Every multi-chunk row errs in the SAME direction for each fold, over three decades of
//! chunk size and including four primes that do not divide `d`, so the sign is a property of
//! the rearrangement and not of a chunk size that happened to be chosen badly.
//!
//! The per-pair column is `assert_eq!` against the single-pass value, so "338441553" there
//! is bit-identity and not agreement to a tolerance. `chunk = 5000, 5001, 8192` are the
//! DEGENERATE single-chunk cases: with one chunk all three formulations are the same
//! expression, so they must agree exactly, and the direction assertions are correspondingly
//! not applied there. That is why the strict inequalities below are gated on
//! `chunks >= 2` -- and why `single_chunk_is_the_degenerate_case_where_all_three_agree`
//! exists to stop that gate from quietly swallowing everything.
//!
//! WHAT THIS TEST CAN AND CANNOT REACH. `fixed::sq_and_l1` -- the running `i128` pair that
//! actually accumulates `l1` -- is `pub(crate)`, as is `krum_scores_inner`. An integration
//! test under `tests/` therefore CANNOT call the l1 accumulator directly, and this file does
//! not edit `src/`. The single public window onto that arithmetic is
//! `MarginCertificate::l1_max`, returned by `multi_krum_certified`, so every number in this
//! file is read back out of the real shipped kernel through that field: no coordinate loop
//! is re-implemented here, and a change to `sq_and_l1` moves these numbers.
//!
//! Getting a SINGLE PAIR's `l1` out of a whole-set maximum needs one trick, and
//! `the_pair_probe_reads_back_the_kernels_own_l1_max` is the guard that the trick is honest.
//! See `crate_pair_l1`.
//!
//! GUARD-DELETION PROOF, run this session against this text. `streamed_per_pair_accumulators`
//! was mutated in place -- twice -- and the suite re-run. The BUILD exit code was read before
//! each run: a failed build leaves a stale binary and the previous run's pass looks fresh.
//! Both mutants compiled cleanly (exit 0), so both RED results are real.
//!
//! ```text
//!   MUTANT A -- the max moved INSIDE the stream (this fold becomes max-of-chunk-sums):
//!     exit 101, 3 of 6 FAILED
//!       per_pair_accumulators_are_bit_identical_to_the_single_pass_l1_max
//!           chunk = 1: got 199692 against a single pass of 338441553
//!       the_two_wrong_folds_err_in_opposite_directions_and_only_one_is_safe
//!           chunk = 1: got 199692 against a single pass of 338441553
//!       under_estimating_l1_max_forges_a_certificate_the_true_bound_refuses
//!           clustered set: got 4250 against a single pass of 85000
//!
//!   MUTANT B -- per-chunk maxima summed (this fold becomes sum-of-chunk-maxima):
//!     exit 101, 2 of 6 FAILED
//!       per_pair_accumulators_are_bit_identical_to_the_single_pass_l1_max
//!           chunk = 1: got 715752049 against a single pass of 338441553
//!       the_two_wrong_folds_err_in_opposite_directions_and_only_one_is_safe
//!           chunk = 1: got 715752049 against a single pass of 338441553
//!
//!   RESTORED: exit 0, 6 passed.
//! ```
//!
//! Mutant B leaves `under_estimating_l1_max_forges_a_certificate_the_true_bound_refuses`
//! GREEN, and that is the asymmetry rather than a gap: on the clustered set one pair wins
//! every chunk, so summing per-chunk maxima lands exactly on the true 85 000 and the round is
//! still refused. An over-estimate cannot forge. It is also exactly why the random set exists
//! alongside the clustered one -- the clustered set alone could not have caught mutant B at
//! all, and mutant B is a real mistake someone will make.

use acfa_aggregate::{multi_krum_certified, Contribution};

// ---------------------------------------------------------------------------------------
// Reading `l1_max` back out of the shipped kernel.
// ---------------------------------------------------------------------------------------

/// Distinct opaque tie keys. `check()` refuses `DuplicateTieKey`, so the probe below -- which
/// deliberately submits the SAME vector twice -- needs the keys to differ even when the
/// payloads do not. The keys are never interpreted by the kernel, so any injection works.
fn key(i: usize) -> Vec<u8> {
    vec![b'k', (b'0' + (i / 10) as u8), (b'0' + (i % 10) as u8)]
}

/// `l1_max` over a set, straight out of the certificate the kernel returns.
///
/// `f = 0` so the select-all band (`n < f + 3`) cannot fire for any `n >= 3` used here; the
/// band would return `None` for the certificate and there would be nothing to read. Only the
/// `l1_max` field is consumed -- selection, margin and verdict are irrelevant to this file
/// except in `under_estimating_l1_max_forges_a_certificate_the_true_bound_refuses`.
fn crate_l1_max(vs: &[&[i64]]) -> i128 {
    assert!(
        vs.len() >= 3,
        "n < 3 with f = 0 lands in the select-all band, where the certificate is None and \
         there is no l1_max to read; the probe would then measure nothing at all"
    );
    let cs: Vec<Contribution> = vs
        .iter()
        .enumerate()
        .map(|(i, v)| Contribution {
            tie_key: key(i),
            v: v.to_vec(),
        })
        .collect();
    let (_, cert) = multi_krum_certified(&cs, 0).expect("well-formed set must not be refused");
    cert.expect("n >= f + 3 by the assertion above, so the select-all band cannot fire")
        .l1_max
}

/// The L1 distance of ONE pair, still computed by the kernel.
///
/// The public API only exposes a MAXIMUM over pairs, never an individual pair, so a
/// per-pair accumulator cannot be driven directly. `{a, b, b}` closes that gap: its three
/// unordered pairs are `(a,b)`, `(a,b)` and `(b,b)`, the last of which is identically zero,
/// so the maximum over the set IS `l1(a, b)` -- for any `a` and `b`, including `a == b`,
/// where every pair is zero and the answer is zero.
///
/// This is a PROBE, not a proposed implementation: it pays a whole `multi_krum_certified`
/// call per pair per chunk, which is absurd for production and irrelevant for a test. What
/// matters is that the arithmetic underneath it is `fixed::sq_and_l1`, unmodified, reached
/// through the same `krum_scores_inner::<true>` path `krum_aggregate_certified` uses.
fn crate_pair_l1(a: &[i64], b: &[i64]) -> i128 {
    crate_l1_max(&[a, b, b])
}

// ---------------------------------------------------------------------------------------
// Chunking the dimension.
// ---------------------------------------------------------------------------------------

/// Half-open `[lo, hi)` coordinate ranges covering `0..d`, in order.
///
/// `chunk >= d` yields exactly one range, which is the whole vector -- the degenerate case
/// where streaming is not streaming. `chunk = 0` is refused rather than clamped: a zero
/// chunk is a caller bug, and silently treating it as "one chunk" would make a broken
/// streaming loop look like a passing one.
fn chunk_bounds(d: usize, chunk: usize) -> Vec<(usize, usize)> {
    assert!(
        chunk >= 1,
        "chunk = 0 has no meaning; refusing rather than clamping"
    );
    assert!(
        d >= 1,
        "d = 0 is refused by check() upstream and must not reach here"
    );
    let mut out = Vec::new();
    let mut lo = 0usize;
    while lo < d {
        let hi = (lo + chunk).min(d);
        out.push((lo, hi));
        lo = hi;
    }
    // A gate that iterates zero times passes vacuously. `d >= 1` makes the loop run at least
    // once, and this restates it as an assertion so a future edit to the loop cannot make
    // every caller below silently fold over nothing.
    assert_eq!(
        out.len(),
        d.div_ceil(chunk),
        "chunk cover must be exactly ceil(d/chunk) ranges"
    );
    assert!(!out.is_empty(), "cover must be non-empty");
    out
}

/// THE CORRECT FORM. One running `i128` per unordered pair; the max is taken ONCE, after
/// the final chunk has been folded in. Equivalently: the max is moved OUTSIDE the stream,
/// which is the only rearrangement that preserves `max_ij sum_k |x_ik - x_jk|`.
///
/// COST NOTE, because this is the formulation being recommended and its price is real: it
/// carries `n*(n-1)/2` live `i128` accumulators across the whole stream. At the shipped
/// `MAX_CONTRIBUTIONS = 4096` that is 8 386 560 pairs * 16 bytes = 134.2 MB of state --
/// the same quadratic-memory shape `rust-02` removed from `krum_scores_inner`, reintroduced
/// by the streaming rearrangement. The memory-lean alternative is to put the PAIR loop
/// outside and the chunk loop inside (one accumulator, but the stream is re-read
/// `n*(n-1)/2` times). Either is exact; neither of the cheap one-pass folds is.
fn streamed_per_pair_accumulators(vs: &[Vec<i64>], chunk: usize) -> i128 {
    let n = vs.len();
    let d = vs[0].len();
    let bounds = chunk_bounds(d, chunk);

    let mut acc = vec![0i128; n * n];
    let mut folds = 0usize;
    for &(lo, hi) in &bounds {
        for i in 0..n {
            for j in (i + 1)..n {
                acc[i * n + j] += crate_pair_l1(&vs[i][lo..hi], &vs[j][lo..hi]);
                folds += 1;
            }
        }
    }
    assert_eq!(
        folds,
        bounds.len() * n * (n - 1) / 2,
        "every pair must be folded in every chunk; a short fold is an under-count and \
         under-counting is the dangerous direction"
    );

    let mut best = 0i128;
    let mut pairs = 0usize;
    for i in 0..n {
        for j in (i + 1)..n {
            pairs += 1;
            if acc[i * n + j] > best {
                best = acc[i * n + j];
            }
        }
    }
    assert!(
        pairs > 0,
        "a max over zero pairs is vacuously 0 and must never be returned"
    );
    best
}

/// Per-chunk pairwise maxima: `max_ij sum_{k in chunk} |x_ik - x_jk|`, one entry per chunk.
/// Both WRONG folds are functions of this vector, which is the point -- they differ only in
/// how they collapse it, so the negative control and its safe twin come from one measurement.
fn per_chunk_pairwise_maxima(vs: &[Vec<i64>], chunk: usize) -> Vec<i128> {
    let d = vs[0].len();
    chunk_bounds(d, chunk)
        .into_iter()
        .map(|(lo, hi)| {
            let slices: Vec<&[i64]> = vs.iter().map(|v| &v[lo..hi]).collect();
            crate_l1_max(&slices)
        })
        .collect()
}

/// WRONG, SAFELY. Summing per-chunk maxima lets a DIFFERENT pair win in each chunk, so the
/// result bounds the true max from above. Conservative: it can only withhold a certificate.
fn streamed_sum_of_chunk_maxima(vs: &[Vec<i64>], chunk: usize) -> i128 {
    per_chunk_pairwise_maxima(vs, chunk).iter().sum()
}

/// WRONG, DANGEROUSLY. Taking the largest single chunk sees at most `chunk` of the `d`
/// coordinates that make up any real pairwise distance, so it bounds the true max from
/// BELOW. This is the forging form: it shrinks `delta_star`, `beta` and `threshold`.
fn streamed_max_of_chunk_sums(vs: &[Vec<i64>], chunk: usize) -> i128 {
    per_chunk_pairwise_maxima(vs, chunk)
        .into_iter()
        .max()
        .expect("chunk_bounds guarantees a non-empty cover, so the max is over >= 1 value")
}

// ---------------------------------------------------------------------------------------
// The sets under test.
// ---------------------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    /// Raw Q16.16 units, uniform in `[-span, span]`. Well inside `fixed::MIN..=fixed::MAX`,
    /// so `check()` cannot refuse and the set never exercises the range guard by accident.
    fn next_raw(&mut self, span: i64) -> i64 {
        (self.next_u64() % (2 * span as u64 + 1)) as i64 - span
    }
}

const N: usize = 6;
const D: usize = 5000;

/// Heterogeneous set: no pair dominates every chunk, which is what makes the OVER direction
/// STRICT rather than merely non-strict. (In the clustered set below a single pair wins
/// every chunk, so sum-of-chunk-maxima lands exactly on the truth -- still safe, but it
/// cannot demonstrate the over-estimate, which is why two sets are needed.)
fn random_set() -> Vec<Vec<i64>> {
    let mut r = Lcg(0x5EED_0120);
    (0..N)
        .map(|_| (0..D).map(|_| r.next_raw(100_000)).collect())
        .collect()
}

/// Chunk sizes under test. Deliberately includes:
///   * `1`, the finest possible stream, where the two wrong folds are at their most wrong;
///   * `7`, `13`, `251`, `997`, `4999` -- PRIMES, none of which divides `D = 5000`
///     (`5000 = 2^3 * 5^4`), so the final chunk is SHORT and a fold that assumes uniform
///     chunk length is exposed;
///   * `250`, `1000`, `2500` -- the sizes measured in the issue report;
///   * `5000`, `5001`, `8192` -- `chunk == d` and `chunk > d`, the degenerate single-chunk
///     cases that must collapse to the single-pass value exactly.
const CHUNKS: [usize; 12] = [1, 7, 13, 250, 251, 997, 1000, 2500, 4999, 5000, 5001, 8192];

/// The chunk sizes that actually produce more than one chunk. Everything about direction is
/// asserted over THIS list, so it is computed rather than hard-coded, and asserted non-empty
/// at each use: a direction battery over an empty list is the vacuous-gate failure.
fn multi_chunk_sizes() -> Vec<usize> {
    CHUNKS.iter().copied().filter(|&c| c < D).collect()
}

// ---------------------------------------------------------------------------------------
// (0) The probe itself.
// ---------------------------------------------------------------------------------------

/// GUARD THE INSTRUMENT BEFORE TRUSTING ITS READINGS. Everything in this file is measured
/// through `crate_pair_l1`, whose `{a, b, b}` construction is a claim about the kernel, not
/// a fact about arithmetic. If that claim were wrong -- if `l1_max` over `{a, b, b}` were
/// anything other than `l1(a, b)` -- the per-pair accumulator would agree with the
/// single-pass value for the wrong reason, or disagree for no reason.
///
/// So: take the max over all pairs of the probe at FULL dimension and require it to equal
/// the kernel's own single-pass `l1_max` over the same set, bit for bit. That composition
/// uses no chunking at all, so it isolates the probe from the thing being tested.
#[test]
fn the_pair_probe_reads_back_the_kernels_own_l1_max() {
    let vs = random_set();
    let refs: Vec<&[i64]> = vs.iter().map(|v| v.as_slice()).collect();
    let truth = crate_l1_max(&refs);

    let mut best = 0i128;
    let mut pairs = 0usize;
    for i in 0..N {
        for j in (i + 1)..N {
            pairs += 1;
            let p = crate_pair_l1(&vs[i], &vs[j]);
            assert!(
                p >= 0,
                "an L1 distance is non-negative; got {p} for pair ({i},{j})"
            );
            if p > best {
                best = p;
            }
        }
    }
    assert_eq!(
        pairs,
        N * (N - 1) / 2,
        "every unordered pair must be probed"
    );
    assert!(
        pairs > 0,
        "zero pairs probed would make the max below vacuous"
    );
    assert!(
        truth > 0,
        "a degenerate set with l1_max = 0 cannot distinguish any of the folds"
    );
    assert_eq!(
        best, truth,
        "the {{a, b, b}} probe must read back exactly the kernel's own max over pairs; \
         if it does not, every other number in this file is measuring something else"
    );

    // And the zero case the probe's doc claims, since it is relied on for `(b, b)`.
    assert_eq!(
        crate_pair_l1(&vs[0], &vs[0]),
        0,
        "l1(a, a) must be 0, which is what makes the third pair of {{a, b, b}} inert"
    );
}

// ---------------------------------------------------------------------------------------
// (1a) The correct fold is bit-identical to the single pass.
// ---------------------------------------------------------------------------------------

/// The positive claim. `assert_eq!` on `i128`, so this is bit-identity, not a tolerance.
#[test]
fn per_pair_accumulators_are_bit_identical_to_the_single_pass_l1_max() {
    let vs = random_set();
    let refs: Vec<&[i64]> = vs.iter().map(|v| v.as_slice()).collect();
    let truth = crate_l1_max(&refs);
    assert!(
        truth > 0,
        "non-degenerate set required, else every fold agrees trivially"
    );

    let mut checked = 0usize;
    for &chunk in CHUNKS.iter() {
        let got = streamed_per_pair_accumulators(&vs, chunk);
        assert_eq!(
            got, truth,
            "chunk = {chunk}: per-pair accumulators must reproduce the single-pass l1_max \
             exactly; got {got}, single pass {truth}"
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        CHUNKS.len(),
        "every chunk size must have been exercised"
    );
    assert!(checked > 0, "a loop over zero chunk sizes proves nothing");
}

// ---------------------------------------------------------------------------------------
// (1b) The negative control -- it MUST differ, or this file is worthless.
// ---------------------------------------------------------------------------------------

/// A test that cannot tell the correct fold from the forging one certifies nothing. If
/// max-of-chunk-sums ever equals the truth on a genuinely multi-chunk stream, the
/// discrimination this file claims does not exist and it must go RED -- even though
/// "the wrong answer happened to be right" sounds harmless.
#[test]
fn max_of_chunk_sums_is_a_negative_control_that_must_never_match_the_truth() {
    let vs = random_set();
    let refs: Vec<&[i64]> = vs.iter().map(|v| v.as_slice()).collect();
    let truth = crate_l1_max(&refs);

    let sizes = multi_chunk_sizes();
    assert!(
        !sizes.is_empty(),
        "no multi-chunk sizes: the negative control would pass without comparing anything"
    );
    let mut checked = 0usize;
    for &chunk in &sizes {
        let chunks = D.div_ceil(chunk);
        assert!(
            chunks >= 2,
            "chunk = {chunk} was filtered as multi-chunk but yields {chunks}"
        );
        let forged = streamed_max_of_chunk_sums(&vs, chunk);
        assert_ne!(
            forged, truth,
            "chunk = {chunk} ({chunks} chunks): max-of-chunk-sums coincided with the true \
             l1_max, so this battery cannot distinguish the forging fold from the correct \
             one here; the discrimination claim is void until this case is understood"
        );
        checked += 1;
    }
    assert_eq!(checked, sizes.len());
    assert!(checked > 0);
}

// ---------------------------------------------------------------------------------------
// (1c) Direction. The finding.
// ---------------------------------------------------------------------------------------

/// Asserts the SIGN of each wrong fold's error, which is the whole point of the issue:
/// one of them is conservative and one of them forges.
///
/// Printing the table too, because the magnitudes are the argument for why the under-estimate
/// is not a rounding nuisance. Measured at `chunk = 250` on this set: the forging fold returns
/// 18 680 602 against a true 338 441 553, i.e. 18.1x too small. `threshold = 4*m*(2*l1_max +
/// 3*d)` is LINEAR in `l1_max`, so the bar a round has to clear falls with it.
#[test]
fn the_two_wrong_folds_err_in_opposite_directions_and_only_one_is_safe() {
    let vs = random_set();
    let refs: Vec<&[i64]> = vs.iter().map(|v| v.as_slice()).collect();
    let truth = crate_l1_max(&refs);
    assert!(truth > 0);

    println!("true single-pass l1_max = {truth}");
    println!("chunk  chunks  per-pair      sum-of-chunk-maxima   max-of-chunk-sums");

    let sizes = multi_chunk_sizes();
    assert!(
        !sizes.is_empty(),
        "direction battery must not run over an empty list"
    );

    let mut over = 0usize;
    let mut under = 0usize;
    for &chunk in CHUNKS.iter() {
        let chunks = D.div_ceil(chunk);
        let exact = streamed_per_pair_accumulators(&vs, chunk);
        let hi = streamed_sum_of_chunk_maxima(&vs, chunk);
        let lo = streamed_max_of_chunk_sums(&vs, chunk);
        println!(
            "{:5}  {:6}  {:>10}    {:>+14}      {:>+14}",
            chunk,
            chunks,
            exact,
            hi - truth,
            lo - truth
        );

        // The correct fold is the ORIGIN of this table, so it is asserted here and not only
        // printed. First draft printed `exact` and asserted nothing about it, and the
        // consequence was measured: with `streamed_per_pair_accumulators` mutated into the
        // max-of-chunk-sums form, this test stayed GREEN while two others went red. A test
        // that displays the value it is supposed to be checking is not checking it.
        assert_eq!(
            exact, truth,
            "chunk = {chunk}: the row this table is built from must be the exact fold"
        );

        // Holds at EVERY chunk size, single-chunk included: these are non-strict bounds.
        assert!(
            hi >= truth,
            "chunk = {chunk}: sum-of-chunk-maxima must never fall below the truth ({hi} < {truth}); \
             if it can, the 'merely conservative' reading of that fold is false and it forges too"
        );
        assert!(
            lo <= truth,
            "chunk = {chunk}: max-of-chunk-sums must never exceed the truth ({lo} > {truth})"
        );

        if chunks >= 2 {
            // STRICT, and this is the load-bearing pair of assertions.
            assert!(
                hi > truth,
                "chunk = {chunk} ({chunks} chunks): sum-of-chunk-maxima must be STRICTLY over \
                 the truth on this heterogeneous set; equality here means the set stopped \
                 discriminating and the direction is no longer being measured"
            );
            assert!(
                lo < truth,
                "chunk = {chunk} ({chunks} chunks): max-of-chunk-sums must be STRICTLY under \
                 the truth -- UNDER is the dangerous direction and is what this file exists \
                 to pin down; got {lo} against {truth}"
            );
            over += 1;
            under += 1;
        }
    }
    assert_eq!(over, sizes.len(), "one OVER assertion per multi-chunk size");
    assert_eq!(
        under,
        sizes.len(),
        "one UNDER assertion per multi-chunk size"
    );
    assert!(
        over > 0 && under > 0,
        "directions asserted zero times is a vacuous pass"
    );
}

// ---------------------------------------------------------------------------------------
// (1d) The degenerate case the gate above skips.
// ---------------------------------------------------------------------------------------

/// `chunks >= 2` gates the strict assertions, so something has to state what happens on the
/// other side of that gate -- otherwise a future edit that made every chunk size collapse to
/// one chunk would turn the direction battery into a no-op with all its counters still
/// positive. With a single chunk the three folds are literally the same expression and must
/// agree with the single pass exactly.
#[test]
fn single_chunk_is_the_degenerate_case_where_all_three_folds_agree() {
    let vs = random_set();
    let refs: Vec<&[i64]> = vs.iter().map(|v| v.as_slice()).collect();
    let truth = crate_l1_max(&refs);

    let singles: Vec<usize> = CHUNKS.iter().copied().filter(|&c| c >= D).collect();
    assert!(
        !singles.is_empty(),
        "CHUNKS must contain at least one chunk >= d, or chunk > d is untested"
    );
    let mut checked = 0usize;
    for &chunk in &singles {
        assert_eq!(
            D.div_ceil(chunk),
            1,
            "chunk = {chunk} should be a single chunk"
        );
        assert_eq!(
            streamed_per_pair_accumulators(&vs, chunk),
            truth,
            "chunk = {chunk}"
        );
        assert_eq!(
            streamed_sum_of_chunk_maxima(&vs, chunk),
            truth,
            "chunk = {chunk}"
        );
        assert_eq!(
            streamed_max_of_chunk_sums(&vs, chunk),
            truth,
            "chunk = {chunk}"
        );
        checked += 1;
    }
    assert_eq!(checked, singles.len());
    assert!(checked > 0);
}

// ---------------------------------------------------------------------------------------
// (2) The consequence: an under-estimate does not merely differ, it FORGES.
// ---------------------------------------------------------------------------------------

/// A worked round where the true Lemma 12 certificate DECLINES and the max-of-chunk-sums
/// certificate ACCEPTS. Without this, "under-estimates" is an arithmetic observation; with
/// it, it is a false certificate on a concrete input.
///
/// THE CONSTRUCTION, chosen so the boundary sits exactly at `m` and the margin lands inside
/// the band the two thresholds straddle. `n = 6`, `f = 0`, so `m = n - f - 2 = 4`:
///   * four contributions at the origin;
///   * two contributions at `c` on EVERY coordinate -- the displacement is SPREAD over all
///     of `d`, which is precisely the shape a per-chunk maximum cannot see.
///
/// Then with `Q = d*c^2` the squared distance between the groups, `score(origin)` is
/// `0 + 0 + 0 + Q = Q` (its 4 nearest are the 3 twins plus one far one) and `score(far)` is
/// `0 + Q + Q + Q = 3Q`, so the sorted scores are `Q,Q,Q,Q,3Q,3Q`, the boundary
/// `scored[m] - scored[m-1]` is `2Q`, and `l1_max = d*c` exactly.
///
/// `c = 17` is not arbitrary: `certified <=> 2*d*c^2 > 4*m*(2*d*c + 3*d)`, which for `m = 4`
/// reduces to `c^2 - 16c - 24 > 0`, i.e. `c >= 18`. `c = 17` therefore sits just BELOW the
/// certification line on the true bound -- the honest "not certified" -- while being far
/// above the line that a chunk-sized `l1_max` computes.
///
/// MEASURED HERE, this session, at `n = 6, d = 5000, c = 17, chunk = 250`:
/// ```text
///   margin                          2 890 000
///   true    l1_max  85 000  ->  threshold 2 960 000   certified = false   (margin < threshold)
///   forged  l1_max   4 250  ->  threshold   376 000   certified = TRUE    (margin > threshold)
/// ```
/// The forged threshold is 7.87x smaller than the true one, and the round crosses the line.
#[test]
fn under_estimating_l1_max_forges_a_certificate_the_true_bound_refuses() {
    const C: i64 = 17;
    const CHUNK: usize = 250;
    let f = 0usize;
    let m = N - f - 2;

    let mut vs: Vec<Vec<i64>> = vec![vec![0i64; D]; 4];
    vs.push(vec![C; D]);
    vs.push(vec![C; D]);
    assert_eq!(vs.len(), N);

    let cs: Vec<Contribution> = vs
        .iter()
        .enumerate()
        .map(|(i, v)| Contribution {
            tie_key: key(i),
            v: v.clone(),
        })
        .collect();
    let (_, cert) = multi_krum_certified(&cs, f).expect("well-formed");
    let cert = cert.expect("n = 6 >= f + 3");

    // The kernel's own numbers, not re-derived ones.
    assert_eq!(cert.nn_count, m, "boundary must sit at m = n - f - 2");
    assert_eq!(cert.d, D);
    let truth = cert.l1_max;
    let margin = cert.margin;
    assert!(
        margin > 0,
        "an exact tie would be Remark 13's residual, not a margin"
    );

    // The streamed folds over the same vectors.
    let exact = streamed_per_pair_accumulators(&vs, CHUNK);
    let forged = streamed_max_of_chunk_sums(&vs, CHUNK);
    assert_eq!(
        exact, truth,
        "per-pair accumulators must still be exact on the clustered set, not only the random one"
    );
    assert!(
        forged < truth,
        "the forging fold must under-estimate here or this test proves nothing: {forged} vs {truth}"
    );

    // Rebuild Lemma 12 from each l1_max. The formula is the one on `multi_krum_certified`:
    //   delta_star = 2*l1_max + 3*d ; beta = m*delta_star ; threshold = 4*beta.
    let threshold_of = |l1: i128| -> i128 { 4 * (m as i128) * (2 * l1 + 3 * (D as i128)) };
    let true_threshold = threshold_of(truth);
    let forged_threshold = threshold_of(forged);

    // Cross-check the closed form against the kernel's own field before relying on it: if the
    // reconstruction disagreed with the shipped certificate, the "forged" number below would
    // be a statement about this test's arithmetic and not about Lemma 12.
    assert_eq!(
        true_threshold, cert.threshold,
        "the reconstruction must reproduce the kernel's threshold exactly"
    );
    assert_eq!(cert.delta_star, 2 * truth + 3 * (D as i128));
    assert_eq!(cert.beta, (m as i128) * cert.delta_star);

    println!("margin           = {margin}");
    println!(
        "true   l1_max = {truth:>9}  threshold = {true_threshold:>10}  certified = {}",
        cert.certified
    );
    println!(
        "forged l1_max = {forged:>9}  threshold = {forged_threshold:>10}  certified = {}",
        margin > forged_threshold
    );

    assert!(
        !cert.certified,
        "precondition: the honest certificate must DECLINE this round (margin {margin} vs \
         threshold {true_threshold}); if it certifies, the construction no longer straddles \
         the line and the forgery below is not a forgery"
    );
    assert!(
        margin <= true_threshold,
        "restating the precondition in the raw comparison the kernel makes"
    );
    assert!(
        margin > forged_threshold,
        "THE FINDING: with l1_max under-estimated to {forged} the threshold falls to \
         {forged_threshold} and this round certifies, while the true threshold \
         {true_threshold} refuses it. That is a false certificate, not a conservative one."
    );

    // And the safe fold must NOT do this, on the same input, at the same chunk size.
    let safe = streamed_sum_of_chunk_maxima(&vs, CHUNK);
    assert!(
        safe >= truth,
        "sum-of-chunk-maxima must not under-estimate: {safe} < {truth}"
    );
    assert!(
        margin <= threshold_of(safe),
        "the conservative fold must still decline this round; it may only ever withhold"
    );

    // POSITIVE CONTROL, and it is not decoration. "The true certificate declines" is a weak
    // statement if the certificate declines everything of this shape -- then the forgery
    // would merely be crossing a line nothing ever crosses, and the construction would prove
    // nothing about where the line IS. `c = 18` is the very next integer, one step over
    // `c^2 - 16c - 24 > 0`, and it must certify honestly on the SAME code path. So `c = 17`
    // is a genuine near-miss: measured `bits_short = Some(1)`, meaning a single extra
    // fractional bit is predicted to close it.
    assert_eq!(
        cert.bits_short,
        Some(1),
        "c = 17 must miss by ONE doubling; a larger shortfall would mean the construction is \
         nowhere near the certification line and the forgery is jumping a chasm, not a line"
    );
    let mut vs18: Vec<Vec<i64>> = vec![vec![0i64; D]; 4];
    vs18.push(vec![C + 1; D]);
    vs18.push(vec![C + 1; D]);
    let cs18: Vec<Contribution> = vs18
        .iter()
        .enumerate()
        .map(|(i, v)| Contribution {
            tie_key: key(i),
            v: v.clone(),
        })
        .collect();
    let cert18 = multi_krum_certified(&cs18, f)
        .expect("well-formed")
        .1
        .expect("n = 6 >= f + 3");
    assert!(
        cert18.certified,
        "positive control: c = {} must certify honestly (margin {} vs threshold {}), otherwise \
         'c = 17 declines' says nothing about the location of the line",
        C + 1,
        cert18.margin,
        cert18.threshold
    );
}
