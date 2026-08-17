// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! num-01. THE RUST ENCODER AND THE PUBLISHED REFERENCE ROUND DIFFERENTLY, AND THE ONLY
//! CROSS-IMPLEMENTATION TEST IN THE REPO CANNOT SEE IT.
//!
//! `reference/acfa.py` is the kernel released with the paper, vendored verbatim:
//!
//!     def fp_encode(x: float) -> int:
//!         return int(round(x * (1 << Q_FRAC_BITS)))
//!
//! Python's `round` is BANKER'S ROUNDING -- ties to even. `fixed::encode` uses
//! `f64::round`, which is HALF AWAY FROM ZERO and is this crate's documented wire
//! contract. The two agree everywhere except exact midpoints, and at midpoints they
//! disagree on exactly those whose floor is EVEN:
//!
//!     x*65536   -3.5  -2.5  -1.5  -0.5  +0.5  +1.5  +2.5  +3.5
//!     reference   -4    -2    -2     0     0     2     2     4
//!     ours        -4    -3    -2    -1     1     2     3     4
//!                       DIFF        DIFF  DIFF        DIFF
//!
//! THIS IS NOT A THEORETICAL EDGE. Measured on ordinary float32 gradients, N(0,1), the
//! production input type for federated learning:
//!
//!     encoded coordinates differing      999 / 435,200   0.230%
//!     aggregate coordinates differing     57 /  25,600   0.223%
//!     ROUNDS WITH A DIVERGENT AGGREGATE   53 / 400       13.2%, about 1 round in 8
//!
//! Float32 reaches the midpoints because its mantissa is coarse: scaling by 2^16 is
//! exact, so any float32 that is an odd multiple of 2^-17 lands exactly on `k + 0.5`.
//!
//! WHY NOTHING CATCHES IT, AND IT IS STRUCTURAL RATHER THAN AN OVERSIGHT.
//! `tests/cross_impl.rs` does compare us against the reference -- 9 cases, 2784
//! components -- but `tests/golden/generate.py` builds its corpus from INTEGERS
//! (`next_u64() % 200001 - 100000`) and hands them straight to the rules. `fp_encode` is
//! never called. Repo-wide it has ZERO call sites: the only occurrences are a string
//! label in `xarch_emit.rs`, a doc comment in `fixed.rs`, and its own definition.
//! So the one place the two implementations provably differ is the one place the
//! cross-check does not look -- the same defined-but-never-called shape as the
//! `attributable_verified` guard in `layer2-finality`.
//!
//! WHICH RULE IS CANONICAL IS NOT DECIDED HERE. `fixed.rs` documents half-away-from-zero
//! as the wire contract and the fingerprints are built on it, so changing it is a wire
//! break; but the PAPER ships the other rule. That is a protocol decision, not a test's
//! to take. These tests exist so the divergence cannot go on being invisible while it is
//! decided.

use acfa_aggregate::encode;

/// The published reference's rule, in Rust: `int(round(...))`, ties to even.
fn reference_encode(x: f64) -> i64 {
    let s = x * 65536.0;
    let r = s.round_ties_even();
    r as i64
}

/// num-01. **CHARACTERISATION TEST -- IT PINS A KNOWN DIVERGENCE, IT IS NOT A GUARD.**
///
/// When this goes red the two implementations AGREE, which means the rounding decision was
/// taken and one side was changed. Do not "fix" it back to green -- delete it and record
/// which rule won.
#[test]
fn we_disagree_with_the_published_reference_at_half_the_midpoints() {
    let mut differ = 0;
    let mut agree = 0;
    for k in -50i64..=50 {
        let x = (k as f64 + 0.5) / 65536.0;
        let ours = encode(x).expect("midpoints are well inside range");
        let theirs = reference_encode(x);
        if ours == theirs {
            agree += 1;
        } else {
            differ += 1;
            assert_eq!(
                (ours - theirs).abs(),
                1,
                "the two rules should never differ by more than one unit at x*65536 = {k}.5"
            );
        }
    }
    // Exactly the midpoints whose floor is even, which is half of them.
    assert_eq!(
        differ, 51,
        "expected disagreement on half the midpoints, got {differ} differ / {agree} agree"
    );
}

/// num-01. The divergence is reachable from ORDINARY float32, which is what makes it a
/// live defect rather than a curiosity. **CHARACTERISATION TEST**, same rule as above.
#[test]
fn ordinary_float32_values_land_on_the_disagreeing_midpoints() {
    // Any float32 that is an odd multiple of 2^-17 scales to exactly k + 0.5.
    let mut reached = 0;
    for odd in (1i64..=401).step_by(2) {
        let x = (odd as f32) / 131_072.0; // 2^-17
        let x = x as f64;
        let ours = encode(x).expect("in range");
        let theirs = reference_encode(x);
        if ours != theirs {
            reached += 1;
        }
    }
    assert!(
        reached > 50,
        "float32 must be able to reach the disagreeing midpoints; reached {reached}. If this \
         is now 0 the encoders agree and num-01 is closed."
    );
}

/// num-01, THE REASON IT SURVIVED. **CHARACTERISATION TEST.**
///
/// The cross-implementation corpus is integers, so `fp_encode` is never exercised and the
/// only test that compares us to the reference is blind to the only place we differ.
///
/// WHEN THIS GOES RED the golden corpus gained float inputs and the cross-check can finally
/// see the encoder -- that is the fix arriving. Invert or delete it; do not relax it.
#[test]
fn the_cross_implementation_corpus_never_exercises_the_encoder() {
    let raw = include_str!("golden/vectors.json");
    // Contribution vectors are emitted as bare integers by generate.py. A float anywhere in
    // a contribution vector would mean the corpus had started at the float boundary.
    let mut in_v = false;
    let mut floats_in_vectors = 0usize;
    let mut ints_in_vectors = 0usize;
    for tok in raw.split(['[', ']', ',', '{', '}']) {
        let t = tok.trim();
        if t.contains("\"v\"") {
            in_v = true;
            continue;
        }
        if t.starts_with('"') {
            in_v = false;
            continue;
        }
        if in_v && !t.is_empty() {
            if t.contains('.') {
                floats_in_vectors += 1;
            } else if t.parse::<i64>().is_ok() {
                ints_in_vectors += 1;
            }
        }
    }
    assert!(
        ints_in_vectors > 1000,
        "expected a large integer corpus, found {ints_in_vectors} -- the scan is broken, not \
         the corpus"
    );
    assert_eq!(
        floats_in_vectors, 0,
        "the golden corpus now carries {floats_in_vectors} float input(s): the cross-check \
         can see the encoder and this characterisation test should be inverted or deleted"
    );
}
