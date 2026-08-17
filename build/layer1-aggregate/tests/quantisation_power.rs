// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! num-02. THE HEADLINE ABSORPTION EXPERIMENT CANNOT FAIL, AND THE PROPERTY IT REPORTS IS
//! NOT THE PROPERTY IT MEASURES.
//!
//! `examples/xarch_absorb.rs` builds 200,000 doubles in `[-5, 5)` and pushes three
//! transcendentals through each -- the 600,000-sample corpus -- then compares the raw IEEE
//! bits (expected to DIFFER across architectures) against the Q16.16 encodings (expected to
//! MATCH). `DETERMINISM-RESULTS.md` and `research/xarch-libm-divergence.md` publish the
//! result as quantisation ABSORBING a real cross-architecture divergence.
//!
//! THE EXPERIMENT'S OWN DOCSTRING GUARDS AGAINST THE WRONG MIRAGE. It says, correctly, that
//! "a pass is only meaningful when `raw` DIFFERS and `enc` MATCHES" -- and so it checks that
//! the INPUT diverged. It never checks that the OUTPUT COULD HAVE DIVERGED. Those are
//! different questions and only the second one is about power.
//!
//! Every divergence the same experiment reports is EXACTLY 1 ULP. An encoding flips only if
//! the scaled value sits within half a ULP of a rounding boundary. Measured over the
//! published corpus, the CLOSEST sample is 20,472 ULPs away, and the expected number of
//! flips is 8.7e-06 -- one would need about 6.9e10 samples, some 114,000x the corpus, to
//! expect a single one. So `enc` matches whatever libm does, and the published result is
//! what you would print if quantisation absorbed nothing at all.
//!
//! Worse, the property is FALSE AS STATED. Quantisation does not absorb a 1-ULP divergence;
//! it makes one RARE AND TOTAL. At a boundary a 1-ULP input difference produces a FULL
//! Q16.16 unit of output difference -- amplification, not absorption -- which is the
//! opposite of what the documents claim, and it is reachable by construction.

use acfa_aggregate::encode;

/// Distance from `v` to the next representable double above it.
fn ulp(v: f64) -> f64 {
    f64::from_bits(v.abs().to_bits() + 1) - v.abs()
}

/// The corpus `examples/xarch_absorb.rs` builds, reproduced exactly. Same LCG, same
/// constants, same seed, same three functions in the same order.
fn published_corpus() -> Vec<f64> {
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 11
        }
        fn next_x(&mut self) -> f64 {
            let n = (self.next_u64() % 10_000_001) as i64 - 5_000_000;
            n as f64 / 1_000_000.0
        }
    }
    let mut r = Lcg(20260816);
    let mut vals = Vec::with_capacity(600_000);
    for _ in 0..200_000 {
        let x = r.next_x();
        vals.push(x.exp());
        vals.push(x.cos());
        vals.push((x.abs() + 1.0).ln());
    }
    vals
}

/// num-02, THE REFUTATION. `encode` is not divergence-absorbing: one ULP in, one whole
/// Q16.16 unit out.
///
/// This is a GUARD, not a characterisation test. If it ever goes red the rounding rule
/// changed, and `fixed.rs`'s contract block is the place to look.
#[test]
fn one_ulp_of_input_can_move_the_encoding_by_a_whole_unit() {
    let mut found = Vec::new();
    for k in [1u64, 3, 7, 100, 1000, 40_000] {
        // A value sitting on a rounding boundary, and its neighbour just below it.
        let target = (k as f64 + 0.5) / 65536.0;
        let below = f64::from_bits(target.to_bits() - 1);
        for v in [below, target] {
            let up = f64::from_bits(v.to_bits() + 1);
            if let (Ok(a), Ok(b)) = (encode(v), encode(up)) {
                if a != b {
                    assert_eq!(
                        (b - a).abs(),
                        1,
                        "a 1-ULP input step should move the encoding by exactly one unit"
                    );
                    found.push(v);
                    break;
                }
            }
        }
    }
    assert!(
        found.len() >= 3,
        "quantisation was expected to AMPLIFY a 1-ULP difference at a boundary, and did so \
         at only {} of the probed values -- if this is now zero, `encode` absorbs and the \
         published claim is true after all",
        found.len()
    );
}

/// num-02, THE POWER MEASUREMENT. **CHARACTERISATION TEST -- IT PINS SOMETHING WRONG.**
///
/// It asserts that the published corpus contains NO sample a 1-ULP libm divergence could
/// flip, which is exactly why the headline result is vacuous. WHEN THIS GOES RED THE CORPUS
/// GAINED POWER -- that is the fix arriving. Invert it or delete it; do NOT adjust the
/// threshold to keep it green, because that would restore the vacuous experiment and add a
/// test defending it.
#[test]
fn the_published_corpus_cannot_detect_a_one_ulp_divergence() {
    let vals = published_corpus();
    assert_eq!(vals.len(), 600_000, "the corpus shape moved");

    let mut min_ulps = f64::INFINITY;
    let mut flippable = 0usize;
    for v in &vals {
        let s = v * 65536.0;
        // Rounding boundaries sit at every half-integer of the scaled value.
        let d = ((s - s.floor()) - 0.5).abs();
        let du = d / ulp(s);
        if du < min_ulps {
            min_ulps = du;
        }
        if du <= 0.5 {
            flippable += 1;
        }
    }

    assert_eq!(
        flippable, 0,
        "the corpus now contains {flippable} sample(s) a 1-ULP divergence could flip -- the \
         experiment has power and this characterisation test should be inverted or deleted"
    );
    assert!(
        min_ulps > 20_000.0,
        "closest sample to a rounding boundary is {min_ulps:.0} ULPs; num-02 measured 20,472"
    );
}

/// num-02, THE CONSTRUCTIVE HALF: a corpus that CAN fail, so the absorption claim becomes
/// testable rather than forced.
///
/// Not wired into `xarch_absorb` on purpose -- that example's output is hashed and compared
/// across eight architectures in CI, so changing its corpus changes a published fingerprint
/// and is a decision for the room, not a side effect of a test. This pins the recipe.
#[test]
fn a_boundary_adjacent_corpus_would_have_power() {
    let mut flippable = 0usize;
    let mut total = 0usize;
    for k in 1u64..=2000 {
        // Straddle the boundary: the double just below it, and the boundary itself.
        let target = (k as f64 + 0.5) / 65536.0;
        for v in [f64::from_bits(target.to_bits() - 1), target] {
            total += 1;
            let up = f64::from_bits(v.to_bits() + 1);
            if let (Ok(a), Ok(b)) = (encode(v), encode(up)) {
                if a != b {
                    flippable += 1;
                }
            }
        }
    }
    assert!(
        flippable > total / 4,
        "a boundary-adjacent corpus must be able to detect a 1-ULP divergence: only \
         {flippable} of {total} samples were flippable. The published corpus manages 0 of \
         600,000, which is the whole of num-02."
    );
}
