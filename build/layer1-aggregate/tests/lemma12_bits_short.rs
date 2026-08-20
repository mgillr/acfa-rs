// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `bits_short` -- turning an opaque `certified: false` into a deployment parameter.
//!
//! In the realistic high-dimensional regime the no-flip certificate fires almost never, and a
//! measured investigation established WHY: not conservatism in the bound, but resolution. Holding
//! the data and the dimension fixed and varying only the fixed-point grid, the
//! requirement-to-margin ratio halves ONCE PER FRACTIONAL BIT -- 37.079 at FRAC_BITS=16 down to
//! 0.603 at 22, exactly one halving per bit over nine doublings, to within 0.5%.
//!
//! So the shortfall is expressible as an integer, and `certified: false` can say how far off it
//! was instead of merely that it was off.
//!
//! WHAT THESE TESTS PIN, and equally what they do NOT. They pin the ARITHMETIC -- that
//! `bits_short` is exactly the number of doublings of `margin` needed to exceed `threshold`,
//! computed in exact integers so it is identical on every architecture. They do NOT pin the
//! PREDICTION, because re-encoding at a finer grid changes the data and not only the arithmetic.
//! The field is honest guidance derived from a measured law, not an entitlement to a certificate,
//! and its doc comment says so.

use acfa_aggregate::{multi_krum_certified, Contribution};

struct Lcg(u64);
impl Lcg {
    fn new(s: u64) -> Self {
        Lcg(s)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn val(&mut self, spread: i64) -> i64 {
        (self.next() % (2 * spread as u64 + 1)) as i64 - spread
    }
}

fn corpus(n: usize, d: usize, spread: i64, seed: u64) -> Vec<Contribution> {
    let mut r = Lcg::new(seed);
    (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i:04}").into_bytes(),
            v: (0..d).map(|_| r.val(spread)).collect(),
        })
        .collect()
}

/// The arithmetic contract: `bits_short` is exactly the doublings needed, and it agrees with
/// `certified`. These two must never disagree -- a round reported certified with a positive
/// shortfall, or uncertified with zero, would be worse than no field at all.
///
/// GUARD-DELETION: change the helper's `while m <= threshold` to `while m < threshold` and this
/// goes RED on the boundary cases where `margin` doublings land exactly on `threshold`.
#[test]
fn bits_short_is_exactly_the_doublings_needed_and_agrees_with_certified() {
    let mut checked = 0usize;
    let mut uncertified = 0usize;
    for trial in 0..300u64 {
        let n = 6 + (trial % 6) as usize;
        let d = 2 + (trial % 5) as usize;
        let f = 1 + (trial % 2) as usize;
        let spread = [4i64, 64, 1024][(trial % 3) as usize];
        let cs = corpus(n, d, spread, 5000 + trial);
        let Ok((_, Some(c))) = multi_krum_certified(&cs, f) else {
            continue;
        };
        checked += 1;

        match c.bits_short {
            None => {
                assert!(
                    c.margin <= 0,
                    "None is reserved for a margin no resolution can fix, got margin {}",
                    c.margin
                );
                assert!(!c.certified, "a non-positive margin cannot be certified");
            }
            Some(0) => assert!(
                c.certified,
                "zero bits short must mean certified: margin {} threshold {}",
                c.margin, c.threshold
            ),
            Some(k) => {
                uncertified += 1;
                assert!(!c.certified, "a positive shortfall must mean NOT certified");
                // Exactly k doublings: k-1 must still fall short, k must clear.
                let below = c.margin.saturating_mul(1i128 << (k - 1));
                let at = c.margin.saturating_mul(1i128 << k);
                assert!(
                    below <= c.threshold,
                    "{} doublings should NOT have sufficed (margin {} threshold {})",
                    k - 1,
                    c.margin,
                    c.threshold
                );
                assert!(
                    at > c.threshold,
                    "{k} doublings must clear the threshold (margin {} threshold {})",
                    c.margin,
                    c.threshold
                );
            }
        }
    }
    assert!(
        checked > 20,
        "premise: enough certificates to test, got {checked}"
    );
    assert!(
        uncertified > 0,
        "vacuous: nothing fell short, so the shortfall arithmetic was never exercised"
    );
}

/// An exact tie reports `None`, not a large number. No amount of resolution closes a zero gap, and
/// a number there would send an operator to buy bits that cannot help.
#[test]
fn an_exact_tie_reports_no_finite_shortfall() {
    // Four points on the axes plus the centre: the four outer scores are exactly equal, so with
    // m = 3 the selection boundary falls between two of them and the margin is 0 by construction.
    let cs: Vec<Contribution> = vec![
        Contribution {
            tie_key: b"a".to_vec(),
            v: vec![1000, 0],
        },
        Contribution {
            tie_key: b"b".to_vec(),
            v: vec![-1000, 0],
        },
        Contribution {
            tie_key: b"c".to_vec(),
            v: vec![0, 1000],
        },
        Contribution {
            tie_key: b"d".to_vec(),
            v: vec![0, -1000],
        },
        Contribution {
            tie_key: b"e".to_vec(),
            v: vec![0, 0],
        },
    ];
    let (_, cert) = multi_krum_certified(&cs, 0).unwrap();
    let c = cert.unwrap();
    assert_eq!(c.margin, 0, "premise: this configuration ties exactly");
    assert_eq!(
        c.bits_short, None,
        "no finite resolution closes a zero margin"
    );
    assert!(!c.certified);
}

/// Deterministic like every other field: identical under a rotation of the input.
#[test]
fn bits_short_is_independent_of_input_order() {
    let cs = corpus(8, 4, 64, 4242);
    let (_, base) = multi_krum_certified(&cs, 1).unwrap();
    let base = base.unwrap();
    for shift in 1..cs.len() {
        let mut rot = cs[shift..].to_vec();
        rot.extend_from_slice(&cs[..shift]);
        let (_, c) = multi_krum_certified(&rot, 1).unwrap();
        assert_eq!(base.bits_short, c.unwrap().bits_short);
    }
}
