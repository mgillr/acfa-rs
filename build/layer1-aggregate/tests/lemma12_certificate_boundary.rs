// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Lemma 12's `beta`, `delta_star` and `threshold` were asserted NOWHERE, and the certificate
//! check re-derived the production comparison rather than pinning it. A test that recomputes what
//! production computes and then agrees with itself cannot fail: mutate `margin > threshold` to
//! `margin >= threshold` and the whole crate stays green, while the mutant FORGES A CERTIFICATE at
//! exactly the boundary Lemma 12 exists to decide.
//!
//! THE TWO OPERATORS DIFFER ON EXACTLY ONE INPUT CLASS: `margin == threshold`. So the first
//! question is whether that equality is REACHABLE -- if it is not, `>=` is an equivalent mutant and
//! no test can kill it. It is reachable, and this file carries a witness.
//!
//! HOW THE WITNESS WAS FOUND, because it was not found by search. `l1_max` for these fixtures is
//! the largest value `Z`, so `threshold = 4*m*(2*Z + 3*d)` is LINEAR in `Z`, while the margin is
//! INDEPENDENT of `Z` once `Z` is too far away to be a nearest neighbour of any selected point.
//! That allows solving for the crossing instead of hunting for it. A first attempt did search
//! blindly over 211,876 configurations on a grid of 0..46 and certified NONE of them -- the margin
//! grows quadratically in the spread while the threshold grows linearly, so nothing that small can
//! ever certify. That run reported "this grid says nothing" rather than "no boundary exists",
//! which is the only reason the search was widened instead of the conclusion being drawn.
//!
//! THE MUTATION WAS RUN, NOT ARGUED. `rules.rs:1066` `certified: margin > threshold` changed to
//! `>=`, whole crate, `--no-fail-fast`: 17 test binaries ran (the same 17 as the clean tree, which
//! is the number that matters -- a crate that fails to BUILD reports zero failures and reads as a
//! clean sweep), 106 passed, 1 failed. The one red was
//! `certification_is_strict_and_the_exact_boundary_is_not_certified`, at the Z=9923 row, reporting
//! `margin=158792 threshold=158792`. Restored: 17 binaries, 107 passed, 0 failed.
//!
//! THE OTHER TWO TESTS WERE MADE TO FAIL TOO, so none of the three is here as decoration. With
//! `delta_star`'s `3*d` term changed to `4*d`, all 3 go red -- `delta_star must be 2*l1_max + 3*d
//! = 19847, got 19848`. With `certified` hardwired to `false`, 2 of 3 go red, including
//! `a_comfortable_margin_still_certifies`, which is the only one that can catch a certifier that
//! refuses everything. Both restored.
//!
//! EVERY CONSTANT BELOW IS DERIVED BY HAND FROM THE LEMMA AND WRITTEN AS A LITERAL. None is read
//! back out of the value under test. That is the whole point of the file: if production's
//! arithmetic drifts, these literals do not drift with it.
use acfa_aggregate::{multi_krum_certified, Contribution};

/// `n = 5`, `f = 1`, so `m = n - f - 2 = 2`. One coordinate, so `d = 1`.
/// Values `{0, 1, 604, 1004, Z}` with `Z` far away.
///
/// Hand-derivation of the SCORES (each is the sum of the `m = 2` smallest squared distances):
/// ```text
///   pt 0    : nearest are 1 and 604    ->        1 +  364816 =  364817
///   pt 1    : nearest are 1 and 603    ->        1 +  363609 =  363610
///   pt 604  : nearest are 400 and 603  ->   160000 +  363609 =  523609
///   pt 1004 : nearest are 400 and 1003 ->   160000 + 1006009 = 1166009
/// ```
/// Sorted, the two smallest are `pt 1` then `pt 0`, so the selection is `{0, 1}` and
/// `margin = s[2] - s[1] = 523609 - 364817 = 158792`, INDEPENDENT of `Z`.
///
/// Re-derived a second time on integration, by a scoring routine written from the definitions in
/// `rules.rs` rather than by calling it, over Z in {9922, 9923, 9924, 3000}: the sorted score
/// vector is (363610, 364817, 523609, 1166009, f(Z)) in all four, so `margin` is 158792 in all
/// four, `threshold` is 158776 / 158792 / 158808 / 48024, and solving `158792 == 16Z + 24` gives
/// Z = 9923.0 exactly -- the boundary row below is the boundary, not a value near it. The one
/// correction that pass made was to this table: pt 1's second-nearest term is 603^2 = 363609, so
/// its score is 363610. It is scored[0] and the margin reads scored[2] - scored[1], so the
/// mis-transcribed digit never reached an assertion, but a hand-derivation table that is wrong in
/// one row is not evidence for the rows next to it.
const MARGIN: i128 = 158_792;

fn fixture(z: i64) -> Vec<Contribution> {
    [0i64, 1, 604, 1004, z]
        .iter()
        .enumerate()
        .map(|(i, &v)| Contribution {
            tie_key: (i as u32).to_be_bytes().to_vec(),
            v: vec![v],
        })
        .collect()
}

/// Hand-derived, NOT read from the certificate:
/// `delta_star = 2*l1_max + 3*d = 2Z + 3`, `beta = m*delta_star = 4Z + 6`,
/// `threshold = 4*beta = 16Z + 24`.
fn expected(z: i64) -> (i128, i128, i128) {
    let z = z as i128;
    (2 * z + 3, 4 * z + 6, 16 * z + 24)
}

/// The lemma's three quantities must equal what the lemma says they are. Without this, every other
/// assertion in the suite is relative to whatever production happens to compute.
#[test]
fn the_lemma_constants_are_what_the_lemma_says_they_are() {
    for z in [9922i64, 9923, 9924, 3000] {
        let (_, cert) = multi_krum_certified(&fixture(z), 1).expect("fixture must be served");
        let c = cert.expect("this shape must carry a certificate");
        let (ds, beta, thr) = expected(z);
        assert_eq!(c.l1_max, z as i128, "l1_max must be the spread, Z");
        assert_eq!(
            c.delta_star, ds,
            "Z={z}: delta_star must be 2*l1_max + 3*d = {ds}, got {}",
            c.delta_star
        );
        assert_eq!(
            c.beta, beta,
            "Z={z}: beta must be (n-f-2)*delta_star = {beta}, got {}",
            c.beta
        );
        assert_eq!(
            c.threshold, thr,
            "Z={z}: threshold must be 4*beta = {thr}, got {}",
            c.threshold
        );
    }
}

/// THE MUTATION KILLER. The margin is held CONSTANT at 158792 across all three rows while the
/// threshold sweeps through it in steps of 16, so the ONLY thing that varies is which side of the
/// comparison the pair falls on. The middle row is the exact boundary.
///
/// `margin > threshold` gives false there. `margin >= threshold` gives true -- a certificate
/// asserting the quantised selection provably equals the real-valued one, at the one point where
/// the lemma does NOT establish that.
#[test]
fn certification_is_strict_and_the_exact_boundary_is_not_certified() {
    let cases = [
        (9922i64, true, "margin exceeds threshold by 16"),
        (
            9923,
            false,
            "margin EQUALS threshold -- the strictness boundary",
        ),
        (9924, false, "margin falls short by 16"),
    ];
    for (z, want, why) in cases {
        let (_, cert) = multi_krum_certified(&fixture(z), 1).expect("fixture must be served");
        let c = cert.expect("certificate");
        let (_, _, thr) = expected(z);

        // The fixture must actually be the shape claimed, or the row below asserts nothing.
        assert_eq!(
            c.margin, MARGIN,
            "Z={z}: the margin must not move between rows"
        );
        assert_eq!(
            c.threshold, thr,
            "Z={z}: threshold must be the hand-derived value"
        );

        assert_eq!(
            c.certified, want,
            "Z={z} ({why}): margin={} threshold={}. Certification must be STRICTLY greater-than. \
             A `>=` comparison certifies the exact-equality row, which claims the quantised \
             selection provably matches the real one at precisely the point the lemma leaves open.",
            c.margin, c.threshold
        );
    }
}

/// ACCEPTING TWIN, well clear of the boundary. Without it, both tests above are satisfied by a
/// certifier that returns `false` unconditionally -- a worse defect than the one they guard.
#[test]
fn a_comfortable_margin_still_certifies() {
    let cs: Vec<Contribution> = [0i64, 1, 1000, 2000, 3000]
        .iter()
        .enumerate()
        .map(|(i, &v)| Contribution {
            tie_key: (i as u32).to_be_bytes().to_vec(),
            v: vec![v],
        })
        .collect();
    let (sel, cert) = multi_krum_certified(&cs, 1).expect("served");
    let c = cert.expect("certificate");
    assert_eq!(sel, vec![0, 1], "the tight pair is the selection");
    assert_eq!(c.delta_star, 6_003, "2*3000 + 3");
    assert_eq!(c.beta, 12_006, "2 * 6003");
    assert_eq!(c.threshold, 48_024, "4 * 12006");
    assert_eq!(c.margin, 998_000);
    assert!(
        c.certified,
        "margin 998000 against threshold 48024 must certify -- if this fails the certifier is \
         refusing everything and the boundary tests above prove nothing"
    );
}

// WHAT THIS FILE DOES NOT COVER, stated so its coverage is not read as wider than it is:
//
//   * It pins the constants at `d = 1` and `n = 5` only. The `3*d*delta^2` term is exercised at a
//     single dimension, so a defect in how `d` enters `delta_star` would show up here only through
//     the constant 3, not through its scaling.
//   * It does not test `multi_krum_certified`'s REFUSAL paths; `certified_resource_bounds.rs` owns
//     those.
//   * It says nothing about whether certification is the RIGHT criterion. It pins that the
//     implementation computes the criterion the lemma states, not that the lemma is sound.
//   * The margin's independence from `Z` is a property of THESE fixtures, not a general fact. It
//     holds because `Z` is never among the two nearest neighbours of a selected point.
