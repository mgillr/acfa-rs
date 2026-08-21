// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `multi_krum_certified` carries its own copies of the two resource guards, and neither had an
//! alarm.
//!
//! FOUND BY MUTATION, not by reading: deleting `if n > MAX_CONTRIBUTIONS` and
//! `if work > MAX_COORDINATE_OPS` **inside `multi_krum_certified` only** left the whole crate at
//! 92 passed / 0 failed, byte-identical to baseline, with a clean build. The guards are present
//! and correct -- what was missing is that removing them changed nothing red.
//!
//! WHY THE SURVIVAL IS A COVERAGE GAP AND NOT A MUTATION THE SUITE CANNOT EXPRESS. The identical
//! guard pair exists FOUR times in this file. Mutating the siblings:
//!
//! | function                | `n > MAX_CONTRIBUTIONS` mutated | result |
//! |-------------------------|--------------------------------|--------|
//! | `multi_krum`            | yes                            | 1 RED, `the_quadratic_matrix_is_bounded` |
//! | `multi_krum_ranked`     | yes                            | 1 RED, `the_ranked_selection_carries_both_caps_too` |
//! | `bulyan_select`         | yes                            | KILLED |
//! | `multi_krum_certified`  | yes                            | **0 RED** |
//!
//! A mutation the suite could not express would survive in all four. It survives in exactly the
//! newest one, which is what a missing witness looks like rather than an inexpressible test.
//!
//! DEMONSTRATED CONSEQUENCE, so the finding rests on an observed behaviour change and not on an
//! absence of red: with both guards deleted, `n = 5000` (over the 4096 cap) returned a fully
//! computed selection; with them restored, the same input returned
//! `TooManyContributions { n: 5000, max: 4096 }`.
//!
//! EACH TEST BELOW HAS AN ACCEPTING TWIN. Without one, both refusal tests are equally satisfied by
//! a `multi_krum_certified` that refuses everything -- which would be a worse defect than the one
//! they were written to catch.
use acfa_aggregate::{multi_krum, multi_krum_certified, AggError, Contribution};

/// Cheap contributions of a requested shape. `d = 1` keeps the over-cap case's allocation small:
/// the point is the guard, not the arithmetic behind it.
fn shape(n: usize, d: usize) -> Vec<Contribution> {
    (0..n)
        .map(|i| Contribution {
            tie_key: (i as u32).to_be_bytes().to_vec(),
            v: (0..d).map(|j| ((i * 7 + j * 13) % 101) as i64).collect(),
        })
        .collect()
}

/// MAX_CONTRIBUTIONS = 4096. Over it, the certified path must refuse for the same reason and with
/// the same payload as the plain path.
#[test]
fn the_certified_path_refuses_too_many_contributions() {
    let cs = shape(5000, 1);
    match multi_krum_certified(&cs, 1) {
        Err(AggError::TooManyContributions { n, max }) => {
            assert_eq!(n, 5000);
            assert_eq!(max, 4096);
        }
        other => panic!(
            "multi_krum_certified accepted {} contributions, over the {} cap, and returned {:?} \
             -- the participant guard on this entry point is not doing anything",
            cs.len(),
            4096,
            other.map(|(sel, _)| sel.len())
        ),
    }
}

/// ACCEPTING TWIN for the participant cap. A guard that refuses everything would satisfy the test
/// above; this one fails if it does.
#[test]
fn the_certified_path_still_serves_a_set_inside_the_participant_cap() {
    let cs = shape(64, 4);
    let (sel, cert) = multi_krum_certified(&cs, 1).expect("an in-cap set must be served");
    assert_eq!(sel.len(), 64 - 1 - 2, "selection size is n - f - 2");
    assert!(
        cert.is_some(),
        "an in-cap set above the select-all band must carry a certificate"
    );
}

/// MAX_COORDINATE_OPS = 1e9 against `krum_work = n^2 * d`. n=1000, d=1001 gives 1.001e9, which is
/// over the cap by the smallest margin that keeps the fixture cheap to build (~8 MB).
#[test]
fn the_certified_path_refuses_too_much_work() {
    let (n, d) = (1000usize, 1001usize);
    assert!(
        (n as u128) * (n as u128) * (d as u128) > 1_000_000_000,
        "precondition: the fixture must actually exceed the work cap, or this test asserts nothing"
    );
    assert!(
        n <= 4096,
        "precondition: must be under the PARTICIPANT cap, so the work guard is \
                        what refuses and not its neighbour"
    );
    let cs = shape(n, d);
    match multi_krum_certified(&cs, 1) {
        Err(AggError::TooMuchWork { work, max }) => {
            assert_eq!(work, (n as u128) * (n as u128) * (d as u128));
            assert_eq!(max, 1_000_000_000);
        }
        other => panic!(
            "multi_krum_certified accepted n={n} d={d} -- {} coordinate ops against a {} cap -- \
             and returned {:?}. The work guard on this entry point is not doing anything.",
            (n as u128) * (n as u128) * (d as u128),
            1_000_000_000u128,
            other.map(|(sel, _)| sel.len())
        ),
    }
}

/// ACCEPTING TWIN for the work cap: just UNDER it, the same shape must be served.
#[test]
fn the_certified_path_still_serves_a_set_inside_the_work_cap() {
    let (n, d) = (300usize, 11usize);
    assert!(
        (n as u128) * (n as u128) * (d as u128) < 1_000_000_000,
        "precondition: this fixture must be inside the cap"
    );
    let (sel, cert) =
        multi_krum_certified(&cs_of(n, d), 1).expect("an in-budget set must be served");
    assert_eq!(sel.len(), n - 1 - 2);
    assert!(cert.is_some(), "and must carry a certificate");
}

fn cs_of(n: usize, d: usize) -> Vec<Contribution> {
    shape(n, d)
}

/// The certified path and the plain path must refuse the SAME inputs. Without this, the two could
/// drift -- one bounded, one not -- and every test above would still pass.
#[test]
fn the_certified_and_plain_paths_refuse_identically() {
    for (n, d) in [(5000usize, 1usize), (1000, 1001)] {
        let cs = shape(n, d);
        let plain = multi_krum(&cs, 1).err();
        let certified = multi_krum_certified(&cs, 1).err();
        assert_eq!(
            plain, certified,
            "n={n} d={d}: the plain path returned {plain:?} and the certified path returned \
             {certified:?}. Both carry their own copies of these guards, so a difference means \
             one of them has stopped enforcing a bound the other still does."
        );
        assert!(
            plain.is_some(),
            "precondition: this shape must be refused at all"
        );
    }
}
