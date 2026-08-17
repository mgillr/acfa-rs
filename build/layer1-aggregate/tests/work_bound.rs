// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! rust-02 / rust-03. THE PARTICIPANT CAPS BOUND `n`. THE COST IS A PRODUCT. `d` WAS FREE.
//!
//! `MAX_CONTRIBUTIONS = 4096` and `MAX_CONTRIBUTIONS_BULYAN = 512` bound the contribution
//! count. The Krum path costs `O(n^2 * d)` and Bulyan costs `O(n^3 * d)`, and nothing
//! anywhere bounded `d` -- the doc on `MAX_CONTRIBUTIONS_BULYAN` even names `O(n^3 * d)`
//! while the constant addresses only its first term.
//!
//! MEASURED ON THE SHIPPED BINARY BEFORE THIS BOUND, `n` PINNED AT THE BULYAN CAP:
//!
//! ```text
//!     d=2      21 KB      0.64 s       d=256    2.2 MB    48.02 s
//!     d=16    143 KB      3.33 s       d=512    4.5 MB   133 s
//!     d=64    561 KB     12.29 s       d=1024   8.9 MB   255 s
//! ```
//!
//! Every row accepted. `f` is not the variable: at `n=512, d=64` every `f` from 0 to 126
//! lands between 10.35 s and 11.93 s.
//!
//! AFTER, same binary, same inputs: `d=1024` is refused in 0.06 s and `d=64` in 0.00 s,
//! while `d=2` still aggregates. The worst case the bound now ACCEPTS measured 3.99 s
//! (`krum`, `n=512`, `d=1024`, 8.9 MB of ASCII) -- most of which is parsing, since wire
//! size is linear and unavoidable. The compute ceiling is what moved.
//!
//! These are guards, not characterisation tests: they pin behaviour that must not regress.

use acfa_aggregate::rules::{MAX_CONTRIBUTIONS, MAX_COORDINATE_OPS};
use acfa_aggregate::*;

/// `n` contributions of dimension `d`, all in range, all distinct tie keys.
fn set(n: usize, d: usize) -> Vec<Contribution> {
    (0..n)
        .map(|i| Contribution {
            tie_key: (i as u32).to_be_bytes().to_vec(),
            v: (0..d).map(|k| ((i * 7 + k) % 97) as i64).collect(),
        })
        .collect()
}

/// The bound must be stated in the unit that varies, so `n` alone cannot buy the work.
#[test]
fn a_small_contribution_count_with_a_huge_dimension_is_refused() {
    // Well inside BOTH participant caps -- 64 contributions, and 4096/512 are the limits --
    // yet 64^3 * 65536 is over 1.7e13 coordinate operations.
    let cs = set(64, 65_536);
    let work = 64u128 * 64 * 64 * 65_536;
    assert!(
        work > MAX_COORDINATE_OPS,
        "fixture must exceed the bound to test anything: {work} vs {MAX_COORDINATE_OPS}"
    );
    assert_eq!(
        bulyan_select(&cs, 1),
        Err(AggError::TooMuchWork {
            work,
            max: MAX_COORDINATE_OPS
        }),
        "bulyan must refuse on the PRODUCT, not only on the contribution count"
    );

    // And the Krum path on its own quadratic.
    let cs = set(4096, 1024);
    let work = 4096u128 * 4096 * 1024;
    const { assert!(4096u128 * 4096 * 1024 > MAX_COORDINATE_OPS) };
    assert_eq!(
        multi_krum(&cs, 1),
        Err(AggError::TooMuchWork {
            work,
            max: MAX_COORDINATE_OPS
        })
    );
}

/// POSITIVE CONTROL. A bound that refuses everything would pass the test above perfectly.
#[test]
fn work_inside_the_bound_still_aggregates() {
    let cs = set(64, 512); // 64^3 * 512 = 1.34e8, inside
    const { assert!(64u128 * 64 * 64 * 512 < MAX_COORDINATE_OPS) };
    assert!(
        bulyan_select(&cs, 1).is_ok(),
        "bulyan refused work that is inside the bound"
    );

    let cs = set(512, 1024); // 512^2 * 1024 = 2.7e8, inside
    const { assert!(512u128 * 512 * 1024 < MAX_COORDINATE_OPS) };
    assert!(
        multi_krum(&cs, 1).is_ok(),
        "multi_krum refused work that is inside the bound"
    );

    // Ordinary shapes must be nowhere near it.
    let cs = set(17, 64);
    assert!(mean(&cs).is_ok() && krum_aggregate(&cs, 3).is_ok() && bulyan_select(&cs, 3).is_ok());
}

/// The refusal must carry the numbers, because the whole point is that the operator can see
/// WHICH ceiling they hit and by how much. `TooManyContributions` would have said only that
/// there were too many participants, which for a `d` blow-up is actively misleading.
#[test]
fn the_refusal_names_the_work_and_the_limit() {
    let cs = set(64, 65_536);
    let e = bulyan_select(&cs, 1).expect_err("must refuse");
    let msg = e.to_string();
    for needle in ["17179869184", &MAX_COORDINATE_OPS.to_string()] {
        assert!(
            msg.contains(needle),
            "message drops {needle}, so the operator cannot see what to change: {msg}"
        );
    }
    assert!(
        msg.contains("dimension"),
        "the message must say the dimension is a factor, or the reader reduces n and \
         hits it again: {msg}"
    );
}

/// The participant caps must still fire on their own, so this bound ADDS a ceiling rather
/// than replacing one. `n = 4097` at `d = 1` is inside the work bound and must still be
/// refused for count.
#[test]
fn the_participant_caps_are_not_superseded() {
    let cs = set(4097, 1);
    // Compile-time, so the fixture cannot silently drift to the wrong side of the bound
    // and make this test pass for the wrong reason.
    const { assert!(4097u128 * 4097 < MAX_COORDINATE_OPS) };
    assert_eq!(
        multi_krum(&cs, 1),
        Err(AggError::TooManyContributions {
            n: 4097,
            max: MAX_CONTRIBUTIONS
        }),
        "the count cap must still bite where the work bound does not"
    );
}
