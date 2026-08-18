// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `Receipt::verify` DERIVES equivocation proofs from the carried contributions, and nothing
//! bounded that work. Linear input, quadratic verifier CPU, chosen entirely by the sender.
//!
//! MEASURED ON THE UNFIXED TREE, one node id repeated, verdict `Ok` every row:
//!
//! ```text
//!     m=50    5.2 KB   0.261 s      m=200   20.4 KB   4.673 s
//!     m=100  10.3 KB   1.123 s      m=400   40.8 KB  18.867 s
//! ```
//!
//! Wire DOUBLES while verify QUADRUPLES. Forty kilobytes buys nineteen seconds of a
//! verifier's CPU and the receipt is accepted.
//!
//! THE INGREDIENT IS ONE SUPPORTED PUBLIC CALL. `State::add_contribution` is a raw insert
//! that runs no detection -- `receipt.rs` says so in its own comment -- so a receipt ISSUED
//! from such a state commits its root to a PROOF-FREE state. The root check then PASSES, and
//! `verify` derives all `m(m-1)/2` proofs itself, each costing a signature verification.
//!
//! WHY NO ORDINARY TEST FINDS IT: every other fixture builds state through `deliver`, which
//! derives proofs as it goes, so the carried set and the derived set already agree and there
//! is nothing left to compute. A comprehensive suite that never calls `add_contribution`
//! directly will report green over this.
//!
//! `State::merge` bounded exactly this quantity already. `verify` did not -- the cap was on
//! the trusted door and the untrusted one was open. The bound is now a single shared
//! function so the two cannot drift.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::state::MAX_MERGE_PROOFS;
use acfa_receipt::{Contribution, Invalid, Policy, Receipt, Rule, State};

/// `m` contributions from ONE node id, inserted RAW so no proofs are derived at build time.
fn raw_state(m: usize) -> (Receipt, Pki) {
    let id = Identity::from_secret(1, &[1u8; 32]);
    let pki: Pki = [(id.node_id, id.public())].into_iter().collect();
    let mut s = State::new();
    for j in 0..m {
        let t = vec![j as i64, (j as i64) * 7 - 3, 1234];
        let sig = id.sign(&contrib_msg(1, &h(&enc_tensor(&t))));
        s.add_contribution(Contribution {
            rnd: 1,
            node_id: id.node_id,
            tensor: t,
            sig,
        });
    }
    (Receipt::issue(&s, 1, &pki, 1, Rule::Krum), pki)
}

/// THE GUARD. Work is refused BEFORE any of it is done.
#[test]
fn a_receipt_that_would_derive_unbounded_proofs_is_refused() {
    // m = 130 derives 130*129/2 = 8,385 proofs -- just over the 8,192 cap, which is the
    // SMALLEST fixture that exercises the bound. Sized deliberately: with the guard deleted
    // this test really performs those derivations, and a larger m makes the guard-deletion
    // proof itself take minutes. The DoS scales; the test of it should not.
    let (r, pki) = raw_state(130);
    let derivable = 130u128 * 129 / 2;
    assert!(
        derivable > MAX_MERGE_PROOFS as u128,
        "fixture must exceed the bound to test anything: {derivable} vs {MAX_MERGE_PROOFS}"
    );
    match r.verify(&Policy::new(pki, 1)) {
        Err(Invalid::TooMuchDerivableWork { would_be, max }) => {
            assert_eq!(max, MAX_MERGE_PROOFS);
            assert!(
                would_be >= MAX_MERGE_PROOFS,
                "the refusal must carry the work it declined: {would_be}"
            );
        }
        other => panic!("expected TooMuchDerivableWork, got {other:?}"),
    }
}

/// POSITIVE CONTROL. A bound that refused every receipt would pass the test above perfectly.
#[test]
fn an_ordinary_receipt_still_verifies() {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        let t = vec![10 + k as i64, 20];
        let sig = id.sign(&contrib_msg(1, &h(&enc_tensor(&t))));
        s.deliver(
            Contribution {
                rnd: 1,
                node_id: id.node_id,
                tensor: t,
                sig,
            },
            &pki,
        );
    }
    let r = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);
    assert!(
        r.verify(&Policy::new(pki, 1)).is_ok(),
        "an honest five-node receipt must still verify"
    );
}

/// The refusal must arrive CHEAPLY. A bound that refuses only after doing the work is not a
/// bound, it is a late error message.
///
/// TWO EARLIER VERSIONS OF THIS TEST WERE WRONG, and both failures are worth keeping:
///
/// 1. A WALL-CLOCK THRESHOLD ("under 1 second") passed in `--release` and FAILED in the debug
///    profile tests actually run under, where the same work is ~25x slower. A timing bound
///    pinned to one profile on one machine is a test about the machine.
/// 2. Comparing a refused receipt against an ACCEPTED one was profile-independent and
///    CORRECT, but the accepted case really derives thousands of proofs -- it took the suite
///    to 242 SECONDS. A four-minute test is a test that gets deleted.
///
/// So this asserts the SCALING of the refusal instead, which is what "before the work"
/// actually means: the bound is arithmetic on counts, so a refusal must cost roughly the
/// SAME whether it declines 19,900 proofs or 79,800. If the guard ran after the work, the
/// larger case would be ~4x the smaller. Both refuse instantly, so the whole test is cheap,
/// and a ratio is immune to both profile and machine.
#[test]
fn the_refusal_does_not_scale_with_the_work_it_declines() {
    let (small, pki_s) = raw_state(130); //  8,385 derivable -- just over the cap
    let (large, pki_l) = raw_state(260); // 33,670 derivable -- 4x the work, same refusal

    let t0 = std::time::Instant::now();
    let vs = small.verify(&Policy::new(pki_s, 1));
    let small_t = t0.elapsed().as_secs_f64();

    let t1 = std::time::Instant::now();
    let vl = large.verify(&Policy::new(pki_l, 1));
    let large_t = t1.elapsed().as_secs_f64();

    assert!(vs.is_err() && vl.is_err(), "both must be refused");
    // 4x the declined work (8,385 -> 33,670). Refused-before-the-work is ~flat; refused-after
    // would be ~4x.
    // The 3x ceiling leaves room for the linear signature check that legitimately precedes
    // the bound, while still failing a quadratic.
    assert!(
        large_t < small_t.max(1e-6) * 3.0,
        "refusing 4x the work took {large_t:.4}s against {small_t:.4}s -- that scales with the \
         work, so the bound is being checked AFTER it rather than before"
    );
}
