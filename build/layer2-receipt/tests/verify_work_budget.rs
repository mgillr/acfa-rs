// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The THIRD door on `Receipt::verify`, and the first one on a PRODUCT.
//!
//! `TooMuchDerivableWork` bounds the derivable-proof count. `TooManyContributions` bounds
//! `n`. Verification cost is proportional to `n * d`, and `d` was bounded by nothing at all
//! beyond `filesize / 8`. Both existing guards therefore PASS on a set of all-distinct node
//! ids carrying long vectors: distinctness puts the derivable-proof bound at ZERO, and the
//! count can sit at a sixteenth of its cap while `d` supplies the whole product.
//!
//! MEASURED ON THE UNFIXED CODE, release, CPU time (`getrusage` user+sys, because the
//! calibration host was shared and its wall clock moved 4x under load while CPU did not).
//! Every row returned `Ok`:
//!
//! ```text
//!    n      d      receipt     verify CPU   peak RSS   derivable   carried    kernel
//!    256   1024     2.04 MiB      1.11 s      19 MiB     0/8192    256/4096   ran
//!    256   8192    16.09 MiB      8.72 s     114 MiB     0/8192    256/4096   ran
//!    256  16384    32.03 MiB     11.78 s     194 MiB     0/8192    256/4096   REFUSED
//!   4096   1024    32.45 MiB     16.18 s     217 MiB     0/8192   4096/4096   REFUSED
//!   4096   2048    64.45 MiB     31.54 s     401 MiB     0/8192   4096/4096   REFUSED
//! ```
//!
//! The `n = 256` rows are the ones to read: 32 MiB of attacker-chosen receipt buys 11.8 s of
//! verifier CPU with BOTH existing guards nowhere near firing. Cost is linear in `d` (fitted
//! exponent 0.99 over d = 64..8192 at n = 256).
//!
//! `MAX_COORDINATE_OPS` does not close it either, for two independent reasons, and the rows
//! above witness both. It fires on the four marked REFUSED -- but `resolve` treats a kernel
//! refusal as a legitimate deterministic OUTCOME (`Err(_) =>` a `"refused|"` root), so it
//! changes the answer rather than the cost and arrives after the work. And on the
//! `n = 256, d = 8192` row the kernel's own quantity `n^2 * d` is 5.4e8, comfortably INSIDE
//! its 1e9 cap, while this door burned 8.7 s: the kernel's number is small exactly where the
//! verifier's is large, so reusing that constant here would not have refused the attack.

use acfa_receipt::hash::{enc_tensor, h};

/// The premise that `derivable_proof_bound == 0` cannot exceed the proof cap, checked at COMPILE
/// time rather than at runtime. As a runtime `assert!` this was a constant expression -- it could
/// never fail, which makes it exactly the kind of assertion that reads as a guard and is not one.
const _: () = assert!(
    MAX_MERGE_PROOFS > 0,
    "the proof cap must be positive, or a derivable bound of 0 could exceed it"
);
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::state::{derivable_proof_bound, MAX_MERGE_CONTRIBUTIONS, MAX_MERGE_PROOFS};
use acfa_receipt::{
    Contribution, Invalid, Policy, Receipt, Rule, State, DEFAULT_MAX_VERIFY_COORDINATES,
};

/// An HONESTLY ISSUED receipt over `n` all-distinct identities carrying `d`-length vectors.
///
/// Honestly issued, not hand-crafted, and that is load-bearing for the twin tests below: a
/// struct literal with blank roots would be refused by the state-root check the moment the
/// work budget let it through, so it could not witness that raising the budget ADMITS the
/// receipt. Distinct keys, because `wire::decode` refuses a PKI that reuses one (crypto-03),
/// and a fixture that cannot survive the decoder is not a faithful untrusted-door attack.
fn attacker_receipt(n: u32, d: usize) -> (Receipt, Pki) {
    let ids: Vec<Identity> = (0..n)
        .map(|id| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&id.to_be_bytes());
            seed[4] = 1;
            Identity::from_secret(id, &seed)
        })
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    let mut state = State::new();
    for id in &ids {
        let t: Vec<i64> = (0..d)
            .map(|k| ((id.node_id as i64 * 7 + k as i64 * 13) % 2048) - 1024)
            .collect();
        let sig = id.sign(&contrib_msg(1, &h(&enc_tensor(&t))));
        state.add_contribution(Contribution {
            rnd: 1,
            node_id: id.node_id,
            tensor: t,
            sig,
        });
    }
    (Receipt::issue(&state, 1, &pki, 1, Rule::Krum), pki)
}

/// 64 contributions of 8192 values: 524 288 coordinates, twice the default budget, and a
/// shape BOTH existing guards wave through.
const N: u32 = 64;
const D: usize = 8192;
const COORDS: u128 = N as u128 * D as u128;

/// The premise, asserted rather than asserted-in-prose: neither existing guard can fire on
/// this shape, so anything that refuses it is the new one.
///
/// GUARD-DELETION: this test does not depend on the fix and stays GREEN when it is removed.
/// It exists to stop a future reader concluding the count cap or the proof cap already
/// covered this, which is the reasoning that left the door open after #57 and #68.
#[test]
fn neither_existing_guard_can_fire_on_an_all_distinct_long_vector_set() {
    let (receipt, _) = attacker_receipt(N, D);

    assert_eq!(
        derivable_proof_bound(&receipt.contributions),
        0,
        "all node ids distinct -> the #57 proof guard's quantity is ZERO, not merely small"
    );
    assert!(
        receipt.contributions.len() <= MAX_MERGE_CONTRIBUTIONS,
        "the #68 count guard cannot fire: {} carried against a cap of {MAX_MERGE_CONTRIBUTIONS}",
        receipt.contributions.len()
    );
    assert!(
        receipt.contributions.len() * 16 <= MAX_MERGE_CONTRIBUTIONS,
        "and it is not a near miss either -- this shape sits at a sixteenth of the cap"
    );

    let coordinates: u128 = receipt
        .contributions
        .iter()
        .map(|c| c.tensor.len() as u128)
        .sum();
    assert_eq!(coordinates, COORDS);
    assert!(
        coordinates > DEFAULT_MAX_VERIFY_COORDINATES,
        "premise: this fixture must exceed the budget to test anything ({coordinates} vs \
         {DEFAULT_MAX_VERIFY_COORDINATES})"
    );
}

/// THE GUARD. `verify` refuses a receipt whose carried coordinates exceed the checker's work
/// budget, and refuses it BEFORE doing any of the work.
///
/// GUARD-DELETION: remove the `coordinates > max_coordinates` check at step 0b of
/// `Receipt::recompute` and this test goes RED -- verify runs the full path over 524 288
/// coordinates and returns `Ok`, because the receipt is honestly issued and every other
/// check passes. Confirmed by deleting exactly that block and re-running: 4 of the 7 tests
/// in this file fail, this one with `expected TooMuchCoordinateWork refusal, got Ok(..)`.
#[test]
fn verify_refuses_a_receipt_over_the_work_budget() {
    let (receipt, pki) = attacker_receipt(N, D);

    match receipt.verify(&Policy::new(pki, 1)) {
        Err(Invalid::TooMuchCoordinateWork { coordinates, max }) => {
            assert_eq!(coordinates, COORDS);
            assert_eq!(max, DEFAULT_MAX_VERIFY_COORDINATES);
            assert!(
                coordinates > max,
                "must report the bound it exceeded ({coordinates} > {max})"
            );
        }
        other => panic!("expected TooMuchCoordinateWork refusal, got {other:?}"),
    }
}

/// The refusal runs BEFORE the signature loop, not merely early in the function.
///
/// A receipt whose signatures are all garbage would fail at step 1 with
/// `BadContributionSignature` if step 1 ran first. It must fail with the work refusal
/// instead, because step 1 is exactly the `O(n * d)` work the budget exists to prevent: it
/// hashes every tensor to rebuild the signed message. This is the ordering claim, and it is
/// the difference between a bound and a label.
///
/// GUARD-DELETION: remove the check and this goes RED with `BadContributionSignature` --
/// which is the unfixed code proving it hashed all 524 288 coordinates before deciding.
#[test]
fn the_work_refusal_precedes_the_signature_loop() {
    let (mut receipt, pki) = attacker_receipt(N, D);
    for c in &mut receipt.contributions {
        c.sig = [0u8; 64];
    }
    assert!(
        matches!(
            receipt.verify(&Policy::new(pki, 1)),
            Err(Invalid::TooMuchCoordinateWork { .. })
        ),
        "the budget must be checked before any tensor is hashed"
    );
}

/// The refusal names the number an operator would raise it to, not only the number exceeded.
///
/// `TooMuchDerivableWork` and `TooManyContributions` both report a `would_be` against a
/// compile-time `max` an operator cannot change without forking. This bound IS changeable,
/// so the message has to carry the argument, or the knob is undiscoverable from the failure.
#[test]
fn the_refusal_names_the_number_to_raise() {
    let (receipt, pki) = attacker_receipt(N, D);
    let e = receipt
        .verify(&Policy::new(pki, 1))
        .expect_err("must refuse");
    let msg = e.to_string();

    assert!(
        msg.contains(&COORDS.to_string()),
        "the refusal must print the count that admits this receipt: {msg}"
    );
    assert!(
        msg.contains(&DEFAULT_MAX_VERIFY_COORDINATES.to_string()),
        "and the budget it exceeded: {msg}"
    );
    assert!(
        msg.contains("with_max_coordinates") && msg.contains("--max-coordinates"),
        "and both spellings of the knob, library and CLI: {msg}"
    );
}

/// THE ACCEPTING TWIN, HALF ONE: the budget is the CHECKER'S, and raising it to the number
/// the refusal printed admits the SAME receipt -- through the whole path, aggregate and all.
///
/// Without this the guard could be a reject-everything stub and every other test here would
/// still pass. It also pins the refusal as being about the BUDGET and not about the receipt
/// being malformed: the identical bytes verify once the ceiling moves.
#[test]
fn raising_the_budget_admits_the_same_receipt() {
    let (receipt, pki) = attacker_receipt(N, D);

    let v = receipt
        .verify(&Policy::new(pki, 1).with_max_coordinates(COORDS))
        .expect("the same receipt must verify once the checker allows the work");
    assert_eq!(v.admitted.len(), N as usize);
    assert!(
        v.aggregate.is_some(),
        "the raised budget must let the FULL path run, not just get past step 0b"
    );
}

/// THE ACCEPTING TWIN, HALF TWO: a legitimate large receipt still verifies under the DEFAULT
/// budget, with nothing raised.
///
/// `n = 25, d = 10 000` is 250 000 coordinates and a 2 MiB receipt -- the largest shape this
/// crate's own `examples/scale.rs` treats as legitimate, and one of the two constraints the
/// default was chosen from. It clears the default by 5%, which is thin on purpose: the
/// default is set where real use stops, not comfortably past it.
#[test]
fn a_legitimate_large_receipt_still_verifies_under_the_default_budget() {
    let (receipt, pki) = attacker_receipt(25, 10_000);

    let coordinates: u128 = receipt
        .contributions
        .iter()
        .map(|c| c.tensor.len() as u128)
        .sum();
    assert_eq!(coordinates, 250_000);
    assert!(
        coordinates <= DEFAULT_MAX_VERIFY_COORDINATES,
        "premise: this legitimate shape is inside the default budget"
    );
    assert!(
        acfa_receipt::encode(&receipt).len() > 1024 * 1024,
        "premise: the accepting twin must be genuinely LARGE, or it witnesses nothing"
    );

    let v = receipt
        .verify(&Policy::new(pki, 1))
        .expect("a large-but-budgeted receipt must still verify");
    assert_eq!(v.admitted.len(), 25);
    assert!(v.aggregate.is_some(), "the full path must have run");
}

/// `Policy::new` installs the default rather than "unlimited", and `check_self_consistent`
/// -- which takes no policy at all -- is bounded by the same number.
///
/// The second half is the one that matters: `acfa-verify` reaches
/// `check_self_consistent` whenever `--pki` is omitted, so an unbounded diagnosis path would
/// be the same door under another name, reachable by leaving a flag off.
///
/// GUARD-DELETION: change `Policy::new` to install `u128::MAX`, or give
/// `check_self_consistent` an exemption, and this goes RED.
#[test]
fn the_default_is_fail_closed_on_both_entry_points() {
    let (receipt, pki) = attacker_receipt(N, D);

    assert_eq!(
        Policy::new(pki, 1).max_coordinates,
        DEFAULT_MAX_VERIFY_COORDINATES,
        "a checker that never thought about work must still have a bounded door"
    );
    assert!(
        matches!(
            receipt.check_self_consistent(),
            Err(Invalid::TooMuchCoordinateWork { .. })
        ),
        "the no-policy diagnosis path is a door too -- it is what acfa-verify uses \
         without --pki"
    );
}
