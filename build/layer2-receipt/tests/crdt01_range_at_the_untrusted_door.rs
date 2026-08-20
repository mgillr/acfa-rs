// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crdt-01 (critical) -- the Q16.16 range bound is enforced at the untrusted door, and
//! SOMETHING NOW TESTS THAT IT IS.
//!
//! The finding: *layer 2 never range-checks the tensor, so one signed contribution panics
//! the shipped `acfa-verify` and silently wraps the aggregate for library consumers.* The
//! bound is `+/-2^31`, and it is what makes the aggregator's `i128` accumulators safe by
//! construction -- an unbounded value reaching them overflows the score accumulator, which
//! is a panic reachable from bytes an attacker chooses.
//!
//! WHY THIS FILE EXISTS RATHER THAN JUST THE GUARD. The guard in `wire::decode` was already
//! present and correct. IT WAS NOT TESTED. Measured by deletion on a fresh clone: replacing
//! the bound check with `if false` left the ENTIRE 118-TEST SUITE GREEN AT EXIT 0, with
//! `decode()` called 15 times in `tests/wire.rs` -- so the path is exercised, and nothing
//! asserted the refusal. A critical finding was closed by a guard that any later edit could
//! delete without turning anything red.
//!
//! That is this repository's signature defect applied to a fix rather than to a check: the
//! remedy was real, and its evidence was absent. These tests are the evidence.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{decode, encode, Contribution, Receipt, Rule, State, WireError};

/// The Q16.16 representable range. A value outside this must never reach the aggregator.
const MAX: i64 = (1i64 << 31) - 1;
const MIN: i64 = -(1i64 << 31);

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn signed(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            rnd,
            a.node_id,
            &th,
        )),
    }
}

/// Build a receipt whose carried tensor holds `v`, and hand back its wire bytes. The
/// contribution is GENUINELY SIGNED -- this is not a forgery, it is a participant sending a
/// value outside the contract, which is the case the finding names.
fn wire_carrying(v: i64) -> Vec<u8> {
    let ids: Vec<Identity> = (1..=5).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        let t = if i == 0 {
            vec![v, 1]
        } else {
            vec![i as i64 * 3, i as i64 + 1]
        };
        s.deliver(signed(id, 1, &t), &pki);
    }
    encode(&Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    ))
}

#[test]
fn a_tensor_value_past_the_q16_16_bound_is_refused_at_decode() {
    for v in [MAX + 1, MIN - 1, i64::MAX, i64::MIN] {
        let bytes = wire_carrying(v);
        assert_eq!(
            decode(&bytes).err(),
            Some(WireError::ValueOutOfRange),
            "decode accepted a tensor value of {v}, outside the Q16.16 range \
             [{MIN}, {MAX}]. This is the UNTRUSTED entry point: an unbounded value reaching \
             the aggregator's i128 score accumulator overflows it, which is a panic \
             reachable from bytes an attacker chooses, and for a library consumer it \
             silently wraps the aggregate instead."
        );
    }
}

/// Without this, the refusal above is satisfied by a decoder that refuses everything -- and
/// the boundary is where an off-by-one lives, so test the extremes that must be ACCEPTED.
#[test]
fn the_extreme_values_inside_the_bound_still_decode() {
    for v in [MAX, MIN, 0, 1, -1] {
        let bytes = wire_carrying(v);
        assert!(
            decode(&bytes).is_ok(),
            "decode REFUSED {v}, which is inside the representable range [{MIN}, {MAX}]. \
             A bound that rejects its own endpoints would make every extreme-but-legal \
             contribution unusable, and this test is what stops the refusal above being \
             satisfied by a decoder that refuses everything."
        );
    }
}
