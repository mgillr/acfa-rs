// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! rust-12. `encode` is not total with respect to `decode`: `f` is a `usize` written as a
//! `u32`, so it truncates modulo 2^32 with no error path.
//!
//! THE CONSEQUENCE IS A VERDICT THAT DEPENDS ON WHETHER THE RECEIPT WAS SERIALISED.
//! Measured at `f = 2^32 + 1` against a policy of `f = 1`: in memory the receipt is refused
//! with `FaultBoundMismatch`, and after `encode` + `decode` it is ACCEPTED -- two honest
//! verifiers holding the same receipt reach opposite verdicts. `encode` is also
//! non-injective as a direct result: two receipts differing only in `f` produce identical
//! bytes, so receipt bytes do not determine the receipt.
//!
//! RECONSTRUCTION NOTE: this is a rebuild of B\'s work after A destroyed the original with a
//! blanket `git checkout` in the shared clone. The design is B\'s -- the destroyed symbol was
//! `WireError::FaultBoundTooLarge { f }` and the surviving `acfa-verify` arm (recovered
//! verbatim by C) documents it as an ENCODE-side refusal on a shared enum. If the intent
//! differed, correct it.
use acfa_receipt::identity::{Identity, Pki};
use acfa_receipt::wire::{decode, encode, encode_checked, WireError};
use acfa_receipt::{Receipt, Rule};

fn receipt(f: usize) -> Receipt {
    let id = Identity::from_secret(1, &[1u8; 32]);
    let pki: Pki = [(id.node_id, id.public())].into_iter().collect();
    let mut r = Receipt::issue(
        &acfa_receipt::State::new(),
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        0,
        Rule::Krum,
    );
    r.f = f;
    r
}

/// The guard. A fault bound that does not fit the wire is REFUSED, not truncated.
#[test]
fn the_total_encoder_refuses_a_fault_bound_that_does_not_fit() {
    let too_big = (u32::MAX as usize).checked_add(1);
    let Some(too_big) = too_big else {
        return; // 32-bit target: usize cannot exceed u32, so there is nothing to refuse.
    };
    assert_eq!(
        encode_checked(&receipt(too_big)),
        Err(WireError::FaultBoundTooLarge { f: too_big }),
        "encode_checked must refuse a fault bound the wire cannot carry"
    );
    // POSITIVE CONTROL: a bound that fits must still encode, or the guard is refuse-everything.
    assert!(
        encode_checked(&receipt(1)).is_ok(),
        "encode_checked refused an ordinary fault bound"
    );
    assert_eq!(
        encode_checked(&receipt(u32::MAX as usize)).map(|b| b.len()),
        encode_checked(&receipt(1)).map(|b| b.len()),
        "the boundary value itself must be accepted"
    );
}

/// **CHARACTERISATION TEST** -- it pins the defect that REMAINS. `encode` still truncates,
/// because changing its signature breaks 33 call sites and the ruling on that is not this
/// test\'s to take. When this goes red, `encode` became total and this should be inverted or
/// deleted rather than repaired.
#[test]
fn the_infallible_encoder_still_truncates_and_is_still_non_injective() {
    let Some(too_big) = (u32::MAX as usize).checked_add(1) else {
        return;
    };
    let wrapped = encode(&receipt(too_big));
    let small = encode(&receipt(0));
    assert_eq!(
        wrapped, small,
        "2^32 truncates to 0, so encode is non-injective -- if this differs, encode became total"
    );
    // And the round trip does not return what went in.
    assert_eq!(
        decode(&wrapped).expect("decodes").f,
        0,
        "the decoded fault bound is the truncated one, not the one encoded"
    );
}
