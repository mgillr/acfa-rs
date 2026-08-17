// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `crypto02_key_strength` -- a conjunction, encoded so each half fails on its own site.
//!
//!   HALF 1  `identity::verify` uses `verify_strict`, so a small-order key cannot verify
//!           the forged `R = identity, S = 0` signature
//!   HALF 2  `wire::decode` refuses a PKI containing an unusable key, so such an identity
//!           never enters the trusted set in the first place
//!
//! Neither is sufficient alone: strict verification alone still lets a weak key sit in the
//! PKI occupying an identity slot, and ingress validation alone would leave `verify`
//! permissive for any caller that builds a `Pki` by hand.

use acfa_receipt::identity::{is_usable_pubkey, verify};

/// The eight encodings of points of order dividing 8, which are the weak keys.
const SMALL_ORDER: [[u8; 32]; 3] = [
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    [0u8; 32],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// HALF 1. Fails if `verify` is reverted to the permissive form.
#[test]
fn crypto02_half1_a_small_order_key_cannot_verify_a_forged_signature() {
    // R = identity point, S = 0: the signature nobody needs a secret key to produce.
    let mut forged = [0u8; 64];
    forged[0] = 0x01;

    let mut accepted = 0usize;
    let mut tried = 0usize;
    for pk in SMALL_ORDER.iter() {
        for m in 0..200u32 {
            tried += 1;
            if verify(pk, &m.to_be_bytes(), &forged) {
                accepted += 1;
            }
        }
    }
    assert_eq!(
        accepted, 0,
        "{accepted} of {tried} forged signatures verified against small-order keys -- \
         `verify` rather than `verify_strict` makes an identity anyone can sign for"
    );
}

/// HALF 2. Fails if the ingress validation in `wire::decode` is removed.
#[test]
fn crypto02_half2_weak_keys_are_not_usable_identities() {
    for pk in SMALL_ORDER.iter() {
        assert!(
            !is_usable_pubkey(pk),
            "a small-order point was accepted as a usable identity key"
        );
    }
    // NOT asserted: that arbitrary bytes are rejected. Measured -- `[0xff; 32]` decodes to
    // a VALID, non-weak point, and a point whose discrete log nobody knows is not a forgery
    // risk. The property that matters is smallness of order, not arbitrariness of encoding,
    // and asserting the latter would have been a test of something untrue.
    let genuine = acfa_receipt::identity::Identity::from_secret(9, &[9u8; 32]).public();
    assert!(is_usable_pubkey(&genuine));
}

/// THE ACCEPTING TWIN: real keys still work, and real signatures still verify. Without this
/// the two refusals above are equally satisfied by a verifier that rejects everything.
#[test]
fn crypto02_accepting_real_keys_and_signatures_still_verify() {
    use acfa_receipt::identity::Identity;
    let id = Identity::from_secret(1, &[1u8; 32]);
    let pk = id.public();
    assert!(is_usable_pubkey(&pk), "a genuine key must remain usable");

    let msg = b"ACFA-CONTRIB|round|hash";
    let sig = id.sign(msg);
    assert!(
        verify(&pk, msg, &sig),
        "a genuine signature must still verify"
    );
    assert!(!verify(&pk, b"a different message", &sig));
}
