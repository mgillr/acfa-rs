// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `crypto02_key_strength` HALF 4 -- the DECODE INGRESS GUARD ITSELF.
//!
//! `wire::decode` refuses a PKI carrying an unusable public key (`wire.rs`, "pki contains an
//! unusable public key"). MEASURED: deleting that check leaves the layer2-receipt suite at
//! 121 passed 0 failed. The guard is dead to every existing test.
//!
//! That is not for want of trying, and the gap is instructive:
//!   * half 1 calls `verify` directly -- the key never goes through `decode`.
//!   * half 2 calls `is_usable_pubkey` directly. Its doc says "Fails if the ingress
//!     validation in `wire::decode` is removed" -- MEASURED, IT DOES NOT. Calling the
//!     predicate is not exercising the call site that uses it.
//!   * half 3 covers the CLI path through `Receipt::verify`'s PKI equality, which is a
//!     different mechanism reached a different way.
//!
//! Three tests named for one finding, none of them touching the line that enforces it.
//!
//! This one hands `decode` actual BYTES carrying a small-order key, which is the only
//! vantage point from which the ingress guard exists.

use acfa_receipt::identity::{Identity, Pki, PubKey};
use acfa_receipt::receipt::Receipt;
use acfa_receipt::{decode, Rule, State, WireError};

const SMALL_ORDER: &str = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";

fn unhex32(s: &str) -> PubKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    k
}

fn receipt_with(pki: Pki) -> Vec<u8> {
    let st = State::new();
    let r = Receipt::issue(
        &st,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    acfa_receipt::wire::encode(&r)
}

#[test]
fn decode_refuses_a_pki_carrying_an_unusable_key() {
    // A genuine identity, so the receipt is otherwise well formed.
    let good = Identity::from_secret(1, &[7u8; 32]);
    let mut pki: Pki = Pki::new();
    pki.insert(good.node_id, good.public());

    // CONTROL FIRST: the same receipt with only genuine keys must DECODE, or a refusal
    // below would prove nothing about the key at all.
    let clean = receipt_with(pki.clone());
    assert!(
        decode(&clean).is_ok(),
        "a receipt with only genuine keys must decode, or this test cannot discriminate"
    );

    // Now the same shape carrying a small-order key.
    pki.insert(2, unhex32(SMALL_ORDER));
    let hostile = receipt_with(pki);
    match decode(&hostile) {
        Err(WireError::NotCanonical(why)) => {
            assert!(
                why.contains("unusable"),
                "refused for the wrong reason: {why}"
            );
        }
        other => panic!("decode accepted a PKI carrying a small-order key: {other:?}"),
    }
}
