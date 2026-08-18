// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `crypto02_key_strength` HALF 3 -- the CLI path.
//!
//! Halves 1 and 2 both live at DECODE time, and the `acfa-verify` CLI never decodes its trust
//! anchor -- `parse_pki` reads it from a TEXT FILE. TWO independent layers now close the CLI
//! path, and this test pins the second:
//!
//!   1. INGRESS (crypto-10). `parse_pki` calls `is_usable_pubkey` on every key, so a small-order
//!      point is refused where it ENTERS -- the door crypto-10 added, symmetric with wire decode.
//!   2. DOWNSTREAM (crypto-02, pinned here). `Receipt::verify`'s full-PKI equality
//!      (`src/receipt.rs`, `PkiMismatch`) compares ids AND keys, so an operator's trust file can
//!      only be USED if it is identical to the one the receipt carries -- and the carried one has
//!      already been through decode. That line is a SECOND-half dependency of crypto-02 exactly
//!      as it is of crypto-03.
//!
//! This test constructs the policy PKI DIRECTLY, bypassing `parse_pki`, so it isolates and pins
//! the downstream layer -- which must hold on its own even though the ingress guard would also
//! stop this key at the CLI.
//!
//! This test exists because `wire.rs::swapping_one_key_in_the_policy_is_enough_to_refuse`
//! was the ONLY thing pinning that line, and it pins it under the FORGED-DEPLOYMENT story.
//! Relaxing the equality turns that one test red, which reads as the cost of a deliberate
//! change and gets paid; the editor then has no signal that crypto-02's CLI path reopened
//! too. N findings resting on one site need N failing tests, not one.
//!
//! VERIFIED IN BOTH DIRECTIONS, and the sibling was verified too rather than assumed:
//! unmodified, both tests here pass. With the equality in `Receipt::verify` relaxed to
//! compare only the id sets (the plausible "rekeying" edit named in that function's own
//! doc comment), EXACTLY TWO tests go red across the crate -- this one and the wire.rs
//! one named above. Run that check with `--no-fail-fast`: cargo stops after the first
//! failing test BINARY, so a plain `cargo test` reports only one of the two and looks
//! like this file is the sole pinner.

use acfa_receipt::identity::{Identity, Pki, PubKey};
use acfa_receipt::{Invalid, Policy, Receipt, Rule, State};

/// A canonical order-8 point: a valid encoding whose order is small.
const SMALL_ORDER: &str = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";

fn unhex32(s: &str) -> PubKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    k
}

fn room(n: u32) -> (Vec<Identity>, Pki) {
    let ids: Vec<Identity> = (1..=n)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    (ids, pki)
}

fn issued(pki: &Pki) -> Receipt {
    // A genuinely issued receipt, so the only thing this test varies is the POLICY's PKI.
    let state = State::new();
    Receipt::issue(&state, 1, pki, 0, Rule::Krum)
}

#[test]
fn crypto02_half3_a_weak_key_trust_file_cannot_be_used_against_a_clean_receipt() {
    let (_ids, clean) = room(3);
    let receipt = issued(&clean);

    // The operator's text file: same identities, but node 3's key swapped for a small-order
    // point. Since crypto-10 `parse_pki` REJECTS such a file at ingress; this test builds the
    // policy PKI directly to isolate the downstream `PkiMismatch` layer, which closes the path
    // even if the ingress guard were absent.
    let mut weak_file = clean.clone();
    weak_file.insert(3, unhex32(SMALL_ORDER));
    assert_ne!(weak_file, clean, "the fixture must actually differ");

    let policy = Policy::new(weak_file, 0);
    assert_eq!(
        receipt.verify(&policy).err(),
        Some(Invalid::PkiMismatch),
        "a trust file carrying a small-order key must be refused; if this fails, the \
         full-PKI equality in Receipt::verify has been relaxed and crypto-02's CLI path \
         is open again (wire.rs::swapping_one_key_in_the_policy_is_enough_to_refuse \
         should be red alongside this -- if it is NOT, the relaxation is narrower than an \
         id-set comparison and you have found a third way through)"
    );
}

#[test]
fn crypto02_half3_accepting_a_matching_clean_trust_file_still_verifies() {
    // Without this the refusal above is satisfied by a verifier that refuses everything.
    let (_ids, clean) = room(3);
    let receipt = issued(&clean);
    let policy = Policy::new(clean, 0);
    assert!(
        receipt.verify(&policy).is_ok(),
        "a matching clean trust file must still verify"
    );
}
