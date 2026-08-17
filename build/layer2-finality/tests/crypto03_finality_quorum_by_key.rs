// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crypto-03 at layer2-finality -- the quorum counts KEYS, not ids.
//!
//! `CertTuple::msg` omits the signer, so authorship rests on the PKI's id -> key map being
//! injective. `wire::decode` refuses a non-injective PKI in `acfa-receipt`, but a finality
//! PKI never touches that decoder: `Certificate::check` counted distinct *ids*, and the
//! `acfa-finality` parser rejects a duplicate node_id and NOT a duplicate key. So two ids
//! sharing one key let a SINGLE signature be replayed under both, and `check(pki, f=1)`
//! read `f+1` where only ONE independent key had signed.
//!
//! This FAILS ON THE UNFIXED CODE (`check` counting ids): the replay certifies. On the fix
//! (`check` counting `verified_signer_keys`) it is refused, and a certificate signed by two
//! GENUINELY DISTINCT keys still certifies -- the accepting twin proves the fix does not
//! just reject everything.

use acfa_finality::{CertTuple, Certificate};
use acfa_receipt::hash::h;
use acfa_receipt::identity::{Identity, Pki};

fn tuple() -> CertTuple {
    CertTuple {
        round: 4,
        a_root: h(b"A"),
        e_cut_root: h(b"ecut"),
        rho: h(b"rho"),
    }
}

#[test]
fn one_key_under_two_ids_cannot_alone_satisfy_the_quorum() {
    let holder = Identity::from_secret(1, &[1u8; 32]);
    let mut pki = Pki::new();
    pki.insert(1, holder.public());
    pki.insert(2, holder.public()); // SAME key, second id -- non-injective PKI

    let mut c = Certificate::new(tuple());
    c.sign(&holder); // one genuine signature, as id 1
    let sig = *c.sigs.get(&1).expect("signed");
    c.sigs.insert(2, sig); // replay the SAME bytes under id 2

    // Premise: both ids verify, so the OLD id-count would read 2. If this is not 2 the
    // test is not exercising the bypass.
    assert_eq!(
        c.verified_signers(&pki).len(),
        2,
        "premise: both ids verify against the shared key, so the id-count is 2"
    );

    // The fix: distinct keys is 1, and f+1 = 2 is therefore NOT met.
    assert_eq!(
        c.verified_signer_keys(&pki).len(),
        1,
        "one key signed, however many ids wear it"
    );
    assert!(
        c.check(&pki, 1).is_err(),
        "a round certified on ONE signature replayed under two ids. `check` must count \
         distinct KEYS: the safety argument is that f+1 INDEPENDENT signers guarantee one \
         honest signer per quorum intersection, and one key under two ids collapses f+1 to 1."
    );
}

#[test]
fn two_genuinely_distinct_keys_still_certify() {
    // Without this, the refusal above is satisfied by a `check` that rejects everything.
    let a = Identity::from_secret(1, &[1u8; 32]);
    let b = Identity::from_secret(2, &[2u8; 32]); // a DIFFERENT key
    let mut pki = Pki::new();
    pki.insert(1, a.public());
    pki.insert(2, b.public());

    let mut c = Certificate::new(tuple());
    c.sign(&a);
    c.sign(&b);

    assert_eq!(
        c.verified_signer_keys(&pki).len(),
        2,
        "two distinct keys signed"
    );
    assert!(
        c.check(&pki, 1).is_ok(),
        "f+1 = 2 distinct keys is a real quorum and must certify"
    );
}
