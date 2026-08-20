// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! One key is one identity, enforced rather than assumed.
//!
//! `contrib_msg` binds the round and the tensor hash but NOT the signer, so authorship
//! rests entirely on the PKI's id -> key map being injective. Nothing enforced that. A
//! PKI registering a second id to an honest node's key let anyone REPLAY that node's
//! signed bytes under the extra identity, holding no secret key at all.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::wire::{decode, encode, WireError};
use acfa_receipt::{Contribution, Receipt, Rule, State};
use std::collections::BTreeMap;

/// Krum at `f = 1` on this build's fixed-point scale.
///
/// A NAMED FIXTURE, NOT A DEFAULT. A contribution signed under different round parameters is
/// filtered out of the round by `Receipt::issue`, exactly as a foreign `ctx` is, so a test that
/// needs other parameters has to say so rather than inherit these silently.
const PARAMS_DEFAULT: acfa_receipt::RoundParams = acfa_receipt::RoundParams {
    rule: acfa_receipt::Rule::Krum,
    f: 1,
    frac_bits: acfa_receipt::FRAC_BITS,
};

fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &PARAMS_DEFAULT,
            rnd,
            a.node_id,
            &th,
        )),
    }
}

/// FAILS ON THE UNFIXED CODE: `decode` accepted the non-injective PKI and returned Ok.
#[test]
fn a_pki_that_reuses_one_key_for_two_identities_is_refused_at_decode() {
    let honest = Identity::from_secret(1, &[1u8; 32]);
    let other = Identity::from_secret(9, &[9u8; 32]);

    let mut pki: Pki = BTreeMap::new();
    pki.insert(1, honest.public());
    pki.insert(2, honest.public()); // the same key, a second identity
    pki.insert(3, other.public());

    let mut s = State::new();
    s.deliver(contrib(&honest, 7, &[10, 20]), &pki);
    let bytes = encode(&Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        7,
        &pki,
        0,
        Rule::Krum,
    ));

    assert_eq!(
        decode(&bytes).err(),
        Some(WireError::NotCanonical("pki reuses a public key")),
        "a PKI in which one key holds two identities must not decode"
    );
}

/// The accepting side, so the refusal above is not vacuous: an injective PKI still decodes.
#[test]
fn an_injective_pki_still_decodes() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let b = Identity::from_secret(2, &[2u8; 32]);

    let mut pki: Pki = BTreeMap::new();
    pki.insert(1, a.public());
    pki.insert(2, b.public());

    let mut s = State::new();
    s.deliver(contrib(&a, 7, &[10, 20]), &pki);
    s.deliver(contrib(&b, 7, &[11, 21]), &pki);
    let bytes = encode(&Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        7,
        &pki,
        0,
        Rule::Krum,
    ));

    assert!(
        decode(&bytes).is_ok(),
        "a well-formed PKI must still decode"
    );
}

// ------------------------------------------------------- crypto-09-3

/// `required_n` took `f` from an untrusted receipt and computed `2f+3` in `usize`, which
/// WRAPPED. At `f = usize::MAX` the bound came out as 1, so the population check passed on
/// a single admitted contribution: the guard failed OPEN, and got weaker as the claimed
/// adversary budget grew.
///
/// FAILS ON THE UNFIXED CODE: the bound is 1 (Krum) and 3 (Bulyan).
#[test]
fn the_population_bound_saturates_rather_than_wrapping() {
    use acfa_receipt::Rule;

    // Honest values are unchanged.
    assert_eq!(Rule::Krum.required_n(1), 5);
    assert_eq!(Rule::Krum.required_n(3), 9);
    assert_eq!(Rule::Bulyan.required_n(1), 7);

    // Adversarial values must be UNMEETABLE, never small.
    // `1usize << 62` does not COMPILE on a 32-bit target -- usize is 32 bits there and the
    // shift is a deny-by-default overflow, so this test broke the i386 and armv7 builds
    // while passing everywhere else. Deriving the value from usize::BITS keeps the intent
    // (a large power of two well inside the type) on every width. This is the same
    // target-width assumption the suite exists to catch, reintroduced by a test written to
    // catch it.
    for f in [
        usize::MAX,
        usize::MAX - 1,
        usize::MAX / 2,
        1usize << (usize::BITS - 2),
    ] {
        let k = Rule::Krum.required_n(f);
        let b = Rule::Bulyan.required_n(f);
        assert!(
            k >= f && b >= f,
            "f={f}: bound wrapped to krum={k}, bulyan={b} -- a larger claimed fault bound \
             must never produce a SMALLER population requirement"
        );
    }
}

// ------------------------------------------------------- crypto-04

/// The anti-framing guard must survive widening the equivocation predicate.
///
/// `EquivProof::valid` used to reject any proof with `h1 == h2`, which also rejected the
/// real case of two DISTINCT valid signatures over the SAME content. The guard now rejects
/// only `(h1, sig1) == (h2, sig2)` -- the same entry twice. This test pins the half that
/// must NOT change: one honest contribution, paired with itself, still cannot convict its
/// own author.
#[test]
fn an_entry_paired_with_itself_still_cannot_convict_its_author() {
    use acfa_receipt::entry::EquivProof;
    use acfa_receipt::hash::{enc_tensor, h};
    use acfa_receipt::identity::{contrib_msg, Identity, Pki};

    let honest = Identity::from_secret(1, &[1u8; 32]);
    let mut pki: Pki = BTreeMap::new();
    pki.insert(1, honest.public());

    let th = h(&enc_tensor(&[10, 20]));
    let sig = honest.sign(&contrib_msg(
        &acfa_receipt::identity::NO_CONTEXT,
        &PARAMS_DEFAULT,
        7,
        honest.node_id,
        &th,
    ));

    // The forgery the guard exists to stop: one real entry, presented as both halves.
    let self_paired = EquivProof::canonical(
        acfa_receipt::identity::NO_CONTEXT,
        acfa_receipt::identity::PreimageVersion::V2,
        PARAMS_DEFAULT,
        7,
        1,
        (th, sig),
        (th, sig),
    );
    assert!(
        !self_paired.valid(&pki),
        "an entry paired with itself convicted its own author"
    );
}
