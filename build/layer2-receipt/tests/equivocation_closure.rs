// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The equivocation proof set must be the CLOSURE of the conflicts, not a sample of them.
//!
//! README: "Replicas that received the same contributions in different orders, with
//! duplicates, compute identical bytes." Recording only the first conflicting pair made
//! that false for an identity that equivocates three or more ways.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, State};
use std::collections::BTreeMap;

fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(rnd, &th)),
    }
}

fn room() -> (Identity, Identity, Pki) {
    let liar = Identity::from_secret(1, &[1u8; 32]);
    let honest = Identity::from_secret(2, &[2u8; 32]);
    let mut pki: Pki = BTreeMap::new();
    pki.insert(1, liar.public());
    pki.insert(2, honest.public());
    (liar, honest, pki)
}

/// FAILS ON THE UNFIXED CODE: forward and reversed delivery of a THREE-way equivocation
/// record different proofs, so the state roots differ.
#[test]
fn a_three_way_equivocator_gives_the_same_state_root_in_any_delivery_order() {
    let (liar, honest, pki) = room();
    let halves = [
        contrib(&liar, 7, &[10]),
        contrib(&liar, 7, &[20]),
        contrib(&liar, 7, &[30]),
    ];
    let clean = contrib(&honest, 7, &[1]);

    let mut fwd = State::new();
    for c in halves.iter().cloned() {
        fwd.deliver(c, &pki);
    }
    fwd.deliver(clean.clone(), &pki);

    let mut rev = State::new();
    for c in halves.iter().rev().cloned() {
        rev.deliver(c, &pki);
    }
    rev.deliver(clean, &pki);

    assert_eq!(
        fwd.convicted(&pki),
        rev.convicted(&pki),
        "the same contributions must convict the same identities"
    );
    assert_eq!(
        fwd.root(),
        rev.root(),
        "same contributions, different delivery order, different state root"
    );
}

/// The closure, at the API that builds it: a third half must pair with BOTH halves already
/// held, not with the first one found. FAILS ON THE UNFIXED CODE, which returns one pair.
#[test]
fn a_third_half_pairs_with_every_half_already_held() {
    let (liar, _honest, pki) = room();
    let mut s = State::new();
    s.deliver(contrib(&liar, 7, &[10]), &pki);
    s.deliver(contrib(&liar, 7, &[20]), &pki);

    let third = contrib(&liar, 7, &[30]);
    assert_eq!(
        s.detect_equivocations(&third, &pki).len(),
        2,
        "a third conflicting half pairs with both halves already held"
    );
}

/// The accepting side, so the tests above are not passed by a state that convicts
/// everything: an honest round derives no proofs and convicts nobody.
#[test]
fn an_honest_round_derives_nothing() {
    let (liar, honest, pki) = room();
    let mut s = State::new();
    s.deliver(contrib(&liar, 7, &[10]), &pki);
    let clean = contrib(&honest, 7, &[11]);
    assert!(s.detect_equivocations(&clean, &pki).is_empty());
    s.deliver(clean, &pki);
    assert!(s.convicted(&pki).is_empty());
}
