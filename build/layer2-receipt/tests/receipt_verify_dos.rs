// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! A remote DoS on the UNTRUSTED verify door. `Receipt::verify` derives an equivocation proof
//! for every same-(round,node_id) PAIR in the carried set -- k(k-1)/2 signature verifications
//! -- and nothing bounded it. `State::merge` bounded exactly this on the trusted door; verify
//! did not, so a sender-chosen receipt bought quadratic verifier CPU (measured 81 KB -> 67 s,
//! verdict Ok). `merge` caps BOTH the derivable-proof count AND the contribution count;
//! verify now carries both -- the proof half via `derivable_proof_bound` vs `MAX_MERGE_PROOFS`,
//! and the contribution half via `contributions.len()` vs `MAX_MERGE_CONTRIBUTIONS`. The
//! second half is NOT redundant: an all-distinct-id set derives zero proofs (bound 0) yet
//! still forces the n(n-1)/2 `deliver` scan, so the proof guard alone lets it through.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::state::{derivable_proof_bound, MAX_MERGE_CONTRIBUTIONS, MAX_MERGE_PROOFS};
use acfa_receipt::{Contribution, Invalid, Policy, Receipt, Rule, State};

fn signed(id: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        rnd,
        node_id: id.node_id,
        tensor: t.to_vec(),
        sig: id.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            rnd,
            id.node_id,
            &th,
        )),
    }
}

/// The bound arithmetic: a single (round,node) group of size k contributes k(k-1)/2.
#[test]
fn derivable_proof_bound_is_quadratic_in_a_repeated_node_id() {
    let id = Identity::from_secret(1, &[1u8; 32]);
    // 130 distinct tensors for ONE (round, node) -> one group of 130.
    let cs: Vec<Contribution> = (0..130i64).map(|i| signed(&id, 1, &[i, 0])).collect();
    assert_eq!(derivable_proof_bound(&cs), 130 * 129 / 2);
    assert!(
        derivable_proof_bound(&cs) > MAX_MERGE_PROOFS,
        "premise: this exceeds the cap"
    );
}

/// verify() REFUSES a receipt whose carried set would derive more proofs than the cap, BEFORE
/// doing the quadratic work.
///
/// GUARD-DELETION: remove the `derivable_proof_bound(..) > MAX_MERGE_PROOFS` check from
/// Receipt::verify and this returns Ok after the full derivation instead of TooMuchDerivableWork.
#[test]
fn verify_refuses_a_receipt_that_would_derive_too_much() {
    let id = Identity::from_secret(1, &[1u8; 32]);
    let pki: Pki = [(id.node_id, id.public())].into_iter().collect();

    // 130 same-(round,node) contributions, distinct tensors -> 8385 derivable pairs > 8192.
    let mut s = State::new();
    for i in 0..130i64 {
        s.add_contribution(signed(&id, 1, &[i, 0]));
    }
    let receipt = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        0,
        Rule::Krum,
    );
    assert!(
        receipt.contributions.len() >= 130,
        "the raw set is carried unthinned"
    );

    match receipt.verify(&Policy::new(pki, 0)) {
        Err(Invalid::TooMuchDerivableWork { would_be, max }) => {
            assert!(
                would_be > max,
                "must report the bound it exceeded ({would_be} > {max})"
            );
            assert_eq!(max, MAX_MERGE_PROOFS);
        }
        other => panic!("expected TooMuchDerivableWork refusal, got {other:?}"),
    }
}

/// The bound does not refuse an honest receipt: a normal small carried set verifies.
#[test]
fn verify_still_accepts_an_honest_receipt() {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for id in &ids {
        s.deliver(signed(id, 1, &[1, 2]), &pki);
    }
    let receipt = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    assert!(
        receipt.verify(&Policy::new(pki, 1)).is_ok(),
        "an honest receipt must still verify"
    );
}

/// The ALL-DISTINCT-id half of the verify DoS -- the one the proof-cap guard does NOT
/// catch. A carried set whose node ids are all distinct derives ZERO equivocation proofs,
/// so `derivable_proof_bound` is 0 and the `MAX_MERGE_PROOFS` guard passes -- yet `deliver`
/// still scans every held contribution on each call, so `recompute` does n(n-1)/2 leaf
/// comparisons and returns Ok. Reproduced end to end this session: 12 000 all-distinct
/// contributions verify Ok in 2.4 s, cost unbounded in n.
///
/// GUARD-DELETION: neutralise the `contributions.len() > MAX_MERGE_CONTRIBUTIONS` check at
/// the top of `Receipt::recompute` and this test goes RED -- verify stops refusing at step 0
/// and instead PROCESSES all 4097 carried contributions (measured 49 s of signature
/// verification in a debug build before it even reaches the state-root check), and for a
/// self-consistent issued receipt returns Ok after the full O(n^2) scan (reproduced this
/// session at n = 12 000 -> Ok in 2.4 s release). The derivable-proof guard does NOT cover it
/// -- the bound is 0, asserted below -- so the count cap is a second, independent guard.
#[test]
fn verify_refuses_more_contributions_than_it_will_scan() {
    // ONE key, MANY distinct node ids. Node-id distinctness is the load-bearing property
    // (it sets the derivable-proof bound to 0); the shared key only keeps the test instant.
    // `contrib_msg` does not bind the node id, so a single signature is valid for every
    // node id the PKI points at this key -- the signatures are genuine, so deleting the
    // guard genuinely reaches the scan rather than failing at BadContributionSignature.
    let base = Identity::from_secret(0, &[7u8; 32]);
    let pk = base.public();
    let t = [1i64, 2];
    let th = h(&enc_tensor(&t));
    let sig = base.sign(&contrib_msg(
        &acfa_receipt::identity::NO_CONTEXT,
        1,
        base.node_id,
        &th,
    ));

    let n = MAX_MERGE_CONTRIBUTIONS + 1;
    let pki: Pki = (0..n as u32).map(|id| (id, pk)).collect();
    // Craft the receipt directly -- a received receipt is attacker-chosen bytes, not one
    // this node issued, so a struct literal is the faithful shape. The step-0 count guard
    // fires before `claimed_*` is examined, so those roots are left blank on purpose; this
    // also keeps the test off issue()/resolve's O(n^2) krum path at n = 4097.
    let contributions: Vec<Contribution> = (0..n as u32)
        .map(|id| Contribution {
            ctx: acfa_receipt::identity::NO_CONTEXT,
            sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
            rnd: 1,
            node_id: id,
            tensor: t.to_vec(),
            sig,
        })
        .collect();
    assert_eq!(
        derivable_proof_bound(&contributions),
        0,
        "premise: all node ids distinct -> only the COUNT guard can fire, not the proof guard"
    );
    let receipt = Receipt {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        round: 1,
        f: 0,
        rule: Rule::Krum,
        pki: pki.clone(),
        contributions,
        proofs: Vec::new(),
        claimed_state_root: [0u8; 32],
        claimed_output_root: [0u8; 32],
        claimed_aggregate: None,
    };
    assert_eq!(
        receipt.contributions.len(),
        n,
        "the raw distinct set is carried unthinned"
    );

    match receipt.verify(&Policy::new(pki, 0)) {
        Err(Invalid::TooManyContributions { would_be, max }) => {
            assert_eq!(would_be, n);
            assert_eq!(max, MAX_MERGE_CONTRIBUTIONS);
            assert!(
                would_be > max,
                "must report the bound it exceeded ({would_be} > {max})"
            );
        }
        other => panic!("expected TooManyContributions refusal, got {other:?}"),
    }
}

/// The count guard refuses only ABOVE the cap, so a large-but-bounded distinct set still
/// verifies -- it is not a reject-everything stub, and it exercises the quadratic scan at a
/// size the cap admits.
#[test]
fn verify_admits_a_bounded_distinct_set() {
    let ids: Vec<Identity> = (1..=100u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for id in &ids {
        s.deliver(signed(id, 1, &[1, 2]), &pki);
    }
    let receipt = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    assert!(
        receipt.contributions.len() <= MAX_MERGE_CONTRIBUTIONS,
        "premise: this distinct set (100) is well within the cap"
    );
    assert!(
        receipt.verify(&Policy::new(pki, 1)).is_ok(),
        "a distinct set within the cap must still verify"
    );
}
