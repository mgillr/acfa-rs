// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! A remote DoS on the UNTRUSTED verify door. `Receipt::verify` derives an equivocation proof
//! for every same-(round,node_id) PAIR in the carried set -- k(k-1)/2 signature verifications
//! -- and nothing bounded it. `State::merge` bounded exactly this on the trusted door; verify
//! did not, so a sender-chosen receipt bought quadratic verifier CPU (measured 81 KB -> 67 s,
//! verdict Ok). Now bounded by the shared `derivable_proof_bound` against `MAX_MERGE_PROOFS`.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::state::{derivable_proof_bound, MAX_MERGE_PROOFS};
use acfa_receipt::{Contribution, Invalid, Policy, Receipt, Rule, State};

fn signed(id: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        rnd,
        node_id: id.node_id,
        tensor: t.to_vec(),
        sig: id.sign(&contrib_msg(rnd, &th)),
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
    let receipt = Receipt::issue(&s, 1, &pki, 0, Rule::Krum);
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
    let receipt = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);
    assert!(
        receipt.verify(&Policy::new(pki, 1)).is_ok(),
        "an honest receipt must still verify"
    );
}
