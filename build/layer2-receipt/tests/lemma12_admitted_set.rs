// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Lemma 12 across the layer boundary: the certificate must describe the set that produced
//! the aggregate.
//!
//! The paper states `beta := (|A| - f - 2) * Delta*` over the ADMITTED set `A`. The kernel
//! computes `(n - f - 2)` over the slice it is handed, and those agree only because Layer 2
//! hands down `admit()`'s output. The dangerous edit -- identified by C in adversarial review
//! before the wiring was written -- is to compute the certificate over a receipt's RAW CARRIED
//! contributions instead. That set is a superset whenever anything was excluded or convicted,
//! so it is a different problem instance from the one that produced the shipped aggregate, and
//! a certificate about it would be a statement about a selection nobody performed.
//!
//! These tests pin the two sets apart and then check the certificate tracks the right one.

use acfa_aggregate::{multi_krum_certified, Contribution as AggContribution};
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, Policy, Receipt, Rule, State};

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

/// An equivocator's contributions are CARRIED (they are the evidence) but NOT ADMITTED.
/// The certificate must be computed over the admitted set only.
///
/// GUARD-DELETION: in `resolve`, build `cs` from `state.c.values()` instead of from
/// `state.admit(rnd, pki)` and this goes RED -- the certificate starts describing a selection
/// over a set two contributions larger than the one the aggregate came from.
#[test]
fn certificate_is_computed_over_the_admitted_set_not_the_carried_set() {
    let ids: Vec<Identity> = (1..=7u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    let mut s = State::new();
    // Six honest contributors, deliberately close together so the boundary is interesting.
    for (k, id) in ids.iter().take(6).enumerate() {
        s.deliver(signed(id, 1, &[100 + k as i64, 200 - k as i64]), &pki);
    }
    // The seventh EQUIVOCATES: two conflicting contributions in the same round. Both are
    // carried (they are the proof) and neither is admitted.
    s.deliver(signed(&ids[6], 1, &[9_000, 9_000]), &pki);
    s.deliver(signed(&ids[6], 1, &[-9_000, -9_000]), &pki);

    let receipt = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    assert_eq!(receipt.contributions.len(), 8, "all eight are carried");

    let v = receipt
        .verify(&Policy::new(pki.clone(), 1))
        .expect("receipt verifies");
    assert_eq!(v.admitted.len(), 6, "the equivocator's pair is excluded");
    let got = v
        .margin
        .expect("krum on a non-empty admitted set yields a certificate");

    // The certificate the ADMITTED set implies, computed directly from the kernel.
    let admitted_cs: Vec<AggContribution> = {
        let mut adm: Vec<&Contribution> = receipt
            .contributions
            .iter()
            .filter(|c| v.admitted.contains(&c.node_id))
            .collect();
        adm.sort_by_key(|c| c.leaf());
        adm.iter()
            .map(|c| AggContribution {
                tie_key: c.leaf().to_vec(),
                v: c.tensor.clone(),
            })
            .collect()
    };
    let (_, want) = multi_krum_certified(&admitted_cs, 1).unwrap();
    assert_eq!(
        got,
        want.expect("boundary exists at n=6, f=1"),
        "the certificate must be the one the ADMITTED set implies"
    );

    // And it must NOT be the one the full carried set implies -- otherwise this test could
    // pass with the bug present because the two happened to coincide.
    let carried_cs: Vec<AggContribution> = {
        let mut all: Vec<&Contribution> = receipt.contributions.iter().collect();
        all.sort_by_key(|c| c.leaf());
        all.iter()
            .map(|c| AggContribution {
                tie_key: c.leaf().to_vec(),
                v: c.tensor.clone(),
            })
            .collect()
    };
    let (_, carried_cert) = multi_krum_certified(&carried_cs, 1).unwrap();
    assert_ne!(
        got,
        carried_cert.expect("boundary exists at n=8, f=1"),
        "PREMISE: the two sets must imply DIFFERENT certificates, or this test proves nothing"
    );
}

/// Bulyan yields no certificate: Lemma 12 is stated for multi-Krum's selection boundary, and
/// silently reusing it for Bulyan's iterated selection would be a claim the paper does not make.
#[test]
fn bulyan_yields_no_certificate_rather_than_a_borrowed_one() {
    let ids: Vec<Identity> = (1..=9u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        s.deliver(signed(id, 1, &[10 + k as i64, 20]), &pki);
    }
    let receipt = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Bulyan,
    );
    let v = receipt.verify(&Policy::new(pki, 1)).expect("verifies");
    assert!(
        v.margin.is_none(),
        "Bulyan must report no certificate, not a multi-Krum one"
    );
}

/// The certificate is recomputed by the verifier, so two independent verifications of the
/// same bytes agree -- there is nothing on the wire for an issuer to forge or omit.
#[test]
fn certificate_is_reproducible_from_the_receipt_bytes_alone() {
    let ids: Vec<Identity> = (1..=6u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        s.deliver(signed(id, 1, &[5 + k as i64, 7]), &pki);
    }
    let receipt = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    let bytes = acfa_receipt::wire::encode(&receipt);
    let decoded = acfa_receipt::decode(&bytes).expect("round-trips");

    let a = receipt.verify(&Policy::new(pki.clone(), 1)).unwrap().margin;
    let b = decoded.verify(&Policy::new(pki, 1)).unwrap().margin;
    assert_eq!(
        a, b,
        "the certificate must survive an encode/decode round trip"
    );
    assert!(a.is_some(), "premise: this configuration has a certificate");
}
