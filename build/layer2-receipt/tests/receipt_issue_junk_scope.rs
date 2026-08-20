// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Composition defect between the read side and the issue side. `State::admit` (which the
//! aggregate is taken over) SKIPS a bad-signature contribution, but `Receipt::issue` carried
//! the raw state, and `recompute`'s step 1 HARD-FAILS on any carried bad-signature entry. So
//! one unauthenticated contribution merged into a replica's state made every receipt it
//! issued for that round fail verification everywhere -- an availability defect, and a
//! receipt whose committed state root and whose aggregate were over DIFFERENT sets.
//!
//! `issue` now scopes the carried set to `rnd == round && signature_valid`, exactly what
//! `recompute` accepts. On an honest state the filter is a no-op, so the golden vectors and
//! the cross-architecture fingerprint are unchanged.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, Policy, Receipt, Rule, State};

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

fn signed(id: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd,
        node_id: id.node_id,
        tensor: t.to_vec(),
        sig: id.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &PARAMS_DEFAULT,
            rnd,
            id.node_id,
            &th,
        )),
    }
}

/// A receipt issued from a state polluted with ONE unsigned contribution still verifies, and
/// commits to the SAME aggregate as the clean state -- `admit` ignored the junk, so the
/// receipt must not fail on it either.
///
/// GUARD-DELETION: drop the `&& c.signature_valid(pki)` clause from `Receipt::issue`'s carry
/// loop and this test goes RED -- verify returns `BadContributionSignature`, i.e. one junk
/// gossip message nullifies the round's receipt on every checker.
#[test]
fn receipt_issued_over_junk_verifies_and_matches_the_clean_aggregate() {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    // Clean state: five valid contributions for round 1.
    let mut clean = State::new();
    for id in &ids {
        clean.deliver(signed(id, 1, &[10, 20]), &pki);
    }
    let clean_agg = Receipt::issue(
        &clean,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    )
    .verify(&Policy::new(pki.clone(), 1))
    .expect("clean receipt verifies")
    .aggregate;

    // Polluted state: the same five, plus ONE contribution with a known node id but a
    // signature that does not verify -- a junk gossip message an unauthenticated merge let in.
    let mut dirty = clean.clone();
    dirty.add_contribution(Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd: 1,
        node_id: ids[0].node_id,
        tensor: vec![999_000, 999_000],
        sig: [0u8; 64],
    });
    assert_eq!(dirty.c.len(), 6, "the junk really is in the state");

    let verified = Receipt::issue(
        &dirty,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    )
    .verify(&Policy::new(pki, 1))
    .expect("a receipt issued over a junk-polluted state must still verify");
    assert_eq!(
        verified.aggregate, clean_agg,
        "junk must not change the committed aggregate -- admit already ignores it"
    );
}
