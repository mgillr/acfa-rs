// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Two guards on the VERIFY door that nothing witnessed, found by mutation sweep and confirmed
//! over three independent serial runs.
//!
//! Both survived deletion with the entire suite green, and neither is an inert line -- each was
//! shown non-equivalent by constructing the attack it exists to refuse.
//!
//! **`recompute`'s round binding.** Delete it and a correctly-signed contribution from ANOTHER
//! round, smuggled into this receipt with `claimed_state_root` recomputed over the enlarged set,
//! verifies `Ok`. The subtle part is what that buys: `resolve` still filters the foreign-round
//! entry out of ADMISSION, so the receipt's committed state root covers a set the aggregate was
//! never taken over. That is the verifier half of exactly the composition defect the long comment
//! in `Receipt::issue` describes fixing on the issuer side -- the issuer half was fixed and
//! witnessed, and the verifier half was neither.
//!
//! **`recompute`'s output-root check.** Delete it and a tampered `claimed_output_root` is
//! accepted. Worse than a silent accept: `Verified.output_root` is populated from the RECOMPUTED
//! value rather than from the claim, so an operator following this project's own documented
//! withholding mitigation -- compare the verified output root against one obtained independently
//! -- would be shown the honest value and would never learn the receipt had claimed something
//! else. The tamper is not merely accepted, it is masked.
//!
//! Also here: a DIRECT assertion on `Verified.admitted` ordering. That canonicalisation was
//! already killed by a mutant, but only INDIRECTLY, via the redacted-receipt equality test. A
//! guard whose only witness is a side effect of an unrelated test is one refactor away from being
//! unwitnessed again, and the ordering is load-bearing because `State.c` is keyed by leaf hash,
//! so node ids arrive in hash order and not ascending.
//!
//! NOT INCLUDED, deliberately: `convictable.sort_unstable()`. `State::convicted` returns a
//! `BTreeSet<u32>`; `into_iter` yields ascending, `filter` preserves order and `collect` preserves
//! it, so that vector is already sorted for EVERY possible input. The mutant is equivalent by
//! construction, no test can kill it, and writing one would be theatre.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, Invalid, Policy, Receipt, Rule, State};

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

fn fixture() -> (Vec<Identity>, Pki, Receipt) {
    let ids: Vec<Identity> = (1..=6u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        s.deliver(signed(id, 1, &[100 + k as i64, 200 - k as i64]), &pki);
    }
    let r = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    (ids, pki, r)
}

/// A correctly-signed contribution from another round must be refused, even when the committed
/// state root is honestly recomputed over the set that includes it.
///
/// GUARD-DELETION: remove the `if c.rnd != self.round { return Err(WrongRound) }` arm from
/// `Receipt::recompute` and this goes RED -- the smuggled receipt returns
/// `Ok(Verified { round: 1, .. })`.
#[test]
fn a_foreign_round_contribution_is_refused_even_with_a_recomputed_state_root() {
    let (ids, pki, mut r) = fixture();
    r.contributions.push(signed(&ids[0], 2, &[7_777, -7_777]));
    // Recompute the commitment over the ENLARGED set, so the state-root check cannot be what
    // refuses this. Only the round binding can.
    let mut s = State::new();
    for c in &r.contributions {
        s.add_contribution(c.clone());
    }
    for p in &r.proofs {
        s.add_proof(p.clone());
    }
    r.claimed_state_root = s.root();

    match r.verify(&Policy::new(pki, 1)) {
        Err(Invalid::WrongRound { expected, found }) => {
            assert_eq!(expected, 1);
            assert_eq!(found, 2);
        }
        other => {
            panic!("a foreign-round contribution must be refused as WrongRound, got {other:?}")
        }
    }
}

/// The honest receipt this attack is built from must still verify, so the test above cannot pass
/// by refusing everything.
#[test]
fn the_unmodified_fixture_receipt_still_verifies() {
    let (_ids, pki, r) = fixture();
    assert!(r.verify(&Policy::new(pki, 1)).is_ok());
}

/// A tampered claimed output root must be refused, not silently masked by the recomputed value.
///
/// GUARD-DELETION: remove the `if r.output_root != self.claimed_output_root` arm from
/// `Receipt::recompute` and this goes RED -- verification returns `Ok` and `Verified.output_root`
/// reports the honest recomputation, hiding that the receipt claimed something else.
#[test]
fn a_tampered_claimed_output_root_is_refused() {
    let (_ids, pki, mut r) = fixture();
    let honest = r.claimed_output_root;
    r.claimed_output_root[0] ^= 0xff;
    match r.verify(&Policy::new(pki, 1)) {
        Err(Invalid::OutputRootMismatch { claimed, actual }) => {
            assert_eq!(
                claimed, r.claimed_output_root,
                "must report what the receipt CLAIMED"
            );
            assert_eq!(actual, honest, "and what recomputation actually gives");
            assert_ne!(claimed, actual);
        }
        other => {
            panic!("a tampered output root must be refused as OutputRootMismatch, got {other:?}")
        }
    }
}

/// `Verified.admitted` is canonically ordered, asserted DIRECTLY rather than as a side effect of
/// the redacted-receipt equality test.
///
/// This matters because `State.c` is a `BTreeMap` keyed by LEAF HASH, so contributions arrive in
/// hash order; without the sort the admitted node ids come out in an order that depends on hash
/// values, which is deterministic but not canonical and not what a reader expects.
///
/// GUARD-DELETION: remove `admitted.sort_unstable()` from `Receipt::recompute` and this goes RED
/// by name, rather than surfacing three files away in a test about redaction.
#[test]
fn the_admitted_set_is_reported_in_ascending_node_id_order() {
    let (_ids, pki, r) = fixture();
    let v = r.verify(&Policy::new(pki, 1)).expect("fixture verifies");
    let mut sorted = v.admitted.clone();
    sorted.sort_unstable();
    assert_eq!(
        v.admitted, sorted,
        "admitted must be ascending; State.c is keyed by leaf hash so insertion order is not"
    );
    assert_eq!(
        v.admitted,
        vec![1, 2, 3, 4, 5, 6],
        "and this fixture admits all six"
    );
}
