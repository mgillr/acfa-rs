// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crypto-04 -- FAILING-FIRST evidence that detection must key on the LEAF, not the content.
//!
//! Ed25519 verification checks `S*B == R + H(R,A,M)*A`. NOTHING IN THAT EQUATION PINS `R`.
//! RFC 8032 chooses the nonce deterministically as a hygiene measure, so determinism is a
//! property of the SIGNER's discipline and never of the SCHEME. A malicious signer can
//! therefore emit TWO DISTINCT VALID SIGNATURES over ONE message.
//!
//! `Contribution::leaf` covers the signature, so those are two distinct leaves by one
//! identity in one round, and `admit` already excludes that identity on leaf uniqueness.
//! Detection used to key on the TENSOR HASH, which is EQUAL for both. The consequence was
//! not a missed exclusion -- it was an exclusion WITH NO ACCOUNTABILITY ARTEFACT: the node
//! was dropped from the round and nothing on the record said why, so an observer cannot
//! distinguish a node caught double-signing from one that simply went quiet. In a system
//! whose proposition is that misbehaviour leaves self-authenticating evidence, that is the
//! defect. `uc1` already documents the forward direction (not selected is not an
//! accusation); this is the undocumented reverse.
//!
//! THIS TEST FAILS ON THE OLD PREDICATE (`c.tensor_hash() != nh`) and passes on the new one
//! (`c.leaf() != nl`). Verified in both directions.
//!
//! WHY FIXED VECTORS. The crate's signer is deterministic by construction, so it CANNOT
//! produce the second signature -- generating one needs chosen-nonce signing and a
//! dependency this crate does not have and does not need. The constants below were produced
//! out-of-tree and are validated here against this crate's own verifier before use.
//!
//! HONEST LIMIT: these are fixed vectors over a FIXED PREIMAGE. If `contrib_msg` or
//! `enc_tensor` ever changes, they go stale. `fixtures_are_still_live` exists so that a
//! moved preimage fails with a message saying REGENERATE THE FIXTURES rather than
//! masquerading as a broken fix.

use acfa_receipt::entry::Contribution;
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, verify, Identity, Pki, Sig};
use acfa_receipt::State;

/// Node 1 = `Identity::from_secret(1, &[1; 32])`, round 1, tensor `[1, 2]`.
/// Two distinct valid signatures over the one `contrib_msg` preimage.
const SIG_A: &str = "951680142c2862263a73890c83af6c793706db2169a0555e3b83c566f50bb555\
                     39894ac9652841c89a9f7131184ed272c437c760934b83fdc0800f1aa2744d0a";
const SIG_B: &str = "07e211f61344dd897e196f534890ec8807bc5283f59e1bf308a5f8c9f816773e\
                     03fdd04555747a09dbcc75dc8dd9ec0033a041200c12646715d698b99d6b7d0e";

fn unhex64(s: &str) -> Sig {
    let mut out = [0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn setup() -> (Identity, Pki, Vec<u8>) {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let pki: Pki = [(1u32, a.public())].into_iter().collect();
    let msg = contrib_msg(1, &h(&enc_tensor(&[1i64, 2i64])));
    (a, pki, msg)
}

fn contrib(sig: Sig) -> Contribution {
    Contribution {
        rnd: 1,
        node_id: 1,
        tensor: vec![1, 2],
        sig,
    }
}

/// Run this before believing anything below. A failure here means the SIGNED PREIMAGE
/// MOVED, not that the fix regressed.
#[test]
fn fixtures_are_still_live() {
    let (a, _pki, msg) = setup();
    let (sa, sb) = (unhex64(SIG_A), unhex64(SIG_B));

    assert!(
        verify(&a.public(), &msg, &sa) && verify(&a.public(), &msg, &sb),
        "FIXTURES ARE STALE, NOT BROKEN: the constants in this file are signatures over \
         contrib_msg(1, h(enc_tensor([1,2]))). One of those two functions has changed, so \
         the vectors no longer match the preimage. REGENERATE THEM against the new \
         definition -- this is not a failure of the crypto-04 fix."
    );
    assert_ne!(
        sa, sb,
        "the two fixtures must actually differ, or this file tests nothing"
    );

    // The vectors are only interesting because the crate's own signer cannot make them.
    let deterministic = a.sign(&msg);
    assert_eq!(
        deterministic,
        a.sign(&msg),
        "this crate's signer is deterministic"
    );
    assert!(
        deterministic == sa || deterministic == sb,
        "one fixture should be the RFC 8032 signature this crate produces; if neither is, \
         the honest signer's output has changed and these vectors need regenerating"
    );

    // A verifier that accepts anything would satisfy every assertion above.
    let mut bent = sa;
    bent[0] ^= 1;
    assert!(
        !verify(&a.public(), &msg, &bent),
        "NEGATIVE CONTROL: a bent signature must fail"
    );
    let wrong_round = contrib_msg(2, &h(&enc_tensor(&[1i64, 2i64])));
    assert!(
        !verify(&a.public(), &wrong_round, &sa),
        "NEGATIVE CONTROL: a valid signature must not verify under a different round"
    );
}

#[test]
fn crypto04_two_signatures_over_one_content_must_leave_a_proof() {
    let (_a, pki, _msg) = setup();
    let (c1, c2) = (contrib(unhex64(SIG_A)), contrib(unhex64(SIG_B)));

    // Both are genuinely authored by node 1. Neither is a forgery.
    assert!(c1.signature_valid(&pki) && c2.signature_valid(&pki));
    // Same content -- this is what the OLD detection predicate compared, and why it saw nothing.
    assert_eq!(
        c1.tensor_hash(),
        c2.tensor_hash(),
        "the content is identical by construction"
    );
    // Different objects -- this is what `admit` excludes on, and what detection now compares.
    assert_ne!(c1.leaf(), c2.leaf(), "the signature is part of the leaf");

    let mut s = State::new();
    s.deliver(c1, &pki);
    s.deliver(c2, &pki);

    assert!(
        s.convicted(&pki).contains(&1),
        "TWO DISTINCT VALID SIGNATURES OVER ONE MESSAGE LEFT NO PROOF. Detection is keyed on \
         the tensor hash, which is equal here, while `admit` excludes on the leaf, which is \
         not. So node 1 is removed from the round with NOTHING ON THE RECORD explaining why, \
         and an observer cannot tell a convicted equivocator from a node that went quiet."
    );
    assert!(
        s.admit(1, &pki).is_empty(),
        "an equivocator's contributions must not be aggregated"
    );
}

/// Without this, the assertion above is satisfied by a detector that convicts everyone.
#[test]
fn crypto04_an_honest_node_redelivering_the_same_entry_is_not_convicted() {
    let (_a, pki, _msg) = setup();
    let c = contrib(unhex64(SIG_A));

    let mut s = State::new();
    s.deliver(c.clone(), &pki);
    s.deliver(c, &pki); // gossip is at-least-once; the same entry arriving twice is normal

    assert!(
        s.convicted(&pki).is_empty(),
        "redelivering ONE entry is idempotent, not equivocation -- a detector that convicts \
         here would convict every honest node in any real gossip layer"
    );
    assert_eq!(
        s.admit(1, &pki).len(),
        1,
        "and the honest node is still aggregated"
    );
}
