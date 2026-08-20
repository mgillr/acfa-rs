// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crdt-09. A round must bind to the history it extends. This test pins the LIVE-PATH binding
//! (the relay/cut layer authenticates the predecessor) and documents the residual (the
//! FINALISED certificate's preimage does not re-carry it, so an offline single-cert check
//! cannot confirm what it extends -- a wire-version fix, deferred to preserve the fingerprint).

use acfa_finality::{Certificate, DeadlineCut, RelayChain};
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, State};

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

fn room(n: u32) -> (Vec<Identity>, Pki) {
    let ids: Vec<Identity> = (1..=n)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    (ids, pki)
}
fn leaf(a: &Identity, t: &[i64]) -> [u8; 32] {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd: 1,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &PARAMS_DEFAULT,
            1,
            a.node_id,
            &th,
        )),
    }
    .leaf()
}

/// LIVE-PATH BINDING: a relay chain anchored to the WRONG predecessor is excluded from the
/// cut. `DeadlineCut::close` admits only chains whose `anchor` matches the round-(r-1)
/// certificate the cut is being closed against, so a round cannot admit contributions that
/// were broadcast as extending a different history.
///
/// GUARD-DELETION: remove the `if ch.anchor != anchor { ... continue }` check in
/// `DeadlineCut::close` and the spliced leaf below is admitted.
#[test]
fn a_chain_anchored_to_the_wrong_predecessor_is_not_admitted() {
    let (ids, pki) = room(5);
    let f = 1;

    let real_anchor = Certificate::genesis().tuple.id();
    let wrong_anchor = [0x99u8; 32]; // a different, forged predecessor

    let good_leaf = leaf(&ids[0], &[1, 2]);
    let spliced_leaf = leaf(&ids[1], &[3, 4]);

    // A complete broadcast anchored to the REAL predecessor.
    let good = RelayChain::originate(real_anchor, good_leaf, &ids[0])
        .relay(&ids[1])
        .relay(&ids[2]);
    // A complete broadcast anchored to a DIFFERENT predecessor -- a splice attempt.
    let spliced = RelayChain::originate(wrong_anchor, spliced_leaf, &ids[0])
        .relay(&ids[1])
        .relay(&ids[2]);
    assert!(
        good.is_complete(&pki, f) && spliced.is_complete(&pki, f),
        "both broadcasts close"
    );

    let cut = DeadlineCut::close(real_anchor, &[good, spliced], &pki, f);
    let admitted: std::collections::BTreeSet<_> = cut.admitted.iter().copied().collect();
    assert!(
        admitted.contains(&good_leaf),
        "the correctly-anchored leaf is admitted"
    );
    assert!(
        !admitted.contains(&spliced_leaf),
        "a leaf broadcast as extending a DIFFERENT predecessor must NOT be admitted -- \
         this is the round-to-history binding, enforced at cut close"
    );
}

/// RESIDUAL, DOCUMENTED: the finalised certificate's preimage (round, a_root, e_cut_root, rho)
/// does not re-carry the anchor, so an offline verifier holding one certificate in isolation
/// cannot confirm which predecessor it extends. The live path above binds it; full offline
/// self-binding requires committing the predecessor id into `CertTuple::msg`, which changes
/// the signed preimage and moves the cross-architecture fingerprint -- a deliberate
/// wire-version decision, deferred. This test simply records that the anchor is NOT currently
/// in the certificate preimage, so the day it is, this fails and the residual is closed.
#[test]
fn the_certificate_preimage_does_not_yet_carry_the_anchor() {
    let mut s = State::new();
    let (ids, pki) = room(5);
    for id in &ids {
        s.deliver(
            Contribution {
                ctx: acfa_receipt::identity::NO_CONTEXT,
                sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
                params: PARAMS_DEFAULT,
                rnd: 1,
                node_id: id.node_id,
                tensor: vec![1, 2],
                sig: id.sign(&contrib_msg(
                    &acfa_receipt::identity::NO_CONTEXT,
                    &PARAMS_DEFAULT,
                    1,
                    id.node_id,
                    &h(&enc_tensor(&[1, 2])),
                )),
            },
            &pki,
        );
    }
    // The signed message is exactly the four roots; a fifth 32-byte field (an anchor) would
    // make it 32 bytes longer. This pins the CURRENT preimage width so a future wire-version
    // change that adds the anchor is a deliberate, visible edit.
    let tuple = acfa_finality::CertTuple {
        round: 1,
        a_root: s.root(),
        e_cut_root: [0u8; 32],
        rho: [0u8; 32],
    };
    assert_eq!(
        tuple.msg().len(),
        b"ACFA-CERT|".len() + 8 + 32 * 3,
        "the preimage is tag + round + three roots; adding the anchor is the deferred fix"
    );
}
