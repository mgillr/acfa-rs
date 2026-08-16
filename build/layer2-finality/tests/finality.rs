// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! These tests exercise the property the construction exists for: a synchrony violation
//! is never silent. The important one is
//! `a_fork_by_two_disjoint_honest_groups_is_visible_and_names_nobody` -- that is the case
//! a design which only hunts for culprits would miss entirely.

use acfa_finality::{
    CertFork, CertTuple, Certificate, DeadlineCut, Finality, RelayChain, RoundBudget, Status,
};
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, Receipt, Rule, State};

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn room(n: u32) -> (Vec<Identity>, Pki) {
    let ids: Vec<Identity> = (1..=n).map(ident).collect();
    let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    (ids, pki)
}

fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(rnd, &th)),
    }
}

fn tuple(round: u64, a: &str, rho: &str) -> CertTuple {
    CertTuple {
        round,
        a_root: h(a.as_bytes()),
        e_cut_root: h(b"ecut"),
        rho: h(rho.as_bytes()),
    }
}

fn cert_signed_by(t: CertTuple, signers: &[&Identity]) -> Certificate {
    let mut c = Certificate::new(t);
    for s in signers {
        c.sign(s);
    }
    c
}

// ------------------------------------------------------------------ the cut

#[test]
fn a_contribution_is_admitted_only_once_its_broadcast_closes() {
    let (ids, pki) = room(5);
    let f = 2;
    let anchor = Certificate::genesis().tuple.id();
    let leaf = contrib(&ids[0], 1, &[1, 2]).leaf();

    let mut ch = RelayChain::originate(anchor, leaf, &ids[0]);
    // f+1 = 3 distinct signers are needed.
    assert!(!ch.is_complete(&pki, f), "1 hop is not a closed broadcast");
    ch = ch.relay(&ids[1]);
    assert!(!ch.is_complete(&pki, f), "2 hops is not a closed broadcast");
    ch = ch.relay(&ids[2]);
    assert!(ch.is_complete(&pki, f), "3 distinct hops closes it");
}

#[test]
fn one_node_cannot_inflate_a_chain_by_relaying_to_itself() {
    // Without the distinct-signer rule a single Byzantine node reaches any length alone.
    let (ids, pki) = room(5);
    let f = 2;
    let anchor = [7u8; 32];
    let leaf = [9u8; 32];
    let ch = RelayChain::originate(anchor, leaf, &ids[0])
        .relay(&ids[0])
        .relay(&ids[0]);
    assert_eq!(ch.hops.len(), 3);
    assert!(!ch.is_complete(&pki, f), "repeated signers must not count");
}

#[test]
fn a_hop_signature_cannot_be_lifted_into_a_different_chain() {
    // Chain-prefix binding: a signature is valid only at the depth and in the company it
    // was made for, so harvested signatures cannot be reassembled into a fake chain.
    let (ids, pki) = room(5);
    let f = 1;
    let anchor = [7u8; 32];
    let real = RelayChain::originate(anchor, [1u8; 32], &ids[0]).relay(&ids[1]);
    assert!(real.is_complete(&pki, f));

    let mut forged = RelayChain::originate(anchor, [2u8; 32], &ids[0]);
    forged.hops.push(real.hops[1]); // lift node 2's signature across
    assert!(
        !forged.is_complete(&pki, f),
        "signature must not transplant"
    );
}

#[test]
fn deemed_absence_is_uniform_across_nodes_that_saw_different_chain_lengths() {
    // The S6 attack: a Byzantine sender delivers late to one node only. Both nodes must
    // reach the SAME cut, because an incomplete chain is deemed absent everywhere.
    let (ids, pki) = room(5);
    let f = 2;
    let anchor = Certificate::genesis().tuple.id();
    let closed = RelayChain::originate(anchor, [1u8; 32], &ids[0])
        .relay(&ids[1])
        .relay(&ids[2]);
    let straggler = RelayChain::originate(anchor, [2u8; 32], &ids[3]).relay(&ids[4]);

    let node_x = DeadlineCut::close(anchor, &[closed.clone(), straggler.clone()], &pki, f);
    let node_y = DeadlineCut::close(anchor, std::slice::from_ref(&closed), &pki, f);
    assert_eq!(
        node_x.admitted, node_y.admitted,
        "an unclosed broadcast is absent for everyone"
    );
    assert_eq!(node_x.admitted, vec![[1u8; 32]]);
    assert_eq!(node_x.deemed_absent, vec![[2u8; 32]]);
}

#[test]
fn a_chain_anchored_at_the_wrong_certificate_is_absent() {
    let (ids, pki) = room(5);
    let f = 1;
    let ch = RelayChain::originate([1u8; 32], [5u8; 32], &ids[0]).relay(&ids[1]);
    let cut = DeadlineCut::close([2u8; 32], &[ch], &pki, f);
    assert!(cut.admitted.is_empty(), "anchor is content, not decoration");
}

// ---------------------------------------------------------- the certificate

#[test]
fn a_certificate_needs_f_plus_one_distinct_valid_signatures() {
    let (ids, pki) = room(7);
    let f = 2;
    let t = tuple(1, "A", "rho");
    assert!(!cert_signed_by(t, &[&ids[0]]).is_valid(&pki, f));
    assert!(!cert_signed_by(t, &[&ids[0], &ids[1]]).is_valid(&pki, f));
    assert!(cert_signed_by(t, &[&ids[0], &ids[1], &ids[2]]).is_valid(&pki, f));
}

#[test]
fn a_signature_over_one_tuple_does_not_certify_another() {
    let (ids, pki) = room(7);
    let f = 1;
    let mut c = cert_signed_by(tuple(1, "A", "rho"), &[&ids[0], &ids[1]]);
    assert!(c.is_valid(&pki, f));
    c.tuple.rho = h(b"different"); // swap the committed aggregate
    assert!(
        !c.is_valid(&pki, f),
        "the tuple is covered by the signatures"
    );
}

#[test]
fn genesis_anchors_round_zero_and_is_the_same_object_everywhere() {
    assert!(Certificate::genesis().is_genesis());
    assert_eq!(Certificate::genesis(), Certificate::genesis());
}

// ------------------------------------------------------- fail-visible finality

#[test]
fn a_fork_by_two_disjoint_honest_groups_is_visible_and_names_nobody() {
    // THE CASE THE WHOLE CONSTRUCTION EXISTS FOR. n >= 3f+2 with f = 1 means n >= 5.
    // Two disjoint groups of f+1 = 2 honest nodes each certify a different cut. No
    // Byzantine node takes part. Nobody can be blamed -- and the fork is still conclusive
    // proof the timing assumption broke.
    let (ids, pki) = room(5);
    let f = 1;
    let group_a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let group_b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);

    let fork = CertFork::canonical(group_a, group_b).expect("tuples conflict");
    assert!(fork.is_valid(&pki, f), "both halves are genuinely valid");
    assert!(
        fork.is_unattributable(),
        "disjoint honest groups: nobody to name"
    );
    assert!(fork.attributable().is_empty());
}

#[test]
fn the_byzantine_bridging_signer_is_attributed() {
    // The other case: an identity signs BOTH conflicting tuples. That is provable
    // misbehaviour and it is named.
    let (ids, pki) = room(7);
    let f = 1;
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[4]]);
    let b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[4]]); // ids[4] on both
    let fork = CertFork::canonical(a, b).unwrap();
    assert!(fork.is_valid(&pki, f));
    assert!(!fork.is_unattributable());
    assert_eq!(fork.attributable().into_iter().collect::<Vec<_>>(), vec![5]);
}

#[test]
fn a_fork_is_derived_identically_by_both_observers() {
    let (ids, _) = room(5);
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);
    let x = CertFork::canonical(a.clone(), b.clone()).unwrap();
    let y = CertFork::canonical(b, a).unwrap();
    assert_eq!(x, y, "orientation must not depend on who saw what first");
}

#[test]
fn a_fabricated_second_certificate_cannot_halt_the_system() {
    // If an invalid "fork" halted everyone, anyone could stop the protocol for free.
    let (ids, pki) = room(5);
    let f = 1;
    let real = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let fake = Certificate::new(tuple(3, "B", "rho-b")); // zero signatures
    let fork = CertFork::canonical(real, fake).unwrap();
    assert!(
        !fork.is_valid(&pki, f),
        "one side is not a valid certificate"
    );

    let mut fin = Finality::new(f);
    assert!(!fin.observe_fork(fork, &pki));
    assert!(!fin.is_halted());
}

#[test]
fn certificates_for_different_rounds_do_not_conflict() {
    let a = tuple(3, "A", "rho-a");
    let b = tuple(4, "B", "rho-b");
    assert!(!a.conflicts_with(&b));
    assert!(CertFork::canonical(Certificate::new(a), Certificate::new(b)).is_none());
}

// ------------------------------------------------------- halt-and-reconcile

#[test]
fn a_healthy_run_never_halts() {
    let (ids, pki) = room(5);
    let f = 1;
    let mut fin = Finality::new(f);
    for r in 1..=4u64 {
        let c = cert_signed_by(tuple(r, "A", "rho"), &[&ids[0], &ids[1]]);
        assert!(fin.observe(c, &pki).is_ok());
    }
    assert!(!fin.is_halted());
    assert_eq!(fin.status(), Status::Running { last_certified: 4 });
    assert!(fin.is_final(4));
}

#[test]
fn re_delivery_of_the_same_certificate_is_idempotent() {
    let (ids, pki) = room(5);
    let f = 1;
    let mut fin = Finality::new(f);
    let c = cert_signed_by(tuple(1, "A", "rho"), &[&ids[0], &ids[1]]);
    assert!(fin.observe(c.clone(), &pki).is_ok());
    assert!(
        fin.observe(c, &pki).is_ok(),
        "gossip re-delivers constantly"
    );
    assert!(!fin.is_halted());
}

#[test]
fn observing_a_fork_halts_and_reconciles_from_the_last_clean_round() {
    let (ids, pki) = room(5);
    let f = 1;
    let mut fin = Finality::new(f);
    for r in 1..=3u64 {
        fin.observe(
            cert_signed_by(tuple(r, "A", "rho"), &[&ids[0], &ids[1]]),
            &pki,
        )
        .unwrap();
    }
    // Round 4 forks.
    fin.observe(
        cert_signed_by(tuple(4, "A", "rho-a"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .unwrap();
    let err = fin
        .observe(
            cert_signed_by(tuple(4, "B", "rho-b"), &[&ids[2], &ids[3]]),
            &pki,
        )
        .unwrap_err();
    assert_eq!(err, acfa_finality::Rejected::ForkedAt(4));

    assert!(fin.is_halted());
    assert_eq!(fin.reconcile_point(), 3);
    assert_eq!(
        fin.status(),
        Status::Halted {
            at_round: 4,
            reconcile_from: 3,
            unattributable: true
        }
    );
    assert!(fin.is_final(3), "rounds below the fork stay final");
    assert!(!fin.is_final(4), "the forked round is not final");
}

#[test]
fn a_later_round_does_not_inherit_finality_across_an_earlier_fork() {
    // The subtle one. Fork at 2, a clean certificate at 5. Round 5 must NOT be final:
    // it was computed on top of a round whose membership is in dispute.
    let (ids, pki) = room(5);
    let f = 1;
    let mut fin = Finality::new(f);
    fin.observe(
        cert_signed_by(tuple(1, "A", "r1"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .unwrap();
    fin.observe(
        cert_signed_by(tuple(2, "A", "r2a"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .unwrap();
    let _ = fin.observe(
        cert_signed_by(tuple(2, "B", "r2b"), &[&ids[2], &ids[3]]),
        &pki,
    );
    fin.observe(
        cert_signed_by(tuple(5, "A", "r5"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .unwrap();

    assert_eq!(
        fin.reconcile_point(),
        1,
        "reconcile below the EARLIEST fork"
    );
    assert!(fin.is_final(1));
    assert!(!fin.is_final(5), "finality must not jump a disputed round");
}

#[test]
fn evidence_propagates_so_a_node_that_saw_only_the_fork_also_halts() {
    let (ids, pki) = room(5);
    let f = 1;
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);
    let fork = CertFork::canonical(a, b).unwrap();

    let mut elsewhere = Finality::new(f);
    assert!(elsewhere.observe_fork(fork, &pki));
    assert!(
        elsewhere.is_halted(),
        "the pair alone is sufficient evidence"
    );
}

#[test]
fn resuming_into_an_under_provisioned_budget_is_refused() {
    // An under-provisioned budget forks the certificate BY CONSTRUCTION even when the
    // delivery bound holds, so resuming into one guarantees an immediate re-fork.
    let (ids, pki) = room(5);
    let f = 1;
    let mut fin = Finality::new(f);
    fin.observe(
        cert_signed_by(tuple(1, "A", "a"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .unwrap();
    let _ = fin.observe(
        cert_signed_by(tuple(1, "B", "b"), &[&ids[2], &ids[3]]),
        &pki,
    );
    assert!(fin.is_halted());

    assert!(
        fin.resume(RoundBudget::new(100)).is_err(),
        "1.0tau is unsafe"
    );
    assert!(fin.is_halted(), "a refused resume must not half-resume");
    assert_eq!(fin.resume(RoundBudget::new(200)).unwrap(), 0);
    assert!(!fin.is_halted());
}

#[test]
fn a_resumed_run_still_carries_the_record_that_it_halted() {
    // A run that halted and recovered must not be indistinguishable from one that never
    // halted, or the failure becomes invisible after the fact.
    let (ids, pki) = room(5);
    let f = 1;
    let mut fin = Finality::new(f);
    fin.observe(
        cert_signed_by(tuple(1, "A", "a"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .unwrap();
    let _ = fin.observe(
        cert_signed_by(tuple(1, "B", "b"), &[&ids[2], &ids[3]]),
        &pki,
    );
    fin.resume(RoundBudget::new(200)).unwrap();
    assert_eq!(
        fin.fork_history().len(),
        1,
        "the evidence survives recovery"
    );
}

#[test]
fn the_round_budget_threshold_is_two_tau() {
    assert!(!RoundBudget::new(199).is_safe());
    assert!(RoundBudget::new(200).is_safe());
    assert!(RoundBudget::new(400).is_safe());
}

// ------------------------------------------------------------- end to end

#[test]
fn a_certified_round_binds_the_receipt_it_committed_to() {
    // The two layers meet here: rho in the certificate IS the receipt's output root, so
    // a certificate commits to a specific, re-executable aggregate.
    let (ids, pki) = room(5);
    let f = 1;
    let mut state = State::new();
    for (i, id) in ids.iter().enumerate() {
        state.deliver(contrib(id, 1, &[i as i64 * 3, i as i64 + 1]), &pki);
    }
    let receipt = Receipt::issue(&state, 1, &pki, f, Rule::Krum);
    let verified = receipt
        .verify(&acfa_receipt::Policy::new(pki.clone(), f))
        .expect("receipt verifies");

    let t = CertTuple {
        round: 1,
        a_root: acfa_receipt::hash::merkle_root(
            &state
                .admit(1, &pki)
                .iter()
                .map(|c| c.leaf())
                .collect::<Vec<_>>(),
        ),
        e_cut_root: acfa_receipt::hash::merkle_root(&[]),
        rho: verified.output_root,
    };
    let cert = cert_signed_by(t, &[&ids[0], &ids[1]]);
    assert!(cert.is_valid(&pki, f));

    let mut fin = Finality::new(f);
    assert!(fin.observe(cert, &pki).is_ok());
    assert!(fin.is_final(1));
    assert_eq!(fin.status(), Status::Running { last_certified: 1 });
}
