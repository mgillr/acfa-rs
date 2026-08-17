// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! These tests exercise the property the construction exists for: a synchrony violation
//! is never silent. The important one is
//! `a_fork_by_two_disjoint_honest_groups_is_visible_and_names_nobody` -- that is the case
//! a design which only hunts for culprits would miss entirely.

use acfa_finality::{
    CertFork, CertTuple, Certificate, DeadlineCut, Finality, Rejected, RelayChain, RoundBudget,
    Status,
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
        fork.is_unattributable_verified(&pki),
        "disjoint honest groups: nobody to name"
    );
    assert!(fork.attributable_verified(&pki).is_empty());
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
    assert!(!fork.is_unattributable_verified(&pki));
    assert_eq!(
        fork.attributable_verified(&pki)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![5]
    );
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

/// crdt-05a: a resume must STICK. The evidence is designed to be unsuppressible and to
/// keep propagating, so a node that re-halts on every re-delivery of a fork it has already
/// reconciled can never resume at all -- ordinary gossip becomes a permanent denial of
/// service, with no Byzantine participation required.
#[test]
fn a_reconciled_fork_redelivered_does_not_re_halt() {
    let (ids, pki) = room(5);
    let mut fin = Finality::new(1);
    fin.observe(
        cert_signed_by(tuple(1, "A", "a"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .unwrap();
    let a = cert_signed_by(tuple(1, "A", "a"), &[&ids[0], &ids[1]]);
    let b = cert_signed_by(tuple(1, "B", "b"), &[&ids[2], &ids[3]]);
    let _ = fin.observe(b.clone(), &pki);
    assert!(fin.is_halted());

    fin.resume(RoundBudget::new(200)).unwrap();
    assert!(!fin.is_halted(), "resume did not clear the halt");

    // A peer re-gossips the very fork we just reconciled. This is normal operation.
    let fork = CertFork::canonical(a, b).expect("a and b fork round 1");
    assert!(
        fin.observe_fork(fork.clone(), &pki),
        "valid evidence is still accepted"
    );
    assert!(
        !fin.is_halted(),
        "re-delivery of an already-reconciled fork re-halted the node, so resume can never stick"
    );
    assert_eq!(fin.fork_history().len(), 1, "and the record is still there");
}

/// crdt-05b: evidence merges "by union", so the historical record must be idempotent.
/// It was a Vec with an unconditional push, so every re-delivery grew it -- unbounded
/// memory driven by exactly the propagation the design depends on.
#[test]
fn the_fork_record_is_idempotent_under_redelivery() {
    let (ids, pki) = room(5);
    let mut fin = Finality::new(1);
    let a = cert_signed_by(tuple(1, "A", "a"), &[&ids[0], &ids[1]]);
    let b = cert_signed_by(tuple(1, "B", "b"), &[&ids[2], &ids[3]]);
    let fork = CertFork::canonical(a, b).expect("fork");

    for _ in 0..50 {
        assert!(fin.observe_fork(fork.clone(), &pki));
    }
    assert_eq!(
        fin.fork_history().len(),
        1,
        "fifty deliveries of one fork stored fifty copies; a union is not a push"
    );
}

/// crdt-05c: a fork the node has NEVER SEEN must halt it, even at a round below the
/// reconcile point. Suppressing evidence by round number lets an adversary withhold a fork
/// until after reconciliation and have it ignored forever.
#[test]
fn a_new_fork_at_an_earlier_round_still_halts_after_a_resume() {
    let (ids, pki) = room(5);
    let mut fin = Finality::new(1);

    // Rounds 1..=3 certified cleanly.
    for r in 1..=3u64 {
        fin.observe(
            cert_signed_by(tuple(r, "A", "a"), &[&ids[0], &ids[1]]),
            &pki,
        )
        .unwrap();
    }
    // A fork at round 3, then reconcile past it.
    let _ = fin.observe(
        cert_signed_by(tuple(3, "B", "b"), &[&ids[2], &ids[3]]),
        &pki,
    );
    assert!(fin.is_halted());
    fin.resume(RoundBudget::new(200)).unwrap();
    assert!(!fin.is_halted());

    // Now a DIFFERENT, previously unseen fork surfaces at round 1 -- an adversary held it
    // back. It invalidates round 1 onward, including everything just reconciled.
    let a1 = cert_signed_by(tuple(1, "A", "a"), &[&ids[0], &ids[1]]);
    let c1 = cert_signed_by(tuple(1, "C", "c"), &[&ids[2], &ids[3]]);
    let new_fork = CertFork::canonical(a1, c1).expect("round-1 fork");
    assert!(
        fin.observe_fork(new_fork, &pki),
        "valid evidence must be accepted"
    );
    assert!(
        fin.is_halted(),
        "a previously unseen fork was ignored because its round was below the reconcile \
         point -- withholding evidence until after a resume would suppress it permanently"
    );
}

// ------------------------------------------------------- crypto-01 and crdt-05

/// crypto-01. `msg()` signs `e_cut_root` and `id()` commits to it, but the conflict
/// predicate compared a strict SUBSET of the signed tuple. Two valid round-r certificates
/// that agreed on membership and aggregate while committing to different equivocation cuts
/// were therefore neither equal nor conflicting: `observe` fell through to
/// `Rejected::Invalid` and silently kept whichever arrived first.
///
/// FAILS ON THE UNFIXED CODE: `halted=false`, both certificates accepted, no fork recorded.
#[test]
fn a_cut_disagreement_is_a_fork_and_halts() {
    let f = 1;
    let (ids, pki) = room(6);

    let mut t1 = tuple(1, "A", "rho");
    let mut t2 = tuple(1, "A", "rho");
    t1.e_cut_root = h(b"cut-convicts-node-7");
    t2.e_cut_root = h(b"cut-convicts-nobody");
    assert_ne!(t1.msg(), t2.msg(), "the cut is inside the signed bytes");
    assert_ne!(
        t1.id(),
        t2.id(),
        "and inside the id round r+1 anchors against"
    );
    assert!(t1.conflicts_with(&t2), "so they must conflict");

    let mut node = Finality::new(f);
    node.observe(cert_signed_by(t1, &[&ids[0], &ids[1]]), &pki)
        .ok();
    let second = node.observe(cert_signed_by(t2, &[&ids[2], &ids[3]]), &pki);
    assert_eq!(second, Err(Rejected::ForkedAt(1)));
    assert!(
        node.is_halted(),
        "two certificates over different signed tuples is a fork"
    );
}

/// crdt-05. Suppression of re-delivered fork evidence was keyed on `CertFork` equality,
/// which covers the signature map, so re-signing the SAME pair of tuples with a different
/// valid `f+1` quorum produced a byte-different, semantically identical fork that slipped
/// the check and re-halted a resumed node -- the denial of service the record exists to close.
///
/// FAILS ON THE UNFIXED CODE: the re-signed conflict returns `ForkedAt(1)` and halts.
#[test]
fn a_resumed_node_is_not_re_halted_by_the_same_conflict_re_signed() {
    let f = 1;
    let (ids, pki) = room(6);
    let mut node = Finality::new(f);

    let ta = tuple(1, "A", "rho");
    let tb = tuple(1, "B", "rho");

    node.observe(Certificate::new(tuple(0, "genesis", "g")), &pki)
        .ok();
    node.observe(cert_signed_by(ta, &[&ids[0], &ids[1]]), &pki)
        .ok();
    node.observe(cert_signed_by(tb, &[&ids[2], &ids[3]]), &pki)
        .ok();
    assert!(node.is_halted(), "precondition: the fork halts the node");

    node.resume(RoundBudget::new(200)).expect("resume");
    assert!(!node.is_halted());

    // Verbatim re-gossip: old news.
    node.observe(cert_signed_by(ta, &[&ids[0], &ids[1]]), &pki)
        .ok();
    node.observe(cert_signed_by(tb, &[&ids[2], &ids[3]]), &pki)
        .ok();
    assert!(
        !node.is_halted(),
        "verbatim re-delivery must stay suppressed"
    );

    // SAME two tuples, DIFFERENT valid quorum. Byte-different, semantically identical.
    node.observe(cert_signed_by(ta, &[&ids[0], &ids[4]]), &pki)
        .ok();
    node.observe(cert_signed_by(tb, &[&ids[2], &ids[5]]), &pki)
        .ok();
    assert!(
        !node.is_halted(),
        "re-signing the same conflict with another quorum must not re-halt a resumed node"
    );
}

/// The property the FIRST attempt at crdt-05 broke: evidence never seen before must halt
/// regardless of round, including a fork withheld until after a resume. This one PASSES on
/// the current code and is a guard, not a failing-first test; it fails against the
/// round-suppression version (`6d5f48e`), which is where its teeth were demonstrated.
#[test]
fn a_withheld_earlier_fork_still_halts_after_a_resume() {
    let f = 1;
    let (ids, pki) = room(6);
    let mut node = Finality::new(f);

    node.observe(Certificate::new(tuple(0, "genesis", "g")), &pki)
        .ok();
    for r in 1..=3u64 {
        node.observe(
            cert_signed_by(tuple(r, "A", "rho"), &[&ids[0], &ids[1]]),
            &pki,
        )
        .ok();
    }
    node.observe(
        cert_signed_by(tuple(3, "B", "rho"), &[&ids[2], &ids[3]]),
        &pki,
    )
    .ok();
    assert!(node.is_halted());
    node.resume(RoundBudget::new(200)).expect("resume");

    node.observe(
        cert_signed_by(tuple(2, "A", "rho"), &[&ids[0], &ids[1]]),
        &pki,
    )
    .ok();
    node.observe(
        cert_signed_by(tuple(2, "C", "rho"), &[&ids[2], &ids[3]]),
        &pki,
    )
    .ok();
    assert!(
        node.is_halted(),
        "a fork never seen before must halt, whatever its round"
    );
}

// ------------------------------------------------------------------- crdt-07

/// PART ONE. `check` required EVERY carried signature to verify, returning on the first
/// bad one before it counted the good ones. The wire format accepts any strictly-ascending
/// signer list, so a relay could append one junk entry to GENUINE fork evidence and an
/// honest node would decline to halt on it -- valid evidence made refusable by a bystander
/// holding no key.
///
/// FAILS ON THE UNFIXED CODE: `halted=false`, the padded evidence is rejected.
#[test]
fn junk_appended_to_real_evidence_does_not_stop_the_halt() {
    let f = 1;
    let (ids, pki) = room(6);
    let mut node = Finality::new(f);

    let ta = tuple(1, "A", "rho");
    let tb = tuple(1, "B", "rho");
    let ca = cert_signed_by(ta, &[&ids[0], &ids[1]]);
    let mut cb = cert_signed_by(tb, &[&ids[2], &ids[3]]);

    // A bystander appends an entry for an id in the PKI, with a signature over nothing.
    cb.sigs.insert(ids[5].node_id, [0u8; 64]);

    node.observe(ca, &pki).ok();
    let second = node.observe(cb, &pki);
    assert_eq!(second, Err(Rejected::ForkedAt(1)));
    assert!(
        node.is_halted(),
        "one junk signature must not make real fork evidence refusable"
    );
}

/// PART TWO, and it is why counting alone is not enough. Once `check` counts valid
/// signatures instead of requiring all, junk survives into the carried map -- and
/// `attributable()` reads `sigs.keys()`, which is MEMBERSHIP, not proof. Without pruning at
/// ingest, an attacker appends entries naming an HONEST node to BOTH halves of a real fork
/// and that node is reported as having double-signed. Attribution is an accusation.
///
/// This test passes trivially on the UNFIXED code (which refuses the padded fork outright),
/// so it is a guard on the FIX, not a failing-first test -- and it fails if part two is
/// removed while part one is kept.
#[test]
fn padded_signatures_cannot_frame_an_honest_node() {
    let f = 1;
    let (ids, pki) = room(6);
    let mut node = Finality::new(f);

    let ta = tuple(1, "A", "rho");
    let tb = tuple(1, "B", "rho");
    let mut ca = cert_signed_by(ta, &[&ids[0], &ids[1]]);
    let mut cb = cert_signed_by(tb, &[&ids[2], &ids[3]]);

    // Node 6 signed NEITHER half. Forge its membership in BOTH.
    let victim = ids[5].node_id;
    ca.sigs.insert(victim, [0u8; 64]);
    cb.sigs.insert(victim, [0u8; 64]);

    node.observe(ca, &pki).ok();
    node.observe(cb, &pki).ok();
    assert!(node.is_halted(), "precondition: the fork is real and halts");

    assert!(
        !node.attributed().contains(&victim),
        "an honest node that signed neither half was named as a double-signer"
    );
}

/// A threshold must never get EASIER as the claimed adversary budget grows. `f + 1` in
/// `usize` wraps to zero at `usize::MAX`, making `have < need` vacuously false, so
/// `Certificate::check` returned Ok on a certificate carrying NO valid signatures and
/// `RelayChain::check` accepted a chain with no hops.
///
/// FAILS ON THE UNFIXED CODE: both return Ok.
#[test]
fn an_unreachable_fault_bound_does_not_make_the_threshold_vacuous() {
    let (_ids, pki) = room(4);

    // A certificate with NO signatures at all, offered under an absurd fault bound.
    let empty = Certificate::new(tuple(1, "A", "rho"));
    assert!(
        empty.check(&pki, usize::MAX).is_err(),
        "a certificate with zero valid signatures was accepted because f+1 wrapped to 0"
    );
    assert!(
        empty.check(&pki, usize::MAX - 1).is_err(),
        "same, one below the wrap point"
    );

    // The honest side, so the refusal is not vacuous: f+1 real signers still validate.
    let (ids, pki2) = room(6);
    let ok = cert_signed_by(tuple(1, "A", "rho"), &[&ids[0], &ids[1]]);
    assert!(
        ok.check(&pki2, 1).is_ok(),
        "a genuine f+1 certificate must still validate"
    );
}
