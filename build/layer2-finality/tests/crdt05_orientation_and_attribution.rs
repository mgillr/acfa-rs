// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crdt-05, the two halves the termination fix did not cover.
//!
//! The filed finding is two claims, not one: *halt-and-reconcile does not terminate, AND it
//! attributes the fork to honest nodes after a legitimate resume.* Only the first half was
//! ever addressed. `fork_key` keyed `reconciled` on the conflict rather than on the round or
//! the signature bytes, which closed termination. These are the other two doors.
//!
//! BOTH TESTS FAIL ON THE UNFIXED CODE, and the failures are the reproductions:
//!
//!   ORIENTATION   re-offering a reconciled fork with `a` and `b` swapped returned
//!                 `Halted { at_round: 3, reconcile_from: 0, unattributable: true }`
//!                 where the canonical re-offer correctly returned `Running`.
//!   ATTRIBUTION   a 64-zero-byte signature entry forged for an honest node left
//!                 `fork.is_valid` TRUE and `attributable()` returning `{1}`, and the junk
//!                 survived into `fork_history()`.
//!
//! WHY THESE ARE ONE FINDING AND NOT TWO. They interact: the swapped case reports
//! `unattributable: true` while the record simultaneously names the wrong node, so the
//! system can both accuse an innocent party and report that nobody is accusable.

use acfa_finality::{CertFork, CertTuple, Certificate, Finality, RoundBudget, Status};
use acfa_receipt::hash::h;
use acfa_receipt::identity::{Identity, Pki};

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn room(n: u32) -> (Vec<Identity>, Pki) {
    let ids: Vec<Identity> = (1..=n).map(ident).collect();
    let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    (ids, pki)
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

/// A conflict this node has already reconciled must stay settled however the pair is
/// oriented. `CertFork`'s fields are public, so orientation is caller-controlled.
#[test]
fn a_reconciled_fork_stays_settled_when_the_pair_is_swapped() {
    let (ids, pki) = room(7);
    let f = 1;
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);

    let canon = CertFork::canonical(a, b).expect("the tuples conflict");
    let mut node = Finality::new(f);
    assert!(
        node.observe_fork(canon.clone(), &pki),
        "a valid fork is accepted"
    );
    node.resume(RoundBudget {
        centi_tau: RoundBudget::REQUIRED_CENTI_TAU,
    })
    .expect("reconcile the fork we just observed");

    // Premise: the swapped literal really is a DIFFERENT value, or this test is vacuous.
    let swapped = CertFork {
        a: canon.b.clone(),
        b: canon.a.clone(),
    };
    assert_ne!(
        canon, swapped,
        "premise: the swapped pair must be a distinct value, else nothing is being tested"
    );

    let mut n = node.clone();
    n.observe_fork(canon, &pki);
    assert!(
        matches!(n.status(), Status::Running { .. }),
        "control: the CANONICAL re-offer must stay settled, else the test proves nothing \
         about orientation"
    );

    let mut n = node.clone();
    n.observe_fork(swapped, &pki);
    assert!(
        matches!(n.status(), Status::Running { .. }),
        "a fork this node ALREADY RECONCILED re-halted it because the pair arrived the other \
         way round. `fork_key` must sort the pair rather than trust the caller's field \
         order: `CertFork {{ a, b }}` is constructible by struct literal outside the crate, \
         so orientation is not an invariant this map may rely on."
    );
}

/// `observe_fork` must prune unverifiable signature entries at ingest exactly as `observe`
/// does, or an honest node is published as a double-signer on bytes it never produced.
#[test]
fn a_forged_signature_entry_cannot_name_an_honest_node_through_observe_fork() {
    let (ids, pki) = room(7);
    let f = 1;
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let mut b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);

    // Node 1 signed ONLY `a`. Forge a junk entry for it on `b`.
    b.sigs.insert(1, [0u8; 64]);

    let fork = CertFork::canonical(a, b).expect("the tuples conflict");
    // Premise: the fork still validates. `check` counts valid signatures rather than
    // requiring all of them, which is exactly why junk survives to be read as meaning.
    assert!(
        fork.is_valid(&pki, f),
        "premise: the forged entry does not invalidate the fork, or nothing is being tested"
    );
    // The ONLY public attributer takes a PKI and names nobody here: node 1's forged entry
    // is 64 zero bytes and does not verify. (`attributable()` -- the raw membership reader
    // that WOULD name node 1 -- is now `pub(crate)` and unreachable from this external test;
    // that is the crdt-05 third-door fix, exercised end to end in the sibling file.)
    assert!(
        fork.attributable_verified(&pki).is_empty(),
        "premise: the verified reader does not name an unverifiable entry"
    );

    let mut node = Finality::new(f);
    assert!(node.observe_fork(fork, &pki));

    for rec in node.fork_history() {
        assert!(
            !rec.attributable_verified(&pki).contains(&1),
            "node 1 is named as a double-signer on 64 ZERO BYTES it never produced. Both \
             ingest paths prune with `fork.pruned(pki)`, so membership in `sigs` means \
             verified again, and the only public accuser is `attributable_verified`."
        );
    }
}
