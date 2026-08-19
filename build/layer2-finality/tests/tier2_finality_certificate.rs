// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Tier-2: the three guards on the **A half** of a `CertFork` that nothing could witness.
//!
//! ## What was unwitnessed, and why that is not a paperwork problem
//!
//! `CertFork` has PUBLIC FIELDS. `CertFork::canonical` is the only constructor that checks
//! anything, and it is not the only way to obtain the object: `CertFork { a, b }` is a struct
//! literal any external caller can write, and `fork.a.sigs.insert(..)` is a public mutation of
//! a carried one. So every clause of [`CertFork::is_valid`] has to hold against a fork that
//! never passed through `canonical`, and against a fork edited after it did. The sibling suite
//! already says this out loud -- `crdt05_orientation_and_attribution.rs` builds a swapped fork
//! by struct literal precisely because "orientation is not an invariant this map may rely on".
//!
//! The existing suite does attack all three of these guards. Every one of its attacks lands on
//! the **B half**. That is not a design decision anywhere in the code; it is an artefact of how
//! the reproductions happened to be written (`b.sigs.insert(1, [0u8; 64])`, the fabricated
//! second certificate, the forged entry planted on `b`). The A half was left standing by
//! coincidence, and a by-line mutation sweep of this file found exactly that: delete the
//! A-half clauses and the whole repository stays green.
//!
//! | Site | Clause | What survives its deletion |
//! |---|---|---|
//! | `certificate.rs:293` | `self.a.tuple.conflicts_with(&self.b.tuple)` | two certificates that AGREE, or that belong to different rounds, are accepted as proof they disagree |
//! | `certificate.rs:294` | `&& self.a.is_valid(pki, f)` | a fabricated A half halts the network; the doc's "both halves must be checked" is true of one half |
//! | `certificate.rs:367` | `let a = self.a.verified_signers(pki);` | an honest node is published as a double-signer on 64 bytes it never produced -- crdt-07, mirrored onto A |
//!
//! ## Why the A half is the worse half to leave open
//!
//! The first two are the same failure wearing two hats: **a party with no keys at all can halt
//! the system using only material that is already public.** Round certificates are gossiped by
//! design -- that is the entire point of the finality layer, evidence anyone can check. A relay
//! that has never signed anything can pick up two genuine, unrelated certificates, staple them
//! into a `CertFork` by struct literal, and offer it. Without site 293 that pair is accepted as
//! a proof that the synchrony bound broke. Without site 294 the relay does not even need a real
//! second certificate; it invents one. Both convert "fail-visible" into "haltable on demand",
//! and the layer's own thesis is that a halt is only ever supposed to follow a violation that
//! *actually happened*.
//!
//! Site 367 is the reverse polarity of the same object: not refusing false evidence, but
//! refusing to draw a false name out of true evidence. `attributable_verified` is the ONLY
//! public accuser (`attributable` is `pub(crate)` -- crdt-05's third door). `wire::decode_fork`
//! holds no `Pki` and therefore cannot prune, so a gossip consumer necessarily reads an
//! un-pruned fork. The B-side of that read is guarded and tested. The A-side was guarded and
//! untested, and an accusation is not a nuisance failure -- attributed identities are excluded
//! from round `r+1` onward.
//!
//! ## What these tests do NOT cover
//!
//! - **They do not test the B half.** Deliberately. Each A-half test is written so that
//!   deleting the corresponding B-half clause (295, 368) leaves it GREEN, which is what makes
//!   it evidence about site 293/294/367 specifically rather than about `is_valid` in general.
//!   The B-half twins already have witnesses; these do not duplicate them.
//! - **They do not claim the fork is rejected in the 367 case, and must not.** A decoded fork
//!   carrying a junk entry is still valid evidence *on purpose*: crdt-07 chose counting over
//!   requiring-all so that a bystander cannot make genuine evidence refusable by appending
//!   garbage. The guarantee tested here is narrower and is the correct one -- the evidence
//!   stands, the innocent name does not appear.
//! - **They say nothing about whether `f+1` is the right threshold**, nor about the honest
//!   signing rule, which `Certificate::sign` documents as uncheckable here.
//! - **They do not reach `pub(crate)` visibility.** From `tests/`, calling a `pub(crate)`
//!   method is a build break rather than a test failure, so the visibility of `attributable`
//!   is the `compile_fail` doc-test's job and structurally cannot be this file's.
//! - **They exercise `observe_fork`, not `observe`.** `observe_fork` is the path decoded gossip
//!   evidence enters by, which is where an unauthenticated third party gets to speak. The
//!   single-certificate `observe` path builds its fork through `canonical` and so cannot
//!   present a non-conflicting pair in the first place.

use acfa_finality::{
    decode_fork, encode_fork, CertError, CertFork, CertTuple, Certificate, Finality, Status,
};
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

/// Assert the node is untouched: it did not halt, it recorded no evidence, and it accused
/// nobody. Checking the SPECIFIC end state rather than a bare boolean is deliberate -- a
/// rejection that happens to fall out of an unrelated arm proves nothing about the guard the
/// test names, and this repository has already been bitten once by an assertion satisfied
/// through a downstream exit it was not testing.
fn assert_untouched(node: &Finality, why: &str) {
    assert!(
        matches!(node.status(), Status::Running { .. }),
        "{why}: the node HALTED"
    );
    assert!(!node.is_halted(), "{why}: the node HALTED");
    assert!(
        node.fork_history().is_empty(),
        "{why}: the pair was recorded as fork evidence, so the round is permanently non-final"
    );
    assert!(node.attributed().is_empty(), "{why}: somebody was accused");
    assert!(
        node.evidence().is_empty(),
        "{why}: the pair is being published onward as proof of a violation"
    );
}

// ---------------------------------------------------------------------------------------
// certificate.rs:293 -- `self.a.tuple.conflicts_with(&self.b.tuple)`
//
// GUARD-DELETION: drop the `conflicts_with` clause from `CertFork::is_valid`, leaving
// `self.a.is_valid(pki, f) && self.b.is_valid(pki, f)`. Both tests below go RED; the
// accepting twin stays green.
// ---------------------------------------------------------------------------------------

/// Two `f+1`-signed certificates for the SAME tuple are two quorums that AGREE. Reporting
/// agreement as a synchrony violation is not a false positive at the margin -- it inverts the
/// meaning of the object.
///
/// The pair is assembled by struct literal because that is the only way to assemble it:
/// `canonical` refuses, and the test asserts that refusal as its premise, so the bypass being
/// exercised is named rather than assumed.
#[test]
fn two_certificates_for_the_same_tuple_are_agreement_not_a_fork() {
    let (ids, pki) = room(7);
    let f = 1;
    let t = tuple(3, "A", "rho-a");
    let x = cert_signed_by(t, &[&ids[0], &ids[1]]);
    let y = cert_signed_by(t, &[&ids[2], &ids[3]]);

    // Premise 1: each half is INDIVIDUALLY valid. This is what forces the verdict onto the
    // conflict clause -- if `is_valid` returns false it cannot be because a half was weak.
    assert!(
        x.is_valid(&pki, f),
        "premise: the first half is valid alone"
    );
    assert!(
        y.is_valid(&pki, f),
        "premise: the second half is valid alone"
    );
    // Premise 2: the sanctioned constructor agrees these do not conflict. The struct literal
    // is the door under test.
    assert!(
        CertFork::canonical(x.clone(), y.clone()).is_none(),
        "premise: `canonical` must refuse this pair, else the struct literal is not a bypass"
    );

    let fork = CertFork { a: x, b: y };
    assert!(
        !fork.is_valid(&pki, f),
        "two quorums that signed the IDENTICAL tuple are agreement. Accepting them as a fork \
         reports consensus as a synchrony violation, and `CertFork`'s fields are public, so \
         `is_valid` must re-establish the conflict `canonical` checked rather than assume it."
    );

    let mut node = Finality::new(f);
    assert!(
        !node.observe_fork(fork, &pki),
        "the node accepted agreement as fork evidence"
    );
    assert_untouched(&node, "agreement offered as a fork");
}

/// A round-4 certificate and a round-9 certificate are two different rounds, not a
/// disagreement about one. Both are public by design.
///
/// This is the cheapest denial of service the layer admits: the attacker signs NOTHING. It
/// collects two genuine certificates off the gossip it is already relaying and staples them
/// together. Without site 293 the node halts, records the pair in permanent history, and
/// republishes it as proof that the synchrony bound broke -- on evidence of nothing.
#[test]
fn two_certificates_from_different_rounds_are_not_a_fork() {
    let (ids, pki) = room(7);
    let f = 1;
    let x = cert_signed_by(tuple(4, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let y = cert_signed_by(tuple(9, "B", "rho-b"), &[&ids[2], &ids[3]]);

    assert!(x.is_valid(&pki, f), "premise: the round-4 half is valid");
    assert!(y.is_valid(&pki, f), "premise: the round-9 half is valid");
    assert!(
        !x.tuple.conflicts_with(&y.tuple),
        "premise: different rounds do not conflict, they are simply different rounds"
    );

    let fork = CertFork { a: x, b: y };
    assert!(
        !fork.is_valid(&pki, f),
        "a pair spanning two ROUNDS was accepted as a round-r fork. A relay that has never \
         signed anything can halt the network with two certificates it merely forwarded."
    );

    let mut node = Finality::new(f);
    assert!(
        !node.observe_fork(fork, &pki),
        "the node halted on two unrelated rounds stapled together"
    );
    assert_untouched(&node, "two rounds stapled together");
}

/// ACCEPTING TWIN for site 293. A conflict predicate that refuses everything closes the door
/// on the failure this entire layer exists to make visible: a real fork must still halt, be
/// recorded, and be republished.
#[test]
fn a_genuinely_conflicting_pair_is_still_accepted_as_evidence() {
    let (ids, pki) = room(7);
    let f = 1;
    let x = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let y = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);
    assert!(
        x.tuple.conflicts_with(&y.tuple),
        "premise: same round, different tuple -- a real conflict"
    );

    let fork = CertFork::canonical(x, y).expect("the tuples conflict");
    assert!(
        fork.is_valid(&pki, f),
        "a REAL fork was refused. The guards above must reject fabrications without rejecting \
         the violation the layer exists to surface."
    );

    let mut node = Finality::new(f);
    assert!(node.observe_fork(fork, &pki), "real evidence must be taken");
    assert!(node.is_halted(), "a real fork must halt this node");
    assert!(
        !node.evidence().is_empty(),
        "a real fork must be republished for onward gossip"
    );
    // Disjoint honest quorums, nobody Byzantine: the fork is conclusive and names nobody.
    // That case is the one a culprit-hunting design would miss, so assert it explicitly.
    assert!(
        node.attributed().is_empty(),
        "no identity signed both halves; an unattributable fork must accuse nobody"
    );
}

// ---------------------------------------------------------------------------------------
// certificate.rs:294 -- `&& self.a.is_valid(pki, f)`
//
// GUARD-DELETION: drop the `self.a.is_valid(pki, f)` clause, leaving
// `self.a.tuple.conflicts_with(&self.b.tuple) && self.b.is_valid(pki, f)`. Both tests below
// go RED; the accepting twin stays green. Deleting the *b* clause (295) instead leaves both
// GREEN, which is what makes these tests evidence about 294 rather than about `is_valid`.
// ---------------------------------------------------------------------------------------

/// A fabricated A half that is one signature short of quorum must not halt anyone.
///
/// The doc on `is_valid` states the stake exactly: "A 'fork' where one side is invalid is not
/// evidence of a timing violation, it is evidence of a forgery, and conflating the two would
/// let anyone halt the system by fabricating a second certificate." That sentence was true of
/// the B side and untested on the A side.
#[test]
fn an_a_half_below_quorum_cannot_halt_the_system() {
    let (ids, pki) = room(7);
    let f = 1;
    // The fabrication: one real signature, which is what an attacker who controls exactly one
    // key can produce honestly. It is short of `f+1 = 2`.
    let bad = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0]]);
    let good = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);

    // Premise, stated as the EXACT error rather than `is_err()`: the half fails for the
    // quorum reason, with the counts the test intends. A bare `is_err()` here would be
    // satisfied by any unrelated rejection arm and would witness nothing.
    assert_eq!(
        bad.check(&pki, f),
        Err(CertError::Insufficient { have: 1, need: 2 }),
        "premise: the A half must fail on the QUORUM count, at exactly 1 of 2"
    );
    // Premise: every OTHER clause of `CertFork::is_valid` holds, so the verdict can only be
    // the A-half check.
    assert!(good.is_valid(&pki, f), "premise: the B half is valid");
    assert!(
        bad.tuple.conflicts_with(&good.tuple),
        "premise: the tuples conflict, so site 293 is not what rejects this pair"
    );

    let fork = CertFork { a: bad, b: good };
    assert!(
        !fork.is_valid(&pki, f),
        "a fork whose A half carries 1 of the 2 required signatures was accepted as evidence \
         of a synchrony violation. One key is enough to halt the network."
    );

    let mut node = Finality::new(f);
    assert!(
        !node.observe_fork(fork, &pki),
        "the node halted on a fabricated A half"
    );
    assert_untouched(&node, "under-quorum A half");
}

/// The same guard reached from zero: an A half whose signature entries are all unverifiable.
///
/// Sites 293 and 294 must be distinguishable from *how much* of the A half is fake, not just
/// *that* it is. This variant carries the right NUMBER of entries -- two, for `f+1 = 2` -- and
/// none of them verify, so it is the case an attacker who controls NO key can build: append
/// two ids that exist in the PKI and 64 zero bytes each. `check` counts verifying keys, so the
/// count is 0, and the premise assertion pins that at 0 rather than merely "an error", which
/// is how the test proves it reached the verification branch instead of stopping earlier.
#[test]
fn an_a_half_of_pure_forgeries_cannot_halt_the_system() {
    let (ids, pki) = room(7);
    let f = 1;
    let mut bad = Certificate::new(tuple(3, "A", "rho-a"));
    // Ids 5 and 6 are real PKI members who signed nothing. The entries are junk.
    bad.sigs.insert(5, [0u8; 64]);
    bad.sigs.insert(6, [0u8; 64]);
    let good = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);

    assert!(
        pki.contains_key(&5) && pki.contains_key(&6),
        "premise: the forged ids are KNOWN signers, so this tests signature verification and \
         not an unknown-signer path"
    );
    assert_eq!(
        bad.sigs.len(),
        2,
        "premise: the A half carries a full quorum's worth of ENTRIES, so only verification \
         can reject it"
    );
    assert_eq!(
        bad.check(&pki, f),
        Err(CertError::Insufficient { have: 0, need: 2 }),
        "premise: ZERO of the two entries verify -- if `have` were nonzero the forgery would \
         not be reaching the branch this test names"
    );
    assert!(good.is_valid(&pki, f), "premise: the B half is valid");
    assert!(
        bad.tuple.conflicts_with(&good.tuple),
        "premise: the tuples conflict, so site 293 is not what rejects this pair"
    );

    let fork = CertFork { a: bad, b: good };
    assert!(
        !fork.is_valid(&pki, f),
        "an A half signed by NOBODY was accepted as half of a synchrony-violation proof"
    );

    let mut node = Finality::new(f);
    assert!(
        !node.observe_fork(fork, &pki),
        "the node halted on an A half nobody signed"
    );
    assert_untouched(&node, "wholly forged A half");
}

/// ACCEPTING TWIN for site 294, at the boundary. An A half carrying EXACTLY `f+1` verifying
/// signatures is a real quorum and must be accepted -- otherwise the guard above is
/// indistinguishable from a stub that refuses every A half, and every genuine fork built by
/// two minimal quorums would be silently discarded.
#[test]
fn an_a_half_exactly_at_quorum_is_still_accepted() {
    let (ids, pki) = room(7);
    let f = 1;
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);
    assert_eq!(
        a.check(&pki, f),
        Ok(()),
        "premise: exactly f+1 = 2 distinct verifying keys is a quorum"
    );

    let fork = CertFork { a, b };
    assert!(
        fork.is_valid(&pki, f),
        "a fork whose A half sits exactly at the f+1 threshold was refused; the A-half check \
         must be a threshold, not a blanket refusal"
    );
    let mut node = Finality::new(f);
    assert!(node.observe_fork(fork, &pki), "real evidence must be taken");
    assert!(node.is_halted(), "a real fork must halt this node");
}

// ---------------------------------------------------------------------------------------
// certificate.rs:367 -- `let a = self.a.verified_signers(pki);`
//
// GUARD-DELETION: replace with the raw membership read the doc warns about,
// `let a: BTreeSet<u32> = self.a.sigs.keys().copied().collect();`. The framing test goes RED;
// the accepting twin stays green. Doing the same to line 368 (the b half) instead leaves BOTH
// green -- every existing framing test plants its forgery on B, which is precisely the gap.
// ---------------------------------------------------------------------------------------

/// crdt-07's framing vector, mirrored onto the A half, and delivered the way it would really
/// arrive: over the wire.
///
/// `wire::decode_fork` takes no `Pki`. It structurally CANNOT prune, so what a gossip consumer
/// holds is an un-pruned fork -- the `Finality` ingest invariant ("after pruning, membership
/// IS proof") does not reach it. That consumer's only sanctioned question is
/// `attributable_verified`, and the answer must be read from signatures that verify on BOTH
/// halves. Reading raw `sigs` membership on either one names a node that never signed.
///
/// The victim here genuinely signed the OTHER half. That matters: it is what puts them in the
/// B-side set, so a raw read of the A side produces a non-empty intersection and the mutant is
/// actually distinguishable. Framing somebody who signed neither half would leave the mutant
/// green and witness nothing.
#[test]
fn a_forged_entry_on_the_a_half_cannot_name_an_honest_node() {
    let (ids, pki) = room(7);
    let f = 1;
    let x = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let y = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);
    let mut fork = CertFork::canonical(x, y).expect("the tuples conflict");

    // Canonical orientation is decided by `tuple.id()`, a hash, so which certificate lands in
    // `a` is not something a test may assume. Ask the object, then pick a victim who really
    // signed `b` and really did not sign `a`.
    let victim = *fork
        .b
        .verified_signers(&pki)
        .iter()
        .next()
        .expect("premise: the B half has verified signers to draw a victim from");
    assert!(
        !fork.a.verified_signers(&pki).contains(&victim),
        "premise: the victim must NOT have signed the A half, or there is nothing to frame"
    );

    // The attack. No key required: append an id and 64 zero bytes to a carried certificate.
    fork.a.sigs.insert(victim, [0u8; 64]);

    // Deliver it as evidence really travels. The bytes survive the round trip unchanged, so
    // the forgery is present in what the consumer decodes.
    let decoded = decode_fork(&encode_fork(&fork)).expect("forged entries do not break framing");
    assert!(
        decoded.a.sigs.contains_key(&victim),
        "premise: the forged entry must survive the wire, or the branch under test is never \
         reached"
    );
    assert!(
        !decoded.a.verified_signers(&pki).contains(&victim),
        "premise: the forged entry must NOT verify, or the victim really did sign"
    );
    // Premise, and the reason this test cannot assert rejection: the evidence is still VALID.
    // crdt-07 chose counting over requiring-all so a bystander cannot make a genuine fork
    // refusable by appending junk. The junk therefore reaches the attribution reader by
    // design, and attribution is where it has to be stopped.
    assert!(
        decoded.is_valid(&pki, f),
        "premise: appended junk must not invalidate real evidence"
    );

    assert!(
        !decoded.attributable_verified(&pki).contains(&victim),
        "node {victim} is named as a DOUBLE-SIGNER on 64 zero bytes it never produced, from a \
         fork it could not prune. Attribution is an accusation and attributed identities are \
         excluded from round r+1 onward, so both halves must be read through \
         `verified_signers`, never through `sigs.keys()`."
    );
    assert!(
        decoded.attributable_verified(&pki).is_empty(),
        "nobody signed both halves; this fork must name nobody at all"
    );
    assert!(
        decoded.is_unattributable_verified(&pki),
        "the public unattributability reader must agree: real violation, no culprit"
    );
}

/// ACCEPTING TWIN for site 367. Reading the A half through `verified_signers` must still NAME
/// a genuine double-signer -- otherwise the fix is a stub that accuses nobody, and the layer
/// loses the attribution half of its accountability claim.
///
/// The double-signer's entry is a REAL signature over each conflicting tuple, which is what
/// makes it provable misbehaviour rather than an appended byte string.
#[test]
fn a_genuine_double_signer_is_still_named_from_the_a_half() {
    let (ids, pki) = room(7);
    let f = 1;
    // Node 3 signs BOTH conflicting tuples. That is equivocation, and it is attributable.
    let x = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1], &ids[2]]);
    let y = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);
    let fork = CertFork::canonical(x, y).expect("the tuples conflict");
    assert!(fork.is_valid(&pki, f), "premise: both halves are valid");

    let named = fork.attributable_verified(&pki);
    assert!(
        named.contains(&3),
        "node 3 signed both conflicting tuples with its real key and was NOT attributed"
    );
    assert_eq!(
        named.len(),
        1,
        "exactly one identity signed both halves; attribution must not spread beyond it"
    );
    assert!(
        !fork.is_unattributable_verified(&pki),
        "a fork with a proven double-signer is not unattributable"
    );

    let mut node = Finality::new(f);
    assert!(node.observe_fork(fork, &pki), "real evidence must be taken");
    assert!(
        node.attributed().contains(&3),
        "the proven double-signer must reach the node's attribution set"
    );
}
