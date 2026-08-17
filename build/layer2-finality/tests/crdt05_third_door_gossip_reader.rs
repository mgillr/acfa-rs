// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crdt-05, the THIRD DOOR: the public gossip reader can no longer accuse an honest node.
//!
//! The two `Finality` ingest paths (`observe`, `observe_fork`) prune unverifiable signature
//! entries at ingest, so a fork inside `Finality` names on verified membership by invariant.
//! But `wire::decode_fork` is a SEPARATE public entry: it canonicalises and hands a
//! `CertFork` straight back to a caller, and it has no `Pki`, so it CANNOT prune. A gossip
//! consumer that forwarded evidence (`Finality::evidence()` -> `encode_fork`), received it,
//! decoded it, and called a public `attributable()` would name an honest node as a
//! double-signer -- membership, not proof.
//!
//! Measured on the pre-fix public API: a 702-byte decoded fork carrying a forged
//! `(node 1, 64 zero bytes)` entry returned `attributable() == {1}` and
//! `is_unattributable() == false` -- accusing an innocent AND claiming someone is accusable,
//! in one call.
//!
//! THE FIX IS NOT TO PRUNE AT DECODE (there is no PKI there). It is that an accusation that
//! cannot be verified must not be OFFERED: `attributable()` and `is_unattributable()` are now
//! `pub(crate)`, so the only public way to name a signer is `attributable_verified(pki)` /
//! `is_unattributable_verified(pki)`, which can name only a signature that actually verifies.
//!
//! HOW THIS TEST PROVES THE FIX. It exercises the exact gossip round-trip and asserts the
//! decoded fork names nobody through the only public accuser. That the RAW accuser is gone is
//! enforced by the compiler: uncomment the `decoded.attributable()` line below and this file
//! fails to build with `method `attributable` is private` -- which is the "fails on the
//! current public API" proof, turned structural. On the pre-fix tree that same line compiled
//! and returned `{1}`.

use acfa_finality::wire::{decode_fork, encode_fork};
use acfa_finality::{CertFork, CertTuple, Certificate};
use acfa_receipt::hash::h;
use acfa_receipt::identity::{Identity, Pki};

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

/// A fork forwarded over the wire, carrying a forged entry for an honest node, must not
/// accuse that node when the recipient reads it through the public API.
#[test]
fn a_decoded_fork_with_a_forged_entry_cannot_accuse_an_honest_node() {
    let ids: Vec<Identity> = (1..=7)
        .map(|n| Identity::from_secret(n, &[n as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    // Node 1 signs `a` honestly and NEVER signs `b`. Someone forges a junk entry for node 1
    // on `b` -- 64 zero bytes -- then forwards the fork.
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[1]]);
    let mut b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[3]]);
    b.sigs.insert(1, [0u8; 64]);
    let fork = CertFork::canonical(a, b).expect("the tuples conflict");

    // The gossip round-trip: encode, decode. `decode_fork` does not prune.
    let bytes = encode_fork(&fork);
    let decoded = decode_fork(&bytes).expect("well-formed evidence decodes");

    // Premise: the decoded fork is genuinely valid evidence of a timing violation, so the
    // recipient will read it -- this is not a forgery that gets rejected wholesale.
    assert!(
        decoded.is_valid(&pki, 1),
        "premise: the fork itself is valid evidence, or the recipient never reads it"
    );

    // The compiler enforces that the unverified accuser is gone from the public surface.
    // Uncommenting this line must fail the build with `method `attributable` is private`:
    //     assert_eq!(decoded.attributable(), [1].into_iter().collect::<std::collections::BTreeSet<_>>());

    // The only public accuser takes the PKI and names NOBODY: node 1's entry does not verify.
    assert!(
        decoded.attributable_verified(&pki).is_empty(),
        "a forwarded fork carrying a forged entry for node 1 accused an honest node. The \
         public accuser must take a PKI so it can only name a verifying signature; the raw \
         membership reader must not be reachable from a decoded fork."
    );
    // And it does not claim someone IS accusable while naming nobody.
    assert!(
        decoded.is_unattributable_verified(&pki),
        "the fork names nobody verifiably, so the verified reader must report it \
         unattributable rather than asserting a phantom accused"
    );
}

/// Without this, the assertions above are satisfied by a reader that names nobody ever. A
/// GENUINE bridging signer -- one identity signing both conflicting tuples -- must still be
/// named after the same gossip round-trip.
#[test]
fn a_decoded_fork_still_names_a_real_bridging_signer() {
    let ids: Vec<Identity> = (1..=7)
        .map(|n| Identity::from_secret(n, &[n as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    // ids[4] (node 5) signs BOTH conflicting tuples -- provable misbehaviour.
    let a = cert_signed_by(tuple(3, "A", "rho-a"), &[&ids[0], &ids[4]]);
    let b = cert_signed_by(tuple(3, "B", "rho-b"), &[&ids[2], &ids[4]]);
    let fork = CertFork::canonical(a, b).expect("the tuples conflict");

    let decoded = decode_fork(&encode_fork(&fork)).expect("decodes");

    assert_eq!(
        decoded
            .attributable_verified(&pki)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![5],
        "a real double-signer must still be named through the verified reader after the \
         gossip round-trip, or the fix has simply disabled attribution"
    );
    assert!(!decoded.is_unattributable_verified(&pki));
}
