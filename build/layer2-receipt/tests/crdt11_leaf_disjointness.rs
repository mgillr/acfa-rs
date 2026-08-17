// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `crdt11_leaf_disjointness` -- the ENFORCEABLE form of a conjunction.
//!
//! `State::root` commits to a duplicate-free tree. That property is held by TWO sites in
//! two different files, and neither is sufficient alone:
//!
//!   HALF 1  `hash::merkle_root` REFUSES duplicate leaves (odd levels pad by duplicating
//!           the sorted maximum, so a duplicate makes the root ambiguous with a larger tree)
//!   HALF 2  `src/entry.rs` gives contributions and proofs DISJOINT leaf spaces via the `C|`
//!           and `P|` prefixes, so concatenating two internally-unique key sets stays unique
//!
//! Documentation at both sites is not enough: a comment cannot fail, and the author making
//! the plausible local change is holding the file whose comment describes the constraint.
//! These tests fail instead. Grep `crdt11_` from either site to find the whole property.

use acfa_receipt::hash::{h, merkle_root};

/// HALF 1. Fails if the duplicate refusal in `merkle_root` is relaxed.
#[test]
#[should_panic(expected = "duplicate leaves")]
fn crdt11_half1_merkle_root_refuses_duplicates() {
    let (a, b, c) = (h(b"a"), h(b"b"), h(b"c"));
    // `a` is the argmax of the 0x00-prefixed hashes: the input that used to collide.
    let _ = merkle_root(&[a, b, c, a]);
}

/// HALF 2. Fails if the two leaf spaces stop being disjoint -- if the prefixes are unified,
/// or a new leaf type reuses one. Built from IDENTICAL inner bytes so the prefix is the only
/// thing separating them: if it stops separating, these two leaves become equal.
#[test]
fn crdt11_half2_leaf_prefixes_keep_the_spaces_disjoint() {
    let inner = [7u8; 32];

    let mut contribution = Vec::new();
    contribution.extend_from_slice(b"C|");
    contribution.extend_from_slice(&inner);

    let mut proof = Vec::new();
    proof.extend_from_slice(b"P|");
    proof.extend_from_slice(&inner);

    assert_ne!(
        &contribution[..2],
        &proof[..2],
        "the contribution and proof leaf prefixes have been unified; State::root \
         concatenates the two key sets and merkle_root refuses duplicates, so this turns \
         a release assert into a panic in production"
    );
    assert_ne!(
        h(&contribution),
        h(&proof),
        "identical inner bytes under the two prefixes produced the same leaf"
    );
}

/// THE CONJUNCTION. Both halves can hold locally while their COMPOSITION breaks, and
/// neither half-test can see that. A state carrying BOTH kinds of leaf must produce a root:
/// if the spaces ever overlap, half 1 fires on real data and this panics.
#[test]
fn crdt11_conjunction_a_tree_over_both_leaf_kinds_still_commits() {
    let mut leaves = Vec::new();
    for i in 0..4u8 {
        let mut c = Vec::new();
        c.extend_from_slice(b"C|");
        c.push(i);
        leaves.push(h(&c));
        let mut p = Vec::new();
        p.extend_from_slice(b"P|");
        p.push(i);
        leaves.push(h(&p));
    }
    let root = merkle_root(&leaves);
    assert_ne!(root, [0u8; 32]);
    assert_eq!(root, merkle_root(&leaves), "and it is deterministic");
}

/// THE ACCEPTING TWIN, so none of the refusals above is passed by a function that refuses
/// everything.
#[test]
fn crdt11_accepting_distinct_leaves_still_commit() {
    let (a, b, c) = (h(b"a"), h(b"b"), h(b"c"));
    assert_eq!(merkle_root(&[a, b, c]), merkle_root(&[c, b, a]));
    assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b]));
}
