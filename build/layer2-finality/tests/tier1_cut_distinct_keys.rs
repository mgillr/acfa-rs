// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! TIER 1 — crypto-03 for RELAY CHAINS, which had the guard but no witness.
//!
//! A mutation sweep found `cut.rs:174/175` unwitnessed: the distinct-KEY check on a relay chain
//! could be deleted and the whole suite stayed green. `certificate.rs` has
//! `one_key_under_two_ids_cannot_alone_satisfy_the_quorum` for exactly this attack; `cut.rs` had
//! no equivalent, so the same fix was guarded on one door and unguarded on the other.
//!
//! Why it matters: chain completeness is `f+1` DISTINCT signers, and `f+1` is what guarantees at
//! least one HONEST relayer. Two ids sharing one key are one signer wearing two labels, so
//! counting ids lets a single key supply an entire chain and the honesty guarantee evaporates.
//!
//! Both tests are verified to FAIL on their mutant and pass on pristine.

use acfa_finality::cut::RelayChain;
use acfa_receipt::hash::h;
use acfa_receipt::identity::{Identity, Pki};

/// One key wearing `f+1` ids must NOT complete a chain.
///
/// GUARD-DELETION: remove the `if !seen_keys.insert(*pk) { return Err(...) }` arm from
/// `RelayChain::check` and this goes RED — one signer supplies the whole chain.
#[test]
fn one_key_under_two_ids_cannot_alone_complete_a_relay_chain() {
    // Same secret, two different node ids: one key, two labels.
    let a = Identity::from_secret(1, &[7u8; 32]);
    let b = Identity::from_secret(2, &[7u8; 32]);
    assert_eq!(a.public(), b.public(), "premise: these ids share one key");

    let pki: Pki = [(a.node_id, a.public()), (b.node_id, b.public())]
        .into_iter()
        .collect();

    let base = RelayChain {
        anchor: h(b"anchor"),
        leaf: h(b"leaf"),
        hops: Vec::new(),
    };
    let chain = base.relay(&a).relay(&b);
    assert_eq!(chain.hops.len(), 2, "premise: f+1 = 2 hops for f = 1");

    assert!(
        chain.check(&pki, 1).is_err(),
        "one key wearing two ids must not complete an f+1 chain"
    );
}

/// The accepting twin: two GENUINELY distinct keys still complete the chain, so the guard is not
/// a reject-everything stub.
#[test]
fn two_distinct_keys_still_complete_a_relay_chain() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let b = Identity::from_secret(2, &[2u8; 32]);
    assert_ne!(a.public(), b.public(), "premise: genuinely distinct keys");

    let pki: Pki = [(a.node_id, a.public()), (b.node_id, b.public())]
        .into_iter()
        .collect();

    let base = RelayChain {
        anchor: h(b"anchor"),
        leaf: h(b"leaf"),
        hops: Vec::new(),
    };
    let chain = base.relay(&a).relay(&b);
    assert!(
        chain.check(&pki, 1).is_ok(),
        "a chain of two independent signers must still be accepted"
    );
}
