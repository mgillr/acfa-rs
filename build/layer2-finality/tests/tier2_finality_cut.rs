// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! TIER 2 — the two entrance guards of `RelayChain::check`, which had no witness at all.
//!
//! A by-line mutation sweep of 291 guard sites found 111 that no test in this repository
//! could distinguish from their mutants. Three of those sites are the first two guards of
//! [`RelayChain::check`] — `cut.rs:155` (the saturating hop threshold) and `cut.rs:171/172`
//! (the off-PKI hop refusal). That function is the door to the admitted set: it decides
//! whether a contribution's Dolev-Strong broadcast CLOSED, and a leaf that closes enters the
//! cut, enters the Merkle root, and enters the certificate every honest node signs. A guard
//! on that door with no test behind it is a guard that can be deleted in a refactor and
//! noticed by nobody.
//!
//! ## Why each one was unwitnessed, which is the more useful half of the story
//!
//! **`cut.rs:155`, `let need = f.saturating_add(1)`.** `f` arrives from an untrusted receipt.
//! Without saturation, `f + 1` at `usize::MAX` wraps to `0`, `self.hops.len() < 0` is
//! vacuously false, and a chain with ZERO hops passes — a threshold that gets *easier* as
//! the claimed adversary budget grows, failing open in the one direction an attacker picks.
//! The identical guard at `certificate.rs:246` IS witnessed, by
//! `finality.rs::an_unreachable_fault_bound_does_not_make_the_threshold_vacuous`. That test's
//! own doc comment asserts, in prose, that `RelayChain::check` accepted a chain with no hops
//! — but its body calls `Certificate::check` twice and `RelayChain::check` never. The relay
//! copy of the guard was covered by a *sentence*. A doc comment is not a witness, and a fix
//! applied to two doors is only tested on the door the test actually opens.
//!
//! **`cut.rs:171/172`, the `pki.get(id)` miss.** `ChainError::UnknownSigner` is constructed
//! in exactly one place outside `cut.rs` itself: `tests/error_traits.rs`, which builds the
//! value by hand and checks that it renders a non-empty `Display` string. Formatting an
//! error proves the message exists; it proves nothing about whether any code path ever
//! produces it. No test had ever driven a hop whose signer is absent from the PKI, so the
//! arm that refuses one was dead as far as the suite could tell.
//!
//! Why that arm carries weight: chain completeness is `f+1` DISTINCT signers, and `f+1` is
//! what guarantees at least one HONEST relayer — the node that carries the message to every
//! honest peer inside the bound. "Honest" is only meaningful relative to the PKI that says
//! who the participants are. If a PKI miss SKIPS the hop instead of refusing the chain, then
//! `f+1` hops signed by identities nobody registered satisfy `is_complete`, and a set of
//! complete strangers has `f+1` distinct signers and zero participants. Worse, skipping the
//! hop also skips the distinct-KEY check three lines below it (there is no `pk` to insert),
//! so an unregistered attacker can supply an entire chain from a single key wearing `f+1`
//! labels — the exact attack `tier1_cut_distinct_keys.rs` closes for registered signers,
//! reopened for unregistered ones.
//!
//! ## How these tests are built, given two traps this project has already fallen into
//!
//! Every refusal here is asserted as an EXACT `ChainError` value, never as `is_err()`.
//! `check` has four refusal arms and a test that only demands "some error" is satisfied by
//! whichever arm happens to fire first — that is how a test passes for a coincidental reason
//! and witnesses nothing. Each test therefore also asserts its PREMISES, so the named arm is
//! provably the one being reached: the chain is long enough that `TooShort` cannot fire, the
//! hop ids are distinct so `RepeatedSigner` cannot fire, and each stranger's signature is
//! independently verified under its own key so `BadHop` cannot fire. Reaching the branch you
//! named is not automatic — this repository has already shipped a "malformed key" test whose
//! key was merely weak, so the decode-failure arm never executed and three mutants survived.
//!
//! Each site also gets an ACCEPTING TWIN, so none of these guards can be satisfied by a
//! reject-everything stub, and the site-155 tests pin an ordinary threshold in both
//! directions (`f=2` accepts three hops, refuses two) so saturation is not mistaken for
//! "large `f` refuses everything".
//!
//! ## What this file does NOT cover
//!
//! - It does not test the `RepeatedSigner`, distinct-key, or `BadHop` arms; those are
//!   witnessed elsewhere (`tier1_cut_distinct_keys.rs`, `finality.rs`) and are used here only
//!   as premises to prove the target arm is the one firing.
//! - It says nothing about the *protocol* claim that `f+1` distinct signers implies an honest
//!   relayer, nor about the `>= 2tau` round budget. Those are arguments about the
//!   construction, not properties of this function.
//! - It does not cover PKI INGRESS — whether a weak or malformed key should have been allowed
//!   into the `Pki` in the first place (`crypto10_finality_pki_ingress.rs`). Here the PKI is
//!   taken as given; the only question is what happens to a signer who is not in it.
//! - `usize::MAX` is an unreachable fault bound in any real deployment. The point is not that
//!   someone will run at that `f`; it is that the threshold must be monotone in `f`, and a
//!   wrapping threshold is non-monotone at exactly one attacker-chosen value.

use acfa_finality::cut::{relay_msg, ChainError, DeadlineCut, RelayChain};
use acfa_receipt::hash::h;
use acfa_receipt::identity::{verify, Identity, Pki};

fn anchor() -> [u8; 32] {
    h(b"round r-1 certificate")
}

fn leaf() -> [u8; 32] {
    h(b"the contribution being relayed")
}

fn pki_of(ids: &[&Identity]) -> Pki {
    ids.iter().map(|i| (i.node_id, i.public())).collect()
}

/// Build a chain over `anchor`/`leaf` by relaying through `signers` in order.
fn chain_through(signers: &[&Identity]) -> RelayChain {
    let mut c = RelayChain {
        anchor: anchor(),
        leaf: leaf(),
        hops: Vec::new(),
    };
    for s in signers {
        c = c.relay(s);
    }
    c
}

/// Every hop signature verifies under its own signer's key over the prefix it extends.
/// Asserted as a PREMISE: it rules `ChainError::BadHop` out as the reason for any refusal
/// below, so a refusal cannot be credited to the wrong guard.
fn assert_every_hop_signature_is_genuine(chain: &RelayChain, signers: &[&Identity]) {
    assert_eq!(
        chain.hops.len(),
        signers.len(),
        "premise: one hop per signer"
    );
    for (depth, (id, sig)) in chain.hops.iter().enumerate() {
        let signer = signers[depth];
        assert_eq!(
            *id, signer.node_id,
            "premise: hop {depth} is the expected id"
        );
        let msg = relay_msg(&chain.anchor, &chain.leaf, &chain.hops[..depth]);
        assert!(
            verify(&signer.public(), &msg, sig),
            "premise: hop {depth} carries a genuine signature, so BadHop cannot be the \
             refusal we observe"
        );
    }
}

// ---------------------------------------------------------------------------
// cut.rs:155 — the hop threshold must not wrap.
// ---------------------------------------------------------------------------

/// A chain with NO hops must still be refused at `f = usize::MAX`.
///
/// GUARD-DELETION: change `f.saturating_add(1)` to `f.wrapping_add(1)` (the pre-fix form —
/// note `[profile.release] overflow-checks = true`, so plain `f + 1` panics rather than
/// wraps in both profiles) and `need` becomes 0, `0 < 0` is false, the hop loop has nothing
/// to iterate, and `check` returns `Ok(())` on a zero-hop chain. This test goes RED.
#[test]
fn a_zero_hop_chain_is_refused_at_an_unreachable_fault_bound() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let pki = pki_of(&[&a]);

    let empty = RelayChain {
        anchor: anchor(),
        leaf: leaf(),
        hops: Vec::new(),
    };
    assert!(empty.hops.is_empty(), "premise: the chain carries no hops");

    // The EXACT refusal, not `is_err()`: a zero-hop chain has exactly one honest reason to
    // be refused, and `need` must be the saturated value rather than a wrapped one.
    assert_eq!(
        empty.check(&pki, usize::MAX),
        Err(ChainError::TooShort {
            have: 0,
            need: usize::MAX
        }),
        "a zero-hop chain closed the broadcast because f+1 wrapped to zero"
    );
    assert!(
        !empty.is_complete(&pki, usize::MAX),
        "is_complete is the predicate the cut actually consults"
    );
}

/// A chain that is perfect in every other respect — distinct signers, all in the PKI, all
/// signatures genuine — must STILL be refused at `f = usize::MAX`, because it is short.
///
/// This is the sharper of the two: it shows the refusal comes from the threshold and from
/// nothing else, since the very same chain is accepted at `f = 2`.
///
/// GUARD-DELETION: `f.wrapping_add(1)` makes `need` 0, every hop then verifies cleanly, and
/// `check` returns `Ok(())`. RED.
#[test]
fn an_otherwise_perfect_chain_is_refused_at_an_unreachable_fault_bound() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let b = Identity::from_secret(2, &[2u8; 32]);
    let c = Identity::from_secret(3, &[3u8; 32]);
    let signers = [&a, &b, &c];
    let pki = pki_of(&signers);

    let chain = chain_through(&signers);
    assert_every_hop_signature_is_genuine(&chain, &signers);
    assert_eq!(
        chain.check(&pki, 2),
        Ok(()),
        "premise: at f = 2 this exact chain is ACCEPTED, so nothing about it is malformed"
    );

    assert_eq!(
        chain.check(&pki, usize::MAX),
        Err(ChainError::TooShort {
            have: 3,
            need: usize::MAX
        }),
        "three hops satisfied an unreachable fault bound because f+1 wrapped to zero"
    );
}

/// The consequence, at the layer that matters: a zero-hop chain must not be ADMITTED.
///
/// `RelayChain::check` is not the interesting object on its own — `DeadlineCut::close` is,
/// because its output is what gets Merkle-rooted into the round certificate. This test
/// asserts the leaf lands in `deemed_absent` and not in `admitted`.
///
/// GUARD-DELETION: with `f.wrapping_add(1)` the zero-hop chain is complete, so the leaf is
/// admitted and the round certifies a contribution nobody ever relayed. RED.
#[test]
fn a_zero_hop_chain_is_not_admitted_into_the_cut_at_an_unreachable_fault_bound() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let pki = pki_of(&[&a]);

    let empty = RelayChain {
        anchor: anchor(),
        leaf: leaf(),
        hops: Vec::new(),
    };
    let cut = DeadlineCut::close(anchor(), std::slice::from_ref(&empty), &pki, usize::MAX);

    assert_eq!(
        cut.admitted,
        Vec::<[u8; 32]>::new(),
        "a contribution with zero relay hops was admitted into the cut"
    );
    assert_eq!(
        cut.deemed_absent,
        vec![leaf()],
        "an unclosed broadcast must be deemed absent, uniformly"
    );
}

/// ACCEPTING TWIN, in both directions: saturation must not turn the threshold into a
/// reject-everything stub, and a large `f` must not be the only thing it can refuse.
///
/// At `f = 0` one hop suffices; at `f = 2` three hops are accepted and two are refused with
/// the ordinary, unsaturated `need`. If a "fix" for the wrap had clamped `need` low or high,
/// one of these three assertions would catch it.
#[test]
fn the_saturated_threshold_still_accepts_and_refuses_at_ordinary_fault_bounds() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let b = Identity::from_secret(2, &[2u8; 32]);
    let c = Identity::from_secret(3, &[3u8; 32]);
    let pki = pki_of(&[&a, &b, &c]);

    assert_eq!(
        chain_through(&[&a]).check(&pki, 0),
        Ok(()),
        "f = 0 needs one hop and must accept one hop"
    );
    assert_eq!(
        chain_through(&[&a, &b, &c]).check(&pki, 2),
        Ok(()),
        "f = 2 needs three hops and must accept three hops"
    );
    assert_eq!(
        chain_through(&[&a, &b]).check(&pki, 2),
        Err(ChainError::TooShort { have: 2, need: 3 }),
        "f = 2 must still refuse two hops, with the ordinary need"
    );
}

// ---------------------------------------------------------------------------
// cut.rs:171/172 — a hop signed by an identity absent from the PKI is refused,
// and the refusal is specifically UnknownSigner.
// ---------------------------------------------------------------------------

/// A full-length chain whose signers are all absent from the PKI must be refused, and the
/// refusal must NAME the unknown signer.
///
/// The premises rule out every other arm: the chain is long enough (`TooShort` cannot fire),
/// the ids are distinct (`RepeatedSigner` cannot fire), and both signatures verify under
/// their own keys (`BadHop` cannot fire). The PKI is deliberately NON-EMPTY, so the refusal
/// cannot be credited to "there were no keys at all".
///
/// GUARD-DELETION A (`cut.rs:171`): replace the `else { return Err(...) }` arm with
/// `else { continue; }` — the mutant skips the hop, both hops are skipped, the loop ends,
/// and `check` returns `Ok(())`. RED.
///
/// GUARD-DELETION B (`cut.rs:172`): keep the arm but return a different variant, e.g.
/// `ChainError::BadHop { depth, node_id: *id }`. The chain is still refused, so an
/// `is_err()` test would stay GREEN — this one goes RED because it demands the exact value.
#[test]
fn a_chain_of_hops_absent_from_the_pki_is_refused_as_unknown_signer() {
    // The registered room. Non-empty, and none of its members ever touch the chain.
    let member = Identity::from_secret(1, &[1u8; 32]);
    let pki = pki_of(&[&member]);

    // Two genuine, independent keys that were simply never registered.
    let stranger_a = Identity::from_secret(40, &[0x4au8; 32]);
    let stranger_b = Identity::from_secret(41, &[0x4bu8; 32]);
    assert!(
        !pki.contains_key(&stranger_a.node_id) && !pki.contains_key(&stranger_b.node_id),
        "premise: the hop identities are genuinely absent from the PKI"
    );
    assert!(!pki.is_empty(), "premise: the PKI is populated, not empty");
    assert_ne!(
        stranger_a.public(),
        stranger_b.public(),
        "premise: two independent keys, so RepeatedSigner cannot be the refusal"
    );

    let signers = [&stranger_a, &stranger_b];
    let chain = chain_through(&signers);
    assert_eq!(
        chain.hops.len(),
        2,
        "premise: f+1 = 2 hops at f = 1, so TooShort cannot be the refusal"
    );
    assert_every_hop_signature_is_genuine(&chain, &signers);

    assert_eq!(
        chain.check(&pki, 1),
        Err(ChainError::UnknownSigner(stranger_a.node_id)),
        "a chain of f+1 unregistered signers closed the broadcast"
    );
    assert!(
        !chain.is_complete(&pki, 1),
        "is_complete is the predicate the cut consults, and it must agree"
    );
}

/// The first off-PKI hop is named even when it is preceded by a legitimate one.
///
/// This is the mixed case, and it is the one a skip-the-hop mutant survives most easily: the
/// registered hop verifies perfectly, so a mutant that merely ignores the stranger produces a
/// chain that looks complete and well-signed. The stranger sits at depth 1, so a variant-swap
/// mutant returning `BadHop { depth: 1, .. }` is also distinguished here.
///
/// GUARD-DELETION A (`else { continue; }`): the stranger's hop is skipped, the member's hop
/// verifies, `hops.len() == 2 >= need`, and `check` returns `Ok(())`. RED.
///
/// GUARD-DELETION B (variant swap): the value is no longer `UnknownSigner(41)`. RED.
#[test]
fn the_first_off_pki_hop_is_named_even_when_an_earlier_hop_is_registered() {
    let member = Identity::from_secret(1, &[1u8; 32]);
    let stranger = Identity::from_secret(41, &[0x4bu8; 32]);
    let pki = pki_of(&[&member]);
    assert!(
        pki.contains_key(&member.node_id) && !pki.contains_key(&stranger.node_id),
        "premise: exactly one of the two hop identities is registered"
    );

    let signers = [&member, &stranger];
    let chain = chain_through(&signers);
    assert_eq!(chain.hops.len(), 2, "premise: the chain is long enough");
    assert_every_hop_signature_is_genuine(&chain, &signers);

    assert_eq!(
        chain.check(&pki, 1),
        Err(ChainError::UnknownSigner(stranger.node_id)),
        "an unregistered relayer was allowed to contribute a hop toward f+1"
    );
}

/// The consequence at the cut: a leaf relayed only by strangers must be deemed absent.
///
/// GUARD-DELETION A (`else { continue; }`): the stranger chain is complete, the leaf is
/// admitted, and the round certificate commits to a contribution whose entire broadcast was
/// carried by identities the PKI never heard of. RED.
#[test]
fn a_chain_of_off_pki_hops_is_not_admitted_into_the_cut() {
    let member = Identity::from_secret(1, &[1u8; 32]);
    let pki = pki_of(&[&member]);
    let stranger_a = Identity::from_secret(40, &[0x4au8; 32]);
    let stranger_b = Identity::from_secret(41, &[0x4bu8; 32]);

    let chain = chain_through(&[&stranger_a, &stranger_b]);
    let cut = DeadlineCut::close(anchor(), std::slice::from_ref(&chain), &pki, 1);

    assert_eq!(
        cut.admitted,
        Vec::<[u8; 32]>::new(),
        "a leaf relayed only by unregistered identities was admitted"
    );
    assert_eq!(
        cut.deemed_absent,
        vec![leaf()],
        "an off-PKI relay chain must be deemed absent"
    );
}

/// ACCEPTING TWIN: the SAME two identities, the SAME chain bytes, once they are registered.
///
/// Nothing changes except the PKI, which is the point — the guard must be about registration
/// and not about anything else in the chain. If a mutant refused every chain, this goes RED
/// and the refusing tests above would be worthless.
#[test]
fn the_same_chain_is_accepted_and_admitted_once_its_signers_are_registered() {
    let stranger_a = Identity::from_secret(40, &[0x4au8; 32]);
    let stranger_b = Identity::from_secret(41, &[0x4bu8; 32]);
    let signers = [&stranger_a, &stranger_b];
    let chain = chain_through(&signers);

    let outside = pki_of(&[&Identity::from_secret(1, &[1u8; 32])]);
    assert_eq!(
        chain.check(&outside, 1),
        Err(ChainError::UnknownSigner(stranger_a.node_id)),
        "premise: unregistered, this exact chain is refused"
    );

    let inside = pki_of(&signers);
    assert_eq!(
        chain.check(&inside, 1),
        Ok(()),
        "registering the signers must make the identical chain acceptable"
    );

    let cut = DeadlineCut::close(anchor(), std::slice::from_ref(&chain), &inside, 1);
    assert_eq!(
        cut.admitted,
        vec![leaf()],
        "a complete chain of registered signers must be admitted into the cut"
    );
    assert_eq!(
        cut.deemed_absent,
        Vec::<[u8; 32]>::new(),
        "and nothing must be deemed absent"
    );
}
