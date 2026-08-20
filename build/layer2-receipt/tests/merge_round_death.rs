// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! #70 -- gossip stopped permanently at round ~4096/n, and the obvious fix would have opened a
//! silent conviction hole.
//!
//! `State::merge` bounded the contribution set by unioning ALL keys across ALL rounds against a
//! global cap, with no round scoping and no way to retire settled rounds. The set only grows, so
//! once the bound is reached every later merge fails FOREVER. Measured before the fix: n=20 dies
//! at round 205, n=100 at round 41, no recovery.
//!
//! The trap is that simply dropping old contributions is NOT semantically inert. Equivocation is
//! detected by comparing a new contribution against the ones held, so dropping round R destroys
//! the ability to convict an equivocator whose second message for round R arrives AFTER the
//! prune -- and an adversary who withholds it until then is exactly who the machinery exists to
//! catch. So the fix keeps the WITNESS and discards only the vector.
//!
//! These tests pin both halves: the stop is gone, AND a late equivocation for a pruned round
//! still convicts.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, Policy, Receipt, Rule, State};

/// One key, many ids: `contrib_msg` does not bind the node id, so a single signature is valid
/// for every id the PKI points at that key. Keeps a 400-round test instant without weakening
/// anything the tests actually assert.
fn cohort(n: u32) -> (Identity, Pki) {
    let base = Identity::from_secret(0, &[9u8; 32]);
    let pk = base.public();
    let pki: Pki = (0..n).map(|id| (id, pk)).collect();
    (base, pki)
}

fn round_batch(base: &Identity, n: u32, rnd: u64) -> State {
    let mut s = State::new();
    let t = vec![rnd as i64, 2];
    let th = h(&enc_tensor(&t));
    let sig = base.sign(&contrib_msg(
        &acfa_receipt::identity::NO_CONTEXT,
        rnd,
        base.node_id,
        &th,
    ));
    for id in 0..n {
        s.add_contribution(Contribution {
            ctx: acfa_receipt::identity::NO_CONTEXT,
            sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
            rnd,
            node_id: id,
            tensor: t.clone(),
            sig,
        });
    }
    s
}

/// **The control.** Without pruning the stop is still there -- so the test below is measuring
/// the fix and not an environment in which the bug never fired.
#[test]
fn without_pruning_gossip_still_dies_at_the_documented_round() {
    let (base, pki) = cohort(20);
    let mut held = State::new();
    let mut died = None;
    for rnd in 1..=400u64 {
        if held.merge(&round_batch(&base, 20, rnd), &pki).is_err() {
            died = Some(rnd);
            break;
        }
    }
    assert_eq!(
        died,
        Some(205),
        "premise: unpruned gossip must still die where it always did"
    );
}

/// **The stop is gone.** With a prune horizon a replica gossips indefinitely.
///
/// GUARD-DELETION: remove the `!self.w.contains_key(k)` filter from `merge`'s union, or make
/// `prune_through` a no-op, and this goes RED at round 205.
#[test]
fn with_a_prune_horizon_gossip_survives_far_past_the_old_ceiling() {
    let (base, pki) = cohort(20);
    let mut held = State::new();
    for rnd in 1..=400u64 {
        held.merge(&round_batch(&base, 20, rnd), &pki)
            .unwrap_or_else(|e| panic!("merge failed at round {rnd}: {e:?} -- the stop is back"));
        // Retire everything older than a 5-round working window.
        if rnd > 5 {
            held.prune_through(rnd - 5);
        }
    }
    assert!(
        held.c.len() <= 20 * 6,
        "the live set stays bounded by the window, got {}",
        held.c.len()
    );
    assert!(
        held.w.len() > 4096,
        "premise: far more than the old cap has been retired to witnesses ({})",
        held.w.len()
    );
}

/// **THE ONE THAT MATTERS.** A conflicting contribution for a round that has already been pruned
/// must still produce a valid conviction. This is the security half of #70, and a fix that only
/// cleared the stop would ship a silent hole here.
///
/// GUARD-DELETION: delete the witness loop at the top of `detect_equivocations` and this goes
/// RED -- the equivocator is never convicted, which is precisely the adversary that withholds a
/// second message until the prune horizon passes.
#[test]
fn a_late_equivocation_for_a_pruned_round_still_convicts() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let b = Identity::from_secret(2, &[2u8; 32]);
    let pki: Pki = [(a.node_id, a.public()), (b.node_id, b.public())]
        .into_iter()
        .collect();

    let signed = |id: &Identity, rnd: u64, t: &[i64]| {
        let th = h(&enc_tensor(t));
        Contribution {
            ctx: acfa_receipt::identity::NO_CONTEXT,
            sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
            rnd,
            node_id: id.node_id,
            tensor: t.to_vec(),
            sig: id.sign(&contrib_msg(
                &acfa_receipt::identity::NO_CONTEXT,
                rnd,
                id.node_id,
                &th,
            )),
        }
    };

    let mut s = State::new();
    s.deliver(signed(&a, 1, &[10, 20]), &pki);
    s.deliver(signed(&b, 1, &[11, 21]), &pki);

    // Round 1 settles and is retired. Its vectors are gone.
    let retired = s.prune_through(1);
    assert_eq!(retired, 2, "both round-1 contributions retired");
    assert!(s.c.is_empty(), "no live contributions remain");
    assert_eq!(s.w.len(), 2, "but their witnesses are kept");
    assert!(s.convicted(&pki).is_empty(), "nobody convicted yet");

    // NOW the equivocator's second round-1 message arrives -- after the prune.
    s.deliver(signed(&a, 1, &[999, 999]), &pki);

    let convicted = s.convicted(&pki);
    assert!(
        convicted.contains(&a.node_id),
        "a late equivocation for a PRUNED round must still convict -- got {convicted:?}"
    );
    assert!(
        !convicted.contains(&b.node_id),
        "and must not convict the honest node"
    );
}

/// Pruning must not move what a receipt commits to. Receipts are built from freshly constructed
/// states, so an older round's absence cannot reach them -- asserted rather than assumed.
#[test]
fn pruning_does_not_move_a_receipt_root() {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let signed = |id: &Identity, rnd: u64, t: &[i64]| {
        let th = h(&enc_tensor(t));
        Contribution {
            ctx: acfa_receipt::identity::NO_CONTEXT,
            sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
            rnd,
            node_id: id.node_id,
            tensor: t.to_vec(),
            sig: id.sign(&contrib_msg(
                &acfa_receipt::identity::NO_CONTEXT,
                rnd,
                id.node_id,
                &th,
            )),
        }
    };

    let mut s = State::new();
    for id in &ids {
        s.deliver(signed(id, 1, &[1, 2]), &pki);
        s.deliver(signed(id, 2, &[3, 4]), &pki);
    }
    let before = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        2,
        &pki,
        1,
        Rule::Krum,
    );
    s.prune_through(1); // retire round 1 only
    let after = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        2,
        &pki,
        1,
        Rule::Krum,
    );

    assert_eq!(
        before.claimed_state_root, after.claimed_state_root,
        "a round-2 receipt must not observe round 1's retirement"
    );
    assert_eq!(before.claimed_aggregate, after.claimed_aggregate);
    assert!(
        after.verify(&Policy::new(pki, 1)).is_ok(),
        "and it still verifies"
    );
}

/// A peer replaying a retired round must not be able to re-inflate the live set back to the cap
/// -- that would be the same permanent stop by another route.
#[test]
fn replaying_a_retired_round_does_not_re_inflate_the_live_set() {
    let (base, pki) = cohort(20);
    let mut held = State::new();
    let batch = round_batch(&base, 20, 1);
    held.merge(&batch, &pki).unwrap();
    assert_eq!(held.c.len(), 20);

    held.prune_through(1);
    assert!(held.c.is_empty(), "retired");

    // The peer sends round 1 again, repeatedly.
    for _ in 0..10 {
        held.merge(&batch, &pki).unwrap();
    }
    assert!(
        held.c.is_empty(),
        "a replayed retired round must not come back to life, got {} live",
        held.c.len()
    );
    assert_eq!(held.w.len(), 20, "witnesses unchanged");
}
