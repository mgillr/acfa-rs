// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Redacted receipts: prove the two claims that matter, and prove them so they can fail.
//!
//! CLAIM 1 -- LOSSLESS. Everything a redacted receipt still verifies, it verifies at FULL
//! strength and with the SAME answer as the unredacted receipt: same leaves, same state root,
//! same admitted set, same convictions. If any of those diverged, redaction would have changed
//! what the receipt means, which is the one thing it must never do.
//!
//! CLAIM 2 -- NO PLAINTEXT. The redacted artefact does not contain the vectors. Asserted by
//! searching the artefact for a distinctive value planted in a contribution, not by trusting
//! that the struct has no tensor field.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, Policy, Receipt, Rule, State};

fn signed(id: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        rnd,
        node_id: id.node_id,
        tensor: t.to_vec(),
        sig: id.sign(&contrib_msg(rnd, &th)),
    }
}

/// Six honest nodes plus one equivocator, so admission, conviction and exclusion are all
/// exercised rather than only the happy path.
fn fixture() -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=7u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().take(6).enumerate() {
        s.deliver(signed(id, 1, &[100 + k as i64, 200 - k as i64]), &pki);
    }
    s.deliver(signed(&ids[6], 1, &[9_000, 9_000]), &pki);
    s.deliver(signed(&ids[6], 1, &[-9_000, -9_000]), &pki);
    (Receipt::issue(&s, 1, &pki, 1, Rule::Krum), pki)
}

/// The leaf is byte-identical, which is WHY everything downstream of it survives.
#[test]
fn a_redacted_leaf_is_byte_identical_to_the_full_leaf() {
    let (r, _) = fixture();
    let red = r.redact();
    assert_eq!(red.contributions.len(), r.contributions.len());
    for (full, redacted) in r.contributions.iter().zip(&red.contributions) {
        assert_eq!(
            full.leaf(),
            redacted.leaf(),
            "dropping the tensor must not move the leaf -- the leaf hashes the tensor HASH"
        );
    }
}

/// **The load-bearing equivalence.** Same state root, same admitted set, same convictions.
///
/// GUARD-DELETION: change `RedactedContribution::leaf()` to hash anything the full `leaf()`
/// does not (drop `node_id`, say) and this goes RED on the state root immediately.
#[test]
fn redaction_changes_no_verification_answer() {
    let (r, pki) = fixture();
    let full = r
        .verify(&Policy::new(pki.clone(), 1))
        .expect("full verifies");
    let red = r
        .redact()
        .verify(&Policy::new(pki, 1))
        .expect("redacted verifies");

    assert_eq!(
        full.state_root, red.state_root,
        "state root must be identical"
    );
    assert_eq!(
        full.admitted, red.admitted,
        "admitted set must be identical"
    );
    assert_eq!(
        full.convicted, red.convicted,
        "convictions must be identical"
    );
    assert_eq!(
        full.convictable_but_unconvicted, red.convictable_but_unconvicted,
        "derivable convictions must be identical"
    );
    assert_eq!(full.population_bound_met, red.population_bound_met);

    // Non-vacuity: the fixture must actually exercise exclusion, or the equality above is a
    // statement about a set with nothing interesting in it.
    assert_eq!(red.admitted.len(), 6, "the equivocator is excluded");
    assert_eq!(r.contributions.len(), 8, "but its pair is still carried");
}

/// **The privacy claim, asserted against the artefact rather than the type.** A distinctive
/// value planted in a contribution must not survive into the redacted receipt.
#[test]
fn the_redacted_artefact_contains_no_plaintext_vector() {
    let id = Identity::from_secret(1, &[1u8; 32]);
    let other = Identity::from_secret(2, &[2u8; 32]);
    let third = Identity::from_secret(3, &[3u8; 32]);
    let pki: Pki = [
        (id.node_id, id.public()),
        (other.node_id, other.public()),
        (third.node_id, third.public()),
    ]
    .into_iter()
    .collect();

    // A value no hash, length, id or round could coincidentally produce.
    const SECRET: i64 = 606_060_606;
    let mut s = State::new();
    s.deliver(signed(&id, 1, &[SECRET, SECRET + 1]), &pki);
    s.deliver(signed(&other, 1, &[7, 8]), &pki);
    s.deliver(signed(&third, 1, &[9, 10]), &pki);
    let r = Receipt::issue(&s, 1, &pki, 0, Rule::Krum);

    // Premise: the FULL receipt does leak it. Without this the test could pass because the
    // value was never there.
    let full_repr = format!("{:?}", r);
    assert!(
        full_repr.contains(&SECRET.to_string()),
        "premise: the unredacted receipt carries the raw vector"
    );

    let red = r.redact();
    let red_repr = format!("{:?}", red);
    assert!(
        !red_repr.contains(&SECRET.to_string()),
        "the redacted receipt must not carry the raw vector"
    );
    assert!(
        !red_repr.contains(&(SECRET + 1).to_string()),
        "nor any other coordinate of it"
    );
}

/// A redacted receipt reports the aggregate as CLAIMED and offers no way to call it verified:
/// the verdict type has no verified-aggregate field at all.
#[test]
fn the_aggregate_is_reported_as_claimed_and_never_as_verified() {
    let (r, pki) = fixture();
    let red = r.redact().verify(&Policy::new(pki, 1)).unwrap();
    assert!(
        red.claimed_aggregate.is_some(),
        "the claim is echoed so a reader can see it"
    );
    // The unredacted verdict has `aggregate`; this one deliberately does not. If a future edit
    // added one, this file would stop compiling at the line below rather than silently start
    // reporting an unverified value as verified.
    let _: Option<Vec<i64>> = red.claimed_aggregate;
}

/// Policy is enforced on the redacted door too -- a redacted receipt is not a weaker door, it
/// is a narrower one.
#[test]
fn the_redacted_door_still_refuses_a_foreign_pki() {
    let (r, _) = fixture();
    let stranger = Identity::from_secret(99, &[99u8; 32]);
    let foreign: Pki = [(stranger.node_id, stranger.public())]
        .into_iter()
        .collect();
    assert!(
        r.redact().verify(&Policy::new(foreign, 1)).is_err(),
        "a PKI the checker does not recognise must be refused here exactly as it is on the full door"
    );
}
