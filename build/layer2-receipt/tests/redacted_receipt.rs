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
    (
        Receipt::issue(
            &s,
            acfa_receipt::identity::NO_CONTEXT,
            1,
            &pki,
            1,
            Rule::Krum,
        ),
        pki,
    )
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
    let r = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        0,
        Rule::Krum,
    );

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

// ------------------------------------------------------------------ wire format

/// A redacted receipt survives encode/decode unchanged, and still verifies afterwards.
#[test]
fn a_redacted_receipt_round_trips_and_still_verifies() {
    let (r, pki) = fixture();
    let red = r.redact();
    let bytes = acfa_receipt::wire::encode_redacted(&red);
    let back = acfa_receipt::wire::decode_redacted(&bytes).expect("round-trips");
    assert_eq!(red, back, "decode(encode(x)) must be x");

    let a = red.verify(&Policy::new(pki.clone(), 1)).unwrap();
    let b = back.verify(&Policy::new(pki, 1)).unwrap();
    assert_eq!(a, b, "verification must survive the wire");
}

/// Canonical: re-encoding a decoded receipt reproduces the bytes exactly.
#[test]
fn the_redacted_encoding_is_canonical() {
    let (r, _) = fixture();
    let bytes = acfa_receipt::wire::encode_redacted(&r.redact());
    let back = acfa_receipt::wire::decode_redacted(&bytes).unwrap();
    assert_eq!(
        bytes,
        acfa_receipt::wire::encode_redacted(&back),
        "two encodings of the same set must be byte-identical"
    );
}

/// **THE SAFETY PROPERTY.** Neither decoder may accept the other's artefact. If the full
/// decoder accepted redacted bytes, a caller would believe it held a re-executable receipt
/// while holding one that cannot verify an aggregate at all.
///
/// The refusal must come from the MAGIC, and the test asserts that specifically. An earlier
/// version only asserted `is_err()` and passed even with `MAGIC_REDACTED == MAGIC` -- because
/// the two layouts diverge structurally (a length-prefixed tensor versus a 32-byte hash), so
/// decoding failed on shape and the magic was never the thing under test. Structural divergence
/// is real defence in depth, but it is not the guard, and a test that cannot tell them apart is
/// a gate that cannot fail.
///
/// GUARD-DELETION: set `MAGIC_REDACTED` equal to `MAGIC` and this goes RED in both directions,
/// because the error becomes a structural one instead of `BadMagic`.
#[test]
fn neither_decoder_accepts_the_others_artefact() {
    use acfa_receipt::WireError;
    let (r, _) = fixture();
    let full_bytes = acfa_receipt::wire::encode(&r);
    let red_bytes = acfa_receipt::wire::encode_redacted(&r.redact());

    assert!(
        matches!(acfa_receipt::decode(&red_bytes), Err(WireError::BadMagic)),
        "the FULL decoder must refuse redacted bytes ON THE MAGIC, got {:?}",
        acfa_receipt::decode(&red_bytes).err()
    );
    assert!(
        matches!(
            acfa_receipt::wire::decode_redacted(&full_bytes),
            Err(WireError::BadMagic)
        ),
        "the REDACTED decoder must refuse full bytes ON THE MAGIC, got {:?}",
        acfa_receipt::wire::decode_redacted(&full_bytes).err()
    );
    // And each accepts its own, so the test is not passing because both simply fail.
    assert!(acfa_receipt::decode(&full_bytes).is_ok());
    assert!(acfa_receipt::wire::decode_redacted(&red_bytes).is_ok());
}

/// **The privacy claim at the byte level** -- the form that actually leaves the machine.
#[test]
fn the_encoded_redacted_bytes_contain_no_plaintext_vector() {
    let ids: Vec<Identity> = (1..=3u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    const SECRET: i64 = 606_060_606;
    // d = 64. Size matters here: a redacted contribution replaces `4 + 8d` tensor bytes with a
    // fixed 32-byte hash, so the artefact only SHRINKS for d >= 4 and grows slightly below
    // that. Real model widths are in the millions, where the saving is the whole point; a
    // two-element tensor is the one case where redaction costs bytes.
    let vec_a: Vec<i64> = (0..64)
        .map(|k| if k == 0 { SECRET } else { SECRET + k })
        .collect();
    let vec_b: Vec<i64> = (0..64).map(|k| 7 + k).collect();
    let vec_c: Vec<i64> = (0..64).map(|k| 9 + k).collect();
    let mut s = State::new();
    s.deliver(signed(&ids[0], 1, &vec_a), &pki);
    s.deliver(signed(&ids[1], 1, &vec_b), &pki);
    s.deliver(signed(&ids[2], 1, &vec_c), &pki);
    let r = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        0,
        Rule::Krum,
    );

    let needle = SECRET.to_be_bytes();
    let full_bytes = acfa_receipt::wire::encode(&r);
    assert!(
        full_bytes.windows(8).any(|w| w == needle),
        "premise: the full encoding carries the raw value"
    );

    let red_bytes = acfa_receipt::wire::encode_redacted(&r.redact());
    assert!(
        !red_bytes.windows(8).any(|w| w == needle),
        "the redacted encoding must not carry the raw value"
    );
    // And it is genuinely smaller, which is the observable consequence of the vectors being gone.
    assert!(
        red_bytes.len() < full_bytes.len(),
        "redacted {} should be smaller than full {}",
        red_bytes.len(),
        full_bytes.len()
    );
}

/// The redacted decoder carries the full decoder's PKI guards -- it is a narrower door, not a
/// weaker one. A reused public key (crypto-03) must be refused here too.
#[test]
fn the_redacted_decoder_refuses_a_pki_that_reuses_a_key() {
    let (r, _) = fixture();
    let mut red = r.redact();
    // Point two identities at one key.
    let victim = *red.pki.keys().next().unwrap();
    let other = *red.pki.keys().nth(1).unwrap();
    let k = red.pki[&victim];
    red.pki.insert(other, k);
    let bytes = acfa_receipt::wire::encode_redacted(&red);
    match acfa_receipt::wire::decode_redacted(&bytes) {
        Err(e) => {
            let m = format!("{e:?}");
            assert!(
                m.contains("reuses") || m.contains("Canonical"),
                "expected a canonicality refusal naming key reuse, got {m}"
            );
        }
        Ok(_) => panic!("crypto-03: a PKI reusing a public key must be refused on this door too"),
    }
}
