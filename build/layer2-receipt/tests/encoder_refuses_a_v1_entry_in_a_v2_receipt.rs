// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! #105 -- the doc comment on `Contribution::sig_preimage` promised a refusal that no encoder
//! performed.
//!
//! IT SAID: "such a contribution can never be mixed into a v2 receipt because the encoder refuses
//! it". `encode_checked` refused exactly two things -- `FaultBoundTooLarge` and
//! `ParamsDisagreeWithHeader` -- and had no preimage check of any kind; `encode` is infallible by
//! signature and refuses nothing at all. So a v1-marked entry inside a v2 receipt encoded
//! silently, and the sentence telling a reader it could not was the only thing standing between
//! that receipt and the wire.
//!
//! WHY IT MATTERS, and it is the same argument as `ParamsDisagreeWithHeader` one field over. The
//! preimage version is carried by the MAGIC and by nothing else, so `decode` of an `ACFA-R2`
//! receipt stamps v2 onto every entry it reads. A v1-marked entry therefore comes back v2 --
//! `Contribution::leaf` folds `ctx` and `params` in for v2 only, and `signature_valid` dispatches
//! to `contrib_msg` rather than `contrib_msg_v1` -- so the receipt does not decode to itself and
//! the entry is afterwards checked against a message its author never signed.
//!
//! GUARD-DELETION, measured on this tree rather than asserted. Deleting the contribution-half
//! check from `wire::encode_checked`: 4 passed, 1 failed, the failure being
//! `encode_checked_refuses_a_v1_marked_contribution` with `got Ok(1116)`. Deleting the proof-half
//! check instead: 4 passed, 1 failed, the failure being `..._a_v1_marked_proof`, also `Ok(1116)`.
//! Deleting both: 3 passed, 2 failed. The three that stay green under every deletion are the
//! accepting fixture, the round-trip demonstration and the message check -- which is the shape
//! that says this guard refuses THIS receipt rather than every receipt.

use acfa_receipt::identity::{contrib_msg, Identity, Pki, PreimageVersion, RoundParams};
use acfa_receipt::wire::{decode, encode, encode_checked};
use acfa_receipt::{Contribution, Receipt, Rule, State, WireError};

/// A real, non-zero context, following `context_and_scale_are_load_bearing.rs`. Every fixture in
/// this repository once used `NO_CONTEXT`, and a mutation sweep found the context binding was
/// therefore exercised only where all its alternatives agree. The v1 and v2 leaves do differ at
/// `NO_CONTEXT` too -- v1 omits `ctx` and `params` from the preimage rather than zeroing them --
/// but a fixture that never sets a context cannot show that, so this one sets one.
const STUDY: [u8; 32] = [0x5C; 32];

fn params() -> RoundParams {
    RoundParams {
        rule: Rule::Krum,
        f: 1,
        frac_bits: acfa_receipt::FRAC_BITS,
    }
}

fn signed(id: &Identity, t: &[i64]) -> Contribution {
    let th = acfa_receipt::hash::h(&acfa_receipt::hash::enc_tensor(t));
    Contribution {
        ctx: STUDY,
        sig_preimage: PreimageVersion::V2,
        params: params(),
        rnd: 1,
        node_id: id.node_id,
        tensor: t.to_vec(),
        sig: id.sign(&contrib_msg(&STUDY, &params(), 1, id.node_id, &th)),
    }
}

/// Five honest nodes and one of them equivocating, so the receipt carries BOTH kinds of entry.
/// The proof half of the guard is a separate loop in `encode_checked` and a fixture with no
/// proofs in it would iterate that loop zero times and pass vacuously.
fn deployment() -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        s.deliver(signed(id, &[10 + k as i64, 20 - k as i64]), &pki);
    }
    // Node 5 signs a SECOND, different tensor for the same round and context. `deliver` forms the
    // equivocation proof itself, so the proof in this fixture is a real one that `valid` accepts,
    // not a struct filled in by hand.
    s.deliver(signed(&ids[4], &[999, 999]), &pki);
    let r = Receipt::issue(&s, STUDY, 1, &pki, 1, Rule::Krum);
    (r, pki)
}

/// PREMISE, AND THE ACCEPTING CONTROL. Measured on this tree: 6 contributions and 1 proof, every
/// one of them v2, and the whole receipt encodes. Without this the two refusal tests below could
/// both pass against an empty receipt, a receipt with no proofs, or a `encode_checked` that had
/// simply been made to refuse everything.
#[test]
fn the_fixture_carries_both_kinds_of_entry_and_encodes() {
    let (r, pki) = deployment();
    assert_eq!(
        r.contributions.len(),
        6,
        "five honest contributions plus the equivocator's second one"
    );
    assert_eq!(
        r.proofs.len(),
        1,
        "the equivocation must actually be caught"
    );
    assert!(
        r.proofs[0].valid(&pki),
        "the fixture's proof must be a genuine conviction, not a filled-in struct"
    );
    assert!(
        r.contributions
            .iter()
            .all(|c| c.sig_preimage == PreimageVersion::V2)
            && r.proofs
                .iter()
                .all(|p| p.sig_preimage == PreimageVersion::V2),
        "anything built in memory is v2; if this is false the refusal tests prove nothing"
    );
    assert!(
        encode_checked(&r).is_ok(),
        "the honest all-v2 receipt must still encode"
    );
}

/// THE GUARD, contribution half.
#[test]
fn encode_checked_refuses_a_v1_marked_contribution() {
    let (mut r, _) = deployment();
    encode_checked(&r).expect("control: the untouched receipt encodes");

    let victim = r.contributions[0].node_id;
    r.contributions[0].sig_preimage = PreimageVersion::V1;
    match encode_checked(&r) {
        Err(WireError::PreimageDisagreesWithMagic { node_id }) => assert_eq!(node_id, victim),
        // `.map(|b| b.len())` because the success case here is 1116 bytes of receipt and a
        // failing test that dumps them is a failing test nobody reads.
        other => panic!(
            "expected PreimageDisagreesWithMagic, got {:?}",
            other.map(|b| b.len())
        ),
    }

    // AND THE FIELD IS THE ONLY REASON. Putting it back must restore acceptance -- otherwise the
    // refusal above could be coming from anything else the fixture happens to carry.
    r.contributions[0].sig_preimage = PreimageVersion::V2;
    assert!(
        encode_checked(&r).is_ok(),
        "restoring the marking must restore acceptance"
    );
}

/// THE GUARD, proof half. A separate loop in `encode_checked`, so a separate test: deleting only
/// the proof check leaves the contribution test green.
#[test]
fn encode_checked_refuses_a_v1_marked_proof() {
    let (mut r, _) = deployment();
    encode_checked(&r).expect("control: the untouched receipt encodes");

    let victim = r.proofs[0].node_id;
    r.proofs[0].sig_preimage = PreimageVersion::V1;
    match encode_checked(&r) {
        Err(WireError::PreimageDisagreesWithMagic { node_id }) => assert_eq!(node_id, victim),
        // `.map(|b| b.len())` because the success case here is 1116 bytes of receipt and a
        // failing test that dumps them is a failing test nobody reads.
        other => panic!(
            "expected PreimageDisagreesWithMagic, got {:?}",
            other.map(|b| b.len())
        ),
    }

    r.proofs[0].sig_preimage = PreimageVersion::V2;
    assert!(
        encode_checked(&r).is_ok(),
        "restoring the marking must restore acceptance"
    );
}

/// THE REASON THE GUARD EXISTS, demonstrated rather than asserted: a receipt carrying a v1-marked
/// entry does not survive its own round trip. `encode` is used deliberately -- it is the
/// infallible one, so it still writes these bytes, which is what makes the refusal on
/// `encode_checked` worth having.
///
/// The assertion is on the round trip itself and not on a particular error, because the two
/// halves fail DIFFERENTLY and only one of them is loud. Measured on this tree, 1116-byte
/// receipt, marking one entry and re-decoding:
///
/// ```text
///   contribution marked v1 -> Err(NotCanonical("contributions not strictly ascending by leaf"))
///   proof        marked v1 -> Ok(receipt), with the marking silently replaced by v2
/// ```
///
/// The contribution is caught by the canonical-order check only because its v1 leaf sorts it
/// somewhere its v2 leaf does not. THE PROOF IS NOT CAUGHT AT ALL -- one proof cannot be
/// out of order -- so it decodes cleanly into a receipt that is not the one that was encoded.
/// That silent half is the case the encoder's refusal is actually for.
#[test]
fn a_v1_marked_entry_does_not_survive_its_own_round_trip() {
    let (r, _) = deployment();
    assert_eq!(
        decode(&encode(&r)),
        Ok(r.clone()),
        "PREMISE: the untouched receipt must round-trip to itself, or this test measures nothing"
    );

    let mut marked = r.clone();
    marked.contributions[0].sig_preimage = PreimageVersion::V1;
    assert_ne!(
        decode(&encode(&marked)).as_ref(),
        Ok(&marked),
        "a v1-marked contribution cannot come back out of a v2 magic"
    );

    marked = r.clone();
    marked.proofs[0].sig_preimage = PreimageVersion::V1;
    let back =
        decode(&encode(&marked)).expect("the one-proof case decodes cleanly -- that is the point");
    assert_eq!(
        back.proofs[0].sig_preimage,
        PreimageVersion::V2,
        "decode stamps every entry from the magic, silently"
    );
    assert_ne!(
        back, marked,
        "so the receipt read back is not the one written"
    );
}

/// The operator-facing half. `error_traits.rs` enumerates variants by hand and does not know
/// about this one, so the message it prints is checked here instead.
#[test]
fn the_refusal_names_both_versions_and_is_not_the_debug_rendering() {
    let e = WireError::PreimageDisagreesWithMagic { node_id: 7 };
    let shown = e.to_string();
    assert_ne!(
        shown,
        format!("{e:?}"),
        "Display must not just forward to Debug"
    );
    assert!(
        shown.contains('7') && shown.contains("v1") && shown.contains("v2"),
        "the message must name the node and both versions: {shown}"
    );
}
