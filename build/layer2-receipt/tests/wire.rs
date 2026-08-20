// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Wire-format tests.
//!
//! A canonical encoding is only canonical if the DECODER refuses the non-canonical
//! forms. An encoder that emits one form while the decoder accepts three has not
//! removed the ambiguity, it has hidden it -- so most of these tests are about what the
//! decoder rejects, not what the encoder produces.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{decode, encode, Contribution, Policy, Receipt, Rule, State, WireError};

/// Krum at `f = 1` on this build's fixed-point scale.
///
/// A NAMED FIXTURE, NOT A DEFAULT. A contribution signed under different round parameters is
/// filtered out of the round by `Receipt::issue`, exactly as a foreign `ctx` is, so a test that
/// needs other parameters has to say so rather than inherit these silently.
const PARAMS_DEFAULT: acfa_receipt::RoundParams = acfa_receipt::RoundParams {
    rule: acfa_receipt::Rule::Krum,
    f: 1,
    frac_bits: acfa_receipt::FRAC_BITS,
};

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &PARAMS_DEFAULT,
            rnd,
            a.node_id,
            &th,
        )),
    }
}

fn sample(n: u32) -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=n).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        s.deliver(contrib(id, 1, &[i as i64 * 3, i as i64 + 1]), &pki);
    }
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

#[test]
fn a_receipt_round_trips_exactly() {
    let (r, _) = sample(5);
    let bytes = encode(&r);
    let back = decode(&bytes).expect("decodes");
    assert_eq!(r, back);
    assert_eq!(bytes, encode(&back), "re-encoding is stable");
}

#[test]
fn encoding_is_deterministic_across_repeated_calls() {
    let (r, _) = sample(5);
    assert_eq!(encode(&r), encode(&r));
}

#[test]
fn a_decoded_receipt_still_verifies() {
    let (r, pki) = sample(5);
    let back = decode(&encode(&r)).unwrap();
    assert!(
        back.verify(&Policy::new(pki, 1)).is_ok(),
        "verification survives serialisation"
    );
}

#[test]
fn an_empty_round_round_trips_with_no_aggregate() {
    let ids: Vec<Identity> = (1..=3).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let r = Receipt::issue(
        &State::new(),
        acfa_receipt::identity::NO_CONTEXT,
        9,
        &pki,
        1,
        Rule::Krum,
    );
    assert!(r.claimed_aggregate.is_none());
    let back = decode(&encode(&r)).unwrap();
    assert_eq!(r, back);
    assert!(back.verify(&Policy::new(pki, 1)).is_ok());
}

#[test]
fn both_rules_survive_the_wire() {
    for rule in [Rule::Krum, Rule::Bulyan] {
        let ids: Vec<Identity> = (1..=7).map(ident).collect();
        let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
        let mut s = State::new();
        for (i, id) in ids.iter().enumerate() {
            s.deliver(contrib(id, 1, &[i as i64, i as i64 * 2]), &pki);
        }
        let r = Receipt::issue(&s, acfa_receipt::identity::NO_CONTEXT, 1, &pki, 1, rule);
        assert_eq!(decode(&encode(&r)).unwrap().rule, rule);
    }
}

// ---------------------------------------------------------------- rejections

#[test]
fn foreign_input_is_rejected_rather_than_misread() {
    assert_eq!(decode(b"").unwrap_err(), WireError::Truncated);
    assert_eq!(
        decode(b"not a receipt at all").unwrap_err(),
        WireError::BadMagic
    );
}

#[test]
fn a_truncated_receipt_is_refused_at_every_cut_point() {
    let (r, _) = sample(4);
    let bytes = encode(&r);
    // Every proper prefix must fail. A decoder that succeeds on a short read is
    // reconstructing fields the sender never sent.
    for cut in 0..bytes.len() {
        assert!(
            decode(&bytes[..cut]).is_err(),
            "prefix of length {cut} must not decode"
        );
    }
}

#[test]
fn trailing_bytes_are_refused() {
    let (r, _) = sample(4);
    let mut bytes = encode(&r);
    bytes.push(0x00);
    assert_eq!(decode(&bytes).unwrap_err(), WireError::TrailingBytes);
}

#[test]
fn an_unknown_rule_is_refused_rather_than_defaulted() {
    // Defaulting an unknown rule to Krum would let a sender claim one rule and have
    // the verifier apply another.
    let (r, _) = sample(4);
    let mut bytes = encode(&r);
    let rule_off = 8 + 2 + 32 + 8 + 4; // magic, version, ctx, round, f
    bytes[rule_off] = 0xAA;
    assert_eq!(decode(&bytes).unwrap_err(), WireError::UnknownRule(0xAA));
}

#[test]
fn a_wrong_version_is_refused() {
    let (r, _) = sample(4);
    let mut bytes = encode(&r);
    bytes[9] = 0x02;
    assert_eq!(
        decode(&bytes).unwrap_err(),
        WireError::UnsupportedVersion(2)
    );
}

#[test]
fn out_of_order_contributions_are_refused_as_non_canonical() {
    // The attack this closes: two encodings of the same logical receipt. A verifier
    // shown one and a third party shown the other would hash different bytes.
    let (r, _) = sample(5);
    let mut shuffled = r.clone();
    shuffled.contributions.reverse();
    // encode() sorts defensively, so build the non-canonical stream by hand from the
    // canonical one: swap the first two contribution records.
    let bytes = encode(&shuffled);
    let canonical = encode(&r);
    assert_eq!(bytes, canonical, "encoder must normalise order");

    // Now corrupt the order directly in the byte stream.
    let mut hand = canonical.clone();
    let head = 8 + 2 + 32 + 8 + 4 + 1 + 4; // magic, version, ctx, round, f, rule, frac_bits
    let n_pki = u32::from_be_bytes(hand[head..head + 4].try_into().unwrap()) as usize;
    let c_off = head + 4 + n_pki * 36;
    let n_c = u32::from_be_bytes(hand[c_off..c_off + 4].try_into().unwrap()) as usize;
    assert!(n_c >= 2);
    // Each record here is 8 + 4 + 4 + 2*8 + 64 = 96 bytes (dimension 2).
    let rec = 8 + 4 + 4 + 2 * 8 + 64;
    let a = c_off + 4;
    let b = a + rec;
    let (first, second) = (hand[a..b].to_vec(), hand[b..b + rec].to_vec());
    hand[a..b].copy_from_slice(&second);
    hand[b..b + rec].copy_from_slice(&first);

    match decode(&hand) {
        Err(WireError::NotCanonical(_)) => {}
        other => panic!("expected NotCanonical, got {other:?}"),
    }
}

#[test]
fn a_duplicated_identity_in_the_pki_is_refused() {
    let (r, _) = sample(3);
    let bytes = encode(&r);
    let head = 8 + 2 + 32 + 8 + 4 + 1 + 4; // magic, version, ctx, round, f, rule, frac_bits
    let mut hand = bytes.clone();
    // Overwrite the second identity's id with the first's: no longer ascending.
    let first_id = hand[head + 4..head + 8].to_vec();
    hand[head + 4 + 36..head + 8 + 36].copy_from_slice(&first_id);
    match decode(&hand) {
        Err(WireError::NotCanonical(_)) => {}
        other => panic!("expected NotCanonical, got {other:?}"),
    }
}

#[test]
fn a_hostile_length_prefix_cannot_make_the_verifier_allocate() {
    // REGRESSION. The decoder used to call Vec::with_capacity on a count read straight
    // out of the input. A tiny hostile receipt could then ask for gigabytes and abort
    // the process before a single signature was checked -- a denial of service on the
    // tool third parties are meant to point at untrusted input.
    //
    // CI found it as `memory allocation of 15050658272 bytes failed` on Linux; macOS
    // overcommit had hidden it completely, which is why this test asserts the refusal
    // explicitly instead of trusting the platform to notice.
    let (r, _) = sample(4);
    let bytes = encode(&r);
    let head = 8 + 2 + 32 + 8 + 4 + 1 + 4; // magic, version, ctx, round, f, rule, frac_bits

    // Every count field in the format, each blown up to ~4 billion.
    let n_pki = u32::from_be_bytes(bytes[head..head + 4].try_into().unwrap()) as usize;
    let c_off = head + 4 + n_pki * 36;
    for off in [head, c_off] {
        let mut hand = bytes.clone();
        hand[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode(&hand).unwrap_err(),
            WireError::Truncated,
            "a count of u32::MAX at offset {off} must be refused, not allocated"
        );
    }

    // And the per-contribution tensor dimension, which is a second, inner length.
    let mut hand = bytes.clone();
    let dim_off = c_off + 4 + 8 + 4;
    hand[dim_off..dim_off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(decode(&hand).unwrap_err(), WireError::Truncated);
}

#[test]
fn flipping_any_single_byte_is_detected() {
    // Not a cryptographic claim -- just that no byte in the encoding is dead space that
    // a tamperer could use as a covert channel without changing decode-or-verify.
    let (r, pki) = sample(4);
    let bytes = encode(&r);
    let policy = Policy::new(pki, 1);
    let mut undetected = Vec::new();
    for i in 0..bytes.len() {
        let mut m = bytes.clone();
        m[i] ^= 0x01;
        let detected = match decode(&m) {
            Err(_) => true,
            Ok(rr) => rr != r || rr.verify(&policy).is_err(),
        };
        if !detected {
            undetected.push(i);
        }
    }
    assert!(
        undetected.is_empty(),
        "bytes tampered without detection at offsets {undetected:?}"
    );
}

// -------------------------------------------------------------- trust model

#[test]
fn a_receipt_carrying_a_fabricated_pki_is_refused() {
    // THE MOST IMPORTANT REJECTION IN THE CRATE. An attacker mints identities nobody
    // authorised and issues a receipt over them. Every signature in it is genuine -- for
    // keys the attacker owns -- so it is internally flawless. Only the policy check can
    // reject it, and it must.
    let forger: Vec<Identity> = (200..=204)
        .map(|n| Identity::from_secret(n, &[n as u8; 32]))
        .collect();
    let forged_pki: Pki = forger.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (i, id) in forger.iter().enumerate() {
        s.deliver(contrib(id, 1, &[i as i64, 0]), &forged_pki);
    }
    let forged = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &forged_pki,
        1,
        Rule::Krum,
    );

    // Internally consistent: the forgery is well-formed.
    assert!(forged.check_self_consistent().is_ok());

    // But it is not about the deployment the checker knows.
    let (_, real_pki) = sample(5);
    assert_eq!(
        forged.verify(&Policy::new(real_pki, 1)).unwrap_err(),
        acfa_receipt::Invalid::PkiMismatch
    );
}

#[test]
fn the_fault_bound_cannot_be_chosen_by_the_receipt() {
    // A three-node receipt declaring f = 0 satisfies n >= 2f+3 and would report itself
    // population_bound_met. The checker's own f must govern.
    let ids: Vec<Identity> = (1..=3).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        s.deliver(contrib(id, 1, &[i as i64, 0]), &pki);
    }
    let flattering = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        0,
        Rule::Krum,
    );
    assert!(
        flattering.check_self_consistent().is_ok(),
        "self-consistent, and that is exactly why it is not enough"
    );
    assert_eq!(
        flattering.verify(&Policy::new(pki, 1)).unwrap_err(),
        acfa_receipt::Invalid::FaultBoundMismatch {
            policy: 1,
            receipt: 0
        }
    );
}

#[test]
fn a_rule_substitution_is_refused_when_the_policy_names_one() {
    let (r, pki) = sample(5);
    assert!(r
        .verify(&Policy::new(pki.clone(), 1).expecting(Rule::Krum))
        .is_ok());
    assert_eq!(
        r.verify(&Policy::new(pki, 1).expecting(Rule::Bulyan))
            .unwrap_err(),
        acfa_receipt::Invalid::RuleMismatch {
            policy: Rule::Bulyan,
            receipt: Rule::Krum
        }
    );
}

#[test]
fn swapping_one_key_in_the_policy_is_enough_to_refuse() {
    // Not just wholesale substitution: a single identity the checker does not recognise
    // must sink the receipt, or partial infiltration passes.
    let (r, mut pki) = sample(5);
    let intruder = Identity::from_secret(99, &[99u8; 32]);
    pki.insert(3, intruder.public()); // replace node 3's key
    assert_eq!(
        r.verify(&Policy::new(pki, 1)).unwrap_err(),
        acfa_receipt::Invalid::PkiMismatch
    );
}

// ------------------------------------------------- accountability completeness

#[test]
fn a_receipt_holding_both_halves_reports_the_conviction_it_did_not_make() {
    // The verifier used to rebuild state with a raw insert that runs no detection, so a
    // receipt carrying BOTH signed halves of an equivocation verified clean with an empty
    // convicted list. The evidence was present and the conviction was never computed,
    // which made a withholding issuer indistinguishable from an inattentive one.
    let ids: Vec<Identity> = (1..=5).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    let mut s = State::new();
    for id in ids.iter().skip(1) {
        s.deliver(contrib(id, 1, &[id.node_id as i64, 2]), &pki);
    }
    // raw inserts: both halves present, no proof formed
    s.add_contribution(contrib(&ids[0], 1, &[3, 3]));
    s.add_contribution(contrib(&ids[0], 1, &[7, 7]));

    let v = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    )
    .verify(&Policy::new(pki, 1))
    .expect("still a valid receipt: the aggregate is right");

    assert!(v.convicted.is_empty(), "the receipt carries no proof");
    assert_eq!(
        v.convictable_but_unconvicted,
        vec![1],
        "the receipt PROVES node 1 equivocated and does not convict it; say so"
    );
    assert!(
        !v.admitted.contains(&1),
        "uniqueness excludes it from the aggregate anyway"
    );
}

#[test]
fn an_honest_receipt_has_nothing_convictable_outstanding() {
    let (r, pki) = sample(5);
    let v = r.verify(&Policy::new(pki, 1)).unwrap();
    assert!(v.convictable_but_unconvicted.is_empty());
}

#[test]
fn conviction_carries_across_rounds_by_design() {
    // A proof is bound to the round it was made in, and conviction is permanent: an
    // identity that equivocated in an earlier round stays excluded. Contributions are
    // round-checked and proofs deliberately are not. Pinned here so the asymmetry reads
    // as intent rather than an oversight.
    let ids: Vec<Identity> = (1..=5).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    let a0 = contrib(&ids[0], 0, &[1, 1]);
    let b0 = contrib(&ids[0], 0, &[9, 9]);
    let old = acfa_receipt::EquivProof::canonical(
        acfa_receipt::identity::NO_CONTEXT,
        acfa_receipt::identity::PreimageVersion::V2,
        PARAMS_DEFAULT,
        0,
        1,
        (a0.tensor_hash(), a0.sig),
        (b0.tensor_hash(), b0.sig),
    );
    assert!(old.valid(&pki), "a genuine round-0 proof");

    let mut s = State::new();
    for id in ids.iter() {
        s.deliver(contrib(id, 5, &[id.node_id as i64, 1]), &pki);
    }
    s.add_proof(old);

    let v = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        5,
        &pki,
        1,
        Rule::Krum,
    )
    .verify(&Policy::new(pki, 1))
    .expect("verifies");
    assert_eq!(
        v.convicted,
        vec![1],
        "the round-0 equivocator is still convicted"
    );
    assert!(!v.admitted.contains(&1), "and excluded from round 5");
}
