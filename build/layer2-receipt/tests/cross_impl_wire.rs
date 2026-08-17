// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Cross-implementation agreement for the RECEIPT wire format.
//!
//! Until this file existed, the receipt encoding had cross-ARCHITECTURE coverage and no
//! cross-IMPLEMENTATION coverage. `examples/digest.rs` hashes `encode` output and CI diffs
//! those digests across eight targets including big-endian s390x, which is strong -- but
//! one implementation agreeing with itself on eight architectures is a DIFFERENT PROPERTY
//! from two implementations agreeing. `tests/golden/generate_l2.py` is an independent
//! Python reference but covers `resolve` only. `acfa-finality` had the mirror-image gap
//! and closed it with `build/layer2-finality/tests/cross_impl_cert.rs`; this is the receipt half.
//!
//! THE SECOND AUTHOR DID NOT READ THIS CRATE'S ENCODER. `tests/golden/decode_wire.py` was
//! written from the `wire.rs` doc comments, the public constants and the public struct
//! declarations, with the `encode`/`decode` bodies unread -- because a second author who
//! reads the first one's code reproduces the first one's misreadings and calls the result
//! agreement. Its byte-length predictions were made from that prose BEFORE any decoder was
//! written, and came out exact (208 / 516 / 760 / 324).
//!
//! WHAT THE VECTORS PIN. They are chosen to discriminate, not to pad a count:
//!
//!   empty-krum           the empty case; absence encoded as a presence byte
//!   three-contribs       ordering by leaf, and an aggregate that IS present
//!   five-bulyan          Bulyan's discriminant, and an ABSENT aggregate -- at n = 5 the
//!                        rule needs 4f+3 = 7, so refusal is the correct outcome and the
//!                        byte count only lands on 760 if the aggregate is missing
//!   high-round           round = 2^32 EXACTLY -- catches a 32-bit round field
//!   byte-distinct-round  round = 0x0102030405060708 -- second witness for the same
//!
//! WHAT THE LARGE-ROUND VECTORS ACTUALLY BUY, MEASURED RATHER THAN ASSUMED. The prediction
//! when they were added was that a small round would survive an ENDIANNESS error, since
//! its bytes still parse into some number. THAT PREDICTION IS WRONG, and mutating
//! `tests/golden/decode_wire.py` to read little-endian shows why: all five vectors fail,
//! because the harness compares the decoded round to its EXPECTED value rather than merely
//! checking that decoding succeeded. Any nonzero round catches endianness once you compare
//! values.
//!
//! What the large rounds DO catch, uniquely, is a 32-BIT ROUND FIELD -- the mistake a third
//! implementation in a fixed-width language would make. Simulating that (`round & 0xFFFFFFFF`):
//!
//!   empty-krum / three-contribs / five-bulyan   PASS -- small rounds are unaffected
//!   high-round / byte-distinct-round            FAIL -- the only two that bite
//!
//! So they earn their place, for a different reason than the one they were added for. Keep
//! at least one round above 2^32.
//!
//! Regenerate:
//!   cargo run --release --example wire_vectors > tests/golden/vectors_wire.json
//!   python3 tests/golden/decode_wire.py tests/golden/vectors_wire.json

use acfa_receipt::wire::{decode, encode, WireError};
use acfa_receipt::Rule;
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let raw = include_str!("golden/vectors_wire.json");
    serde_json::from_str::<Vec<Value>>(raw).expect("golden vectors parse")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn wire_of(name: &str) -> Vec<u8> {
    let v = vectors();
    let hit = v
        .iter()
        .find(|x| x["name"] == name)
        .unwrap_or_else(|| panic!("no vector named {name}"));
    unhex(hit["wire"].as_str().expect("wire is hex"))
}

/// Offset of the rule discriminant: MAGIC(8) + VERSION(2) + round(8) + f(4).
const RULE_OFFSET: usize = 22;

#[test]
fn every_vector_decodes_to_its_declared_fields_and_re_encodes_identically() {
    let vs = vectors();
    // Refuse at zero. A loop over an empty vector set prints nothing and passes.
    assert_eq!(
        vs.len(),
        5,
        "expected 5 golden vectors -- if this changed, say so deliberately rather than \
         letting the suite silently check fewer cases"
    );

    for v in &vs {
        let name = v["name"].as_str().unwrap();
        let bytes = unhex(v["wire"].as_str().unwrap());

        assert_eq!(
            bytes.len() as u64,
            v["bytes"].as_u64().unwrap(),
            "{name}: stored byte count disagrees with the stored hex"
        );

        let r = decode(&bytes).unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));

        assert_eq!(r.round, v["round"].as_u64().unwrap(), "{name}: round");
        assert_eq!(r.f as u64, v["f"].as_u64().unwrap(), "{name}: f");
        assert_eq!(
            format!("{:?}", r.rule),
            v["rule"].as_str().unwrap(),
            "{name}: rule"
        );
        assert_eq!(
            r.pki.len() as u64,
            v["pki_n"].as_u64().unwrap(),
            "{name}: pki size"
        );
        assert_eq!(
            r.contributions.len() as u64,
            v["contribs"].as_u64().unwrap(),
            "{name}: contribution count"
        );
        assert_eq!(
            r.proofs.len() as u64,
            v["proofs"].as_u64().unwrap(),
            "{name}: proof count"
        );

        // "absent" is a DISTINCT wire state from "present and empty", so compare presence
        // before contents.
        assert_eq!(
            r.claimed_aggregate.is_none(),
            v["agg"].is_null(),
            "{name}: aggregate PRESENCE disagrees -- absent and present-but-empty are \
             different states on the wire"
        );

        // Re-encoding pins the ENCODER against the golden, not just the decoder.
        assert_eq!(
            encode(&r),
            bytes,
            "{name}: re-encoding a decoded receipt did not reproduce the golden bytes"
        );
    }
}

/// The reference decoder's rule table was DERIVED from the two discriminants its vectors
/// happened to contain, and two values is thin evidence for a mapping. This makes the
/// crate's own table exhaustive, so adding a third rule fails here loudly instead of
/// leaving the reference silently wrong about a value it never saw.
#[test]
fn the_rule_discriminant_table_is_exhaustive() {
    for rule in [Rule::Krum, Rule::Bulyan] {
        let b = rule.as_wire();
        assert_eq!(
            Rule::from_wire(b),
            Some(rule),
            "rule {rule:?} does not round-trip through its wire discriminant"
        );
    }
    assert_eq!(Rule::Krum.as_wire(), 0);
    assert_eq!(Rule::Bulyan.as_wire(), 1);
    assert!(
        Rule::from_wire(2).is_none(),
        "an unassigned discriminant must not decode; if a third rule was added, give it a \
         golden vector and update tests/golden/decode_wire.py, whose table is derived from \
         the vectors it has seen"
    );
}

// ------------------------------------------------------------------ negative controls
//
// Four decoding vectors from a decoder that accepts anything are worth nothing. Each of
// these must be REFUSED, and `the_accepting_control_still_decodes` proves the refusals are
// not simply a decoder that refuses everything.

#[test]
fn the_accepting_control_still_decodes() {
    assert!(decode(&wire_of("three-contribs")).is_ok());
}

#[test]
fn truncation_is_refused() {
    let w = wire_of("three-contribs");
    assert_eq!(decode(&w[..w.len() - 1]), Err(WireError::Truncated));
}

#[test]
fn trailing_bytes_are_refused() {
    let mut w = wire_of("three-contribs");
    w.push(0);
    assert_eq!(decode(&w), Err(WireError::TrailingBytes));
}

#[test]
fn bad_magic_is_refused() {
    let mut w = wire_of("three-contribs");
    w[0] ^= 0xff;
    assert_eq!(decode(&w), Err(WireError::BadMagic));
}

#[test]
fn an_unsupported_version_is_refused() {
    let mut w = wire_of("three-contribs");
    w[9] = 9;
    assert_eq!(decode(&w), Err(WireError::UnsupportedVersion(9)));
}

/// Patching a fixed offset is layout-dependent: if the layout moves, this control silently
/// starts poking a different field and may refuse FOR THE WRONG REASON. So assert what is
/// at that offset BEFORE changing it.
#[test]
fn an_unknown_rule_byte_is_refused() {
    let mut w = wire_of("three-contribs");
    assert_eq!(
        w[RULE_OFFSET],
        Rule::Krum.as_wire(),
        "the rule discriminant is not at offset {RULE_OFFSET} any more -- this control is \
         poking a different field and its refusal would prove nothing. Fix the offset."
    );
    w[RULE_OFFSET] = 9;
    assert_eq!(decode(&w), Err(WireError::UnknownRule(9)));
}

#[test]
fn a_nonsense_aggregate_presence_byte_is_refused() {
    // The presence byte is the last byte of the empty-aggregate encoding.
    let mut w = wire_of("five-bulyan");
    let last = w.len() - 1;
    assert_eq!(w[last], 0, "five-bulyan should encode an ABSENT aggregate");
    w[last] = 7;
    assert!(
        decode(&w).is_err(),
        "a presence byte outside {{0, 1}} must be refused, not treated as present"
    );
}
