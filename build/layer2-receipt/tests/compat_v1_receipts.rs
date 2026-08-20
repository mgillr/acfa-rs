// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! COMPATIBILITY.md is a PROMISE; this file is the only thing that makes it a FACT.
//!
//! v0.4.0 changed what a signature MEANS (the preimage now binds the context and the node id).
//! `COMPATIBILITY.md` promises that receipts written by v0.3.0 keep decoding and keep verifying
//! forever. Until this file existed that promise was untested in the strongest sense: deleting
//! the `MAGIC_V1` arm from `wire::decode` left **154 tests passing and 0 failing**. A promise no
//! test can falsify is not a guarantee, it is a comment.
//!
//! THE FIXTURES ARE NOT HAND-ROLLED. They are the `wire_vectors` example output of the actual
//! `v0.3.0` tag, byte for byte. Fixtures written by hand against the CURRENT reading of the old
//! format would only prove that this file agrees with itself -- the same trap the second-author
//! decoder in `golden/decode_wire.py` exists to avoid. These bytes were produced by code that
//! never knew v2 would exist.
//!
//! HONEST LIMIT: this pins the FULL-receipt v1 path. The redacted v1 path (`ACFA-X1`) has its
//! own decode arm and is NOT covered here -- see the `redacted_v1` note at the bottom.

use acfa_receipt::identity::{PreimageVersion, NO_CONTEXT};
use acfa_receipt::wire::{decode, MAGIC_V1, MAGIC_V2};

use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn vectors() -> Vec<Value> {
    let v: Value =
        serde_json::from_str(include_str!("golden/vectors_v1_compat.json")).expect("v1 fixtures");
    v.as_array().expect("array").clone()
}

fn name(v: &Value) -> &str {
    v["name"].as_str().expect("name")
}

fn wire(v: &Value) -> Vec<u8> {
    unhex(v["wire"].as_str().expect("wire"))
}

fn agg_of(v: &Value) -> Option<Vec<i64>> {
    match &v["agg"] {
        Value::Null => None,
        Value::Array(a) => Some(a.iter().map(|x| x.as_i64().expect("i64")).collect()),
        other => panic!("unexpected agg {other:?}"),
    }
}

/// Guard: if these stop being v1 bytes, everything below is testing the wrong thing.
#[test]
fn the_fixtures_really_are_v0_3_0_v1_receipts() {
    let vs = vectors();
    assert_eq!(vs.len(), 5, "expected the five v0.3.0 wire vectors");
    for v in &vs {
        let b = wire(v);
        assert_eq!(
            &b[..8],
            &MAGIC_V1[..],
            "{} is not an ACFA-R1 receipt -- these fixtures must be the OLD format, or this \
             file proves nothing about compatibility",
            name(v)
        );
    }
}

#[test]
fn v0_3_0_receipts_still_decode_and_report_v1_signature_semantics() {
    for v in vectors() {
        let n = name(&v).to_string();
        let r = decode(&wire(&v)).unwrap_or_else(|e| panic!("{n} failed to decode: {e:?}"));
        assert_eq!(r.round, v["round"].as_u64().expect("round"), "{n}");
        assert_eq!(r.f as u64, v["f"].as_u64().expect("f"), "{n}");
        assert_eq!(
            r.contributions.len() as u64,
            v["contribs"].as_u64().expect("contribs"),
            "{n}"
        );
        assert_eq!(
            hexs(&r.claimed_state_root),
            v["state_root"].as_str().unwrap(),
            "{n} state root moved"
        );
        assert_eq!(
            hexs(&r.claimed_output_root),
            v["output_root"].as_str().unwrap(),
            "{n} output root moved"
        );
        assert_eq!(r.claimed_aggregate, agg_of(&v), "{n} aggregate moved");

        // A v1 receipt has no context, and must be MARKED as v1 rather than merely defaulting
        // to an empty context -- otherwise NO_CONTEXT becomes a silent v1-signature downgrade.
        assert_eq!(r.ctx, NO_CONTEXT, "{n}");
        for c in &r.contributions {
            assert_eq!(
                c.sig_preimage,
                PreimageVersion::V1,
                "{n} contribution not marked v1"
            );
            assert_eq!(c.ctx, NO_CONTEXT, "{n}");
        }
    }
}

/// The load-bearing one: v1 signatures must still VERIFY, not merely survive decoding.
#[test]
fn v0_3_0_signatures_still_verify_under_the_v1_preimage() {
    let mut checked = 0;
    for v in vectors() {
        let n = name(&v).to_string();
        let r = decode(&wire(&v)).expect("decode");
        for c in &r.contributions {
            assert!(
                c.signature_valid(&r.pki),
                "{n}: a signature written by v0.3.0 no longer verifies -- COMPATIBILITY.md is broken"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 11,
        "only {checked} v1 signatures exercised; expected all 11"
    );
}

/// NEGATIVE CONTROL for the claim in `wire.rs` that distinct magics keep v2 rules off v1 bytes.
///
/// Relabel a genuine v0.3.0 receipt as `ACFA-R2` and it must NOT quietly verify. Without this,
/// "the magics make it a decode dispatch" is an assertion about intent, not about behaviour.
#[test]
fn a_v1_receipt_relabelled_as_v2_does_not_silently_verify() {
    let v = vectors()
        .into_iter()
        .find(|x| name(x) == "three-contribs")
        .expect("vector");
    let mut b = wire(&v);
    b[..8].copy_from_slice(&MAGIC_V2[..]);

    match decode(&b) {
        // Preferred: the length shift from the absent 32-byte ctx makes this structurally invalid.
        Err(_) => {}
        // If it DOES parse, the signatures must fail -- v2 rules applied to v1 bytes must never
        // produce a receipt that looks honestly signed.
        Ok(r) => {
            let any_valid = r.contributions.iter().any(|c| c.signature_valid(&r.pki));
            assert!(
                !any_valid,
                "a v0.3.0 receipt relabelled ACFA-R2 produced VALID-looking v2 signatures -- \
                 the magic dispatch is not actually separating the two signature meanings"
            );
        }
    }
}

fn hexs(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// redacted_v1: `MAGIC_REDACTED_V1` has its own decode arm and no v0.3.0 fixture here, because
// the v0.3.0 `wire_vectors` example emits full receipts only. That arm remains uncovered and is
// recorded as such rather than assumed safe.
