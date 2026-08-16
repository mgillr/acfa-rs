// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Cross-implementation agreement for the certificate and fork wire formats.
//!
//! This is the test that carries the wire module's actual claim. `tests/wire.rs` is
//! self-consistent by construction -- it encodes with this encoder and decodes with this
//! decoder -- and self-consistency is precisely the standard this project rejects
//! everywhere else. `acfa-receipt` is held to byte-identical agreement with an
//! independently written reference; until this file existed, `acfa-finality` was not,
//! and saying so was the honest answer to "is the certificate encoding cross-checked".
//!
//! The vectors in `golden/vectors_cert.json` are produced by `golden/generate_cert.py`,
//! written from the specification rather than transliterated from this crate.
//! Transliterating would reproduce this crate's mistakes and call the result agreement.
//!
//! The independence is not only linguistic. Rust signs with `ed25519-dalek`; the
//! generator signs with `cryptography` (OpenSSL). A disagreement about Ed25519 for a
//! fixed seed and message would break these vectors, so the signature path is checked
//! rather than assumed.
//!
//! Regenerate:
//!   python3 tests/golden/generate_cert.py > tests/golden/vectors_cert.json

use acfa_finality::wire::{decode_cert, decode_fork, encode_cert, encode_fork};
use acfa_finality::{CertFork, CertTuple, Certificate};
use acfa_receipt::identity::{Identity, Pki, PubKey};
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("golden/vectors_cert.json");
    serde_json::from_str(raw).expect("golden vectors parse")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn h32(v: &Value) -> [u8; 32] {
    unhex(v.as_str().expect("hex string"))
        .try_into()
        .expect("32 bytes")
}

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn build(case: &Value) -> Certificate {
    let mut c = Certificate::new(CertTuple {
        round: case["round"].as_u64().expect("round"),
        a_root: h32(&case["a_root"]),
        e_cut_root: h32(&case["e_cut"]),
        rho: h32(&case["rho"]),
    });
    for s in case["signers"].as_array().expect("signers") {
        c.sign(&ident(s.as_u64().expect("signer id") as u32));
    }
    c
}

#[test]
fn rust_reproduces_the_independent_encoder_byte_for_byte() {
    let v = vectors();
    let cases = v["certs"].as_array().expect("certs");
    assert!(!cases.is_empty(), "golden corpus is empty");

    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let expected = unhex(case["wire"].as_str().expect("wire"));
        let got = encode_cert(&build(case));
        assert_eq!(
            got, expected,
            "[{name}] Rust encoding disagrees with the independent encoder"
        );
    }

    // Guard the guard: an emptied or truncated golden file would pass every assertion
    // above without comparing anything.
    assert!(cases.len() >= 5, "corpus too small to be meaningful");
}

#[test]
fn the_tuple_id_agrees_and_it_is_what_orders_a_fork() {
    // Fork orientation is decided by tuple id. If the two implementations disagreed
    // about the id they would still each be self-consistent and would orient forks
    // differently -- two honest observers publishing different bytes for one violation.
    let v = vectors();
    for case in v["certs"].as_array().expect("certs") {
        let name = case["name"].as_str().unwrap_or("?");
        let c = build(case);
        let expected = unhex(case["tuple_id"].as_str().expect("tuple_id"));
        assert_eq!(
            c.tuple.id().to_vec(),
            expected,
            "[{name}] tuple id disagrees with the independent implementation"
        );
    }
}

#[test]
fn rust_decodes_what_the_independent_encoder_produced() {
    // Byte equality on the encode side would still leave a decoder that cannot read
    // foreign bytes. This is the direction that matters operationally: evidence
    // arriving from somebody else's implementation.
    let v = vectors();
    for case in v["certs"].as_array().expect("certs") {
        let name = case["name"].as_str().unwrap_or("?");
        let bytes = unhex(case["wire"].as_str().expect("wire"));
        let decoded = decode_cert(&bytes).unwrap_or_else(|e| panic!("[{name}] {e:?}"));
        assert_eq!(decoded, build(case), "[{name}] decoded value differs");
        assert_eq!(
            encode_cert(&decoded),
            bytes,
            "[{name}] re-encode is not stable"
        );
    }
}

#[test]
fn foreign_signatures_verify_against_the_foreign_pki() {
    // The signatures in the vectors were produced by OpenSSL; they are verified here by
    // ed25519-dalek, against public keys the generator also emitted. If the two Ed25519
    // implementations disagreed for a fixed seed, this is where it would show.
    let v = vectors();
    let mut pki: Pki = Pki::new();
    for (id, pk) in v["pki"].as_object().expect("pki") {
        let key: PubKey = unhex(pk.as_str().expect("hex"))
            .try_into()
            .expect("32 bytes");
        pki.insert(id.parse().expect("u32 id"), key);

        // The public key derived from the same seed on this side must match too,
        // otherwise the agreement above would be over keys nobody actually holds.
        let local = ident(id.parse().expect("u32 id")).public();
        assert_eq!(
            local, key,
            "public key for {id} differs across implementations"
        );
    }

    for case in v["certs"].as_array().expect("certs") {
        let name = case["name"].as_str().unwrap_or("?");
        let n_sigs = case["signers"].as_array().expect("signers").len();
        if n_sigs == 0 {
            continue; // genesis carries none by construction
        }
        let decoded = decode_cert(&unhex(case["wire"].as_str().expect("wire"))).expect("decodes");
        // f + 1 = n_sigs is the exact threshold this certificate can satisfy.
        assert!(
            decoded.is_valid(&pki, n_sigs - 1),
            "[{name}] foreign signatures did not verify locally"
        );
    }
}

#[test]
fn fork_orientation_agrees_including_when_observed_the_other_way_round() {
    let v = vectors();
    let forks = v["forks"].as_array().expect("forks");
    assert!(forks.len() >= 3, "fork corpus too small");

    for case in forks {
        let name = case["name"].as_str().unwrap_or("?");
        let bytes = unhex(case["wire"].as_str().expect("wire"));
        let decoded = decode_fork(&bytes).unwrap_or_else(|e| panic!("[{name}] {e:?}"));
        assert_eq!(
            encode_fork(&decoded),
            bytes,
            "[{name}] re-encoding a foreign fork is not byte-stable"
        );
    }

    // The mirrored case exists to prove the point directly: the same violation seen in
    // the opposite order must serialise identically in BOTH implementations.
    let straight = unhex(
        forks
            .iter()
            .find(|c| c["name"] == "differing-a-root")
            .expect("case")["wire"]
            .as_str()
            .expect("wire"),
    );
    let mirrored = unhex(
        forks
            .iter()
            .find(|c| c["name"] == "mirrored-input-order")
            .expect("case")["wire"]
            .as_str()
            .expect("wire"),
    );
    assert_eq!(
        straight, mirrored,
        "the independent encoder did not orient a mirrored fork canonically"
    );

    // And Rust must reach the same orientation building it locally from either side.
    let a = build(&vectors()["certs"][0]);
    let mut b_tuple = a.tuple;
    b_tuple.rho = [9u8; 32];
    let mut b = Certificate::new(b_tuple);
    b.sign(&ident(2));
    let k1 = CertFork::canonical(a.clone(), b.clone()).expect("conflicting");
    let k2 = CertFork::canonical(b, a).expect("conflicting");
    assert_eq!(encode_fork(&k1), encode_fork(&k2));
}
