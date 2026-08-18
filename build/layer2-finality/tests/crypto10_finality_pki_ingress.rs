// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crypto-10, FINALITY door: the `acfa-finality` `pki` directive refuses an unusable public
//! key at ingress, symmetric with the receipt wire decoder and with the verify door (#66).
//!
//! The `pki` directive validated hex, 32-byte length and a unique node id, then inserted -- it
//! never called `is_usable_pubkey`, so a small-order or malformed key entered the trusted set.
//!
//! ONE CORPUS ACROSS BOTH DOORS. This test uses the SAME three canonical order-8 encodings that
//! `crypto02_key_strength` characterises and that the verify door's `crypto10_verify_pki_ingress`
//! iterates, so "small-order" means one thing across the whole finding rather than a different
//! definition per door.
//!
//! GUARD-DELETION: delete the `is_usable_pubkey` check in `bin/acfa-finality.rs` and
//! `the_finality_pki_ingress_refuses_a_small_order_key` goes RED (the key is accepted and the
//! otherwise-clean run exits 0); `the_finality_pki_ingress_admits_a_usable_key` stays green, so
//! the guard discriminates on key strength rather than refusing every PKI line.

use acfa_finality::wire::encode_cert;
use acfa_finality::{CertTuple, Certificate};
use acfa_receipt::hash::h;
use acfa_receipt::identity::Identity;
use std::io::Write;
use std::process::{Command, Stdio};

/// The three canonical order-8 encodings -- identical to `crypto02_key_strength` and to the
/// verify door's `crypto10_verify_pki_ingress`, so both doors of crypto-10 share one corpus.
const SMALL_ORDER: [[u8; 32]; 3] = [
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    [0u8; 32],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn tuple(round: u64, a: &str) -> CertTuple {
    CertTuple {
        round,
        a_root: h(a.as_bytes()),
        e_cut_root: h(b"ecut"),
        rho: h(a.as_bytes()),
    }
}

fn signed(t: CertTuple, signers: &[u32]) -> Certificate {
    let mut c = Certificate::new(t);
    for &s in signers {
        c.sign(&ident(s));
    }
    c
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(input: &str) -> i32 {
    let mut child = Command::new(env!("CARGO_BIN_EXE_acfa-finality"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn acfa-finality");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait().expect("wait").code().expect("exit code")
}

/// Signers 1,2,3 are all usable; node 4 is a NON-signer whose PKI key we vary. With a usable key
/// for node 4 this is a clean run that exits 0. Replacing node 4's key with a small-order point
/// changes nothing but that one PKI line's key strength.
fn input_with_node4_key(node4_hex: &str) -> String {
    format!(
        "f 1\npki 1 {}\npki 2 {}\npki 3 {}\npki 4 {}\ncert {}\n",
        hex(&ident(1).public()),
        hex(&ident(2).public()),
        hex(&ident(3).public()),
        node4_hex,
        hex(&encode_cert(&signed(tuple(1, "A"), &[1, 2, 3]))),
    )
}

#[test]
fn the_finality_pki_ingress_refuses_a_small_order_key() {
    for (i, weak) in SMALL_ORDER.iter().enumerate() {
        let code = run(&input_with_node4_key(&hex(weak)));
        assert_ne!(
            code, 0,
            "vector {i}: the finality CLI pki ingress accepted a small-order key. \
             is_usable_pubkey must be checked at the `pki` directive, symmetric with receipt \
             wire::decode and with the verify door."
        );
    }
}

#[test]
fn the_finality_pki_ingress_admits_a_usable_key() {
    // Control: the SAME shape with a usable key for node 4 is a clean run that exits 0, so the
    // refusal above discriminates on key strength rather than rejecting every PKI line.
    let code = run(&input_with_node4_key(&hex(&ident(4).public())));
    assert_eq!(
        code, 0,
        "control: a usable key at the same ingress must pass and the run must exit 0"
    );
}
