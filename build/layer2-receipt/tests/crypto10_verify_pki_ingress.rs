// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crypto-10, SECOND DOOR -- `acfa-verify --pki` must refuse an unusable identity key.
//!
//! G found this at the finality CLI's `pki` directive. Sweeping every site that builds a
//! `Pki` from input found the same gap here, so the finding is two doors, not one:
//!
//! ```text
//!     wire.rs                  inserts=1  guard=1  guarded
//!     bin/acfa-finality.rs     inserts=1  guard=0  GAP   (G's #59)
//!     bin/acfa-verify.rs       inserts=1  guard=0  GAP   (this file)
//! ```
//!
//! `is_usable_pubkey` documents itself as "checked where keys ENTER, because by the time
//! `verify` sees one the damage is a policy decision already made". `parse_pki` checked
//! length, ASCII and hex -- every property except the one that matters -- and then inserted.
//!
//! WHY THIS IS NOT ONLY A WIRE-TRUST ARGUMENT: `--pki` is documented as identities the
//! operator independently trusts. That makes a weak key here LESS LIKELY, not less harmful;
//! it is precisely the set nobody re-examines. A small-order key accepts `R = identity,
//! S = 0` under the cofactorless equation, so the node it names becomes an identity whose
//! signatures need no secret key.

use acfa_receipt::identity::{Identity, Pki};
use acfa_receipt::receipt::Receipt;
use acfa_receipt::{Rule, State};
use std::io::Write;
use std::process::Command;

/// Encodings of points of order dividing 8 -- the weak keys, same vectors as
/// `crypto02_key_strength`.
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

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The CLI decodes the receipt BEFORE it parses `--pki`, so without a real receipt the run
/// short-circuits ahead of the guard and the test passes while exercising nothing. Measured
/// in rust-04: a missing path exits 2 on "cannot read input", an empty file exits 2 on "bad
/// magic", and neither reaches `parse_pki`.
fn run_with_pki(tag: &str, contents: &str) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!("acfa_crypto10_{tag}"));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let id = Identity::from_secret(1, &[7u8; 32]);
    let mut pki: Pki = Pki::new();
    pki.insert(id.node_id, id.public());
    let r = Receipt::issue(&State::new(), 1, &pki, 1, Rule::Krum);
    let receipt = dir.join("receipt.bin");
    std::fs::write(&receipt, acfa_receipt::wire::encode(&r)).expect("write receipt");

    let path = dir.join("pki.txt");
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(contents.as_bytes()).expect("write");
    drop(f);

    Command::new(env!("CARGO_BIN_EXE_acfa-verify"))
        .arg("--pki")
        .arg(&path)
        .arg(&receipt)
        .output()
        .expect("run acfa-verify")
}

/// REFUSES. Every weak vector must be rejected, and the refusal must name the line and node
/// so the operator can find it in their own trust file.
#[test]
fn a_small_order_pki_key_is_refused_at_the_verify_door() {
    for (i, weak) in SMALL_ORDER.iter().enumerate() {
        let out = run_with_pki(&format!("weak{i}"), &format!("7 {}\n", hex(weak)));
        let err = String::from_utf8_lossy(&out.stderr);

        assert_ne!(
            out.status.code(),
            Some(0),
            "vector {i}: acfa-verify ACCEPTED a small-order identity into the trusted set; \
             signatures for node 7 then need no secret key. stderr: {err}"
        );
        assert!(
            err.contains("unusable public key"),
            "vector {i}: the refusal must say WHY, or the operator cannot fix their trust \
             file: {err}"
        );
        assert!(
            err.contains("node 7"),
            "vector {i}: the refusal must name the node id: {err}"
        );
    }
}

/// ADMITS. Without this a `parse_pki` that rejected every key would satisfy the test above
/// perfectly -- the failure mode this repo keeps rebuilding.
#[test]
fn a_genuine_pki_key_is_still_admitted() {
    let good = Identity::from_secret(7, &[9u8; 32]).public();
    let out = run_with_pki("good", &format!("7 {}\n", hex(&good)));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("unusable public key"),
        "a genuine key was refused as unusable, so the guard rejects everything: {err}"
    );
}
