// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! rust-04 -- a non-ASCII `--pki` line must be REFUSED, not abort the process.
//!
//! `parse_pki` reads the key with `&hex[i * 2..i * 2 + 2]`, which indexes a `&str` by BYTES
//! and PANICS when the boundary falls inside a multi-byte character. The `is_ascii` guard
//! ahead of it turns that abort into a reported bad line.
//!
//! MEASURED: delete the guard and the whole workspace stays green -- there is not one
//! non-ASCII byte in any test fixture in the repository -- while the binary exits 101 on an
//! operator's own trust file.
//!
//! THE CONSTRUCTION IS THE EXPERIMENT, and two obvious ones do NOT reproduce it:
//!   * 62 ASCII + a 2-byte char is 64 bytes, but the char occupies bytes 62..63 so the slice
//!     `[62..64]` lands EXACTLY ON the boundary. Valid slice, no panic, "bad hex" either way.
//!   * a token that is 16 CHARS but 17 BYTES is caught by the length check first, so the
//!     guard is never reached.
//!
//! Only a multi-byte character STRADDLING an even offset splits a pair. ALIGNMENT is the
//! discriminator, not the presence of non-ASCII -- which is why a test written from "use a
//! non-ASCII key" has a good chance of passing whether the guard is there or not.

use acfa_receipt::identity::{Identity, Pki};
use acfa_receipt::receipt::Receipt;
use acfa_receipt::{Rule, State};
use std::io::Write;
use std::process::Command;

/// A real receipt on disk. The CLI DECODES the receipt before it parses `--pki`, so a
/// missing or empty file short-circuits ahead of the guard under test and the whole thing
/// passes while exercising nothing. Measured: a nonexistent path exits 2 on "cannot read
/// input" and an empty file exits 2 on "bad magic", neither of which reaches `parse_pki`.
fn a_real_receipt(dir: &std::path::Path) -> std::path::PathBuf {
    let id = Identity::from_secret(1, &[7u8; 32]);
    let mut pki: Pki = Pki::new();
    pki.insert(id.node_id, id.public());
    let r = Receipt::issue(
        &State::new(),
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    let path = dir.join("receipt.bin");
    std::fs::write(&path, acfa_receipt::wire::encode(&r)).expect("write receipt");
    path
}

fn run_with_pki(contents: &str) -> std::process::Output {
    let dir = std::env::temp_dir().join("acfa_rust04");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let receipt = a_real_receipt(&dir);
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

#[test]
fn a_non_ascii_pki_line_is_reported_not_aborted() {
    // 61 ASCII + a 2-byte char + 1 ASCII = 64 bytes. The char STARTS at byte 61, so the
    // pair at [60..62] splits it -- the only shape that reaches the panic.
    let key = format!("{}{}b", "a".repeat(61), '\u{e9}');
    assert_eq!(
        key.len(),
        64,
        "the key field must be 64 BYTES or the length check fires first"
    );

    let out = run_with_pki(&format!("1 {key}\n"));
    let code = out.status.code();

    assert_ne!(
        code,
        Some(101),
        "acfa-verify ABORTED on a non-ASCII --pki line (exit 101). A malformed trust file \
         must be reported, not crash the verifier: stderr was {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("public key must be hex"),
        "expected a reported bad line, got: {err}"
    );

    // CONTROL: a well-formed ASCII key must NOT produce that error, or the assertion above
    // could pass on a file this test never really exercised.
    let good = run_with_pki(&format!("1 {}\n", "a".repeat(64)));
    assert!(
        !String::from_utf8_lossy(&good.stderr).contains("public key must be hex"),
        "the control file must parse past the key check"
    );
}
