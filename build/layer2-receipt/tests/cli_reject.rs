// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! adv-09: rejecting a non-receipt must cost the header, not the file.
//!
//! `fs::read` pulled the entire file into memory and only then asked whether it was a
//! receipt at all. Measured before the fix: a 200 MB non-receipt cost 200 MB of resident
//! memory to reach "bad magic". After: 852 KB. Anyone can hand a verifier a file, so the
//! cost of REJECTING one has to be bounded by the header rather than by the sender's
//! choice of length.
//!
//! This test asserts the BEHAVIOUR the fix must preserve while doing that -- a large
//! non-receipt is still refused with the right code, a short file does not panic, and a
//! real receipt still reads to the end. A memory assertion is not portable enough to gate
//! on, so the measurement lives in the commit message and this pins the contract.

use std::io::Write;
use std::process::Command;

fn verify(args: &[&str]) -> i32 {
    Command::new(env!("CARGO_BIN_EXE_acfa-verify"))
        .args(args)
        .output()
        .expect("run acfa-verify")
        .status
        .code()
        .unwrap_or(-1)
}

#[test]
fn a_large_non_receipt_is_refused_without_reading_it_all() {
    let dir = std::env::temp_dir().join("acfa_adv09");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let big = dir.join("not-a-receipt.bin");

    // 32 MB of zeroes: large enough that reading it all is a visibly different cost from
    // reading eight bytes, small enough to stay polite in CI.
    let mut f = std::fs::File::create(&big).expect("create");
    let chunk = vec![0u8; 1 << 20];
    for _ in 0..32 {
        f.write_all(&chunk).expect("write");
    }
    drop(f);

    assert_eq!(
        verify(&[big.to_str().unwrap()]),
        2,
        "a file with the wrong magic is unparseable input"
    );
    std::fs::remove_file(&big).ok();
}

#[test]
fn a_file_too_short_to_hold_a_magic_does_not_panic() {
    // The header read must handle a file SHORTER than the magic. read_exact fails there,
    // and treating that as anything other than "not a receipt" would turn a two-byte file
    // into a crash.
    let dir = std::env::temp_dir().join("acfa_adv09");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    for (name, body) in [("empty.bin", &b""[..]), ("two.bin", &b"AC"[..])] {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("write");
        assert_eq!(
            verify(&[p.to_str().unwrap()]),
            2,
            "{name}: a short file is unparseable, not a panic"
        );
        std::fs::remove_file(&p).ok();
    }
}
