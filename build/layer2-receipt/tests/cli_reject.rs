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

/// adv-09, THE COST ASSERTION -- the one the file's own header said was not portable.
///
/// `a_large_non_receipt_is_refused_without_reading_it_all` asserts EXIT CODE 2, which is
/// true whether the binary reads eight bytes or the whole file. MEASURED: replacing the
/// header check with `read_to_end` leaves that test GREEN. Its NAME claims a property its
/// ASSERTION never checks, which is the sharpest form of a check that cannot fail.
///
/// A FIFO makes the cost assertion DETERMINISTIC rather than a timing threshold. The pipe
/// delivers eight bad-magic bytes and is then held open with nothing more to come:
///
///   header-bounded  reads 8, sees bad magic, stops           -> exits at once
///   read-to-end     waits for an EOF that never arrives      -> BLOCKS FOREVER
///
/// So the failure is a HANG, not a slow number, and there is no threshold to tune. This is
/// the same shape as the pty check for adv-08: reach the branch a normal harness cannot.
///
/// `cfg(unix)` because FIFOs are Unix, and the CI matrix includes windows-latest. That is a
/// COMPILE-TIME exclusion, not a runtime skip -- on Unix it always runs. Windows keeps only
/// the exit-code assertion above, and therefore does not cover this property. Stated rather
/// than left for someone to discover.
#[cfg(unix)]
#[test]
fn rejecting_a_non_receipt_never_waits_for_an_eof_that_is_not_coming() {
    use std::time::{Duration, Instant};

    let dir = std::env::temp_dir().join("acfa_adv09_fifo");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let fifo = dir.join("slow-non-receipt");
    std::fs::remove_file(&fifo).ok();
    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must be available on unix");
    assert!(
        made.success(),
        "mkfifo failed -- the test cannot run, so it fails"
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_acfa-verify"))
        .arg(&fifo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn acfa-verify");

    // Opening for write unblocks the reader's open(2). Eight bytes of wrong magic, then the
    // handle is held: a reader that stops at the header is already done, a reader that wants
    // EOF is not.
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        if let Ok(mut w) = std::fs::OpenOptions::new().write(true).open(&fifo) {
            let _ = w.write_all(b"NOTACFA!");
            let _ = w.flush();
            std::thread::sleep(Duration::from_secs(10));
        }
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut code = None;
    while Instant::now() < deadline {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                code = Some(status.code().unwrap_or(-1));
                break;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    if code.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    drop(writer); // the sleeping writer is detached; the fifo goes with the temp dir
    std::fs::remove_file(dir.join("slow-non-receipt")).ok();

    assert_eq!(
        code,
        Some(2),
        "the header decided this was not a receipt, so nothing may wait for an EOF: \
         None here means it BLOCKED, which is adv-09 unfixed"
    );
}
