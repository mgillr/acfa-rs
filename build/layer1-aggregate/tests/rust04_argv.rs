// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! rust-04. `std::env::args()` PANICS on an argument that is not valid Unicode, so this
//! binary aborted at exit 101 where its own contract promises "2 unreadable input".
//!
//! THE FINDING SPLITS AND ONLY THIS HALF WAS LIVE. Its title names `&s[i..i+2]` on a
//! `&str`, and that half does not reproduce: the hex paths are guarded by `is_ascii` or use
//! `str::get`, which returns `None` at a non-char boundary rather than panicking. Closing
//! the finding on its title would have closed the half that was already fixed.
//!
//! An abort is not a refusal. The operator gets a rustc-internal message and an exit code
//! the documented contract does not list. Same shape as `num-05`.
#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};

fn run(args: &[&OsStr]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_acfa-agg"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn acfa-agg");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The guard. Non-UTF-8 argv is REFUSED at the documented code, not aborted.
#[test]
fn a_non_utf8_argument_is_refused_rather_than_aborting() {
    let bad = OsStr::from_bytes(b"--pki=\xff\xfe");
    let (code, err) = run(&[bad]);
    assert_eq!(
        code, 2,
        "non-UTF-8 argv must exit 2 (unreadable), not abort at 101: {err}"
    );
    assert!(
        !err.contains("panicked"),
        "the binary panicked instead of refusing: {err}"
    );
    assert!(
        err.contains("not valid UTF-8"),
        "the operator must be told what was wrong: {err}"
    );
}

/// The message must name the POSITION. The bytes are by definition not printable, so
/// "argument 3" is the only actionable thing the tool can say.
#[test]
fn the_refusal_names_which_argument_it_was() {
    let bad = OsStr::from_bytes(b"\xff\xfe");
    let (code, err) = run(&[OsStr::new("--help-me-not"), OsStr::new("x"), bad]);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("argument 3"),
        "the position must be named so the operator can find it: {err}"
    );
}

/// POSITIVE CONTROL. A binary that refused every argument would pass the tests above.
#[test]
fn ordinary_utf8_arguments_are_unaffected() {
    let (code, _) = run(&[OsStr::new("--help")]);
    assert_eq!(code, 0, "--help must still succeed");
}
