// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `acfa-agg` STDIN-PARSER REFUSALS THAT HAD NO WITNESS.
//!
//! Found by a guard-deletion sweep of the whole crate -- 26 `if <cond> { return … }` sites,
//! addressed by LINE NUMBER so no text anchor could drift. 20 killed, 3 skipped (the mutant
//! does not compile), and these 3 SURVIVED: build clean, file provably changed, zero tests red.
//!
//! ```text
//!     acfa-agg.rs:273  tie-key hex/ASCII check   0 tests RED
//!     acfa-agg.rs:324  contribution has no values 0 tests RED
//!     acfa-agg.rs:351  no contributions at all    0 tests RED
//! ```
//!
//! THE FIRST ONE IS rust-04 AT A FOURTH SITE. rust-04 was "all three shipped CLIs panic on
//! non-ASCII input: `&s[i..i+2]` slices a `&str` by BYTE and panics when the boundary falls
//! inside a multi-byte character". It was closed, and `rust04_argv.rs` witnesses the ARGV path
//! in all three binaries. The TIE-KEY path in this binary is separate code with the same slice
//! at `:278`, and its guard was never witnessed. MEASURED by deleting it and running the real
//! binary:
//!
//! ```text
//!     guard present : exit 2   acfa-agg: line 3: tie key must be hex
//!     guard deleted : exit 101 panicked at src/bin/acfa-agg.rs:278:58
//! ```
//!
//! So this is not a missing refusal, it is a missing CRASH GUARD, and the whole suite stayed
//! green without it. A finding that appears at N sites needs N witnesses; rust-04 got one for
//! a class it has at least two of.
//!
//! ALIGNMENT IS THE DISCRIMINATOR, NOT NON-ASCII-NESS -- the same trap `rust04_pki_ascii.rs`
//! documents. A multi-byte character must STRADDLE an even offset to split a pair; one that
//! lands on the boundary slices cleanly and proves nothing.

use std::io::Write;
use std::process::{Command, Stdio};

/// Run the real binary with `input` on stdin. Returns (exit code, stdout, stderr).
fn run(input: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_acfa-agg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn acfa-agg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

/// rust-04, FOURTH SITE. A non-ASCII tie key must be REPORTED, not abort the process.
#[test]
fn a_non_ascii_tie_key_is_reported_not_aborted() {
    // 61 ASCII + a 2-byte char + 1 ASCII. The char STARTS at byte 61, so the pair at
    // [60..62] splits it -- the only shape that reaches the panic.
    let key = format!("{}{}b", "a".repeat(61), '\u{e9}');
    assert_eq!(
        key.len(),
        64,
        "the tie key must be 64 BYTES or the length check fires first"
    );

    let (code, _out, err) = run(&format!("rule mean\nf 0\n{key} 3ff0000000000000\n"));
    assert_ne!(
        code, 101,
        "acfa-agg ABORTED on a non-ASCII tie key. A malformed input line must be reported, \
         not crash the aggregator: {err}"
    );
    assert_eq!(
        code, 2,
        "a bad input line is exit 2 by this binary's own contract: {err}"
    );
    assert!(
        err.contains("tie key must be hex"),
        "the refusal must name the cause: {err}"
    );

    // CONTROL: an odd-LENGTH key is caught by the same guard's other half.
    let (c2, _, e2) = run("rule mean\nf 0\nabc 3ff0000000000000\n");
    assert_eq!(c2, 2, "an odd-length tie key must also be refused: {e2}");
}

/// A contribution line with a tie key and no values must be refused, not aggregated as empty.
#[test]
fn a_contribution_with_no_values_is_refused() {
    let (code, _out, err) = run("rule mean\nf 0\n01\n");
    assert_eq!(code, 2, "a valueless contribution must be refused: {err}");
    assert!(
        err.contains("no values"),
        "the refusal must say the contribution carried no values: {err}"
    );
}

/// A request with directives but no contributions at all must be refused.
#[test]
fn a_request_with_no_contributions_is_refused() {
    let (code, _out, err) = run("rule mean\nf 0\n");
    assert_eq!(code, 2, "an empty contribution set must be refused: {err}");
    assert!(
        err.contains("no contributions"),
        "the refusal must name the cause: {err}"
    );
}

/// THE ACCEPTING TWIN. Without it all three refusals above are equally satisfied by a parser
/// that rejects every input -- the failure a refusal-shaped fix invites.
#[test]
fn a_well_formed_request_is_still_aggregated() {
    let (code, out, err) = run("rule mean\nf 0\n01 3ff0000000000000\n02 4000000000000000\n");
    assert_eq!(code, 0, "a valid request must still succeed: {err}");
    assert_eq!(out, "ok 98304", "1.5 in Q16.16 is 98304; got {out}");
}
