// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The `acfa-agg` CLI contract, driven through the real binary.
//!
//! WHY THIS FILE EXISTS. This crate had no test that ran its binary at all -- every test
//! linked the library. So the CLI's documented contract was checked by reading it, and half
//! of it was wrong in the shipped artefact without anything noticing.
//!
//! The specific failure this closes: the exit code for a bad input VALUE was corrected from
//! 2 to 1 to match the documented contract, and the stdout token was left behind. That left
//! the binary with two exit-1 paths that disagreed -- the rule path printed
//! `refused <reason>` and the value path printed nothing. Both halves are one contract: a
//! program reads the leading token and branches on the code, so an empty stdout with exit 1
//! says "unclassified failure" where the exit code says "refused". Only one of those can be
//! right, and the caller has no way to tell which.
//!
//! Asserting them TOGETHER, in one table, is the point. Two separate tests could each pass
//! while the pair remained inconsistent, which is exactly how this shipped.

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

#[test]
fn the_exit_code_and_the_stdout_token_agree_on_every_path() {
    // The contract, from USAGE and the module docs:
    //   0 ok      -> stdout begins "ok "
    //   1 refused -> stdout begins "refused "   (bound not met, bad input VALUES)
    //   2 unreadable -> stdout empty; the input could not be parsed at all
    //
    // The distinction between 1 and 2 is not cosmetic. An out-of-range value parses
    // perfectly well as an f64; the program is REFUSING it, not failing to read it.
    // Reporting it as unreadable sends a caller looking for a malformed encoding when the
    // answer is "rescale your data".
    let cases: &[(&str, &str, i32, &str)] = &[
        (
            "ok",
            "rule mean\nf 0\n01 3ff0000000000000\n02 4000000000000000\n",
            0,
            "ok ",
        ),
        (
            "beta denominator zero",
            "rule trimmed\nbeta 1 0\nf 0\n01 3ff0000000000000\n02 4000000000000000\n",
            1,
            "refused ",
        ),
        (
            "value out of Q16.16 range",
            "rule mean\nf 0\n01 46293e5939a08cea\n02 3ff0000000000000\n",
            1,
            "refused ",
        ),
        (
            "value not finite",
            "rule mean\nf 0\n01 7ff8000000000000\n02 3ff0000000000000\n",
            1,
            "refused ",
        ),
        (
            "unparseable hex",
            "rule mean\nf 0\n01 zzzzzzzzzzzzzzzz\n",
            2,
            "",
        ),
        (
            "unknown rule",
            "rule nope\nf 0\n01 3ff0000000000000\n",
            2,
            "",
        ),
    ];

    for (label, input, want_code, want_prefix) in cases {
        let (code, stdout, _) = run(input);
        assert_eq!(
            code, *want_code,
            "{label}: exit code disagrees with the documented contract (stdout: {stdout:?})"
        );
        if want_prefix.is_empty() {
            assert!(
                stdout.is_empty(),
                "{label}: unreadable input must produce no stdout token, got {stdout:?}"
            );
        } else {
            assert!(
                stdout.starts_with(want_prefix),
                "{label}: exit {code} but stdout is {stdout:?}, expected to begin {want_prefix:?} \
                 -- the exit code and the token are one contract and they disagree"
            );
        }
    }
}

#[test]
fn a_refusal_reason_is_a_single_parseable_token() {
    // Callers split on whitespace and read the reason. A reason containing a space would
    // silently truncate for every one of them, so the shape is part of the contract too.
    let (code, stdout, _) = run("rule mean\nf 0\n01 46293e5939a08cea\n02 3ff0000000000000\n");
    assert_eq!(code, 1);
    let reason = stdout
        .strip_prefix("refused ")
        .expect("a refusal must carry the `refused ` prefix");
    assert!(!reason.is_empty(), "the reason must not be empty");
    assert_eq!(
        reason.split_whitespace().count(),
        1,
        "the reason must be one whitespace-free token, got {reason:?}"
    );
}

#[test]
fn help_and_an_absent_stdin_are_distinguishable() {
    // `--help` is a success; an unexpected argument is not. These were both reachable
    // states with no output at all before the CLIs were given a usage path.
    let out = Command::new(env!("CARGO_BIN_EXE_acfa-agg"))
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(out.status.success(), "--help must exit 0");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("acfa-agg"),
        "--help must print usage on stdout"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_acfa-agg"))
        .arg("--nonsense")
        .stdin(Stdio::null())
        .output()
        .expect("run bad arg");
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unexpected argument is unreadable input, not a refusal"
    );
}

#[test]
fn duplicate_and_missing_directives_are_refused() {
    // adv-10. A repeated directive silently took the LAST value and exited 0, so
    // `rule mean` followed by `rule krum` ran krum and reported success. A missing `f`
    // silently defaulted to 0, running an undefended aggregation for anyone who omitted
    // the line. Both changed the answer with no diagnostic, which is the same failure as
    // saturating an out-of-range value -- this program refuses that, and now refuses these.
    //
    // `f` is unbracketed in USAGE while `beta` is bracketed, so `f` is required and `beta`
    // is optional. The test pins that distinction, because it is the kind of thing that
    // drifts silently between the document and the code.
    for (label, input) in [
        (
            "duplicate rule",
            "rule mean\nrule krum\nf 0\n01 3ff0000000000000\n02 4000000000000000\n",
        ),
        (
            "duplicate f",
            "rule mean\nf 0\nf 5\n01 3ff0000000000000\n02 4000000000000000\n",
        ),
        (
            "duplicate beta",
            "rule trimmed\nbeta 1 4\nbeta 1 2\nf 0\n01 3ff0000000000000\n02 4000000000000000\n",
        ),
        (
            "missing f",
            "rule mean\n01 3ff0000000000000\n02 4000000000000000\n",
        ),
    ] {
        let (code, stdout, stderr) = run(input);
        assert_eq!(code, 2, "{label}: must be refused as unreadable input");
        assert!(stdout.is_empty(), "{label}: no aggregate may be produced");
        assert!(
            !stderr.is_empty(),
            "{label}: refusing silently is the defect, not the fix"
        );
    }

    // beta is optional, so omitting it must still work.
    let (code, stdout, _) = run("rule mean\nf 0\n01 3ff0000000000000\n02 4000000000000000\n");
    assert_eq!(code, 0, "omitting the OPTIONAL beta must still succeed");
    assert!(stdout.starts_with("ok "));
}
