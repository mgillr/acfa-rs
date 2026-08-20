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
        // crdt-08. A short vector PARSES PERFECTLY -- the program is refusing it, not
        // failing to read it -- and this row exited 2 until the CLI's own duplicate
        // dimension check was removed. `ee7d221`/`efc785c` made exactly this correction for
        // out-of-range and non-finite values and left this sibling behind, which is what an
        // absent table row buys you.
        (
            "short vector, adversary last",
            "rule mean\nf 0\n01 3ff0000000000000 3ff0000000000000\n\
             02 3ff0000000000000 3ff0000000000000\n03 3ff0000000000000\n",
            1,
            "refused ",
        ),
        (
            "short vector, adversary FIRST",
            "rule mean\nf 0\n01 3ff0000000000000\n\
             02 3ff0000000000000 3ff0000000000000\n03 3ff0000000000000 3ff0000000000000\n",
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
    //
    // THIS TEST USED TO DRIVE ONE INPUT AND THAT MADE IT BLIND. It exercised only
    // `ValueOutOfRange`, a unit variant whose Debug form is a single word no matter what,
    // so it could not fail while any variant carried fields. crdt-08 turned
    // `DimensionMismatch` into a struct variant, `{e:?}` became NINE tokens, and this test
    // stayed green through the whole break. A contract asserted on one of six paths is a
    // claim about one path.
    //
    // Every refusal the CLI can reach now drives it, including the two struct variants.
    let refusals: &[(&str, &str)] = &[
        (
            "value out of range",
            "rule mean\nf 0\n01 46293e5939a08cea\n02 3ff0000000000000\n",
        ),
        (
            "value not finite",
            "rule mean\nf 0\n01 7ff8000000000000\n02 3ff0000000000000\n",
        ),
        (
            "beta denominator zero",
            "rule trimmed\nbeta 1 0\nf 0\n01 3ff0000000000000\n02 4000000000000000\n",
        ),
        (
            "duplicate tie key",
            "rule mean\nf 0\n01 3ff0000000000000\n01 4000000000000000\n",
        ),
        (
            // STRUCT VARIANT -- the one that broke it.
            "dimension mismatch",
            "rule mean\nf 0\n01 3ff0000000000000\n\
             02 3ff0000000000000 3ff0000000000000\n03 3ff0000000000000 3ff0000000000000\n",
        ),
        (
            // STRUCT VARIANT -- no strict plurality, so no offender is named.
            "dimension mismatch, unattributable",
            "rule mean\nf 0\n01 3ff0000000000000\n02 3ff0000000000000 3ff0000000000000\n",
        ),
        (
            "bulyan below its precondition",
            "rule bulyan\nf 1\n01 3ff0000000000000\n02 4000000000000000\n",
        ),
    ];
    for (label, input) in refusals {
        let (code, stdout, _) = run(input);
        assert_eq!(code, 1, "{label}: expected a refusal, got {stdout:?}");
        let reason = stdout
            .strip_prefix("refused ")
            .unwrap_or_else(|| panic!("{label}: a refusal must carry the `refused ` prefix"));
        assert!(!reason.is_empty(), "{label}: the reason must not be empty");
        assert_eq!(
            reason.split_whitespace().count(),
            1,
            "{label}: the reason must be one whitespace-free token, got {reason:?}"
        );
    }
}

/// crdt-08 through the shipped binary, which is where an operator meets it.
///
/// The library test sweeps every placement; this one asserts the CLI does not re-derive
/// the answer. It had its OWN dimension check, against the first contribution, and with the
/// adversary first it printed "line 4: dimension 4 differs from 1" -- accusing an honest
/// node and reporting the adversary's length as the reference.
#[test]
fn the_cli_names_the_short_vector_offender_not_whoever_followed_it() {
    let n = 7;
    for adversary in 0..n {
        let mut req = String::from("rule mean\nf 0\n");
        for i in 0..n {
            let d = if i == adversary { 1 } else { 4 };
            req.push_str(&format!("{:02x}", i + 1));
            for _ in 0..d {
                req.push_str(" 3ff0000000000000");
            }
            req.push('\n');
        }
        let (code, stdout, stderr) = run(&req);
        assert_eq!(code, 1, "adversary at {adversary}: {stdout:?}");
        assert_eq!(stdout, "refused DimensionMismatch");
        // The line number an operator can act on: contributions start on line 3.
        assert!(
            stderr.contains(&format!("that is line {} of this request.", adversary + 3)),
            "adversary at {adversary}: stderr blames the wrong line: {stderr}"
        );
        assert!(
            stderr.contains("4 is the plurality length"),
            "adversary at {adversary}: the plurality must be the honest length: {stderr}"
        );
    }
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

#[test]
fn a_directive_refuses_trailing_tokens_on_its_own_line() {
    // The adv-10 fix refused a directive repeated on TWO LINES and left the SAME LINE open,
    // because each arm took its argument with `it.next()` and never asked whether the
    // iterator was exhausted. `rule mean krum` read `mean`, discarded `krum`, and ran.
    //
    // This is not a parsing nicety. MEASURED on honest [1.0, 2.0, 3.0] plus one adversary at
    // 1000.0, every value inside Q16.16 range:
    //     rule krum       -> ok 65536      (1.0, the robust answer)
    //     rule mean       -> ok 16482304   (251.5, poisoned)
    //     rule mean krum  -> ok 16482304   <-- the poisoned mean under Krum's NAME
    // Exit 0, empty stderr, 251x poisoning from a single adversary, and nothing anywhere
    // telling the caller the rule they asked for was not the rule that ran.
    // n = 5 so multi-Krum runs at f=1 (needs n >= 2f+3 = 5, adv-01): honest 1,2,3,4 plus one
    // adversary at 1000. Krum excludes the outlier; the plain mean is dragged by it.
    let data = "f 1\n                01 3ff0000000000000\n                02 4000000000000000\n                03 4008000000000000\n                04 4010000000000000\n                05 408f400000000000\n";

    // The two rules must genuinely differ on this data, or the test below proves nothing --
    // a poisoning test on data where mean and krum agree is a check that cannot fail.
    let (_, krum_out, _) = run(&format!("rule krum\n{data}"));
    let (_, mean_out, _) = run(&format!("rule mean\n{data}"));
    assert_ne!(
        krum_out, mean_out,
        "the fixture must separate the rules, otherwise this test cannot detect substitution"
    );

    for bad in ["rule mean krum", "rule krum mean", "f 1 2", "beta 1 4 9"] {
        let body = if bad.starts_with("beta") {
            format!("rule trimmed\n{bad}\n{data}")
        } else if bad.starts_with("f ") {
            format!("rule mean\n{bad}\n01 3ff0000000000000\n02 4000000000000000\n")
        } else {
            format!("{bad}\n{data}")
        };
        let (code, stdout, stderr) = run(&body);
        assert_eq!(code, 2, "{bad:?}: trailing tokens must be refused");
        assert!(stdout.is_empty(), "{bad:?}: no aggregate may be produced");
        assert!(
            stderr.contains("trailing"),
            "{bad:?}: the diagnostic must name the trailing token, got {stderr:?}"
        );
    }

    // And the legitimate forms must still work, because a guard that protects the product by
    // breaking it is the other failure direction.
    let (code, stdout, _) = run(&format!("rule trimmed\nbeta 1 4\n{data}"));
    assert_eq!(code, 0, "a well-formed beta must still be accepted");
    assert!(stdout.starts_with("ok "));
    let (code, stdout, _) = run(&format!("rule krum\n{data}"));
    assert_eq!(code, 0);
    assert_eq!(stdout, krum_out, "krum must still return krum's answer");
}

#[test]
fn krum_at_the_select_all_band_is_reported_under_a_distinct_token_not_ok_or_refused() {
    // adv-01 x fl-11 (D-2 final). multi_krum returns EVERY contribution when m = n-f-2 < 1,
    // i.e. n < f+3 -- REFERENCE-FAITHFUL (acfa.py returns list(range(n))). The aggregate is the
    // plain mean: the rule did not run. adv-01 requires this not be handed back SILENTLY as a
    // defended `ok`. The Flower adapter's fl-11 design requires the band still produce a value
    // it can REPORT, with a test. Both are met by a DISTINCT TOKEN: `undefended <values>` at
    // exit 0 -- the value is there for the adapter, under a token a caller reading the contract
    // cannot mistake for `ok`. Regime 2 (f+3 <= n < 2f+3) genuinely SELECTS and stays `ok`.
    //
    // GUARD-DELETION: remove the `undefended_band` handling from acfa-agg.rs and select-all is
    // reported as plain `ok`, indistinguishable from a defended result.
    let select_all = "f 1\n01 3ff0000000000000\n02 4000000000000000\n03 4008000000000000\n"; // n=3, f+3=4
    let (code, stdout, stderr) = run(&format!("rule krum\n{select_all}"));
    assert_eq!(
        code, 0,
        "select-all produces a value the adapter can report, not a hard refusal"
    );
    assert!(
        stdout.starts_with("undefended "),
        "must carry the distinct token, got {stdout:?}"
    );
    assert!(
        !stdout.starts_with("ok "),
        "must NOT be reported as a defended `ok` result"
    );
    assert!(
        stderr.contains("did not run"),
        "stderr must warn the rule did not run: {stderr:?}"
    );

    // Regime 2: f+3 <= n < 2f+3. The rule SELECTS a subset; reported as a normal `ok`.
    let regime2 = "f 1\n01 3ff0000000000000\n02 4000000000000000\n03 4008000000000000\n\
                   04 4010000000000000\n"; // n=4, f=1
    let (code, stdout, _) = run(&format!("rule krum\n{regime2}"));
    assert_eq!(code, 0, "regime 2 selects and is reported as ok");
    assert!(
        stdout.starts_with("ok "),
        "regime 2 is a defended-enough `ok`: {stdout:?}"
    );

    // Bulyan below its precondition errors in the LIBRARY, a distinct named refusal.
    let (code, stdout, _) = run(&format!("rule bulyan\n{select_all}"));
    assert_eq!(code, 1, "bulyan below 4f+3 is refused by the library");
    assert!(
        stdout.starts_with("refused ") && stdout != "refused undefended",
        "{stdout:?}"
    );

    // mean makes no robustness claim and is always a plain ok.
    let (code, stdout, _) = run(&format!("rule mean\n{select_all}"));
    assert_eq!(code, 0);
    assert!(stdout.starts_with("ok "));
}

/// **A fault bound near `usize::MAX` must be REFUSED, not panic after printing an answer.**
///
/// Before the fix the shipped binary wrote `undefended 0` to stdout and then **aborted at 101**
/// with `attempt to add with overflow`: the select-all band computes `f + 3` on `usize`, and with
/// this crate's `overflow-checks = true` profile that is a panic reachable from stdin. Three
/// separate contracts broken at once -- a panic on an untrusted door, an exit code outside the
/// documented `0 ok / 1 refused / 2 unreadable`, and a plausible-looking answer on stdout
/// belonging to a process that died.
///
/// `multi_krum` already fixed this class internally with `f as u128 + 3`. The guard existed one
/// layer down and the door above it did not have one, which is why this is a CLI test and not a
/// library one.
///
/// GUARD-DELETION: remove the `usize::checked_add(v, 3).is_none()` arm from the `f` directive in
/// `acfa-agg.rs` and this goes RED -- exit becomes 101 and stdout becomes `undefended 0`.
#[test]
fn a_fault_bound_that_cannot_do_the_band_arithmetic_is_refused_not_a_panic() {
    let body = "6b31 0000000000010000\n6b32 0000000000010000\n6b33 0000000000010000\n";
    for f in [usize::MAX, usize::MAX - 1, usize::MAX - 2] {
        let (code, out, err) = run(&format!("rule krum\nf {f}\n{body}"));
        assert_eq!(
            code, 2,
            "f = {f} must be refused as unreadable input, not panic; got exit {code}, \
             stdout {out:?}"
        );
        assert!(
            out.is_empty(),
            "a refused request must print NOTHING to stdout -- a caller reading a token here \
             would attach it to a dead process; got {out:?}"
        );
        assert!(
            err.contains("fault bound"),
            "the refusal must name the field so the operator knows what to change; got {err:?}"
        );
    }
}

/// The accepting twin: the largest `f` that CAN do the band arithmetic is still accepted by the
/// parser, so the refusal above is a boundary and not a blanket ban on large values.
#[test]
fn the_largest_fault_bound_that_can_do_the_band_arithmetic_is_still_parsed() {
    let body = "6b31 0000000000010000\n6b32 0000000000010000\n6b33 0000000000010000\n";
    let (code, out, err) = run(&format!("rule krum\nf {}\n{body}", usize::MAX - 3));
    assert_ne!(
        code, 2,
        "f = usize::MAX - 3 must clear the PARSE guard; stderr {err:?}"
    );
    assert_ne!(code, 101, "and must certainly not panic");
    // n = 3 is far below f + 3, so this lands in the documented select-all band.
    assert!(
        out.starts_with("undefended"),
        "expected the select-all token for n far below f+3, got {out:?}"
    );
}
