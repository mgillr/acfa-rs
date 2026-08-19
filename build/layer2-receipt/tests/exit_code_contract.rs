// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! **The exit code is the machine-readable half of this tool's output, and nothing stood behind
//! it.** These tests pin what each code MEANS.
//!
//! WHY. `acfa-verify` reports twice: prose on stderr for a human, and an exit status for
//! everything else -- CI gates, deploy scripts, `&&` chains, Makefiles. Only the second one
//! scales, and only the second one was unguarded. Mutating the `Err` arm's `ExitCode::from(1)`
//! to `SUCCESS` left the whole 167-test suite GREEN while the binary printed `INVALID` on stderr
//! and returned 0 -- a human at a terminal sees the refusal, every script sees success. That is
//! not a guard that stopped guarding; it is a DIVERGENCE between the two channels, silent
//! precisely where it is automated.
//!
//! THE CONTRACT, enumerated from the binary rather than from a list of line numbers, because line
//! numbers drift and a test pinned to one witnesses nothing after the next refactor:
//!
//! | code | meaning                                    |
//! |------|--------------------------------------------|
//! | 0    | VERIFIED against the identities you supplied |
//! | 1    | INVALID -- the receipt failed the check     |
//! | 2    | OPERATOR ERROR -- bad arguments or unreadable input |
//! | 3    | SELF-CONSISTENT ONLY -- no `--pki`, so nobody's identity was checked |
//!
//! The three distinctions that carry weight, and why each is not merely cosmetic:
//!   0 vs 1 -- verified versus rejected. A forged receipt passing a CI gate.
//!   1 vs 2 -- a bad RECEIPT versus a bad INVOCATION. Different remediation entirely: one means
//!             distrust the issuer, the other means fix your command line. Collapsing them sends
//!             an operator hunting a security incident over a typo, or the reverse.
//!   3 vs 0 -- exit 3 says "I checked this receipt against ITSELF; no identity was verified."
//!             If it ever became 0, a WEAKER claim would be silently promoted to a STRONGER one.
//!
//! CORRECTION TO THIS FILE'S FIRST VERSION, which landed in ac49cc6 and was wrong. That version
//! ranked `3 vs 0` as the most dangerous of the three, on the reasoning that no stderr message
//! contradicts it so a human would not catch it either. **That is false, and I had not read the
//! output before asserting it.** The no-`--pki` path opens with
//!
//!     SELF-CONSISTENT ONLY -- THIS IS NOT A SECURITY VERDICT
//!
//! and then states outright that the identity set is chosen by whoever wrote the receipt, so a
//! forgery built from fresh keys reaches the same result. That is a LOUDER human backstop than
//! the `INVALID` line, not an absent one. The two mutants are symmetric in that respect and the
//! ranking was unfounded.
//!
//! What survives the correction is the reason this file exists: in BOTH cases the human channel
//! still warns and the exit status still lies, so automation is fooled either way. The divergence
//! is the defect; which of the two is "worse" was a claim about output I had not looked at.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{encode, Contribution, Receipt, Rule, State};

const BIN: &str = env!("CARGO_BIN_EXE_acfa-verify");

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("acfa_exit_contract_{tag}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).expect("tmpdir");
    d
}

/// An honest receipt over six identities, plus the PKI file in the format `parse_pki` expects.
fn fixture(d: &Path) -> (PathBuf, PathBuf) {
    let ids: Vec<Identity> = (1..=6u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        let t = vec![100 + k as i64, 200 - k as i64];
        let th = acfa_receipt::hash::h(&acfa_receipt::hash::enc_tensor(&t));
        s.deliver(
            Contribution {
                rnd: 1,
                node_id: id.node_id,
                tensor: t,
                sig: id.sign(&contrib_msg(1, &th)),
            },
            &pki,
        );
    }
    let r = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);

    let rp = d.join("receipt.acfa");
    fs::write(&rp, encode(&r)).expect("write receipt");

    let mut txt = String::from("# ACFA trusted identities: <node_id> <hex public key>\n");
    for id in &ids {
        let hex: String = id.public().iter().map(|b| format!("{b:02x}")).collect();
        txt.push_str(&format!("{} {}\n", id.node_id, hex));
    }
    let pp = d.join("trusted.pki");
    fs::write(&pp, txt).expect("write pki");
    (rp, pp)
}

/// A PKI that is well-formed but belongs to strangers: the receipt decodes, and then fails.
fn foreign_pki(d: &Path) -> PathBuf {
    let mut txt = String::from("# strangers\n");
    for i in 1..=6u32 {
        let id = Identity::from_secret(i, &[(i as u8).wrapping_add(200); 32]);
        let hex: String = id.public().iter().map(|b| format!("{b:02x}")).collect();
        txt.push_str(&format!("{i} {hex}\n"));
    }
    let p = d.join("foreign.pki");
    fs::write(&p, txt).expect("write foreign pki");
    p
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("run acfa-verify");
    let code = out.status.code().expect("process returned no exit code");
    let mut s = String::from_utf8_lossy(&out.stderr).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    (code, s)
}

/// NEGATIVE CONTROL, and every other test here is worthless without it. An exit-status assertion
/// is satisfied trivially by a binary that fails everything, so the suite must first pin that the
/// honest path genuinely SUCCEEDS. If this goes red, the others prove nothing.
#[test]
fn the_honest_path_returns_zero_so_the_other_assertions_are_not_vacuous() {
    let d = dir("honest");
    let (r, p) = fixture(&d);
    let (code, out) = run(&[
        r.to_str().unwrap(),
        "--pki",
        p.to_str().unwrap(),
        "--f",
        "1",
    ]);
    assert_eq!(code, 0, "an honest receipt must verify; got {code}\n{out}");
}

#[test]
fn a_receipt_that_fails_verification_returns_one_not_zero() {
    let d = dir("invalid");
    let (r, _) = fixture(&d);
    let f = foreign_pki(&d);
    let (code, out) = run(&[
        r.to_str().unwrap(),
        "--pki",
        f.to_str().unwrap(),
        "--f",
        "1",
    ]);
    assert_eq!(
        code, 1,
        "a receipt whose identities are not the supplied ones must exit 1; got {code}\n{out}"
    );
}

#[test]
fn a_policy_mismatch_returns_one_not_zero() {
    let d = dir("fmismatch");
    let (r, p) = fixture(&d);
    let (code, out) = run(&[
        r.to_str().unwrap(),
        "--pki",
        p.to_str().unwrap(),
        "--f",
        "99",
    ]);
    assert_eq!(
        code, 1,
        "a receipt asserting a different fault bound must exit 1; got {code}\n{out}"
    );
}

/// **THE DIVERGENCE GUARD.** This is the defect itself, stated as an invariant rather than as a
/// list of constants: the two output channels must never disagree. Whatever the binary tells a
/// human, the status it hands a script must not say the opposite.
#[test]
fn saying_invalid_to_a_human_and_success_to_a_script_is_forbidden() {
    let d = dir("divergence");
    let (r, p) = fixture(&d);
    let f = foreign_pki(&d);
    let cases: Vec<Vec<&str>> = vec![
        vec![
            r.to_str().unwrap(),
            "--pki",
            f.to_str().unwrap(),
            "--f",
            "1",
        ],
        vec![
            r.to_str().unwrap(),
            "--pki",
            p.to_str().unwrap(),
            "--f",
            "99",
        ],
    ];
    let mut saw_invalid = 0;
    for args in &cases {
        let (code, out) = run(args);
        if out.contains("INVALID") {
            saw_invalid += 1;
            assert_ne!(
                code, 0,
                "the binary printed INVALID and exited 0 -- a human sees the refusal and every \
                 script gating on $? sees success. args: {args:?}\n{out}"
            );
        }
    }
    assert!(
        saw_invalid > 0,
        "no case produced INVALID, so this test checked nothing -- the probe must see the \
         condition it is asserting about"
    );
}

/// Exit 3 is a WEAKER claim than exit 0 and must never be reported as the stronger one.
#[test]
fn self_consistent_only_is_reported_distinctly_from_verified() {
    let d = dir("selfcons");
    let (r, _) = fixture(&d);
    let (code, out) = run(&[r.to_str().unwrap(), "--f", "1"]);
    assert_ne!(
        code, 0,
        "without --pki nobody's identity was checked, so 0 would promote a self-consistency \
         check to a verification\n{out}"
    );
    assert_eq!(
        code, 3,
        "the self-consistent band is exit 3; got {code}\n{out}"
    );
    // The human channel must keep saying so too. Asserted rather than assumed: the first version
    // of this file claimed no such message existed, which was wrong and unchecked.
    assert!(
        out.contains("NOT A SECURITY VERDICT"),
        "the self-consistent path must tell a human it is not a verdict, not only encode that in \
         the exit status\n{out}"
    );
}

/// An unusable INVOCATION is not an invalid RECEIPT. Collapsing 2 into 1 sends an operator
/// hunting a forged receipt over a typo; collapsing it into 0 hides the mistake entirely.
#[test]
fn operator_errors_return_two_and_are_distinct_from_both_zero_and_one() {
    let d = dir("operr");
    let (r, p) = fixture(&d);
    let missing = d.join("no-such-file.acfa");
    let cases: Vec<(&str, Vec<&str>)> = vec![
        (
            "unreadable receipt",
            vec![missing.to_str().unwrap(), "--pki", p.to_str().unwrap()],
        ),
        (
            "unreadable pki",
            vec![r.to_str().unwrap(), "--pki", "/nonexistent/x.pki"],
        ),
        (
            "non-integer --f",
            vec![
                r.to_str().unwrap(),
                "--pki",
                p.to_str().unwrap(),
                "--f",
                "wat",
            ],
        ),
        (
            "unknown --rule",
            vec![
                r.to_str().unwrap(),
                "--pki",
                p.to_str().unwrap(),
                "--rule",
                "nonsense",
            ],
        ),
    ];
    for (name, args) in &cases {
        let (code, out) = run(args);
        assert_eq!(
            code, 2,
            "{name}: an operator error must exit 2, distinct from 0 (verified) and 1 (invalid); \
             got {code}\n{out}"
        );
    }
}

/// The four codes must be four DIFFERENT values. Asserting each in isolation would still pass if
/// they all collapsed to the same number, which is the failure this whole file exists to prevent.
#[test]
fn the_four_outcomes_are_four_distinct_codes() {
    let d = dir("distinct");
    let (r, p) = fixture(&d);
    let f = foreign_pki(&d);
    let verified = run(&[
        r.to_str().unwrap(),
        "--pki",
        p.to_str().unwrap(),
        "--f",
        "1",
    ])
    .0;
    let invalid = run(&[
        r.to_str().unwrap(),
        "--pki",
        f.to_str().unwrap(),
        "--f",
        "1",
    ])
    .0;
    let operator = run(&[r.to_str().unwrap(), "--pki", "/nonexistent/x.pki"]).0;
    let selfcons = run(&[r.to_str().unwrap(), "--f", "1"]).0;
    let all = [verified, invalid, operator, selfcons];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(
                    a, b,
                    "outcomes {i} and {j} share exit code {a}: verified={verified} \
                     invalid={invalid} operator={operator} self_consistent={selfcons}"
                );
            }
        }
    }
}
