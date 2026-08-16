// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! End-to-end tests of `acfa-finality` AS A BINARY.
//!
//! Exercising the library would not test the thing that matters here: the exit code is
//! the contract a monitor scripts against, and an exit code is only produced by a
//! process. A halt that reports itself in stdout while exiting 0 would look healthy to
//! every supervisor in the world.

use acfa_finality::wire::{encode_cert, encode_fork};
use acfa_finality::{CertFork, CertTuple, Certificate};
use acfa_receipt::hash::h;
use acfa_receipt::identity::Identity;
use std::io::Write;
use std::process::{Command, Stdio};

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

fn pki_lines(ids: &[u32]) -> String {
    ids.iter()
        .map(|&i| format!("pki {i} {}\n", hex(&ident(i).public())))
        .collect()
}

/// Run the binary on `input`, returning (exit code, stdout).
fn run(input: &str) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_acfa-finality"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn acfa-finality");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn a_clean_run_reports_running_and_exits_zero() {
    let input = format!(
        "f 2\n{}cert {}\ncert {}\n",
        pki_lines(&[1, 2, 3, 4]),
        hex(&encode_cert(&signed(tuple(1, "A"), &[1, 2, 3]))),
        hex(&encode_cert(&signed(tuple(2, "B"), &[1, 2, 3]))),
    );
    let (code, out) = run(&input);
    assert_eq!(code, 0, "clean run must exit 0\n{out}");
    assert!(out.contains("status running"), "{out}");
    assert!(out.contains("last_certified 2"), "{out}");
    assert!(!out.contains("evidence "), "no fork, so no evidence\n{out}");
}

#[test]
fn a_fork_halts_the_run_and_exits_one() {
    // Two VALID certificates for round 2 on conflicting tuples. Neither is malformed --
    // that is the whole point of the construction.
    let input = format!(
        "f 1\n{}cert {}\ncert {}\n",
        pki_lines(&[1, 2, 3, 4]),
        hex(&encode_cert(&signed(tuple(2, "A"), &[1, 2]))),
        hex(&encode_cert(&signed(tuple(2, "B"), &[3, 4]))),
    );
    let (code, out) = run(&input);
    assert_eq!(code, 1, "a fork must exit 1, not 0\n{out}");
    assert!(out.contains("status halted"), "{out}");
    assert!(out.contains("at_round 2"), "{out}");
    assert!(out.contains("reconcile_from"), "{out}");
    assert!(
        out.lines().any(|l| l.starts_with("evidence ")),
        "a halt must publish transferable evidence\n{out}"
    );
}

#[test]
fn published_evidence_is_verifiable_by_a_second_process_that_saw_nothing() {
    // The property the wire format exists for: a node that observed NO certificates can
    // be handed the evidence bytes alone and reach the same halt verdict, without
    // trusting the reporter.
    let input = format!(
        "f 1\n{}cert {}\ncert {}\n",
        pki_lines(&[1, 2, 3, 4]),
        hex(&encode_cert(&signed(tuple(3, "A"), &[1, 2]))),
        hex(&encode_cert(&signed(tuple(3, "B"), &[3, 4]))),
    );
    let (code, out) = run(&input);
    assert_eq!(code, 1);
    let evidence = out
        .lines()
        .find(|l| l.starts_with("evidence "))
        .expect("evidence line")
        .trim_start_matches("evidence ")
        .to_string();

    let relayed = format!("f 1\n{}fork {}\n", pki_lines(&[1, 2, 3, 4]), evidence);
    let (code2, out2) = run(&relayed);
    assert_eq!(
        code2, 1,
        "relayed evidence must halt the recipient too\n{out2}"
    );
    assert!(out2.contains("status halted"), "{out2}");
    assert!(out2.contains("at_round 3"), "{out2}");
}

#[test]
fn evidence_is_refused_when_it_does_not_verify_against_our_own_pki() {
    // Transferable means verifiable BY THE RECIPIENT. A recipient with a different PKI
    // must not adopt a halt on the reporter's word.
    let k = CertFork::canonical(
        signed(tuple(4, "A"), &[1, 2]),
        signed(tuple(4, "B"), &[3, 4]),
    )
    .expect("conflicting");
    // Recipient knows an entirely different room, so no signature verifies.
    let strangers = pki_lines(&[90, 91, 92, 93]);
    let (code, out) = run(&format!(
        "f 1\n{}fork {}\n",
        strangers,
        hex(&encode_fork(&k))
    ));
    assert_eq!(code, 0, "unverifiable evidence must NOT halt us\n{out}");
    assert!(out.contains("status running"), "{out}");
    assert!(out.contains("rejected fork unverifiable"), "{out}");
}

#[test]
fn an_undersigned_certificate_is_rejected_without_halting() {
    // f=2 needs three signatures; this carries two. Refusing it is not a fork.
    let input = format!(
        "f 2\n{}cert {}\n",
        pki_lines(&[1, 2, 3, 4]),
        hex(&encode_cert(&signed(tuple(1, "A"), &[1, 2]))),
    );
    let (code, out) = run(&input);
    assert_eq!(code, 0, "an invalid cert is not a halt\n{out}");
    assert!(out.contains("rejected 1 invalid"), "{out}");
    assert!(out.contains("status running"), "{out}");
}

#[test]
fn malformed_input_exits_two_and_says_nothing_about_finality() {
    // Exit 2 must be distinguishable from exit 1: "I could not read this" and "the
    // timing assumption broke" are not the same fact, and a monitor must not conflate
    // a config typo with a synchrony violation.
    for (label, input) in [
        ("no f directive", "pki 1 00\n".to_string()),
        ("cert before f", format!("cert {}\n", hex(&[0u8; 4]))),
        ("garbage directive", "f 1\nwibble\n".to_string()),
        ("odd-length hex", "f 1\ncert abc\n".to_string()),
        ("short pubkey", "f 1\npki 1 aabb\n".to_string()),
        (
            "undecodable cert",
            format!("f 1\ncert {}\n", hex(b"not a certificate")),
        ),
    ] {
        let (code, out) = run(&input);
        assert_eq!(code, 2, "{label} must exit 2, got {code}\n{out}");
        assert!(
            !out.contains("status "),
            "{label} must not report a finality status\n{out}"
        );
    }
}

#[test]
fn a_duplicate_certificate_is_not_a_fork() {
    // Re-delivery is normal in a gossip network. If the same certificate arriving twice
    // halted the run, the halt signal would be worthless.
    let c = hex(&encode_cert(&signed(tuple(2, "A"), &[1, 2])));
    let input = format!("f 1\n{}cert {c}\ncert {c}\n", pki_lines(&[1, 2, 3, 4]));
    let (code, out) = run(&input);
    assert_eq!(code, 0, "re-delivery must not halt\n{out}");
    assert!(out.contains("status running"), "{out}");
}
