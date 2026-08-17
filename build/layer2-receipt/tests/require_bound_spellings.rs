// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `--require-bound` must mean the same thing in every spelling this tool accepts.
//!
//! WHY THIS FILE EXISTS. adv-03 / rust-07 was "a one-character typo disables --require-bound
//! and the tool exits 0". The fix added an unknown-flag guard, and that guard SPLITS ON `=`
//! before comparing, so `--require-bound=true` passes it as a KNOWN option. The consumer was
//! `args.iter().any(|a| a == "--require-bound")` -- an exact match -- so the flag evaluated
//! to FALSE and the only security gate this verifier has was silently not applied.
//!
//! Every OTHER flag on the tool accepts `=`: `flag_value` strips a `name=` prefix, so
//! `--pki=k.txt`, `--f=2` and `--rule=krum` all work. The security switch was the one
//! exception, and it failed OPEN.
//!
//! So the fix for "silently ignores a flag" itself silently ignored a flag. Closing the exact
//! input a finding names while the mechanism stays reachable one keystroke sideways is the
//! shape of eleven fixes reviewed on 2026-08-17; this was one of two that were mine.
//!
//! THE FIXTURE IS BUILT SO THE BOUND IS GENUINELY NOT MET. Krum at f = 1 requires 2f+3 = 5
//! admitted contributions; the room here has FOUR. A test that asserts an exit code on a
//! receipt whose bound is satisfied would pass whether or not the flag is wired to anything,
//! which is the class of check this whole audit exists to eliminate -- so the premise is
//! asserted rather than assumed.
//!
//! Each test writes to its OWN temp subdir. A first version shared one dir and one
//! `pki.txt`, so the two tests raced under parallel `cargo test` and one intermittently
//! read a half-written file -- a flake I introduced, and exactly the kind of
//! non-deterministic failure this project exists to eliminate.

use acfa_receipt::entry::Contribution;
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::wire::encode;
use acfa_receipt::{Receipt, Rule, State};
use std::io::Write;
use std::process::{Command, Stdio};

fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(rnd, &th)),
    }
}

/// A receipt whose population bound is NOT met: four admitted, Krum at f = 1 needs five.
fn under_bound_receipt() -> (Vec<u8>, String) {
    assert_eq!(
        Rule::Krum.required_n(1),
        5,
        "premise: Krum at f=1 requires 2f+3 = 5"
    );

    let ids: Vec<Identity> = (1..=4u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        s.deliver(contrib(id, 1, &[i as i64, 0]), &pki);
    }
    let r = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);

    let mut pki_text = String::new();
    for id in &ids {
        pki_text.push_str(&format!("{} {}\n", id.node_id, hex_of(&id.public())));
    }
    (encode(&r), pki_text)
}

fn hex_of(k: &[u8; 32]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(receipt: &[u8], pki_file: &str, flag: &str) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_acfa-verify"));
    c.arg(format!("--pki={pki_file}"));
    c.arg("--f=1");
    if !flag.is_empty() {
        c.arg(flag);
    }
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn acfa-verify");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(receipt)
        .expect("write receipt");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn every_accepted_spelling_of_require_bound_enforces_the_bound() {
    let dir = std::env::temp_dir().join("acfa-require-bound-spellings-enforce");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let pki_file = dir.join("pki.txt");
    let (receipt, pki_text) = under_bound_receipt();
    std::fs::write(&pki_file, pki_text).expect("write pki");
    let pki_file = pki_file.to_string_lossy().to_string();

    // The premise: with the flag OFF this receipt verifies. If it did not, the assertions
    // below would pass for the wrong reason and prove nothing about the flag.
    let (code, _) = run(&receipt, &pki_file, "");
    assert_eq!(
        code, 0,
        "premise: without --require-bound an under-bound receipt still verifies"
    );

    // Both spellings must refuse. The second is the one that failed open.
    for spelling in ["--require-bound", "--require-bound=true"] {
        let (code, stderr) = run(&receipt, &pki_file, spelling);
        assert_eq!(
            code, 1,
            "{spelling}: the population bound is not met, so this must exit 1 -- \
             a spelling the tool ACCEPTS must not silently disable the check"
        );
        assert!(
            stderr.contains("FAILED --require-bound"),
            "{spelling}: must say which check failed, got {stderr:?}"
        );
    }
}

#[test]
fn a_value_require_bound_does_not_define_is_refused_rather_than_guessed() {
    let dir = std::env::temp_dir().join("acfa-require-bound-spellings-refuse");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let pki_file = dir.join("pki.txt");
    let (receipt, pki_text) = under_bound_receipt();
    std::fs::write(&pki_file, pki_text).expect("write pki");
    let pki_file = pki_file.to_string_lossy().to_string();

    // `--require-bound=false` is NOT read as "off". Guessing that way is a silent security
    // downgrade; guessing the other way ignores what the operator wrote. Refuse instead.
    for bad in [
        "--require-bound=false",
        "--require-bound=0",
        "--require-bound=",
    ] {
        let (code, stderr) = run(&receipt, &pki_file, bad);
        assert_eq!(code, 2, "{bad}: an undefined value must be refused");
        assert!(
            stderr.contains("switch, not a setting"),
            "{bad}: the diagnostic must explain the shape, got {stderr:?}"
        );
    }

    // And the typo that started all of this stays refused.
    let (code, stderr) = run(&receipt, &pki_file, "--require-bounds");
    assert_eq!(code, 2, "the original adv-03 typo must still be refused");
    assert!(stderr.contains("unknown option"));
}
