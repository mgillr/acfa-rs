// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! rust-08. The withholding mitigation this project documents in THREE places was not
//! implementable with the shipped verifier: there was no way to supply an expected root.
//!
//! `SECURITY.md`, `layer2-receipt/src/lib.rs` and `acfa-verify`'s own closing note all tell
//! the operator to "compare the state root against an independently obtained one". The tool
//! accepted `--pki`, `--f`, `--rule` and `--require-bound`, and nothing else. Advice a tool
//! gives and cannot accept is not a mitigation -- it is a sentence.
//!
//! This is the ONLY check that addresses withholding. Verification proves the issuer computed
//! honestly over the set it SHOWED; it can never prove the set was complete, because a
//! withheld entry leaves no trace in the receipt that omits it. The root has to come from
//! somewhere else, so the tool has to accept one from somewhere else.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(receipt: &[u8], args: &[&str]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_acfa-verify"));
    for a in args {
        c.arg(a);
    }
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn acfa-verify");
    // A BROKEN PIPE HERE IS THE TEST PASSING, NOT AN ERROR.
    //
    // Two of these cases are refused during ARGUMENT PARSING -- a malformed
    // `--expect-state-root` and an unknown option -- so the child exits 2 without ever
    // reading stdin. That is the CORRECT behaviour and the desirable one: a verifier should
    // not swallow an arbitrarily large receipt it has already decided to reject. The pipe
    // then closes while this thread is still writing into it.
    //
    // The original `.expect("write")` made that a panic, so the test asserted a contract the
    // binary should not honour. Measured on the shipped tree with cargo's default
    // parallelism: 9 of 12 runs red, 0 of 12 serially -- and `ci.yml` passes no
    // `--test-threads`, so main was intermittently red from the moment rust-08 landed.
    // Under load the child wins the race more often, which is why parallelism changes the
    // rate and not the mechanism.
    //
    // Any OTHER write error still fails loudly.
    if let Err(e) = child.stdin.as_mut().expect("stdin").write_all(receipt) {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe,
            "unexpected error writing the receipt to the child: {e}"
        );
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// Fixture inlined rather than added as a shared `mod`: this crate is not mine and a new
// shared module is a wider change than the finding needs.
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{encode, Contribution, Receipt, Rule, State};

/// Krum at `f = 1` on this build's fixed-point scale.
///
/// A NAMED FIXTURE, NOT A DEFAULT. A contribution signed under different round parameters is
/// filtered out of the round by `Receipt::issue`, exactly as a foreign `ctx` is, so a test that
/// needs other parameters has to say so rather than inherit these silently.
const PARAMS_DEFAULT: acfa_receipt::RoundParams = acfa_receipt::RoundParams {
    rule: acfa_receipt::Rule::Krum,
    f: 1,
    frac_bits: acfa_receipt::FRAC_BITS,
};

fn built() -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        let t = vec![10 + k as i64, 20];
        let sig = id.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &PARAMS_DEFAULT,
            1,
            id.node_id,
            &h(&enc_tensor(&t)),
        ));
        s.deliver(
            Contribution {
                ctx: acfa_receipt::identity::NO_CONTEXT,
                sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
                params: PARAMS_DEFAULT,
                rnd: 1,
                node_id: id.node_id,
                tensor: t,
                sig,
            },
            &pki,
        );
    }
    let r = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        1,
        Rule::Krum,
    );
    (r, pki)
}

fn receipt_bytes() -> Vec<u8> {
    encode(&built().0)
}

fn state_root_hex() -> String {
    built()
        .0
        .claimed_state_root
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Written once into a per-test temp directory. NOT a shared fixed path: two tests in one
/// binary run in parallel threads, and `require_bound_spellings.rs` is measurably flaky
/// (3 failures in 30 runs) precisely because it writes `pki.txt` to one fixed location.
fn pki_file() -> String {
    let (_, pki) = built();
    let dir = std::env::temp_dir().join(format!("acfa-rust08-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let p = dir.join(format!("pki-{:?}.txt", std::thread::current().id()));
    let mut t = String::new();
    for (id, key) in &pki {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        t.push_str(&format!("{id} {hex}\n"));
    }
    std::fs::write(&p, t).expect("write pki");
    p.to_string_lossy().to_string()
}

/// The guard: a root that does not match the receipt is REFUSED, and refused at exit 1
/// rather than folded into "unparseable".
#[test]
fn a_mismatched_expected_root_is_refused() {
    let (bytes, pki) = (receipt_bytes(), pki_file());
    let zero = "0".repeat(64);
    let (code, _, err) = run(
        &bytes,
        &[
            &format!("--pki={pki}"),
            "--f=1",
            &format!("--expect-state-root={zero}"),
        ],
    );
    assert_eq!(
        code, 1,
        "a mismatched root must exit 1 (invalid), got {code}"
    );
    assert!(
        err.contains("STATE ROOT MISMATCH"),
        "the operator must be told which check failed: {err}"
    );
    assert!(
        err.contains(&zero) && err.contains(&state_root_hex()),
        "both roots must be printed so the operator can see WHICH differs: {err}"
    );
}

/// POSITIVE CONTROL. A check that refuses every root would pass the test above perfectly.
#[test]
fn the_receipts_own_root_is_accepted_and_reported() {
    let (bytes, pki) = (receipt_bytes(), pki_file());
    let (code, out, _) = run(
        &bytes,
        &[
            &format!("--pki={pki}"),
            "--f=1",
            &format!("--expect-state-root={}", state_root_hex()),
        ],
    );
    assert_eq!(code, 0, "the receipt's own root must verify: {out}");
    assert!(
        out.contains("MATCHES"),
        "a silent pass is indistinguishable from the flag being ignored: {out}"
    );
}

/// The flag must be OPTIONAL and must not change any existing verdict.
#[test]
fn omitting_the_flag_leaves_the_verdict_untouched() {
    let (bytes, pki) = (receipt_bytes(), pki_file());
    let (code, out, _) = run(&bytes, &[&format!("--pki={pki}"), "--f=1"]);
    assert_eq!(code, 0);
    assert!(out.contains("VERIFIED"));
    assert!(
        !out.contains("MATCHES"),
        "the match note must appear only when a root was supplied"
    );
}

/// A malformed value is REFUSED, not compared. A root that cannot match anything would
/// otherwise report WITHHOLDING for a typo -- the same reasoning as `--require-bound=false`.
#[test]
fn a_root_that_is_not_32_bytes_of_hex_is_refused_rather_than_compared() {
    let (bytes, pki) = (receipt_bytes(), pki_file());
    for bad in ["deadbeef", "", &"g".repeat(64), &"0".repeat(63)] {
        let (code, _, err) = run(
            &bytes,
            &[
                &format!("--pki={pki}"),
                "--f=1",
                &format!("--expect-state-root={bad}"),
            ],
        );
        assert_eq!(code, 2, "{bad:?} must be refused as unreadable, got {code}");
        assert!(
            !err.contains("STATE ROOT MISMATCH"),
            "{bad:?} was COMPARED and reported as withholding: {err}"
        );
    }
}

/// A one-character typo in the flag NAME must not be silently ignored -- that is adv-03 /
/// rust-07, where a mistyped `--require-bound` disabled the only security gate at exit 0.
#[test]
fn a_typo_in_the_flag_name_is_refused_not_ignored() {
    let (bytes, pki) = (receipt_bytes(), pki_file());
    let (code, _, err) = run(
        &bytes,
        &[
            &format!("--pki={pki}"),
            "--f=1",
            &format!("--expect-state-roots={}", state_root_hex()),
        ],
    );
    assert_eq!(code, 2, "an unknown option must be refused, got {code}");
    assert!(err.contains("unknown option"), "{err}");
}

/// Withholding beats "self-consistent only". Without `--pki` the tool exits 3, but a root
/// mismatch is a stronger statement than the absence of a policy: this is not the receipt
/// you were promised, whoever signed it.
#[test]
fn a_mismatch_outranks_the_self_consistent_verdict() {
    let bytes = receipt_bytes();
    let (code, _, err) = run(
        &bytes,
        &[&format!("--expect-state-root={}", "0".repeat(64))],
    );
    assert_eq!(
        code, 1,
        "mismatch must exit 1 even with no --pki, got {code}"
    );
    assert!(err.contains("STATE ROOT MISMATCH"), "{err}");
}
