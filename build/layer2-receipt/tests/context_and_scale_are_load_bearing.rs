// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! GUARD-DELETION WITNESSES for the context binding (#79) and the scale binding (#77).
//!
//! WHY THIS FILE EXISTS, stated plainly because it is an indictment of the work it defends.
//! Both features shipped complete -- the preimage binding, the leaf binding, the `Policy` fields,
//! the `Invalid` variants, the `--ctx` flag, the operator diagnostics -- and an independent
//! mutation sweep found that **not one test in the repository could tell any of it from being
//! absent**. Measured: deleting the `ContextMismatch` guard, deleting the `ScaleMismatch` guard,
//! parsing `--ctx` and discarding it, and hardcoding the signed `frac_bits` to the literal `16`
//! at all four binding sites each left the suite at **204 passed, 0 failed**.
//!
//! The cause is a coincidence, and it is the whole lesson: `acfa_aggregate::FRAC_BITS`,
//! `wire::V1_FRAC_BITS` and every fixture in the repository are all **16**, and no fixture had
//! ever set a context. So the features were exercised only at the one point where all their
//! alternatives agree -- structurally the same trap as a cross-format test that passes because
//! two magic constants happen to be equal.
//!
//! Every test below therefore uses a context that is NOT `NO_CONTEXT` and a scale that is NOT
//! this build's `FRAC_BITS`. Each is written so that removing the guard it names makes it fail.

use acfa_receipt::identity::{
    contrib_msg, Identity, Pki, PreimageVersion, RoundParams, NO_CONTEXT,
};
use acfa_receipt::receipt::Invalid;
use acfa_receipt::{Contribution, Policy, Receipt, Rule, State};

/// A real, non-zero context. The point of every fixture here is that it is NOT `NO_CONTEXT`.
const STUDY_A: [u8; 32] = [0xA1; 32];
const STUDY_B: [u8; 32] = [0xB2; 32];

/// A scale this build was NOT compiled at. It must differ from both `FRAC_BITS` and
/// `V1_FRAC_BITS`, which are the two values everything else in the repo uses.
const OTHER_SCALE: u32 = 22;

fn params_at(ctx_scale: u32) -> RoundParams {
    RoundParams {
        rule: Rule::Krum,
        f: 1,
        frac_bits: ctx_scale,
    }
}

fn signed(id: &Identity, ctx: [u8; 32], params: RoundParams, t: &[i64]) -> Contribution {
    let th = acfa_receipt::hash::h(&acfa_receipt::hash::enc_tensor(t));
    Contribution {
        ctx,
        sig_preimage: PreimageVersion::V2,
        params,
        rnd: 1,
        node_id: id.node_id,
        tensor: t.to_vec(),
        sig: id.sign(&contrib_msg(&ctx, &params, 1, id.node_id, &th)),
    }
}

fn deployment(ctx: [u8; 32], params: RoundParams) -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        s.deliver(
            signed(id, ctx, params, &[10 + k as i64, 20 - k as i64]),
            &pki,
        );
    }
    let r = Receipt::issue(&s, ctx, 1, &pki, 1, Rule::Krum);
    (r, pki)
}

/// PREMISE. Without this the tests below could all pass on an empty round.
#[test]
fn the_fixtures_are_not_degenerate() {
    let (r, _) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    assert_eq!(
        r.contributions.len(),
        5,
        "the round must actually carry work"
    );
    assert_ne!(r.ctx, NO_CONTEXT, "a zero context would test nothing");
    assert_ne!(
        OTHER_SCALE,
        acfa_receipt::FRAC_BITS,
        "OTHER_SCALE must differ from this build's scale, or the scale tests are vacuous"
    );
    assert_ne!(
        OTHER_SCALE, 16,
        "OTHER_SCALE must also differ from V1_FRAC_BITS: FRAC_BITS == V1_FRAC_BITS == 16 is \
         exactly the coincidence that made every scale guard unfalsifiable"
    );
}

// --------------------------------------------------------------- the context binding (#79)

/// GUARD-DELETION: remove the `ContextMismatch` block from `Receipt::verify` and this goes RED.
#[test]
fn a_receipt_from_another_study_is_refused_by_name() {
    let (r, pki) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    match r.verify(&Policy::new(pki, 1).about(STUDY_B)) {
        Err(Invalid::ContextMismatch { policy, receipt }) => {
            assert_eq!(policy, STUDY_B);
            assert_eq!(receipt, STUDY_A);
        }
        other => panic!("a foreign-context receipt must be refused BY NAME, got {other:?}"),
    }
}

/// The accepting control. Without it the test above would pass on a verifier that refuses
/// everything, which is the classic way a refusal test proves nothing.
#[test]
fn the_same_receipt_verifies_when_the_context_is_pinned_correctly() {
    let (r, pki) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    r.verify(&Policy::new(pki, 1).about(STUDY_A))
        .expect("a receipt pinned to its OWN context must verify");
}

/// An unpinned policy still accepts it -- `None` means "I am not asking", not "refuse".
#[test]
fn an_unpinned_policy_accepts_any_context() {
    let (r, pki) = deployment(STUDY_B, params_at(acfa_receipt::FRAC_BITS));
    r.verify(&Policy::new(pki, 1))
        .expect("an unpinned checker must not refuse on context");
}

/// The REDACTED door must refuse for the same reason. It was checking pki/f/rule only, so a
/// redacted receipt from another study verified `Ok` where the full one was refused -- on the
/// artefact documented as outliving every other.
#[test]
fn the_redacted_door_also_refuses_a_foreign_context() {
    let (r, pki) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    let red = r.redact();
    match red.verify(&Policy::new(pki.clone(), 1).about(STUDY_B)) {
        Err(Invalid::ContextMismatch { .. }) => {}
        other => panic!("redacted door accepted a foreign context: {other:?}"),
    }
    red.verify(&Policy::new(pki, 1).about(STUDY_A))
        .expect("redacted receipt pinned to its own context must verify");
}

// ----------------------------------------------------------------- the scale binding (#77)

/// GUARD-DELETION: remove the `ScaleMismatch` block from `Receipt::verify` and this goes RED.
#[test]
fn a_receipt_on_another_fixed_point_grid_is_refused_by_name() {
    let (r, pki) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    match r.verify(&Policy::new(pki, 1).at_scale(OTHER_SCALE)) {
        Err(Invalid::ScaleMismatch { policy, receipt }) => {
            assert_eq!(policy, OTHER_SCALE);
            assert_eq!(receipt, acfa_receipt::FRAC_BITS);
        }
        other => panic!("a foreign-scale receipt must be refused BY NAME, got {other:?}"),
    }
}

#[test]
fn the_redacted_door_also_refuses_a_foreign_scale() {
    let (r, pki) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    match r
        .redact()
        .verify(&Policy::new(pki, 1).at_scale(OTHER_SCALE))
    {
        Err(Invalid::ScaleMismatch { .. }) => {}
        other => panic!("redacted door accepted a foreign scale: {other:?}"),
    }
}

/// THE BINDING ITSELF, not merely the comparison. Two contributions identical in every way
/// except the scale they declare must produce DIFFERENT signed preimages and DIFFERENT leaves.
///
/// GUARD-DELETION: hardcode `frac_bits` to `16` in `contrib_msg` and the first assertion goes
/// RED; hardcode it in `Contribution::leaf` and the second does. That mutation survived the
/// entire suite before this test existed, because every fixture in the repo was at 16.
#[test]
fn the_declared_scale_changes_the_preimage_and_the_leaf() {
    let id = Identity::from_secret(1, &[1u8; 32]);
    let th = acfa_receipt::hash::h(&acfa_receipt::hash::enc_tensor(&[1i64, 2]));

    let here = contrib_msg(&STUDY_A, &params_at(acfa_receipt::FRAC_BITS), 1, 1, &th);
    let there = contrib_msg(&STUDY_A, &params_at(OTHER_SCALE), 1, 1, &th);
    assert_ne!(
        here, there,
        "two scales must not share a signed preimage -- if they do, two builds that disagree \
         about what the numbers MEAN still agree about the signature"
    );
    assert_eq!(
        here.len(),
        there.len(),
        "the preimage is fixed-width at every scale"
    );

    let a = signed(&id, STUDY_A, params_at(acfa_receipt::FRAC_BITS), &[1, 2]);
    let mut b = a.clone();
    b.params = params_at(OTHER_SCALE);
    assert_ne!(a.leaf(), b.leaf(), "the scale must be inside the leaf");
}

/// And the rule and fault bound, for the same reason and by the same mutation.
#[test]
fn the_declared_rule_and_bound_change_the_preimage() {
    let th = acfa_receipt::hash::h(&acfa_receipt::hash::enc_tensor(&[1i64, 2]));
    let base = RoundParams {
        rule: Rule::Krum,
        f: 1,
        frac_bits: acfa_receipt::FRAC_BITS,
    };
    let other_rule = RoundParams {
        rule: Rule::Bulyan,
        ..base
    };
    let other_f = RoundParams { f: 2, ..base };

    let m = |p: &RoundParams| contrib_msg(&STUDY_A, p, 1, 1, &th);
    assert_ne!(
        m(&base),
        m(&other_rule),
        "the rule must be inside the signature"
    );
    assert_ne!(
        m(&base),
        m(&other_f),
        "the fault bound must be inside the signature"
    );
}

/// A contribution signed for one scale must not be admitted into a round running another --
/// the signature is over the scale, so it simply does not verify there.
#[test]
fn a_contribution_signed_at_another_scale_does_not_enter_the_round() {
    let ids: Vec<Identity> = (1..=5u32)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (k, id) in ids.iter().enumerate() {
        s.deliver(
            signed(id, STUDY_A, params_at(OTHER_SCALE), &[10 + k as i64, 20]),
            &pki,
        );
    }
    let r = Receipt::issue(&s, STUDY_A, 1, &pki, 1, Rule::Krum);
    assert!(
        r.contributions.is_empty(),
        "contributions declaring a foreign scale must not be carried into this round"
    );
}

// ------------------------------------------------- the encoder's header/entry agreement

/// GUARD-DELETION: remove the two `for` loops from `encode_checked` and this goes RED.
#[test]
fn encode_checked_refuses_a_receipt_that_would_not_decode_to_itself() {
    let (mut r, _) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    acfa_receipt::wire::encode_checked(&r).expect("the honest receipt must encode");

    // One entry disagrees with the header it would be stamped from.
    r.contributions[0].params = params_at(OTHER_SCALE);
    match acfa_receipt::wire::encode_checked(&r) {
        Err(acfa_receipt::WireError::ParamsDisagreeWithHeader { node_id }) => {
            assert_eq!(node_id, r.contributions[0].node_id);
        }
        other => panic!("expected ParamsDisagreeWithHeader, got {other:?}"),
    }
}

/// The reason that guard exists, demonstrated rather than asserted: such a receipt does not
/// survive its own round trip.
#[test]
fn a_disagreeing_receipt_really_does_not_decode_to_itself() {
    let (mut r, _) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    for c in &mut r.contributions {
        c.params = params_at(OTHER_SCALE);
    }
    let bytes = acfa_receipt::wire::encode(&r);
    match acfa_receipt::wire::decode(&bytes) {
        // Either it is refused outright...
        Err(_) => {}
        // ...or it comes back as a DIFFERENT receipt. Both prove the point; silently equal
        // would mean the header/entry disagreement had no consequence and the guard is theatre.
        Ok(back) => assert_ne!(
            back, r,
            "a receipt whose entries disagree with its header must not round-trip unchanged"
        ),
    }
}

// ------------------------------------------------------------------- the --ctx flag itself

/// GUARD-DELETION: make `acfa-verify` parse `--ctx` and discard it (`let ctx_want = None;`) and
/// this goes RED. That mutation previously survived the ENTIRE suite: no test had ever passed
/// `--ctx`, so the pinned branch, the hex validation, the exit-2 refusal and `Policy::about`
/// were all unreachable from the tests. A security switch that silently fails open is exactly
/// the defect `require_bound_spellings.rs` exists to prevent for `--require-bound`.
#[test]
fn the_ctx_flag_actually_pins_the_context() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let (r, pki) = deployment(STUDY_A, params_at(acfa_receipt::FRAC_BITS));
    let dir = std::env::temp_dir().join(format!("acfa-ctx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pki_file = dir.join("pki.txt");
    let mut txt = String::new();
    for (id, pk) in &pki {
        txt.push_str(&format!(
            "{id} {}\n",
            pk.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
    }
    std::fs::write(&pki_file, txt).unwrap();
    let bytes = acfa_receipt::wire::encode(&r);

    let run = |extra: &[&str]| -> (String, String, i32) {
        let mut c = Command::new(env!("CARGO_BIN_EXE_acfa-verify"));
        c.arg(format!("--pki={}", pki_file.display())).arg("--f=1");
        for a in extra {
            c.arg(a);
        }
        let mut ch = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        ch.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
        let o = ch.wait_with_output().unwrap();
        (
            String::from_utf8_lossy(&o.stdout).to_string(),
            String::from_utf8_lossy(&o.stderr).to_string(),
            o.status.code().unwrap_or(-1),
        )
    };

    let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    // Pinned to its OWN context: verifies, and does NOT carry the not-pinned advisory.
    let (out, _, code) = run(&[&format!("--ctx={}", hex(&STUDY_A))]);
    assert_eq!(code, 0, "correctly pinned receipt must verify: {out}");
    assert!(out.contains("VERIFIED"), "{out}");
    assert!(
        !out.contains("pass --ctx to require the event you expect"),
        "a PINNED context must not be flagged as unpinned: {out}"
    );

    // Pinned to a DIFFERENT context: refused. This is the assertion the mutation kills.
    let (out, err, code) = run(&[&format!("--ctx={}", hex(&STUDY_B))]);
    assert_ne!(
        code, 0,
        "a foreign-context receipt must NOT verify: {out}{err}"
    );
    assert!(
        err.contains("different event") || err.contains("context"),
        "the refusal must name the context: {err}"
    );

    // Malformed: refused rather than ignored. An operator who mistypes the context they meant
    // to require must not silently get "accepts anything" back.
    let (_, err, code) = run(&["--ctx=nothex"]);
    assert_eq!(
        code, 2,
        "a malformed --ctx must be refused, not ignored: {err}"
    );

    // Unpinned: still verifies, and DOES carry the advisory -- which proves the assertion in
    // the first case discriminates rather than simply never finding the string.
    let (out, _, code) = run(&[]);
    assert_eq!(code, 0);
    assert!(
        out.contains("pass --ctx to require the event you expect"),
        "an unpinned context must be flagged: {out}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
