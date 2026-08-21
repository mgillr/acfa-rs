// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! COMPATIBILITY.md is a PROMISE; this file is the only thing that makes it a FACT.
//!
//! v0.4.0 changed what a signature MEANS (the preimage now binds the context and the node id).
//! `COMPATIBILITY.md` promises that receipts written by v0.3.0 keep decoding and keep verifying
//! forever. Until this file existed that promise was untested in the strongest sense: deleting
//! the `MAGIC_V1` arm from `wire::decode` left **154 tests passing and 0 failing**. A promise no
//! test can falsify is not a guarantee, it is a comment.
//!
//! THE FIXTURES ARE NOT HAND-ROLLED. The first five are the `wire_vectors` example output of the
//! actual `v0.3.0` tag, byte for byte -- diffed against a fresh `git archive v0.3.0` build in the
//! session that added the sixth, and identical including the trailing newline, which is why this
//! file is kept in the generator's exact one-object-per-line shape rather than reformatted.
//! Fixtures written by hand against the CURRENT reading of the old format would only prove that
//! this file agrees with itself -- the same trap the second-author decoder in
//! `golden/decode_wire.py` exists to avoid. These bytes were produced by code that never knew v2
//! would exist.
//!
//! THE SIXTH, `equivocation-proof-v1`, IS THE SAME TAG BUT A DIFFERENT GENERATOR, kept verbatim
//! at `golden/gen_v1_equiv_vector.v030.rs.txt`. It exists because `wire_vectors` never makes a
//! node equivocate, so all five of its vectors carry `proofs = 0` and the v1 branch of
//! `EquivProof::leaf` -- the SECOND `matches!(sig_preimage, V2)` site in `entry.rs` -- was
//! reached by no fixture in this file. MEASURED on the five-vector corpus, immediately before the
//! sixth was added: forcing that second site to `true` left this suite entirely green, 5 passed 0
//! failed, while forcing the FIRST site (the contribution leaf) reddened 3 of those 5. One of two
//! textually identical guards was carrying the whole burden of proof, which is the shape of #81.
//! With the sixth vector present the same second-site mutation reddens 2 of 6 --
//! `the_v1_proof_leaf_alone_reproduces_its_v0_3_0_hash` and
//! `v0_3_0_receipts_still_decode_and_report_v1_signature_semantics` -- and first-site reddens 4 of
//! 6, two of those because the reordered contribution leaves make `decode` refuse the receipt
//! outright rather than because any hash was compared.
//!
//! SCOPE OF THE "REACHED BY NOTHING" CLAIM: it is measured for THIS test binary. A crate-wide
//! before/after was attempted and is NOT reported, because other files in the crate were being
//! edited concurrently and one apparent catch turned out to be someone else's in-flight change to
//! `acfa-verify.rs`, not the mutation -- re-run in isolation, that test passed under the mutant.
//!
//! HONEST LIMIT: this pins the FULL-receipt v1 path. The redacted v1 path (`ACFA-X1`) has its
//! own decode arm and is NOT covered here -- see the `redacted_v1` note at the bottom.

use acfa_receipt::identity::{PreimageVersion, NO_CONTEXT};
use acfa_receipt::wire::{decode, MAGIC_V1, MAGIC_V2};
use acfa_receipt::State;

use serde_json::Value;

/// The name of the one fixture that carries an equivocation proof. Named rather than "the last
/// one" so that appending a seventh vector cannot silently move what these tests are aiming at.
const EQUIV_FIXTURE: &str = "equivocation-proof-v1";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn vectors() -> Vec<Value> {
    let v: Value =
        serde_json::from_str(include_str!("golden/vectors_v1_compat.json")).expect("v1 fixtures");
    v.as_array().expect("array").clone()
}

fn name(v: &Value) -> &str {
    v["name"].as_str().expect("name")
}

fn wire(v: &Value) -> Vec<u8> {
    unhex(v["wire"].as_str().expect("wire"))
}

fn agg_of(v: &Value) -> Option<Vec<i64>> {
    match &v["agg"] {
        Value::Null => None,
        Value::Array(a) => Some(a.iter().map(|x| x.as_i64().expect("i64")).collect()),
        other => panic!("unexpected agg {other:?}"),
    }
}

/// Guard: if these stop being v1 bytes, everything below is testing the wrong thing.
#[test]
fn the_fixtures_really_are_v0_3_0_v1_receipts() {
    let vs = vectors();
    assert_eq!(vs.len(), 6, "expected the six v0.3.0 wire vectors");

    // A GATE THAT MUST REFUSE AT ZERO. Every test below iterates the vector list, so a corpus
    // that lost its only proof-carrying fixture would go on passing while covering strictly
    // less -- the loops over `r.proofs` would simply run zero times. This is the assertion that
    // notices, and it is why it lives in the same test as the magic check rather than beside
    // the code it protects.
    let with_proofs = vs
        .iter()
        .filter(|v| v["proofs"].as_u64().expect("proofs") > 0)
        .count();
    assert_eq!(
        with_proofs, 1,
        "expected exactly one fixture carrying an equivocation proof; got {with_proofs}. \
         At zero, the v1 branch of `EquivProof::leaf` is reached by nothing in this file and \
         its guard is unwitnessed -- which is the state this corpus was in before #106."
    );
    assert!(
        vs.iter().any(|v| name(v) == EQUIV_FIXTURE),
        "the proof-carrying fixture is no longer called {EQUIV_FIXTURE}"
    );

    for v in &vs {
        let b = wire(v);
        assert_eq!(
            &b[..8],
            &MAGIC_V1[..],
            "{} is not an ACFA-R1 receipt -- these fixtures must be the OLD format, or this \
             file proves nothing about compatibility",
            name(v)
        );
    }
}

#[test]
fn v0_3_0_receipts_still_decode_and_report_v1_signature_semantics() {
    for v in vectors() {
        let n = name(&v).to_string();
        let r = decode(&wire(&v)).unwrap_or_else(|e| panic!("{n} failed to decode: {e:?}"));
        assert_eq!(r.round, v["round"].as_u64().expect("round"), "{n}");
        assert_eq!(r.f as u64, v["f"].as_u64().expect("f"), "{n}");
        assert_eq!(
            r.contributions.len() as u64,
            v["contribs"].as_u64().expect("contribs"),
            "{n}"
        );
        assert_eq!(
            r.proofs.len() as u64,
            v["proofs"].as_u64().expect("proofs"),
            "{n}: the number of equivocation proofs decoded off the wire moved"
        );
        // RECOMPUTED FROM THE ENTRIES, NOT READ BACK OFF THE WIRE.
        //
        // This compared `r.claimed_state_root` -- a field `wire::decode` PARSED OFF THE BYTE
        // STREAM -- against the fixture's recorded hex. That proves the parse offset is right
        // and NOTHING about reproduction: `State::root` and every v1 leaf derivation could be
        // broken outright and this still passed, because both sides of the comparison came from
        // the same bytes. I cited it as proof that v0.3.0 state roots "reproduce byte for byte",
        // which is a stronger claim than the assertion supported.
        //
        // Rebuilding the state from the decoded entries and rooting it exercises the v1 leaf
        // path, so it fails if `Contribution::leaf` or `EquivProof::leaf` stops hashing a v1
        // entry the v1 way.
        let mut rebuilt = State::new();
        for c in &r.contributions {
            rebuilt.add_contribution(c.clone());
        }
        for p in &r.proofs {
            rebuilt.add_proof(p.clone());
        }
        assert_eq!(
            hexs(&rebuilt.root()),
            v["state_root"].as_str().unwrap(),
            "{n}: the state root RECOMPUTED from the decoded entries does not match the one \
             this receipt published -- the v1 leaf derivation has moved"
        );
        assert_eq!(
            hexs(&r.claimed_state_root),
            hexs(&rebuilt.root()),
            "{n}: the carried root and the recomputed root disagree"
        );
        assert_eq!(
            hexs(&r.claimed_output_root),
            v["output_root"].as_str().unwrap(),
            "{n} output root moved"
        );
        assert_eq!(r.claimed_aggregate, agg_of(&v), "{n} aggregate moved");

        // A v1 receipt has no context, and must be MARKED as v1 rather than merely defaulting
        // to an empty context -- otherwise NO_CONTEXT becomes a silent v1-signature downgrade.
        assert_eq!(r.ctx, NO_CONTEXT, "{n}");
        for c in &r.contributions {
            assert_eq!(
                c.sig_preimage,
                PreimageVersion::V1,
                "{n} contribution not marked v1"
            );
            assert_eq!(c.ctx, NO_CONTEXT, "{n}");
        }
        // The proof half of the same claim. `wire::decode` stamps `sig_preimage` onto proofs
        // from the same magic-derived variable it uses for contributions, so this looks like a
        // duplicate of the loop above -- it is not, because the two are read by DIFFERENT
        // dispatch sites (`Contribution::leaf` / `EquivProof::leaf`, `signature_valid` /
        // `valid`) and only the contribution ones had a fixture reaching them.
        for p in &r.proofs {
            assert_eq!(
                p.sig_preimage,
                PreimageVersion::V1,
                "{n} proof not marked v1 -- its leaf would be hashed the v2 way and its two \
                 signatures checked under the v2 preimage, un-convicting a node on real evidence"
            );
            assert_eq!(p.ctx, NO_CONTEXT, "{n} proof carries a context");
        }
    }
}

/// The load-bearing one: v1 signatures must still VERIFY, not merely survive decoding.
#[test]
fn v0_3_0_signatures_still_verify_under_the_v1_preimage() {
    let mut checked = 0;
    let mut proofs_checked = 0;
    for v in vectors() {
        let n = name(&v).to_string();
        let r = decode(&wire(&v)).expect("decode");
        for c in &r.contributions {
            assert!(
                c.signature_valid(&r.pki),
                "{n}: a signature written by v0.3.0 no longer verifies -- COMPATIBILITY.md is broken"
            );
            checked += 1;
        }
        // CONVICTION PERMANENCE, not merely signature permanence. `EquivProof::valid` has its
        // own V1/V2 preimage dispatch, separate from `Contribution::signature_valid`, and the
        // comment on that dispatch records it once being absent -- a v0.3.0 receipt carrying a
        // genuine conviction decoded, reproduced its root, and then failed to validate, which
        // silently un-convicts a node on evidence it published. No fixture reached that arm
        // until this one existed.
        for p in &r.proofs {
            assert!(
                p.valid(&r.pki),
                "{n}: an equivocation proof written by v0.3.0 no longer validates -- a node \
                 this receipt convicted has been silently un-convicted"
            );
            proofs_checked += 1;
        }
    }
    assert_eq!(
        checked, 17,
        "expected all 17 v1 contribution signatures to be exercised, got {checked}"
    );
    assert_eq!(
        proofs_checked, 1,
        "expected the one v1 equivocation proof to be exercised, got {proofs_checked}; at zero \
         this test says nothing about `EquivProof::valid`'s v1 arm"
    );
}

/// THE WITNESS FOR THE SECOND `matches!(sig_preimage, V2)` SITE, in isolation (#106).
///
/// `v0_3_0_receipts_still_decode_and_report_v1_signature_semantics` already reddens if the proof
/// leaf moves, because it re-roots the whole rebuilt state. But that root mixes six contribution
/// leaves with one proof leaf, so it cannot say WHICH derivation moved, and its failure message
/// points at the contribution path that has always been covered. This test roots a state holding
/// the proof and NOTHING ELSE, so the only input to the number below is `EquivProof::leaf`.
///
/// PROVENANCE OF THE PINNED ROOT. It is not an independent v0.3.0 publication -- v0.3.0 published
/// the root of the FULL state, which is asserted separately. It is the single-proof root measured
/// from this tree, and it is only trustworthy because the full-state root it participates in
/// matches the value the v0.3.0 build wrote into the receipt: a wrong proof leaf here would have
/// to be compensated by an equal and opposite error in the contribution leaves or in
/// `merkle_root` to leave that full root intact.
#[test]
fn the_v1_proof_leaf_alone_reproduces_its_v0_3_0_hash() {
    let v = vectors()
        .into_iter()
        .find(|x| name(x) == EQUIV_FIXTURE)
        .expect("the proof-carrying fixture");
    let r = decode(&wire(&v)).expect("decode");
    assert_eq!(
        r.proofs.len(),
        1,
        "this test is written for exactly one proof; with zero it would pass vacuously"
    );

    let mut only_proof = State::new();
    only_proof.add_proof(r.proofs[0].clone());
    assert_eq!(
        hexs(&only_proof.root()),
        "13bec5eceeeaa8725be6079694be3ec266e7beafcabce8e5b7ca97def9f5ac8a",
        "the v1 equivocation proof's leaf has moved -- `EquivProof::leaf` is folding the \
         context and round params into an entry that was signed before either existed"
    );
}

/// NEGATIVE CONTROL for the claim in `wire.rs` that distinct magics keep v2 rules off v1 bytes.
///
/// Relabel a genuine v0.3.0 receipt as `ACFA-R2` and it must NOT quietly verify. Without this,
/// "the magics make it a decode dispatch" is an assertion about intent, not about behaviour.
#[test]
fn a_v1_receipt_relabelled_as_v2_does_not_silently_verify() {
    let v = vectors()
        .into_iter()
        .find(|x| name(x) == "three-contribs")
        .expect("vector");
    let mut b = wire(&v);
    b[..8].copy_from_slice(&MAGIC_V2[..]);

    match decode(&b) {
        // Preferred: the length shift from the absent 32-byte ctx makes this structurally invalid.
        Err(_) => {}
        // If it DOES parse, the signatures must fail -- v2 rules applied to v1 bytes must never
        // produce a receipt that looks honestly signed.
        Ok(r) => {
            let any_valid = r.contributions.iter().any(|c| c.signature_valid(&r.pki));
            assert!(
                !any_valid,
                "a v0.3.0 receipt relabelled ACFA-R2 produced VALID-looking v2 signatures -- \
                 the magic dispatch is not actually separating the two signature meanings"
            );
        }
    }
}

fn hexs(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// redacted_v1: `MAGIC_REDACTED_V1` has its own decode arm and no v0.3.0 fixture here, because
// the v0.3.0 `wire_vectors` example emits full receipts only. That arm remains uncovered and is
// recorded as such rather than assumed safe.

/// GUARD-DELETION: point the CLI's file fast-path back at `wire::MAGIC` and this goes RED.
///
/// The library kept the v1 promise and the BINARY broke it, which is the worse of the two: an
/// operator handed "UNPARSEABLE -- truncated" on a complete, valid archive concludes the archive
/// is corrupt. Measured on a genuine v0.3.0 receipt before the fix: the file path reported
/// truncated while THE SAME BYTES ON STDIN reported state root 529a1232....
///
/// The test drives BOTH paths and requires them to agree, because agreement is the actual
/// invariant -- a sniff that rejects everything would pass a file-path-only assertion.
#[test]
fn a_v1_receipt_reads_identically_from_a_file_and_from_stdin() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let v = vectors()
        .into_iter()
        .find(|x| name(x) == "three-contribs")
        .expect("vector");
    let bytes = wire(&v);
    assert_eq!(
        &bytes[..8],
        &MAGIC_V1[..],
        "this fixture must be a v1 receipt"
    );

    let dir = std::env::temp_dir().join(format!("acfa-v1-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v1.receipt");
    std::fs::write(&path, &bytes).unwrap();

    let from_file = Command::new(env!("CARGO_BIN_EXE_acfa-verify"))
        .arg(&path)
        .output()
        .unwrap();
    let mut ch = Command::new(env!("CARGO_BIN_EXE_acfa-verify"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ch.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
    let from_stdin = ch.wait_with_output().unwrap();

    let f_out = String::from_utf8_lossy(&from_file.stdout).to_string();
    let f_err = String::from_utf8_lossy(&from_file.stderr).to_string();
    let s_out = String::from_utf8_lossy(&from_stdin.stdout).to_string();

    assert!(
        !f_err.contains("UNPARSEABLE"),
        "a complete v0.3.0 receipt read FROM A FILE was reported unparseable: {f_err}"
    );
    assert!(
        f_out.contains("529a12326ab7ed66544f7b2eed1a4c2cfa3f4ef913a062395db6d08aa56a39ac"),
        "the file path must report the receipt's own state root: {f_out}{f_err}"
    );
    assert_eq!(
        f_out, s_out,
        "the same bytes must read identically from a file and from stdin"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
