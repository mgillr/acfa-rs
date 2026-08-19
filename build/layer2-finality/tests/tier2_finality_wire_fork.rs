// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Strict decoding of FORK evidence: trailing bytes, and re-derived orientation.
//!
//! WHY THIS FILE EXISTS. A by-line mutation sweep of `wire.rs` deleted the two guards at
//! the end of `decode_fork` -- the `remaining() != 0` refusal and the
//! `k.a.tuple.id() != a_id` orientation refusal -- and the whole suite stayed GREEN. Both
//! mutants survived. The certificate twin of the first guard (`decode_cert`'s trailing-byte
//! check) *was* witnessed, by `wire::truncation_at_every_offset_is_refused_and_never_panics`,
//! which is exactly the shape of gap that mutation testing exists to find: the property was
//! believed to be covered because its sibling was, and the fork path -- the path that carries
//! evidence between mutually distrusting parties -- was the uncovered one.
//!
//! The orientation guard was worse off. `wire::fork_evidence_transfers_and_is_orientation_canonical`
//! reads like the orientation test, and it is not: every byte string it hands to `decode_fork`
//! came out of `encode_fork`, which only ever emits canonical orientation. It tests that the
//! ENCODER is canonical. Nothing in the suite tested that the DECODER re-derives orientation
//! instead of trusting the order it was handed, so deleting the re-derivation changed no
//! observable behaviour anywhere.
//!
//! WHY IT MATTERS -- ONE VIOLATION, ONE PROOF. `wire.rs`'s third stated rule is "exactly one
//! encoding per logical value", and for a fork that rule IS the security property, not
//! tidiness. Fork evidence is the finality layer's entire claim: a synchrony violation
//! carries its own proof to anyone. A proof is only useful if two parties looking at the same
//! violation are looking at the same object. A decoder that accepts both orientations gives
//! one violation two valid encodings, and then an adversary can show a verifier form X while
//! a third party checks form Y and hash-addresses, dedupe sets, gossip caches, "have I already
//! seen this fork" checks and signed-over digests all silently disagree about whether two
//! copies of one proof are one fact or two. The same argument covers the trailing-byte guard:
//! if `evidence || junk` decodes to the same fork as `evidence`, an adversary can mint
//! unlimited distinct byte strings for one violation at will.
//!
//! Note both guards fail in the ACCEPTING direction -- deleting them makes the decoder accept
//! more, never less. Nothing crashes, no test that feeds it well-formed input notices, and the
//! damage shows up only later as a canonicality argument that is no longer true. That is
//! precisely the class of defect a green suite is worst at catching, and the reason each test
//! below is paired with an accepting twin: a guard is only witnessed if the test distinguishes
//! it from BOTH a deleted guard and a reject-everything stub.
//!
//! HOW THESE TESTS AVOID THE TWO FAILURE MODES THAT ALREADY BIT THIS PROJECT.
//!
//! 1. *Passing for a coincidental reason.* Nothing here asserts `is_err()`. Every refusal is
//!    compared against the exact `WireError` value, payload included. This is load-bearing and
//!    not pedantry: `WireError::NotCanonical` carries a `&'static str` and `get_cert` raises
//!    the SAME variant with a different payload ("signers must ascend strictly") when a signer
//!    list descends. A half-swap done at a wrong byte offset corrupts a signer list and yields
//!    that other `NotCanonical`, so an `is_err()` -- or even a `matches!(.., NotCanonical(_))`
//!    -- assertion would pass while actually exercising `get_cert`'s signer-ordering guard,
//!    witnessing nothing about orientation at all.
//!
//! 2. *Never reaching the named guard.* Both refusals sit at the END of `decode_fork`, behind
//!    magic, version, two full `get_cert` parses and the `NotAFork` conflict check, so a
//!    sloppily built input exits early and the guard is never executed. Each test therefore
//!    asserts its own preconditions before the refusal: the swap test asserts the swapped
//!    bytes are the same LENGTH as the canonical ones (a permutation, not a corruption), that
//!    they DIFFER from them (the two halves are genuinely distinguishable, so the swap is
//!    real), and that the same two certificates in canonical order DO decode (so magic,
//!    version, both parses and the conflict check all pass on this input and the only thing
//!    left to refuse is the orientation).
//!
//! WHAT THESE TESTS DO NOT COVER. They say nothing about whether the decoded evidence is
//! AUTHENTIC -- signatures are never verified here, and `decode_fork` holds no `Pki` and
//! cannot verify them; that is `check`/`verified_signer_keys`/`attributable_verified`
//! territory, and a decoded fork carrying forged signature entries is well-formed by design
//! (see `CertFork::attributable`'s doc on the third door). They do not cover truncation of
//! fork bytes, the fork magic or version fields, the hostile length prefix, or the `NotAFork`
//! conflict predicate -- all of those live in `tests/wire.rs`. They do not test the encoder's
//! choice of canonical orientation, only that the decoder re-derives it independently. And
//! they do not prove the ORDER of the two guards: trailing junk on an already-swapped
//! encoding is deliberately not asserted, because which of the two refusals wins is an
//! implementation detail neither guard's security argument depends on.

use acfa_finality::wire::{decode_fork, encode_cert, encode_fork, WireError};
use acfa_finality::{CertFork, CertTuple, Certificate};
use acfa_receipt::hash::h;
use acfa_receipt::identity::Identity;

const FORK_MAGIC: &[u8; 8] = b"ACFA-K1\0";
const VERSION: u16 = 1;
/// Magic (8) + version (2). `encode_cert` writes its own frame, so its body starts here.
const FRAME: usize = 10;

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

/// Two conflicting round-`r` certificates, already in canonical orientation.
///
/// Built through `CertFork::canonical` rather than by assuming which label hashes lower:
/// orientation is decided by `tuple.id()`, a SHA-256 digest, so which of `left`/`right`
/// ends up as `k.a` is not knowable by reading the test. Deriving it here means the swap
/// below is a genuine swap for every label pair, not a coin flip.
fn canonical_fork(round: u64, left: &str, right: &str) -> CertFork {
    let x = signed(tuple(round, left), &[1, 2]);
    let y = signed(tuple(round, right), &[3, 4]);
    CertFork::canonical(x, y).expect("same round, different tuples: these conflict")
}

/// The two halves of `k` written in the WRONG order, and nothing else changed.
///
/// Assembled from `encode_cert` bodies rather than by slicing `encode_fork` output at a
/// computed offset, so a mis-derived offset cannot silently produce a corrupt-but-plausible
/// buffer that fails for an unrelated reason. Byte-for-byte this is what a second observer
/// would emit if `encode_fork` had trusted arrival order instead of `tuple.id()`.
fn encode_fork_swapped(k: &CertFork) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(FORK_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&encode_cert(&k.b)[FRAME..]);
    out.extend_from_slice(&encode_cert(&k.a)[FRAME..]);
    out
}

// ---------------------------------------------------------------- wire.rs:218-219

#[test]
fn appended_junk_on_fork_evidence_is_refused_as_trailing_bytes() {
    let k = canonical_fork(5, "A", "B");
    let bytes = encode_fork(&k);

    // ACCEPTING TWIN, AND IT IS THE PRECONDITION TOO. The exact same bytes without a suffix
    // must decode to the exact same fork. This is what stops a reject-everything stub from
    // satisfying the assertions below, and it simultaneously proves the refusals that follow
    // are caused by the suffix and by nothing else in the buffer.
    assert_eq!(
        decode_fork(&bytes),
        Ok(k.clone()),
        "precondition: unsuffixed fork evidence must decode"
    );

    // Four suffixes, chosen to defeat four different wrong implementations rather than to
    // repeat one case: a single byte (an off-by-one bound), eight bytes of zeros (a length
    // field a lax parser might read as "no more records"), a whole third certificate body
    // (a parser that reads what it needs and ignores the rest -- the failure mode that
    // matters most, since that is what a streaming decoder does by default), and the fork's
    // own magic (a concatenation attack: two proofs glued together must not decode as one).
    let third = encode_cert(&signed(tuple(5, "C"), &[5, 6]));
    let suffixes: [(&str, Vec<u8>); 4] = [
        ("one stray byte", vec![0x00]),
        ("eight zero bytes", vec![0u8; 8]),
        ("a whole third certificate", third[FRAME..].to_vec()),
        ("a second fork frame", FORK_MAGIC.to_vec()),
    ];

    for (what, suffix) in suffixes {
        let mut junked = bytes.clone();
        junked.extend_from_slice(&suffix);
        assert_eq!(
            decode_fork(&junked),
            Err(WireError::TrailingBytes),
            "fork evidence followed by {what} must be refused as trailing bytes, \
             or one violation has unlimited valid encodings"
        );
    }
}

#[test]
fn a_fork_is_measured_by_what_it_consumes_not_by_a_fixed_length() {
    // ACCEPTING TWIN for the guard above, aimed at the specific wrong fix: `remaining() != 0`
    // is only meaningful if consumption is derived from the two signer counts actually read.
    // A decoder that assumed both halves are the same size -- true of every fork in
    // `tests/wire.rs`, where both halves carry two signers -- would either reject this
    // legitimate evidence or leave bytes unread on it. Lopsided halves are also the realistic
    // case: two disjoint honest groups certifying different cuts need not be the same size.
    let x = signed(tuple(11, "A"), &[1, 2]);
    let y = signed(tuple(11, "B"), &[3, 4, 5, 6, 7]);
    let k = CertFork::canonical(x, y).expect("conflicting tuples");
    let bytes = encode_fork(&k);

    let (small, large) = if k.a.sigs.len() < k.b.sigs.len() {
        (&k.a, &k.b)
    } else {
        (&k.b, &k.a)
    };
    assert_eq!(small.sigs.len(), 2, "precondition: halves are lopsided");
    assert_eq!(large.sigs.len(), 5, "precondition: halves are lopsided");

    assert_eq!(
        decode_fork(&bytes),
        Ok(k),
        "unequal signer counts are legitimate evidence and must decode"
    );
}

// ---------------------------------------------------------------- wire.rs:223-226

#[test]
fn fork_halves_in_non_canonical_order_are_refused_by_the_decoder() {
    // ONE VIOLATION, ONE PROOF. The decoder must re-derive orientation from `tuple.id()`
    // rather than trust the order it was handed. Several label pairs, because which half is
    // canonically first is a SHA-256 outcome: a single pair would exercise only whichever
    // source ordering that digest happened to produce.
    for (round, left, right) in [
        (5, "A", "B"),
        (5, "B", "A"),
        (12, "cut-x", "cut-y"),
        (0, "p", "q"),
    ] {
        let k = canonical_fork(round, left, right);
        let canonical = encode_fork(&k);
        let swapped = encode_fork_swapped(&k);
        let ctx = format!("round {round}, tuples {left}/{right}");

        // PRECONDITIONS -- these are what stop this test from "passing" without ever reaching
        // the orientation guard, which sits behind magic, version, two `get_cert` parses and
        // the `NotAFork` conflict check.
        assert_ne!(
            k.a.tuple.id(),
            k.b.tuple.id(),
            "{ctx}: the two halves must have distinct ids or there is no orientation to get wrong"
        );
        assert_eq!(
            swapped.len(),
            canonical.len(),
            "{ctx}: the swap must be a permutation of the same bytes, not a corruption"
        );
        assert_ne!(
            swapped, canonical,
            "{ctx}: the halves must be distinguishable or the swap is a no-op"
        );
        // The decisive precondition: the SAME two certificates in canonical order decode
        // cleanly, so every earlier check in `decode_fork` passes on this input and the
        // orientation is the only thing left for it to refuse. This is also the ACCEPTING
        // TWIN -- a decoder that refused both orders would fail right here.
        assert_eq!(
            decode_fork(&canonical),
            Ok(k.clone()),
            "{ctx}: canonically oriented evidence must be ACCEPTED"
        );

        // The refusal. Compared against the exact variant AND its payload: `get_cert` raises
        // `NotCanonical("signers must ascend strictly")` for a mangled signer list, so a
        // variant-only assertion would be satisfied by a corrupt buffer that never reached
        // the orientation check at all.
        assert_eq!(
            decode_fork(&swapped),
            Err(WireError::NotCanonical(
                "fork must be written in canonical orientation"
            )),
            "{ctx}: the decoder must RE-DERIVE orientation, not trust the order it was handed"
        );
    }
}

#[test]
fn a_re_encoded_fork_is_the_only_accepted_encoding_of_that_violation() {
    // The property stated end to end, because the two halves of it are what an adversary
    // plays against each other: exactly one byte string decodes to this fork, and it is the
    // one both observers of the violation emit. Feeding the decoder's own output back to
    // `encode_fork` must be a fixed point, and the only other candidate encoding of the same
    // two certificates -- the swap -- must be refused.
    let k = canonical_fork(9, "left", "right");
    let bytes = encode_fork(&k);

    let back = decode_fork(&bytes).expect("canonical evidence decodes");
    assert_eq!(back, k, "decode must reproduce the fork");
    assert_eq!(
        encode_fork(&back),
        bytes,
        "encode(decode(x)) must be a fixed point or the form is not canonical"
    );

    // An observer who saw the halves in the other order still publishes THESE bytes...
    let mirrored = CertFork::canonical(k.b.clone(), k.a.clone()).expect("conflicting tuples");
    assert_eq!(
        encode_fork(&mirrored),
        bytes,
        "two observers of one violation must emit identical evidence"
    );
    // ...and the encoding they would have published had orientation been trusted is refused,
    // so no verifier will ever accept a second form of this proof.
    assert_eq!(
        decode_fork(&encode_fork_swapped(&k)),
        Err(WireError::NotCanonical(
            "fork must be written in canonical orientation"
        )),
        "a second valid encoding of one violation is exactly what canonicality forbids"
    );
}
