// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! TIER 1 — witnesses for the crypto guards a mutation sweep found unwitnessed.
//!
//! A by-line mutation sweep of 291 guard sites found 111 that no test could distinguish from
//! their mutants. Eleven of those decide whether a signature is trusted, which is the worst
//! class in the tree. The three that made the release RED:
//!
//!   * `identity.rs:82` mutated to `true` makes **`verify()` accept ANY signature whenever the
//!     public key is malformed** — and the whole 149-test suite stayed green, because every
//!     fixture builds keys through `Identity::public()` so no test ever put a malformed key on
//!     the verify path.
//!   * `entry.rs:150-151` short-circuited to `true` means **`EquivProof::valid` never checks
//!     that the accused signatures verify**. A fabricated proof carrying garbage signatures
//!     against a real identity was uncovered end to end — and conviction is the primitive the
//!     entire accountability story rests on.
//!   * `state.rs:329/330` unwitnessed means an unsigned contribution reaching a `State` is
//!     admitted, aggregated and committed.
//!
//! **Every test here is verified to FAIL on its mutant and pass on pristine.** That is the
//! standard the sweep itself set: it found `rust04_argv` passing for a coincidental reason, so
//! "a test exists" is not the bar — "a test that dies when the guard dies" is.
//!
//! THE MALFORMED KEY IS NOT ARBITRARY, AND THE FIRST TWO CANDIDATES WERE WRONG. `[0xFF; 32]`
//! decodes fine. `y = p = 2^255 - 19` LOOKS right -- non-canonical, and `is_usable_pubkey`
//! does return false for it -- but it returns false via `!vk.is_weak()`, NOT via the decode
//! failure, so a test built on it leaves the `Err` arm completely unwitnessed. That was caught
//! by mutating the `Err` arm and observing that the behaviour did not change at all.
//!
//! The value below is a measured one: sweeping 200 000 pseudorandom 32-byte values through
//! `VerifyingKey::from_bytes` showed roughly HALF are rejected (they are not valid curve
//! points), and this is the first such value found. So the `Err` arm is richly reachable, and
//! the earlier belief that it might be unreachable defensive code was itself wrong.
//!
//! The lesson is the one this file exists to enforce: a test that cannot reach the guard it
//! claims to witness is indistinguishable from no test, and only mutating the guard reveals
//! which kind you have.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, is_usable_pubkey, verify, Identity, Pki, PubKey};
use acfa_receipt::{Contribution, EquivProof, State};

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

/// A 32-byte value `VerifyingKey::from_bytes` genuinely REJECTS -- not merely a weak key.
/// Found by sweep, not by construction; see the module note.
fn malformed_pubkey() -> PubKey {
    [
        0x63, 0x96, 0xb3, 0x58, 0x20, 0x31, 0x79, 0x1a, 0x8f, 0x09, 0x35, 0x55, 0x14, 0x0c, 0xa1,
        0x3c, 0x5c, 0xe0, 0x54, 0x51, 0x66, 0xe2, 0x66, 0x9e, 0x9c, 0xde, 0xfd, 0xe9, 0x97, 0xd5,
        0x96, 0xba,
    ]
}

/// **identity.rs:81/82.** A malformed public key must make verification FAIL, not succeed.
///
/// GUARD-DELETION: change `return false` in `verify`'s `let Ok(vk) = ... else` to `return true`
/// and this goes RED. Without it, `verify()` accepts anything at all against a key that does not
/// decode.
#[test]
fn verify_refuses_everything_against_a_malformed_public_key() {
    let pk = malformed_pubkey();
    assert!(
        !is_usable_pubkey(&pk),
        "premise: this key must genuinely fail to decode, or the test cannot reach the guard"
    );
    // A real signature over a real message, offered against the malformed key.
    let id = Identity::from_secret(1, &[1u8; 32]);
    let msg = b"ACFA-CONTRIB|whatever";
    let real_sig = id.sign(msg);
    assert!(
        !verify(&pk, msg, &real_sig),
        "a real signature must not verify against a malformed key"
    );
    assert!(!verify(&pk, msg, &[0u8; 64]), "nor a zero signature");
    assert!(!verify(&pk, msg, &[0xAAu8; 64]), "nor arbitrary bytes");
}

/// **identity.rs:65.** `is_usable_pubkey` must reject a malformed ENCODING, not only a weak key.
/// The weak-key half was already tested; the decode half was not.
///
/// GUARD-DELETION: change `Err(_) => false` to `Err(_) => true` and this goes RED.
#[test]
fn is_usable_pubkey_refuses_a_malformed_encoding() {
    assert!(!is_usable_pubkey(&malformed_pubkey()));
    // Non-vacuity: a genuine key is still usable, so this is not a reject-everything stub.
    let id = Identity::from_secret(1, &[1u8; 32]);
    assert!(is_usable_pubkey(&id.public()));
}

fn signed(id: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd,
        node_id: id.node_id,
        tensor: t.to_vec(),
        sig: id.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &PARAMS_DEFAULT,
            rnd,
            id.node_id,
            &th,
        )),
    }
}

/// **state.rs:329/330.** A contribution whose signature does not verify must not be ADMITTED,
/// even though it is carried. Nothing witnessed the signature half of `admit`'s filter; the
/// neighbouring conviction/PKI exclusions were tested and this was not.
///
/// GUARD-DELETION: remove the `if !c.signature_valid(pki) { continue; }` arm from `State::admit`
/// and this goes RED — the forged contribution is admitted, aggregated and committed.
#[test]
fn admit_excludes_a_contribution_whose_signature_does_not_verify() {
    let a = Identity::from_secret(1, &[1u8; 32]);
    let b = Identity::from_secret(2, &[2u8; 32]);
    let c = Identity::from_secret(3, &[3u8; 32]);
    let pki: Pki = [
        (a.node_id, a.public()),
        (b.node_id, b.public()),
        (c.node_id, c.public()),
    ]
    .into_iter()
    .collect();

    let mut s = State::new();
    s.add_contribution(signed(&a, 1, &[10, 20]));
    s.add_contribution(signed(&b, 1, &[11, 21]));
    // A KNOWN identity, in the PKI, with a signature that is simply wrong.
    s.add_contribution(Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd: 1,
        node_id: c.node_id,
        tensor: vec![99, 99],
        sig: [0u8; 64],
    });

    let admitted = s.admit(1, &pki);
    let ids: Vec<u32> = admitted.iter().map(|x| x.node_id).collect();
    assert!(
        !ids.contains(&c.node_id),
        "a badly-signed contribution must not be admitted, got {ids:?}"
    );
    assert_eq!(
        ids.len(),
        2,
        "and the two honest ones must still be admitted"
    );
    assert_eq!(
        s.c.len(),
        3,
        "premise: all three are CARRIED -- only admission excludes"
    );
}

/// Build a genuinely valid equivocation proof: one signer, one round, two different tensors.
fn real_proof(id: &Identity, rnd: u64) -> EquivProof {
    let h1 = h(&enc_tensor(&[1i64, 2]));
    let h2 = h(&enc_tensor(&[3i64, 4]));
    EquivProof::canonical(
        acfa_receipt::identity::NO_CONTEXT,
        acfa_receipt::identity::PreimageVersion::V2,
        PARAMS_DEFAULT,
        rnd,
        id.node_id,
        (
            h1,
            id.sign(&contrib_msg(
                &acfa_receipt::identity::NO_CONTEXT,
                &PARAMS_DEFAULT,
                rnd,
                id.node_id,
                &h1,
            )),
        ),
        (
            h2,
            id.sign(&contrib_msg(
                &acfa_receipt::identity::NO_CONTEXT,
                &PARAMS_DEFAULT,
                rnd,
                id.node_id,
                &h2,
            )),
        ),
    )
}

/// **entry.rs:147/148.** A proof naming an identity the PKI does not know must be INVALID.
///
/// GUARD-DELETION: change the `else { return false }` on the PKI lookup to fall through to any
/// key and this goes RED.
#[test]
fn an_equivocation_proof_naming_an_unknown_identity_is_invalid() {
    let known = Identity::from_secret(1, &[1u8; 32]);
    let stranger = Identity::from_secret(99, &[99u8; 32]);
    let pki: Pki = [(known.node_id, known.public())].into_iter().collect();

    let p = real_proof(&stranger, 1);
    assert!(
        !p.valid(&pki),
        "a proof accusing an identity outside the PKI must not convict"
    );
    // Non-vacuity: the same construction against a KNOWN identity is valid, so the test is not
    // passing because `real_proof` builds something broken.
    assert!(
        real_proof(&known, 1).valid(&pki),
        "premise: the construction yields a valid proof"
    );
}

/// **entry.rs:150.** The FIRST accused signature must actually verify.
///
/// GUARD-DELETION: short-circuit the first `verify(...)` to `true` and this goes RED — a
/// fabricated proof convicts an honest node.
#[test]
fn an_equivocation_proof_with_a_forged_first_signature_is_invalid() {
    let victim = Identity::from_secret(1, &[1u8; 32]);
    let pki: Pki = [(victim.node_id, victim.public())].into_iter().collect();
    let mut p = real_proof(&victim, 1);
    p.sig1 = [0u8; 64];
    assert!(
        !p.valid(&pki),
        "a proof whose first signature does not verify must not convict an honest node"
    );
}

/// **entry.rs:151.** The SECOND accused signature must actually verify. Separate test from the
/// first: `&&` short-circuits, so a single test can leave one of the two conjuncts unwitnessed.
///
/// GUARD-DELETION: short-circuit the second `verify(...)` to `true` and this goes RED.
#[test]
fn an_equivocation_proof_with_a_forged_second_signature_is_invalid() {
    let victim = Identity::from_secret(1, &[1u8; 32]);
    let pki: Pki = [(victim.node_id, victim.public())].into_iter().collect();
    let mut p = real_proof(&victim, 1);
    p.sig2 = [0xAAu8; 64];
    assert!(
        !p.valid(&pki),
        "a proof whose second signature does not verify must not convict an honest node"
    );
}

/// The framing vector end to end: garbage signatures against a real identity must not convict,
/// through the `State` door rather than by calling `valid` directly.
#[test]
fn a_fabricated_proof_does_not_convict_through_the_state_door() {
    let victim = Identity::from_secret(1, &[1u8; 32]);
    let pki: Pki = [(victim.node_id, victim.public())].into_iter().collect();
    let mut s = State::new();
    let h1 = h(&enc_tensor(&[1i64, 2]));
    let h2 = h(&enc_tensor(&[3i64, 4]));
    s.add_proof(EquivProof::canonical(
        acfa_receipt::identity::NO_CONTEXT,
        acfa_receipt::identity::PreimageVersion::V2,
        PARAMS_DEFAULT,
        1,
        victim.node_id,
        (h1, [0u8; 64]),
        (h2, [1u8; 64]),
    ));
    assert!(
        s.convicted(&pki).is_empty(),
        "64 zero bytes must not convict an honest node"
    );
}
