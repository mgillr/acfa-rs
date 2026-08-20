// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Identities, signatures, and the signed-contribution message.
//!
//! Ed25519 (RFC 8032) is used because signing is deterministic: the same key over the
//! same message yields the same 64 bytes on every implementation. A randomised scheme
//! would put a value in the contribution leaf that no other party can reproduce, and
//! the leaf is what the commitment trace commits to.
//!
//! Sybil resistance is NOT provided here. It is delegated to whatever issues the PKI,
//! exactly as the published paper delegates it. A `Pki` full of keys one party minted
//! is a valid `Pki` as far as this module is concerned.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::BTreeMap;

/// Raw 32-byte Ed25519 public key.
pub type PubKey = [u8; 32];
/// Raw 64-byte Ed25519 signature.
pub type Sig = [u8; 64];

/// Identity -> public key. `BTreeMap` so iteration is ordered, which keeps every
/// derived artefact canonical without the caller having to remember to sort.
pub type Pki = BTreeMap<u32, PubKey>;

/// A signing identity.
pub struct Identity {
    pub node_id: u32,
    key: SigningKey,
}

impl Identity {
    /// Build an identity from raw secret bytes.
    ///
    /// There is deliberately no `generate()` here. Key generation needs an entropy
    /// policy that belongs to the deployment, and a convenience generator is exactly
    /// how a test key reaches production.
    pub fn from_secret(node_id: u32, secret: &[u8; 32]) -> Self {
        Identity {
            node_id,
            key: SigningKey::from_bytes(secret),
        }
    }

    pub fn public(&self) -> PubKey {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Sig {
        self.key.sign(msg).to_bytes()
    }
}

/// Is this a public key that can only ever verify signatures somebody actually made?
///
/// Rejects malformed encodings and SMALL-ORDER points. A small-order key accepts the
/// signature `R = identity, S = 0` under the cofactorless equation for a large fraction of
/// messages -- measured here, 5014 acceptances across 8 such keys and 2000 messages -- so
/// registering one in a PKI creates an identity whose signatures nobody needs a secret key
/// to produce. Checked where keys ENTER, because by the time `verify` sees one the damage
/// is a policy decision already made.
pub fn is_usable_pubkey(pk: &PubKey) -> bool {
    match VerifyingKey::from_bytes(pk) {
        Ok(vk) => !vk.is_weak(),
        Err(_) => false,
    }
}

/// Verify a detached signature. Returns false on every failure mode -- malformed key,
/// malformed signature, wrong signer -- because a caller that distinguishes them tends
/// to leak which one occurred.
///
/// USES `verify_strict`, NOT `verify`. The permissive form implements the cofactorless
/// equation, which accepts `R = identity, S = 0` against small-order public keys: measured
/// over 8 order-dividing-8 encodings and 2000 messages, `verify` accepted 5014 of 16000
/// forgeries and `verify_strict` accepted 0. Strict verification also rejects a
/// non-canonical `R`, closing signature malleability at the same point. This costs nothing
/// on the wire -- no signature an honest signer produces is affected, and the
/// cross-architecture fingerprint is unmoved.
pub fn verify(pk: &PubKey, msg: &[u8], sig: &Sig) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

/// The signed-contribution message.
///
/// DOMAIN SEPARATION IS LOAD-BEARING AND THE ROUND IS INSIDE THE SIGNATURE. Without
/// the round, a signature harvested in round r replays in round r+1 as a fresh
/// contribution the victim never made. Without the `ACFA-CONTRIB` tag, a signature
/// produced for any other purpose by the same key could be replayed as a contribution.
///
/// **THE CONTEXT AND THE NODE ID ARE INSIDE THE SIGNATURE FOR THE SAME REASON, AND THEIR
/// ABSENCE WAS A CRITICAL DEFECT (#79).** The v1 preimage was round and tensor hash only, so it
/// never said WHAT the signature was about or WHO wrote it:
///
/// * **Cross-context framing.** Two HONEST contributions by one node, at the same round number,
///   in two different studies, satisfied `EquivProof::valid` — a valid proof of equivocation
///   carrying the victim's own genuine signatures. Reproduced: `convicted = {1}` for a node that
///   behaved perfectly in both. Conviction is permanent and the proof set is grow-only, so there
///   was no path back. A plain RESTART triggered it too: run 2's round 5 is run 1's round 5.
/// * **Cross-context replay.** Contributions lifted verbatim from one study's round into
///   another's verified `Ok` with the population bound met, no key and no tampering required.
/// * **Authorship rested on an invariant, not on the signature.** `node_id` was absent, so "who
///   wrote this" was decided by which key happened to verify — correct only while every door that
///   builds a `Pki` refuses duplicate KEYS. Two doors checked; three did not. Signing `node_id`
///   makes a cloned identity USELESS rather than DANGEROUS, at zero wire cost, and removes the
///   need to enumerate doors for downstream consumers nobody has met.
///
/// The tag moved to `ACFA-CONTRIB2|` so a v1 signature can never be mistaken for a v2 one in
/// either direction.
pub fn contrib_msg(ctx: &Context, rnd: u64, node_id: u32, tensor_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(14 + 32 + 8 + 4 + 32);
    m.extend_from_slice(b"ACFA-CONTRIB2|");
    m.extend_from_slice(ctx);
    m.extend_from_slice(&rnd.to_be_bytes());
    m.extend_from_slice(&node_id.to_be_bytes());
    m.extend_from_slice(tensor_hash);
    m
}

/// Which signed preimage a signature was made over. See [`Contribution::sig_preimage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PreimageVersion {
    /// v0.3.0 and earlier: `"ACFA-CONTRIB|" || rnd || '|' || tensor_hash`. No context, no node id.
    /// Retained only so old receipts keep verifying; never produced for new contributions.
    V1,
    /// v0.4.0 onward: context and node id inside the signature. The default.
    #[default]
    V2,
}

/// An opaque, caller-defined commitment to WHAT a signature is about.
///
/// **THE PROTOCOL NEVER PARSES THIS.** It commits to it, compares it, and refuses on mismatch.
/// What the 32 bytes MEAN is entirely the caller's business: a study identifier, a mission, a run
/// id, a data feed, a model version, a hash of all of those together. ACFA neither knows nor cares,
/// and that is deliberate -- it is what lets unrelated industries build on this without the
/// protocol acquiring a case for each of them.
///
/// This is the `tie_key` precedent, which is documented as "never interpreted", applied to the one
/// thing that decides whether two signatures are even talking about the same event.
///
/// **THE RULE THAT MAKES IT SAFE, and any future field must meet it: every field of an ACFA signed
/// preimage is FIXED-WIDTH.** Variable-length caller data enters only as a 32-byte hash. With
/// fixed widths the concatenation is injective, so no choice of `ctx` can be made to collide with a
/// different (ctx, round, node, tensor) by re-cutting the byte boundaries -- which is exactly the
/// attack a length-prefixed or delimiter-separated variable field would invite.
///
/// A caller with no notion of context uses `NO_CONTEXT`, and should read its documentation first.
pub type Context = [u8; 32];

/// The v1 signed-contribution message, retained so receipts written before v0.4.0 keep verifying.
///
/// **Never call this for new contributions.** It is the preimage whose missing context and missing
/// node id were the critical defect (#79); it exists here only because the compatibility promise
/// says a receipt written by any released version verifies under every later one, and deleting it
/// would break that promise for every receipt already in the world.
pub fn contrib_msg_v1(rnd: u64, tensor_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(13 + 8 + 1 + 32);
    m.extend_from_slice(b"ACFA-CONTRIB|");
    m.extend_from_slice(&rnd.to_be_bytes());
    m.push(b'|');
    m.extend_from_slice(tensor_hash);
    m
}

/// The all-zero context, for deployments that genuinely have only one.
///
/// **Using this is a decision, not a default.** Two deployments that both use `NO_CONTEXT` are, to
/// this protocol, the same deployment -- which reopens exactly the hole `Context` exists to close:
/// an honest node participating in both becomes permanently convictable by a proof carrying its own
/// genuine signatures. If there is any chance a second study, a second run, or a restart will ever
/// share a round number with this one, do not use it.
pub const NO_CONTEXT: Context = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{enc_tensor, h};

    fn id(n: u32) -> Identity {
        Identity::from_secret(n, &[n as u8; 32])
    }

    #[test]
    fn signing_is_deterministic() {
        let a = id(1);
        let m = b"the same message";
        assert_eq!(a.sign(m), a.sign(m), "Ed25519 must be deterministic");
    }

    #[test]
    fn a_valid_signature_verifies_and_a_foreign_key_does_not() {
        let a = id(1);
        let b = id(2);
        let m = contrib_msg(&NO_CONTEXT, 7, 1, &h(&enc_tensor(&[1, 2, 3])));
        let s = a.sign(&m);
        assert!(verify(&a.public(), &m, &s));
        assert!(!verify(&b.public(), &m, &s), "another key must not verify");
    }

    #[test]
    fn a_signature_does_not_replay_into_another_round() {
        // This is the attack the round-in-message defends. Sign for round 7, then
        // present the same bytes as a round-8 contribution.
        let a = id(1);
        let th = h(&enc_tensor(&[9, 9]));
        let s = a.sign(&contrib_msg(&NO_CONTEXT, 7, 1, &th));
        assert!(verify(
            &a.public(),
            &contrib_msg(&NO_CONTEXT, 7, 1, &th),
            &s
        ));
        assert!(
            !verify(&a.public(), &contrib_msg(&NO_CONTEXT, 8, 1, &th), &s),
            "a round-7 signature must not verify as round 8"
        );
    }

    #[test]
    fn a_mangled_signature_is_refused_rather_than_panicking() {
        let a = id(1);
        let m = contrib_msg(&NO_CONTEXT, 1, 1, &[0u8; 32]);
        let mut s = a.sign(&m);
        s[0] ^= 0xff;
        assert!(!verify(&a.public(), &m, &s));
        assert!(
            !verify(&[0xff; 32], &m, &s),
            "invalid key must return false"
        );
    }
}
