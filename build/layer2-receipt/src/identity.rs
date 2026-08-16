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

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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

/// Verify a detached signature. Returns false on every failure mode -- malformed key,
/// malformed signature, wrong signer -- because a caller that distinguishes them tends
/// to leak which one occurred.
pub fn verify(pk: &PubKey, msg: &[u8], sig: &Sig) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

/// The signed-contribution message.
///
/// DOMAIN SEPARATION IS LOAD-BEARING AND THE ROUND IS INSIDE THE SIGNATURE. Without
/// the round, a signature harvested in round r replays in round r+1 as a fresh
/// contribution the victim never made. Without the `ACFA-CONTRIB` tag, a signature
/// produced for any other purpose by the same key could be replayed as a contribution.
pub fn contrib_msg(rnd: u64, tensor_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(13 + 8 + 1 + 32);
    m.extend_from_slice(b"ACFA-CONTRIB|");
    m.extend_from_slice(&rnd.to_be_bytes());
    m.push(b'|');
    m.extend_from_slice(tensor_hash);
    m
}

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
        let m = contrib_msg(7, &h(&enc_tensor(&[1, 2, 3])));
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
        let s = a.sign(&contrib_msg(7, &th));
        assert!(verify(&a.public(), &contrib_msg(7, &th), &s));
        assert!(
            !verify(&a.public(), &contrib_msg(8, &th), &s),
            "a round-7 signature must not verify as round 8"
        );
    }

    #[test]
    fn a_mangled_signature_is_refused_rather_than_panicking() {
        let a = id(1);
        let m = contrib_msg(1, &[0u8; 32]);
        let mut s = a.sign(&m);
        s[0] ^= 0xff;
        assert!(!verify(&a.public(), &m, &s));
        assert!(
            !verify(&[0xff; 32], &m, &s),
            "invalid key must return false"
        );
    }
}
