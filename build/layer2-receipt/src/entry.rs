// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The two entry types: a signed contribution, and a self-authenticating proof that
//! an identity equivocated.
//!
//! Both are **content-addressed**: `leaf()` is the identity of the object and is what
//! the commitment trace commits to. Two replicas that saw the same object derive the
//! same leaf without communicating, which is what lets the state be a set rather than
//! a log.

use crate::hash::{enc_tensor, h};
use crate::identity::{contrib_msg, verify, Pki, Sig};

/// A round-tagged, signed contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    pub rnd: u64,
    pub node_id: u32,
    /// Q16.16 fixed-point values. Never floats -- see `acfa-aggregate`.
    pub tensor: Vec<i64>,
    pub sig: Sig,
}

impl Contribution {
    pub fn tensor_hash(&self) -> [u8; 32] {
        h(&enc_tensor(&self.tensor))
    }

    /// Content address.
    ///
    /// THE SIGNATURE IS PART OF THE LEAF, AND THAT IS NOT REDUNDANT. Ed25519
    /// verification does not force the deterministic nonce: a malicious signer can
    /// emit a second, differently-encoded, still-valid signature over the same
    /// message. Including the signature makes those two objects distinct leaves, so
    /// the duplicate is visible in the state rather than silently collapsing into one
    /// entry -- and `admit` can then refuse the identity outright.
    ///
    /// THE `C|` PREFIX IS LOAD-BEARING FOR A RELEASE ASSERT IN ANOTHER MODULE. `State::root`
    /// concatenates the contribution and proof leaf sets and hands them to
    /// `hash::merkle_root`, which REFUSES duplicate leaves (crdt-11: padding duplicates the
    /// sorted maximum, so a duplicate makes the root ambiguous with a larger tree). Each set
    /// is internally unique because both are map keys; the CONCATENATION is duplicate-free
    /// only because `C|` and `P|` keep the two leaf spaces disjoint. A third leaf type
    /// sharing either prefix, or these two prefixes being unified, turns that assert into a
    /// panic in production. If you add a leaf type, give it its own prefix.
    pub fn leaf(&self) -> [u8; 32] {
        let mut b = Vec::with_capacity(2 + 8 + 4 + 32 + 64);
        b.extend_from_slice(b"C|");
        b.extend_from_slice(&self.rnd.to_be_bytes());
        b.extend_from_slice(&self.node_id.to_be_bytes());
        b.extend_from_slice(&self.tensor_hash());
        b.extend_from_slice(&self.sig);
        h(&b)
    }

    /// Does this contribution carry a signature by its claimed author?
    pub fn signature_valid(&self, pki: &Pki) -> bool {
        match pki.get(&self.node_id) {
            None => false,
            Some(pk) => verify(pk, &contrib_msg(self.rnd, &self.tensor_hash()), &self.sig),
        }
    }
}

/// A self-authenticating proof of equivocation: two valid signatures by the same key,
/// in the same round, over different content.
///
/// SELF-AUTHENTICATING MEANS NO TRUST AND NO CONTEXT. Anyone holding the PKI can check
/// it offline, with no access to the state, no quorum, and no appeal to who reported
/// it. That is what makes accountability work without a coordinator: the proof carries
/// its own evidence, so a replica that forwards it cannot be lying, and a replica that
/// suppresses it cannot prevent another from re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivProof {
    pub rnd: u64,
    pub node_id: u32,
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub sig1: Sig,
    pub sig2: Sig,
}

impl EquivProof {
    /// Build the proof in **canonical orientation**.
    ///
    /// Both halves are sorted by `(tensor_hash, signature)` so that two independent
    /// observers of the same equivocation construct byte-identical proofs. Without
    /// this, the same misbehaviour yields two different leaves, the G-Set holds both,
    /// and the state root depends on who noticed first -- which would make the receipt
    /// non-reproducible for the exact event it is meant to record.
    pub fn canonical(rnd: u64, node_id: u32, a: ([u8; 32], Sig), b: ([u8; 32], Sig)) -> Self {
        let (lo, hi) = if (a.0, a.1) <= (b.0, b.1) {
            (a, b)
        } else {
            (b, a)
        };
        EquivProof {
            rnd,
            node_id,
            h1: lo.0,
            h2: hi.0,
            sig1: lo.1,
            sig2: hi.1,
        }
    }

    /// The proof's leaf in the state tree.
    ///
    /// THE `P|` PREFIX IS LOAD-BEARING FOR A RELEASE ASSERT IN ANOTHER MODULE, for the same
    /// reason as `Contribution::leaf`: `State::root` concatenates the two leaf sets and
    /// `hash::merkle_root` refuses duplicates, and the concatenation is duplicate-free only
    /// because `C|` and `P|` keep the spaces disjoint. Do not unify these prefixes, and give
    /// any new leaf type its own.
    pub fn leaf(&self) -> [u8; 32] {
        let mut b = Vec::with_capacity(2 + 8 + 4 + 64 + 128);
        b.extend_from_slice(b"P|");
        b.extend_from_slice(&self.rnd.to_be_bytes());
        b.extend_from_slice(&self.node_id.to_be_bytes());
        b.extend_from_slice(&self.h1);
        b.extend_from_slice(&self.h2);
        b.extend_from_slice(&self.sig1);
        b.extend_from_slice(&self.sig2);
        h(&b)
    }

    /// Valid iff the two contents genuinely differ and BOTH signatures verify under
    /// the accused key for this round.
    ///
    /// The self-pairing rejection is what stops the obvious self-serving forgery: without
    /// it, anyone could take one honest contribution, pair it with itself, and convict an
    /// innocent identity.
    ///
    /// It rejects `(h1, sig1) == (h2, sig2)` -- the SAME ENTRY twice -- and not merely
    /// `h1 == h2`. Ed25519 does not force a deterministic nonce, so a signer can emit two
    /// DISTINCT valid signatures over the SAME contribution message. Those are two distinct
    /// entries by one identity in one round, which is equivocation by the definition
    /// `admit` already enforces (it excludes the identity on leaf uniqueness). Keying the
    /// proof on content alone meant that case produced NO PROOF: the node was excluded and
    /// no record of why was ever formed, so an observer could not distinguish it from a
    /// node that simply went quiet. Widening the predicate to the whole entry keeps the
    /// anti-framing guard exactly as strong -- one entry still cannot convict its own
    /// author -- while making the two-signature case attributable.
    pub fn valid(&self, pki: &Pki) -> bool {
        if self.h1 == self.h2 && self.sig1 == self.sig2 {
            return false;
        }
        let Some(pk) = pki.get(&self.node_id) else {
            return false;
        };
        verify(pk, &contrib_msg(self.rnd, &self.h1), &self.sig1)
            && verify(pk, &contrib_msg(self.rnd, &self.h2), &self.sig2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::collections::BTreeMap;

    fn setup() -> (Identity, Pki) {
        let a = Identity::from_secret(1, &[1u8; 32]);
        let mut pki = BTreeMap::new();
        pki.insert(1u32, a.public());
        (a, pki)
    }

    fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
        let th = h(&enc_tensor(t));
        Contribution {
            rnd,
            node_id: a.node_id,
            tensor: t.to_vec(),
            sig: a.sign(&contrib_msg(rnd, &th)),
        }
    }

    #[test]
    fn a_well_formed_contribution_verifies() {
        let (a, pki) = setup();
        assert!(contrib(&a, 1, &[1, 2, 3]).signature_valid(&pki));
    }

    #[test]
    fn an_identity_absent_from_the_pki_is_refused() {
        let (a, _) = setup();
        assert!(!contrib(&a, 1, &[1]).signature_valid(&BTreeMap::new()));
    }

    #[test]
    fn tampering_with_the_tensor_invalidates_the_signature() {
        let (a, pki) = setup();
        let mut c = contrib(&a, 1, &[1, 2, 3]);
        c.tensor[0] = 99;
        assert!(
            !c.signature_valid(&pki),
            "tensor is covered by the signature"
        );
    }

    #[test]
    fn equivocation_is_provable_and_the_proof_is_orientation_independent() {
        let (a, pki) = setup();
        let c1 = contrib(&a, 5, &[1, 1]);
        let c2 = contrib(&a, 5, &[2, 2]);
        let p = EquivProof::canonical(5, 1, (c1.tensor_hash(), c1.sig), (c2.tensor_hash(), c2.sig));
        let q = EquivProof::canonical(5, 1, (c2.tensor_hash(), c2.sig), (c1.tensor_hash(), c1.sig));
        assert!(p.valid(&pki));
        assert_eq!(p.leaf(), q.leaf(), "observers must derive the same proof");
    }

    #[test]
    fn an_innocent_identity_cannot_be_framed_by_pairing_a_contribution_with_itself() {
        let (a, pki) = setup();
        let c = contrib(&a, 5, &[1, 1]);
        let forged =
            EquivProof::canonical(5, 1, (c.tensor_hash(), c.sig), (c.tensor_hash(), c.sig));
        assert!(!forged.valid(&pki), "h1 == h2 must be refused");
    }

    #[test]
    fn a_proof_cannot_be_moved_to_another_round() {
        let (a, pki) = setup();
        let c1 = contrib(&a, 5, &[1, 1]);
        let c2 = contrib(&a, 5, &[2, 2]);
        let mut p =
            EquivProof::canonical(5, 1, (c1.tensor_hash(), c1.sig), (c2.tensor_hash(), c2.sig));
        assert!(p.valid(&pki));
        p.rnd = 6;
        assert!(!p.valid(&pki), "signatures are bound to their round");
    }
}
