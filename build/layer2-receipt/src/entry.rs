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
use crate::identity::{
    contrib_msg, contrib_msg_v1, verify, Context, Pki, PreimageVersion, RoundParams, Sig,
};

/// A round-tagged, signed contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    /// **Opaque, caller-defined commitment to what this contribution is ABOUT.** Never parsed by
    /// the protocol -- see [`crate::identity::Context`]. It is inside the signature, so a
    /// contribution made for one context cannot be replayed into another, and two honest
    /// contributions in different contexts can no longer be forged into an equivocation proof
    /// against their author (#79).
    pub ctx: Context,
    /// **The arithmetic and robustness parameters this contribution was made under.**
    ///
    /// Inside the signature, so a contribution offered for one rule, fault bound, or fixed-point
    /// scale cannot be presented in a round running another. Carried once in the receipt header
    /// rather than repeated per contribution -- the decoder stamps every entry from it, exactly
    /// as it does for `ctx`.
    pub params: RoundParams,
    /// Which signed preimage this contribution's signature was made over.
    ///
    /// **This exists so the compatibility promise can be kept.** A receipt written by v0.3.0 was
    /// signed over the v1 preimage (round and tensor hash only) and must keep verifying forever.
    /// Rather than infer that from a sentinel `ctx` value -- which would make `NO_CONTEXT` a
    /// silent downgrade surface, accepting v1 signatures wherever a caller legitimately chose no
    /// context -- the version is explicit and the decoder sets it from the wire magic it read.
    ///
    /// Anything constructed in memory is v2. Only `wire::decode` of an `ACFA-R1` receipt produces
    /// v1, and such a contribution can never be mixed into a v2 receipt because the encoder
    /// refuses it.
    pub sig_preimage: PreimageVersion,
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
        let mut b = Vec::with_capacity(2 + 32 + 1 + 4 + 4 + 8 + 4 + 32 + 64);
        b.extend_from_slice(b"C|");
        // THE LEAF IS VERSIONED FOR THE SAME REASON THE SIGNATURE IS, and forgetting that
        // silently broke the v1 promise once. The leaf is what `admit` sorts by and what the
        // state root commits to, so folding `ctx` into a v1 contribution's leaf does two
        // things at once: it REORDERS a v0.3.0 receipt (whose contributions were sorted by
        // the v1 leaf), making it fail the strictly-ascending check, and it CHANGES the state
        // root that receipt already published. A v1 entry must therefore hash the v1 way
        // forever. `NO_CONTEXT` is not a substitute -- 32 zero bytes still change the hash.
        if matches!(self.sig_preimage, PreimageVersion::V2) {
            b.extend_from_slice(&self.ctx);
            b.push(self.params.rule.as_wire());
            b.extend_from_slice(&self.params.f.to_be_bytes());
            b.extend_from_slice(&self.params.frac_bits.to_be_bytes());
        }
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
            Some(pk) => match self.sig_preimage {
                PreimageVersion::V1 => verify(
                    pk,
                    &contrib_msg_v1(self.rnd, &self.tensor_hash()),
                    &self.sig,
                ),
                PreimageVersion::V2 => verify(
                    pk,
                    &contrib_msg(
                        &self.ctx,
                        &self.params,
                        self.rnd,
                        self.node_id,
                        &self.tensor_hash(),
                    ),
                    &self.sig,
                ),
            },
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
    /// The context both accused signatures were made under. A proof can only be formed from two
    /// contributions sharing a context, which is what stops an honest node in two studies from
    /// being convicted by its own genuine signatures (#79).
    pub ctx: Context,
    /// See [`Contribution::sig_preimage`].
    pub sig_preimage: PreimageVersion,
    /// The round parameters both accused signatures were made under. See [`RoundParams`].
    pub params: RoundParams,
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
    pub fn canonical(
        ctx: Context,
        sig_preimage: PreimageVersion,
        params: RoundParams,
        rnd: u64,
        node_id: u32,
        a: ([u8; 32], Sig),
        b: ([u8; 32], Sig),
    ) -> Self {
        let (lo, hi) = if (a.0, a.1) <= (b.0, b.1) {
            (a, b)
        } else {
            (b, a)
        };
        EquivProof {
            ctx,
            // TAKEN FROM THE ENTRIES, NOT HARDCODED. Proof DERIVATION is the seventh dispatch
            // site and it was the one still pinned to V2, so two valid v1 contributions by one
            // node in one round produced NO proof at all: the evidence existed and verified,
            // and the formation path could not build it. `admit` still excluded the identity on
            // leaf uniqueness, so the aggregate was safe -- what was lost was the attributable
            // artefact, which is the thing this system exists to produce.
            sig_preimage,
            params,
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
        let mut b = Vec::with_capacity(2 + 32 + 1 + 4 + 4 + 8 + 4 + 64 + 128);
        b.extend_from_slice(b"P|");
        // Versioned for the same reason as `Contribution::leaf` -- see the comment there.
        if matches!(self.sig_preimage, PreimageVersion::V2) {
            b.extend_from_slice(&self.ctx);
            b.push(self.params.rule.as_wire());
            b.extend_from_slice(&self.params.f.to_be_bytes());
            b.extend_from_slice(&self.params.frac_bits.to_be_bytes());
        }
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
        let msg = |th: &[u8; 32]| -> Vec<u8> {
            match self.sig_preimage {
                // A PROOF MUST BE CHECKED UNDER THE PREIMAGE ITS SIGNATURES WERE MADE OVER, and
                // this arm was missing until it was measured. `valid` called the v2 preimage
                // unconditionally, so a v0.1.0-v0.3.0 receipt carrying a genuine conviction
                // decoded cleanly, reproduced its state root, and then failed to validate the
                // proof -- silently UN-CONVICTING a node on real evidence. Conviction permanence
                // is a core claim of this system, so losing it on a version upgrade is the exact
                // inverse of #79 and just as serious. Contribution::signature_valid always
                // dispatched; this did not, and the two must stay in step.
                PreimageVersion::V1 => contrib_msg_v1(self.rnd, th),
                PreimageVersion::V2 => {
                    contrib_msg(&self.ctx, &self.params, self.rnd, self.node_id, th)
                }
            }
        };
        verify(pk, &msg(&self.h1), &self.sig1) && verify(pk, &msg(&self.h2), &self.sig2)
    }
}

#[cfg(test)]
mod tests {
    /// Krum at `f = 1` on this build's scale. A NAMED fixture, not a default -- `Receipt::issue`
    /// filters contributions whose parameters differ, so a test needing others must say so.
    const PARAMS_DEFAULT: crate::identity::RoundParams = crate::identity::RoundParams {
        rule: crate::resolve::Rule::Krum,
        f: 1,
        frac_bits: acfa_aggregate::FRAC_BITS,
    };

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
            ctx: crate::identity::NO_CONTEXT,
            sig_preimage: crate::identity::PreimageVersion::V2,
            params: PARAMS_DEFAULT,
            rnd,
            node_id: a.node_id,
            tensor: t.to_vec(),
            sig: a.sign(&contrib_msg(
                &crate::identity::NO_CONTEXT,
                &PARAMS_DEFAULT,
                rnd,
                a.node_id,
                &th,
            )),
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
        let p = EquivProof::canonical(
            crate::identity::NO_CONTEXT,
            PreimageVersion::V2,
            PARAMS_DEFAULT,
            5,
            1,
            (c1.tensor_hash(), c1.sig),
            (c2.tensor_hash(), c2.sig),
        );
        let q = EquivProof::canonical(
            crate::identity::NO_CONTEXT,
            PreimageVersion::V2,
            PARAMS_DEFAULT,
            5,
            1,
            (c2.tensor_hash(), c2.sig),
            (c1.tensor_hash(), c1.sig),
        );
        assert!(p.valid(&pki));
        assert_eq!(p.leaf(), q.leaf(), "observers must derive the same proof");
    }

    #[test]
    fn an_innocent_identity_cannot_be_framed_by_pairing_a_contribution_with_itself() {
        let (a, pki) = setup();
        let c = contrib(&a, 5, &[1, 1]);
        let forged = EquivProof::canonical(
            crate::identity::NO_CONTEXT,
            PreimageVersion::V2,
            PARAMS_DEFAULT,
            5,
            1,
            (c.tensor_hash(), c.sig),
            (c.tensor_hash(), c.sig),
        );
        assert!(!forged.valid(&pki), "h1 == h2 must be refused");
    }

    #[test]
    fn a_proof_cannot_be_moved_to_another_round() {
        let (a, pki) = setup();
        let c1 = contrib(&a, 5, &[1, 1]);
        let c2 = contrib(&a, 5, &[2, 2]);
        let mut p = EquivProof::canonical(
            crate::identity::NO_CONTEXT,
            PreimageVersion::V2,
            PARAMS_DEFAULT,
            5,
            1,
            (c1.tensor_hash(), c1.sig),
            (c2.tensor_hash(), c2.sig),
        );
        assert!(p.valid(&pki));
        p.rnd = 6;
        assert!(!p.valid(&pki), "signatures are bound to their round");
    }
}
