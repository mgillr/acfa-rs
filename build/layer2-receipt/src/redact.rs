// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Redacted receipts: full accountability, zero plaintext.
//!
//! **THE DEFECT THIS CLOSES.** A receipt carries every participant's raw update. That is what
//! makes it independently re-executable, and it is also why the audit artefact cannot be shown
//! to anyone the participants do not already trust with their gradients -- fatal for exactly
//! the regulated, cross-institution deployments the design is aimed at. An external review put
//! it plainly: the artefact ships all participants' vectors in the clear.
//!
//! **WHAT MAKES REDACTION LOSSLESS HERE, AND IT IS NOT A DESIGN CHOICE WE GET TO MAKE -- IT IS A
//! PROPERTY THE CRYPTO ALREADY HAD.** Two facts, both checkable in `entry.rs`:
//!
//!   * a contribution's signature is over `contrib_msg(rnd, tensor_hash)` -- the HASH, never the
//!     tensor. So authentication survives dropping the tensor, exactly, with no weakening.
//!   * `leaf()` is `h("C|" || rnd || node_id || tensor_hash || sig)` -- also only the hash. So
//!     the Merkle state root over those leaves is bit-identical after redaction.
//!
//! and `EquivProof` was already plaintext-free: `(rnd, node_id, h1, h2, sig1, sig2)`. Conviction
//! -- the whole accountability story -- never needed a gradient in the first place.
//!
//! So a redacted receipt still establishes, at FULL strength: every carried contribution is
//! genuinely signed by its claimed author; the state root commits to exactly this set; who was
//! admitted and who was excluded; and who equivocated, with the proof. What it CANNOT do is
//! re-execute the aggregate, because that genuinely needs the vectors.
//!
//! **WHAT THIS IS NOT, STATED HERE SO IT CANNOT BE MISREAD DOWNSTREAM.** This is redaction. It
//! is NOT secure aggregation and it is NOT differential privacy, and it must never be described
//! as either.
//!
//!   * It gives no formal privacy guarantee. It withholds the vectors from the ARTEFACT; it says
//!     nothing about what the aggregator itself saw, and the aggregator saw everything.
//!   * `tensor_hash` is a commitment, not a hiding one. A recipient who can guess a plausible
//!     update can confirm it by hashing. Low-entropy or enumerable updates are therefore not
//!     protected against a determined recipient.
//!   * Secure aggregation in the Bonawitz sense does not straightforwardly apply to this rule at
//!     all: masking cancels under a SUM, and multi-Krum is a SELECTION driven by pairwise
//!     distances, so the masks do not cancel. Making that work is a research problem, not a
//!     configuration flag, and nothing here should be read as having solved it.
//!
//! **SIZE: REDACTION IS NOT UNIFORMLY SMALLER, AND THE CROSSOVER IS d = 4.** A contribution's
//! `4 + 8d` tensor bytes are replaced by a fixed 32-byte hash, so the artefact shrinks only for
//! `d >= 4` and grows by a few bytes per contribution below that. Real model widths are in the
//! millions, where the reduction is the entire point (a 1M-parameter update collapses from 8 MB
//! to 32 bytes per contributor) -- but the two-element toy case in the tests genuinely costs
//! bytes, and saying "redacted receipts are smaller" without qualification would be false.
//!
//! **A REDACTED RECEIPT CAN NEVER BE MISTAKEN FOR A FULL ONE.** It has its own wire magic, so a
//! full-receipt decoder rejects it and this decoder rejects a full receipt. The verdict type is
//! also separate and carries no `aggregate` field that could be read as verified -- only a
//! `claimed_aggregate`, named for what it is.

use crate::entry::{Contribution, EquivProof};
use crate::hash::{h, merkle_root};
use crate::identity::{
    contrib_msg, contrib_msg_v1, verify, Context, Pki, PreimageVersion, RoundParams, Sig,
};
use crate::receipt::{Invalid, Receipt};
use crate::resolve::Rule;
use std::collections::{BTreeMap, BTreeSet};

/// A contribution with the tensor removed and its hash kept.
///
/// Every field here is one the signature or the leaf already committed to, which is why
/// dropping the tensor costs no verification strength.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedContribution {
    /// The same opaque context the full contribution carried. **Redaction must not drop it**: the
    /// pruned-witness path outlives every other, so a context-blind witness would keep #79 alive in
    /// exactly the record that survives longest.
    pub ctx: Context,
    /// See [`crate::entry::Contribution::sig_preimage`].
    pub sig_preimage: PreimageVersion,
    /// The round parameters this contribution was made under. See [`RoundParams`].
    pub params: RoundParams,
    pub rnd: u64,
    pub node_id: u32,
    /// `h(enc_tensor(tensor))` of the removed vector -- what the signature actually signed.
    pub tensor_hash: [u8; 32],
    pub sig: Sig,
}

impl RedactedContribution {
    /// Byte-identical to the unredacted `Contribution::leaf()`, by construction: that function
    /// hashes the tensor HASH, not the tensor. A test asserts the equality rather than trusting
    /// this comment.
    pub fn leaf(&self) -> [u8; 32] {
        let mut b = Vec::with_capacity(2 + 32 + 1 + 4 + 4 + 8 + 4 + 32 + 64);
        b.extend_from_slice(b"C|");
        // Versioned for the same reason as `Contribution::leaf` -- see the comment there. A
        // redacted contribution must produce the SAME leaf as the full one it redacts, so this
        // has to track that function exactly.
        if matches!(self.sig_preimage, PreimageVersion::V2) {
            b.extend_from_slice(&self.ctx);
            b.push(self.params.rule.as_wire());
            b.extend_from_slice(&self.params.f.to_be_bytes());
            b.extend_from_slice(&self.params.frac_bits.to_be_bytes());
        }
        b.extend_from_slice(&self.rnd.to_be_bytes());
        b.extend_from_slice(&self.node_id.to_be_bytes());
        b.extend_from_slice(&self.tensor_hash);
        b.extend_from_slice(&self.sig);
        h(&b)
    }

    /// Full-strength authentication with no plaintext: the signature was always over the hash.
    pub fn signature_valid(&self, pki: &Pki) -> bool {
        match pki.get(&self.node_id) {
            None => false,
            Some(pk) => match self.sig_preimage {
                PreimageVersion::V1 => {
                    verify(pk, &contrib_msg_v1(self.rnd, &self.tensor_hash), &self.sig)
                }
                PreimageVersion::V2 => verify(
                    pk,
                    &contrib_msg(
                        &self.ctx,
                        &self.params,
                        self.rnd,
                        self.node_id,
                        &self.tensor_hash,
                    ),
                    &self.sig,
                ),
            },
        }
    }
}

impl From<&Contribution> for RedactedContribution {
    fn from(c: &Contribution) -> Self {
        RedactedContribution {
            ctx: c.ctx,
            sig_preimage: c.sig_preimage,
            params: c.params,
            rnd: c.rnd,
            node_id: c.node_id,
            tensor_hash: c.tensor_hash(),
            sig: c.sig,
        }
    }
}

/// A receipt with every participant's vector removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedReceipt {
    /// The context this receipt is about. Redaction removes the vectors, never the binding.
    pub ctx: Context,
    pub round: u64,
    pub f: usize,
    pub rule: Rule,
    /// The fixed-point scale, carried for the same reason the full receipt carries it (#77).
    /// Redaction removes the vectors; it must not remove the grid they were measured on.
    pub frac_bits: u32,
    pub pki: Pki,
    pub contributions: Vec<RedactedContribution>,
    pub proofs: Vec<EquivProof>,
    pub claimed_state_root: [u8; 32],
    /// Echoed so a reader can see what was claimed. **Not verifiable from a redacted receipt**
    /// and never reported as verified.
    pub claimed_output_root: [u8; 32],
    /// Likewise echoed, never verified. The aggregate is the shared model update, which every
    /// participant receives anyway -- it is not one participant's private data.
    pub claimed_aggregate: Option<Vec<i64>>,
}

/// What a redacted receipt establishes. **Deliberately a different type from `Verified`**, with
/// no field that could be read as a verified aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedVerified {
    pub round: u64,
    /// Recomputed from the carried leaves and matched against the claim -- full strength.
    pub state_root: [u8; 32],
    /// Node ids admitted to the aggregate, derived under exactly `State::admit`'s rules.
    pub admitted: Vec<u32>,
    pub convicted: Vec<u32>,
    pub convictable_but_unconvicted: Vec<u32>,
    pub population_bound_met: bool,
    /// **Claimed, not verified.** Re-execution needs the vectors this receipt does not carry.
    pub claimed_aggregate: Option<Vec<i64>>,
}

impl Receipt {
    /// Drop every tensor, keeping everything that authenticates or commits.
    ///
    /// The state root is carried across UNCHANGED rather than recomputed, and a test asserts the
    /// redacted set reproduces it -- if that ever failed it would mean redaction had changed
    /// what the receipt commits to, which is the one thing it must never do.
    pub fn redact(&self) -> RedactedReceipt {
        RedactedReceipt {
            ctx: self.ctx,
            round: self.round,
            f: self.f,
            rule: self.rule,
            frac_bits: self.frac_bits,
            pki: self.pki.clone(),
            contributions: self.contributions.iter().map(Into::into).collect(),
            proofs: self.proofs.clone(),
            claimed_state_root: self.claimed_state_root,
            claimed_output_root: self.claimed_output_root,
            claimed_aggregate: self.claimed_aggregate.clone(),
        }
    }
}

impl RedactedReceipt {
    /// Verify everything a redacted receipt can support.
    ///
    /// Runs the same checks as `Receipt::verify` in the same order -- policy, then signatures,
    /// then proofs, then the commitment -- and stops before the two that need vectors: the
    /// aggregate and the output root. The verdict type has no place to report those, so a caller
    /// cannot accidentally treat this as the stronger result.
    pub fn verify(&self, policy: &crate::receipt::Policy) -> Result<RedactedVerified, Invalid> {
        if self.pki != policy.pki {
            return Err(Invalid::PkiMismatch);
        }
        // THE SAME CHECKS AS THE FULL DOOR, IN THE SAME ORDER -- which this file claims and, until
        // now, did not do. It stopped at pki/f/rule, so a redacted receipt from another study or
        // another fixed-point grid verified `Ok` where the full receipt was refused by name. That
        // is the wrong way round: redaction is documented here as the pruned-witness path that
        // OUTLIVES every other artefact, so it is the one most likely to be read years later by
        // someone who was never online, and least likely to have its provenance checked by hand.
        if let Some(want) = policy.ctx {
            if want != self.ctx {
                return Err(Invalid::ContextMismatch {
                    policy: want,
                    receipt: self.ctx,
                });
            }
        }
        if self.frac_bits != policy.frac_bits {
            return Err(Invalid::ScaleMismatch {
                policy: policy.frac_bits,
                receipt: self.frac_bits,
            });
        }
        if self.f != policy.f {
            return Err(Invalid::FaultBoundMismatch {
                policy: policy.f,
                receipt: self.f,
            });
        }
        if let Some(want) = policy.rule {
            if want != self.rule {
                return Err(Invalid::RuleMismatch {
                    policy: want,
                    receipt: self.rule,
                });
            }
        }
        // The same count bound the full door carries: work here is linear, but an unbounded
        // carried set is unbounded work whatever the exponent, and the two doors should not
        // disagree about what a receipt may contain.
        if self.contributions.len() > crate::state::MAX_MERGE_CONTRIBUTIONS {
            return Err(Invalid::TooManyContributions {
                would_be: self.contributions.len(),
                max: crate::state::MAX_MERGE_CONTRIBUTIONS,
            });
        }

        for c in &self.contributions {
            if !c.signature_valid(&self.pki) {
                return Err(Invalid::BadContributionSignature {
                    node_id: c.node_id,
                    leaf: c.leaf(),
                });
            }
            if c.rnd != self.round {
                return Err(Invalid::WrongRound {
                    expected: self.round,
                    found: c.rnd,
                });
            }
        }
        for p in &self.proofs {
            if !p.valid(&self.pki) {
                return Err(Invalid::BogusProof {
                    node_id: p.node_id,
                    leaf: p.leaf(),
                });
            }
        }

        // The commitment, recomputed from leaves alone.
        let mut leaves: Vec<[u8; 32]> = self.contributions.iter().map(|c| c.leaf()).collect();
        leaves.extend(self.proofs.iter().map(|p| p.leaf()));
        leaves.sort_unstable();
        leaves.dedup();
        let actual_state_root = merkle_root(&leaves);
        if actual_state_root != self.claimed_state_root {
            return Err(Invalid::StateRootMismatch {
                claimed: self.claimed_state_root,
                actual: actual_state_root,
            });
        }

        // Admission, under exactly `State::admit`'s rules -- all of which read fields a redacted
        // contribution still carries.
        let convicted: BTreeSet<u32> = self
            .proofs
            .iter()
            .filter(|p| p.valid(&self.pki))
            .map(|p| p.node_id)
            .collect();
        let mut per_id: BTreeMap<u32, Vec<&RedactedContribution>> = BTreeMap::new();
        for c in &self.contributions {
            if c.rnd != self.round
                || convicted.contains(&c.node_id)
                || !self.pki.contains_key(&c.node_id)
                || !c.signature_valid(&self.pki)
            {
                continue;
            }
            per_id.entry(c.node_id).or_default().push(c);
        }
        let mut admitted: Vec<u32> = per_id
            .iter()
            .filter(|(_, v)| v.len() == 1)
            .map(|(id, _)| *id)
            .collect();
        admitted.sort_unstable();

        // Derivable-but-unformed convictions: two carried entries for one (round, id) whose
        // leaves differ is equivocation, and the leaf is all that is needed to see it.
        let mut seen: BTreeMap<(u64, u32), BTreeSet<[u8; 32]>> = BTreeMap::new();
        for c in &self.contributions {
            seen.entry((c.rnd, c.node_id)).or_default().insert(c.leaf());
        }
        let mut convictable: Vec<u32> = seen
            .iter()
            .filter(|((_, id), ls)| ls.len() > 1 && !convicted.contains(id))
            .map(|((_, id), _)| *id)
            .collect();
        convictable.sort_unstable();
        convictable.dedup();

        Ok(RedactedVerified {
            round: self.round,
            state_root: actual_state_root,
            population_bound_met: admitted.len() >= self.rule.required_n(self.f),
            admitted,
            convicted: convicted.into_iter().collect(),
            convictable_but_unconvicted: convictable,
            claimed_aggregate: self.claimed_aggregate.clone(),
        })
    }
}
