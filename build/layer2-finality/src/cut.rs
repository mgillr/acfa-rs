// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! # The deadline cut (ERC -- deadline completeness via authenticated broadcast)
//!
//! ## The problem this solves, stated as the attack it defeats
//!
//! A round has to close. The obvious rule -- "accept contributions until the deadline,
//! then re-gossip what you have" -- **cannot work**, and the reason is not a corner case:
//!
//! A Byzantine sender delivers its contribution to node X at `tau-epsilon` before the deadline
//! and to nobody else. X relays it; the relay takes up to `tau` and lands at Y *after* Y's
//! deadline. X deems it present, Y deems it absent. Both are honest, both followed the
//! rule, and they now sign **different cuts**. Agreeing a set under a subset-delivering
//! sender *is* Byzantine broadcast, so no re-gossip rule can fix this -- it needs a
//! broadcast primitive.
//!
//! ## The construction
//!
//! Dolev-Strong authenticated broadcast. A contribution is admitted iff it carries a
//! valid **`f+1`-round signature-accumulating relay chain** by the round deadline;
//! anything else is *deemed absent*. After `f+1` rounds every honest node holds the
//! identical admitted set, so deemed-absence is uniform and no two honest nodes sign
//! different cuts.
//!
//! Two properties worth stating because they are easy to get wrong:
//!
//! * **The anchor is content, not a clock.** The chain is anchored at the round-`(r-1)`
//!   certificate -- a uniformly observable event -- not at a local wall-clock reading.
//! * **`n > f` suffices.** Authenticated broadcast holds for any `n > f` under
//!   known-bound synchrony plus authentication, so the `3f+1` quorum-intersection
//!   barrier does not bind. That is what makes the `2f+3` resilience honest rather than
//!   a trick.

use acfa_receipt::hash::h;
use acfa_receipt::identity::{verify, Identity, Pki, Sig};
use std::collections::BTreeSet;

/// Domain-separated relay message.
///
/// Each relayer signs over the anchor, the contribution leaf, AND every signature
/// already on the chain. Binding to the prefix is what stops a chain being reassembled
/// from signatures harvested out of other chains: a signature is only valid at the exact
/// depth and in the exact company it was produced for.
pub fn relay_msg(anchor: &[u8; 32], leaf: &[u8; 32], prefix: &[(u32, Sig)]) -> Vec<u8> {
    let mut m = Vec::with_capacity(12 + 32 + 32 + prefix.len() * 68);
    m.extend_from_slice(b"ACFA-RELAY|");
    m.extend_from_slice(anchor);
    m.extend_from_slice(leaf);
    for (id, s) in prefix {
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(s);
    }
    h(&m).to_vec()
}

/// A Dolev-Strong relay chain carrying one contribution toward admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayChain {
    /// The round-(r-1) certificate this chain is anchored at.
    pub anchor: [u8; 32],
    /// The contribution being relayed, by leaf.
    pub leaf: [u8; 32],
    /// Signatures in relay order, first is the originator.
    pub hops: Vec<(u32, Sig)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Fewer than f+1 relay hops: the broadcast has not closed.
    TooShort { have: usize, need: usize },
    /// The same identity appears twice. A chain must accumulate DISTINCT signers, or
    /// one Byzantine node could inflate a chain to any length by itself.
    RepeatedSigner(u32),
    /// A signer is not in the PKI.
    UnknownSigner(u32),
    /// A hop's signature does not verify over the chain prefix it claims to extend.
    BadHop { depth: usize, node_id: u32 },
}

impl RelayChain {
    /// Start a chain. The originator signs first, over an empty prefix.
    pub fn originate(anchor: [u8; 32], leaf: [u8; 32], by: &Identity) -> RelayChain {
        let sig = by.sign(&relay_msg(&anchor, &leaf, &[]));
        RelayChain {
            anchor,
            leaf,
            hops: vec![(by.node_id, sig)],
        }
    }

    /// Extend the chain by one relay hop.
    pub fn relay(&self, by: &Identity) -> RelayChain {
        let sig = by.sign(&relay_msg(&self.anchor, &self.leaf, &self.hops));
        let mut hops = self.hops.clone();
        hops.push((by.node_id, sig));
        RelayChain {
            anchor: self.anchor,
            leaf: self.leaf,
            hops,
        }
    }

    /// Is this a complete, well-formed `f+1`-round chain?
    ///
    /// Completeness is `f+1` DISTINCT signers. `f+1` guarantees at least one honest
    /// relayer, which is what carries the message to every honest node in time.
    pub fn check(&self, pki: &Pki, f: usize) -> Result<(), ChainError> {
        // SATURATES. `f` reaches here from an untrusted receipt, and `f + 1` in `usize`
        // WRAPS TO ZERO at `usize::MAX` -- making the threshold comparison below vacuously
        // false, so the check returned Ok on ZERO valid signatures. A threshold that gets
        // easier as the claimed adversary budget grows is the guard failing open, in the
        // one direction an attacker chooses. `usize::MAX` is unreachable, which is the
        // honest answer for a fault bound nobody can satisfy.
        let need = f.saturating_add(1);
        if self.hops.len() < need {
            return Err(ChainError::TooShort {
                have: self.hops.len(),
                need,
            });
        }
        // Distinctness is about KEYS, not ids. `f + 1` distinct hops is a threshold over
        // independent signers, and two ids sharing one key are one signer wearing two
        // labels, so counting ids lets a single key supply the whole chain.
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let mut seen_keys: BTreeSet<acfa_receipt::identity::PubKey> = BTreeSet::new();
        for (depth, (id, sig)) in self.hops.iter().enumerate() {
            if !seen.insert(*id) {
                return Err(ChainError::RepeatedSigner(*id));
            }
            let Some(pk) = pki.get(id) else {
                return Err(ChainError::UnknownSigner(*id));
            };
            if !seen_keys.insert(*pk) {
                return Err(ChainError::RepeatedSigner(*id));
            }
            let msg = relay_msg(&self.anchor, &self.leaf, &self.hops[..depth]);
            if !verify(pk, &msg, sig) {
                return Err(ChainError::BadHop {
                    depth,
                    node_id: *id,
                });
            }
        }
        Ok(())
    }

    pub fn is_complete(&self, pki: &Pki, f: usize) -> bool {
        self.check(pki, f).is_ok()
    }
}

/// The round budget, in units of the known delivery bound `tau`.
///
/// **THIS IS A SAFETY PARAMETER, NOT A PERFORMANCE KNOB.** Honest nodes do not receive
/// the round-`(r-1)` certificate simultaneously -- they receive it up to `tau` apart. If the
/// round length is exactly `tau`, a relay from a node that started its clock `Delta` late
/// arrives after an early starter has already closed the round: the two deem the same
/// contribution present-vs-absent and sign different cuts. That is a **certificate
/// uniqueness (safety) fork**, not a liveness stall.
///
/// So an *under-provisioned budget forks the certificate even when the delivery bound
/// holds*. Setting the round length to `>= 2tau` absorbs the certificate-delivery spread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundBudget {
    /// Round length as a multiple of tau, times 100 (so 2.0tau is 200). Integer, because a
    /// float here would be a determinism leak in a determinism protocol.
    pub centi_tau: u32,
}

impl RoundBudget {
    pub const REQUIRED_CENTI_TAU: u32 = 200;

    pub fn new(centi_tau: u32) -> Self {
        RoundBudget { centi_tau }
    }

    /// Is the budget provisioned at the `>= 2tau` this construction's safety rests on?
    ///
    /// Returned rather than asserted: a deployment may knowingly run under-provisioned,
    /// and the honest thing is to record that its certificates are fork-prone, not to
    /// refuse to run and have someone patch the check out.
    pub fn is_safe(&self) -> bool {
        self.centi_tau >= Self::REQUIRED_CENTI_TAU
    }
}

/// The admitted cut for a round: exactly those contributions whose broadcast closed.
///
/// Everything else is **deemed absent** -- uniformly, which is the whole point.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeadlineCut {
    pub anchor: [u8; 32],
    /// Admitted leaves, ascending. Canonical, so two nodes with the same cut produce
    /// byte-identical certificates.
    pub admitted: Vec<[u8; 32]>,
    /// Leaves seen but deemed absent, ascending. Carried for diagnosis: it is the
    /// difference between "nobody sent it" and "it did not close in time", and those
    /// two have very different operational meanings.
    pub deemed_absent: Vec<[u8; 32]>,
}

impl DeadlineCut {
    /// Compute the cut from the chains observed by the deadline.
    pub fn close(anchor: [u8; 32], chains: &[RelayChain], pki: &Pki, f: usize) -> DeadlineCut {
        let mut admitted = BTreeSet::new();
        let mut absent = BTreeSet::new();
        for ch in chains {
            if ch.anchor != anchor {
                absent.insert(ch.leaf);
                continue;
            }
            if ch.is_complete(pki, f) {
                admitted.insert(ch.leaf);
            } else {
                absent.insert(ch.leaf);
            }
        }
        // A leaf that closed somewhere is admitted, full stop -- an incomplete chain for
        // the same leaf does not demote it.
        for l in &admitted {
            absent.remove(l);
        }
        DeadlineCut {
            anchor,
            admitted: admitted.into_iter().collect(),
            deemed_absent: absent.into_iter().collect(),
        }
    }

    /// Merkle root of the admitted set -- the `A_r` component of the certificate tuple.
    pub fn root(&self) -> [u8; 32] {
        acfa_receipt::hash::merkle_root(&self.admitted)
    }
}
