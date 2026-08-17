// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! # Round certificates, certificate-level equivocation, and fail-visible finality
//!
//! A round-`r` certificate is `f+1` signatures on the tuple `(A_r, E^cut_r, rho_r)`:
//! the final admitted membership, the equivocation cut the trust gate used, and the
//! committed aggregate root. Round 0 anchors to a fixed public genesis certificate.
//! The certificate is the object a later round references.
//!
//! ## Why `f+1` and not a quorum
//!
//! Because the cut is established by authenticated broadcast, not by quorum
//! intersection. `f+1` signatures guarantee at least one honest signer, and an honest
//! node signs only when its completeness predicate holds -- i.e. only for the complete
//! cut's tuple. Under ERC that pins the tuple uniquely. No `3f+1` is needed.
//!
//! ## The failure the whole module exists to make visible
//!
//! If the synchrony bound breaks -- or, just as importantly, if the round budget is
//! under-provisioned below `2tau` while the bound holds -- two **disjoint honest groups**
//! of `f+1` can each certify a different cut. At `n >= 3f+2` this needs **no Byzantine
//! co-signer at all**, so there is *nobody to attribute*. A naive design fails silently
//! here: two conflicting finalities, no misbehaviour, no evidence.
//!
//! The construction's answer is that the **fork is itself the evidence**. Two valid
//! round-`r` certificates on conflicting tuples cannot coexist while ERC holds, so their
//! coexistence *proves* ERC failed -- a decidable check on the two signed objects alone,
//! requiring no knowledge of who was slow. The failure mode becomes
//! **fail-visible-and-halt** rather than fail-silent.

use acfa_receipt::hash::h;
use acfa_receipt::identity::{verify, Identity, Pki, Sig};
use std::collections::{BTreeMap, BTreeSet};

/// The signed tuple. `(A_r, E^cut_r, rho_r)`, by root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CertTuple {
    pub round: u64,
    /// `A_r` -- root of the admitted membership.
    pub a_root: [u8; 32],
    /// `E^cut_r` -- root of the equivocation cut used by the trust gate.
    pub e_cut_root: [u8; 32],
    /// `rho_r` -- the committed aggregate root.
    pub rho: [u8; 32],
}

impl CertTuple {
    /// Domain-separated signing message.
    pub fn msg(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(11 + 8 + 96);
        m.extend_from_slice(b"ACFA-CERT|");
        m.extend_from_slice(&self.round.to_be_bytes());
        m.extend_from_slice(&self.a_root);
        m.extend_from_slice(&self.e_cut_root);
        m.extend_from_slice(&self.rho);
        m
    }

    pub fn id(&self) -> [u8; 32] {
        h(&self.msg())
    }

    /// Do two tuples conflict? Two certificates for *different rounds* do not conflict;
    /// they are simply different rounds. Within one round, ANY difference in the signed
    /// tuple is a conflict.
    ///
    /// The comparison covers `e_cut_root`, not merely `(A_r, rho_r)`, because `msg()` SIGNS
    /// the cut and `id()` -- the anchor round r+1 chains against -- commits to it. Comparing
    /// a strict subset of what the signature covers left two valid round-r certificates that
    /// agreed on membership and aggregate while committing to different equivocation cuts
    /// *neither equal nor conflicting*: `observe` fell through to `Rejected::Invalid` and
    /// silently kept whichever arrived first, so two honest nodes finalised different
    /// certificates for the same round with no fork recorded and nobody halted, and the
    /// divergence then propagated through the anchor. A conflict predicate must cover
    /// everything the signature covers.
    pub fn conflicts_with(&self, other: &CertTuple) -> bool {
        self.round == other.round && self != other
    }
}

/// A round certificate: the tuple plus `f+1` signatures over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub tuple: CertTuple,
    /// Signer -> signature. `BTreeMap` so the set is canonical and a signer cannot be
    /// double-counted toward the `f+1` threshold.
    pub sigs: BTreeMap<u32, Sig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    /// Fewer than f+1 distinct valid signatures.
    Insufficient {
        have: usize,
        need: usize,
    },
    UnknownSigner(u32),
    BadSignature(u32),
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CertError::Insufficient { have, need } => write!(
                f,
                "certificate carries {have} verifying signature(s), quorum needs {need}"
            ),
            CertError::UnknownSigner(id) => {
                write!(f, "signer {id} is not in the checker's PKI")
            }
            CertError::BadSignature(id) => {
                write!(
                    f,
                    "signer {id}'s signature does not verify over the certificate tuple"
                )
            }
        }
    }
}

impl core::error::Error for CertError {}

impl Certificate {
    /// The fixed public genesis certificate that round 0 anchors to.
    ///
    /// It carries no signatures by construction -- there is no prior round to have
    /// admitted anyone -- so it is accepted by identity, never by `check`. Anchoring to
    /// a *fixed public* value rather than to a locally chosen one is what stops a node
    /// starting its own private chain of history.
    pub fn genesis() -> Certificate {
        Certificate {
            tuple: CertTuple {
                round: 0,
                a_root: h(b"ACFA-GENESIS|A"),
                e_cut_root: h(b"ACFA-GENESIS|E"),
                rho: h(b"ACFA-GENESIS|rho"),
            },
            sigs: BTreeMap::new(),
        }
    }

    pub fn is_genesis(&self) -> bool {
        self.tuple == Certificate::genesis().tuple
    }

    pub fn new(tuple: CertTuple) -> Certificate {
        Certificate {
            tuple,
            sigs: BTreeMap::new(),
        }
    }

    /// Add a signature.
    ///
    /// THE HONEST SIGNING RULE IS THE CALLER'S OBLIGATION AND CANNOT BE ENFORCED HERE:
    /// an honest node signs a round-`r` certificate only when its completeness predicate
    /// holds, and by accuracy that is only for the complete cut's tuple. This function
    /// cannot check that -- completeness is a property of what the node has observed, not
    /// of the tuple. Signing an incomplete cut is exactly how an honest-but-hasty node
    /// forks the certificate.
    pub fn sign(&mut self, by: &Identity) {
        self.sigs.insert(by.node_id, by.sign(&self.tuple.msg()));
    }

    /// The signers whose signature over THIS tuple actually verifies against the PKI.
    ///
    /// Anyone can append entries to a carried signature map, so membership of `sigs` means
    /// nothing on its own. Every question about "who signed this" must be asked of this
    /// set, never of `sigs.keys()`.
    pub fn verified_signers(&self, pki: &Pki) -> BTreeSet<u32> {
        let msg = self.tuple.msg();
        self.sigs
            .iter()
            .filter(|(id, sig)| pki.get(id).is_some_and(|pk| verify(pk, &msg, sig)))
            .map(|(id, _)| *id)
            .collect()
    }

    /// This certificate with every unverifiable signature entry removed.
    ///
    /// Pruning at ingest is what makes the counting `check` safe. `Finality` stores forks
    /// and later reads `sigs` for MEANING (who is attributable), and those readers do not
    /// hold the PKI, so the invariant has to be established when the evidence enters rather
    /// than re-checked at every use. After pruning, membership of `sigs` IS proof.
    pub fn pruned(&self, pki: &Pki) -> Certificate {
        let keep = self.verified_signers(pki);
        Certificate {
            tuple: self.tuple,
            sigs: self
                .sigs
                .iter()
                .filter(|(id, _)| keep.contains(id))
                .map(|(id, sig)| (*id, *sig))
                .collect(),
        }
    }

    /// Valid iff at least `f+1` distinct known identities signed this exact tuple.
    ///
    /// COUNTS the valid signatures rather than requiring every carried one to verify.
    /// Requiring all of them made valid evidence REFUSABLE BY A BYSTANDER: the wire format
    /// accepts any strictly-ascending signer list, so a relay could append one junk entry
    /// to a genuine fork and an honest node would decline to halt on real evidence. A
    /// threshold is a lower bound on honest signers; a spurious extra entry cannot lower it.
    pub fn check(&self, pki: &Pki, f: usize) -> Result<(), CertError> {
        // SATURATES. `f` reaches here from an untrusted receipt, and `f + 1` in `usize`
        // WRAPS TO ZERO at `usize::MAX` -- making the threshold comparison below vacuously
        // false, so the check returned Ok on ZERO valid signatures. A threshold that gets
        // easier as the claimed adversary budget grows is the guard failing open, in the
        // one direction an attacker chooses. `usize::MAX` is unreachable, which is the
        // honest answer for a fault bound nobody can satisfy.
        let need = f.saturating_add(1);
        let have = self.verified_signers(pki).len();
        if have < need {
            return Err(CertError::Insufficient { have, need });
        }
        Ok(())
    }

    pub fn is_valid(&self, pki: &Pki, f: usize) -> bool {
        self.check(pki, f).is_ok()
    }
}

/// A certificate fork: two valid round-`r` certificates on conflicting tuples.
///
/// This is **transferable evidence that the timing assumption broke**, verifiable by any
/// node from the two certificates alone. It is sound (a fork proves a violation, by
/// certificate uniqueness) and complete for visibility (a violation that forks always
/// carries its own proof).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFork {
    pub a: Certificate,
    pub b: Certificate,
}

impl CertFork {
    /// Build a fork in canonical orientation, so two observers derive the same object.
    pub fn canonical(x: Certificate, y: Certificate) -> Option<CertFork> {
        if !x.tuple.conflicts_with(&y.tuple) {
            return None;
        }
        let (a, b) = if x.tuple.id() <= y.tuple.id() {
            (x, y)
        } else {
            (y, x)
        };
        Some(CertFork { a, b })
    }

    /// Is this genuinely a fork -- both certificates valid, and their tuples conflicting?
    ///
    /// Both halves must be checked. A "fork" where one side is invalid is not evidence of
    /// a timing violation, it is evidence of a forgery, and conflating the two would let
    /// anyone halt the system by fabricating a second certificate.
    pub fn is_valid(&self, pki: &Pki, f: usize) -> bool {
        self.a.tuple.conflicts_with(&self.b.tuple)
            && self.a.is_valid(pki, f)
            && self.b.is_valid(pki, f)
    }

    pub fn round(&self) -> u64 {
        self.a.tuple.round
    }

    /// Identities whose signature appears on **both** conflicting certificates.
    ///
    /// This is the Byzantine-bridging case: signing two conflicting tuples for the same
    /// round is provable misbehaviour, and those identities are attributed and excluded
    /// from round `r+1` onward.
    ///
    /// An **empty** result is the interesting one. It means two disjoint honest groups
    /// each certified a different cut -- possible at `n >= 3f+2` with no Byzantine
    /// participation at all. Nobody is at fault, nobody can be excluded, and the fork is
    /// still conclusive proof the bound broke. That is precisely the case a design that
    /// only looks for culprits would miss, and it is why this returns a set rather than
    /// a single accused identity.
    pub fn attributable(&self) -> BTreeSet<u32> {
        self.a
            .sigs
            .keys()
            .filter(|k| self.b.sigs.contains_key(k))
            .copied()
            .collect()
    }

    /// Who signed BOTH halves, counting only signatures that verify.
    ///
    /// PART TWO OF THE crdt-07 FIX, AND IT IS NOT OPTIONAL. Once `check` counts valid
    /// signatures instead of requiring all of them, junk entries survive into the carried
    /// map -- and [`CertFork::attributable`] reads `sigs.keys()`, which is membership and
    /// not proof. Counting alone would therefore have closed a denial of service and opened
    /// a FRAMING vector: an attacker appends entries naming honest nodes to both halves of
    /// a real fork, and those nodes are reported as having double-signed. Attribution is an
    /// accusation, so it must be read from verified signatures only.
    pub fn attributable_verified(&self, pki: &Pki) -> BTreeSet<u32> {
        let a = self.a.verified_signers(pki);
        let b = self.b.verified_signers(pki);
        a.intersection(&b).copied().collect()
    }

    /// Both halves pruned to their verified signatures. Canonical orientation is decided by
    /// `tuple.id()`, which pruning does not touch, so a pruned fork keeps its orientation.
    pub fn pruned(&self, pki: &Pki) -> CertFork {
        CertFork {
            a: self.a.pruned(pki),
            b: self.b.pruned(pki),
        }
    }

    /// True when the fork proves a violation but names nobody, judged on verified
    /// signatures. Prefer this to [`CertFork::is_unattributable`].
    pub fn is_unattributable_verified(&self, pki: &Pki) -> bool {
        self.attributable_verified(pki).is_empty()
    }

    /// True when the fork proves a violation but names nobody.
    pub fn is_unattributable(&self) -> bool {
        self.attributable().is_empty()
    }
}
