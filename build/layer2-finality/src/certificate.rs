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

    /// Do two tuples conflict? Conflict is on `(A_r, rho_r)` per the definition -- the
    /// membership and the committed aggregate. Two certificates for *different rounds*
    /// do not conflict; they are simply different rounds.
    pub fn conflicts_with(&self, other: &CertTuple) -> bool {
        self.round == other.round && (self.a_root != other.a_root || self.rho != other.rho)
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

    /// Valid iff at least `f+1` distinct known identities signed this exact tuple.
    pub fn check(&self, pki: &Pki, f: usize) -> Result<(), CertError> {
        let msg = self.tuple.msg();
        for (id, sig) in &self.sigs {
            let Some(pk) = pki.get(id) else {
                return Err(CertError::UnknownSigner(*id));
            };
            if !verify(pk, &msg, sig) {
                return Err(CertError::BadSignature(*id));
            }
        }
        let need = f + 1;
        if self.sigs.len() < need {
            return Err(CertError::Insufficient {
                have: self.sigs.len(),
                need,
            });
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

    /// True when the fork proves a violation but names nobody.
    pub fn is_unattributable(&self) -> bool {
        self.attributable().is_empty()
    }
}
