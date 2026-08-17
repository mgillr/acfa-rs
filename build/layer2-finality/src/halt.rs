// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! # Halt-and-reconcile
//!
//! On observing a certificate fork at round `r`, an honest node:
//!
//! 1. **halts** round `r`;
//! 2. **publishes** the pair `{cert, cert'}` as proof-of-timing-violation -- it merges
//!    into every honest `E` by grow-only union, so it cannot be suppressed;
//! 3. **reconciles** from the last uniquely-certified round `r* < r`, re-running
//!    `r*+1, ...` once the timing assumption is re-established.
//!
//! Safety is preserved because no round past `r*` is treated as final while a fork for
//! it sits in `E`. Liveness resumes when the bound holds again. The failure mode is
//! **fail-visible-and-halt**: the system never finalises two conflicting states, and it
//! always exhibits the reason it stopped.
//!
//! ## The design decision that matters most here
//!
//! Halting is **monotone in the evidence, not in time**. A node halts because it has seen
//! a fork, and it resumes only when an operator explicitly re-establishes the timing
//! assumption. There is deliberately no automatic timeout-based resume: an automatic
//! resume would re-enter exactly the regime that just produced the fork, and would
//! convert a visible failure back into a silent one on the next lap.

use crate::certificate::{CertFork, Certificate};
use acfa_receipt::identity::Pki;
use std::collections::{BTreeMap, BTreeSet};

/// What the node is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Finalising normally. Carries the last uniquely-certified round.
    Running { last_certified: u64 },
    /// A fork was observed. No round past `reconcile_from` is final.
    Halted {
        at_round: u64,
        reconcile_from: u64,
        unattributable: bool,
    },
}

/// A node's view of finality.
#[derive(Debug, Clone)]
pub struct Finality {
    /// Uniquely certified rounds: round -> the one certificate for it.
    certified: BTreeMap<u64, Certificate>,
    /// Observed forks, by round. Grow-only while halted.
    forks: BTreeMap<u64, CertFork>,
    /// Every fork ever observed, retained across a resume. A fork is never retracted:
    /// the evidence does not stop being true because the operator fixed the clock.
    ///
    /// DEDUPLICATED. This was a `Vec` with an unconditional `push`, so re-delivery of the
    /// same fork -- which gossip guarantees, since the whole design is that evidence
    /// propagates to everyone -- grew it without bound. Evidence merging "by union" has to
    /// actually be a union.
    history: Vec<CertFork>,
    /// The specific forks an explicit `resume` has settled. Re-delivering one of THESE is
    /// old news; anything else is not.
    ///
    /// WHY IDENTITY AND NOT A ROUND NUMBER. Resume has to stick: the evidence is
    /// unsuppressible by design and keeps arriving, so a node that re-halts on every
    /// re-delivery can never resume at all. The first version of this fix suppressed by
    /// ROUND -- ignore any fork at or below the reconcile point -- and that was wrong in a
    /// way that mattered. A fork the node has never seen, at an EARLIER round, is not old
    /// news: it invalidates that round and everything after it, including the rounds just
    /// reconciled. Round-suppression let an adversary withhold a fork until after a resume
    /// and have it ignored permanently, which converts a fix for a denial of service into
    /// a way to hide a violation. Matching on the fork itself keeps the resume working and
    /// leaves genuinely new evidence able to halt.
    /// Keyed on the CONFLICT, not on the certificates carrying it. `CertFork` holds two
    /// `Certificate`s and `PartialEq` covers their signature maps, so an adversary who
    /// re-signs the SAME pair of tuples with a different valid `f+1` quorum produces a fork
    /// that is byte-different and semantically identical -- and byte-matching let exactly
    /// that re-halt a resumed node, which is the denial of service this record exists to
    /// close. `CertTuple::id()` covers the whole signed tuple and `canonical` already
    /// orients the pair by it, so the ordered pair of ids IS the conflict.
    reconciled: BTreeSet<([u8; 32], [u8; 32])>,
    /// The ROUNDS at which a fork was ever observed. A round in this set is permanently
    /// non-final, and that is a SAFETY property distinct from the liveness one `reconciled`
    /// serves.
    ///
    /// WHY THIS IS SEPARATE FROM `reconciled`, AND WHY IT IS NEEDED. `reconciled` stops a
    /// re-gossiped fork from re-HALTING a resumed node (liveness). It does nothing about
    /// FINALITY. After a resume the forked round is dropped from `certified`, so an adversary
    /// re-delivers the two halves in OPPOSITE order to two honest nodes: each certifies the
    /// half that arrives first, the second half forms a fork whose key is already in
    /// `reconciled` and is dropped as old news WITHOUT halting -- and `is_final` then reports
    /// the round final on each node, on CONFLICTING states. Measured on the pre-fix code: node
    /// X final on rho=a, node Y final on rho=b, neither halted, no adversary key required, only
    /// delivery order. That is the module's headline property -- "never finalises two
    /// conflicting states" -- broken.
    ///
    /// The audit's remedy was an epoch in the signed tuple so post-resume certificates cannot
    /// be confused with pre-halt ones. That changes the signed preimage and would move the
    /// cross-architecture fingerprint, which is fixed by construction. This is the fix that
    /// does NOT touch the wire: a round that forked is tainted forever. Neither honest node
    /// reports it final, so the divergence a consumer could observe cannot arise; progress
    /// resumes on rounds ABOVE the fork, which is where `reconcile_point` already places it.
    forked_rounds: BTreeSet<u64>,
    f: usize,
}

/// Why a certificate was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// The certificate itself does not carry f+1 valid signatures.
    Invalid,
    /// Accepted, and it forked an existing certificate for that round. The system is
    /// now halted. This is NOT an error in the certificate -- both are valid, which is
    /// the entire point.
    ForkedAt(u64),
}

impl core::fmt::Display for Rejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Rejected::Invalid => write!(f, "the certificate did not verify"),
            Rejected::ForkedAt(r) => write!(
                f,
                "a fork was observed at round {r}; nothing past it is final until reconciled"
            ),
        }
    }
}

impl core::error::Error for Rejected {}

impl Finality {
    pub fn new(f: usize) -> Finality {
        let g = Certificate::genesis();
        let mut certified = BTreeMap::new();
        certified.insert(0u64, g);
        Finality {
            certified,
            forks: BTreeMap::new(),
            history: Vec::new(),
            reconciled: BTreeSet::new(),
            forked_rounds: BTreeSet::new(),
            f,
        }
    }

    /// The identity of a CONFLICT: the two signed-tuple ids as an UNORDERED pair, independent
    /// of which quorum signed it, of the signature bytes, AND of which half arrived first.
    ///
    /// SORTED HERE RATHER THAN TRUSTED FROM THE CALLER. `CertFork::canonical` already fixes
    /// orientation, but `CertFork { a, b }` has PUBLIC fields, so a struct literal built
    /// outside this crate bypasses it entirely -- and `observe_fork` is `pub` and takes a
    /// `CertFork` by value. Reading the pair in field order therefore keyed this map on
    /// something the caller controls.
    ///
    /// MEASURED, on the unfixed code: a fork observed, reconciled and re-offered SWAPPED came
    /// back `Halted { at_round: 3, reconcile_from: 0, unattributable: true }` while the same
    /// conflict re-offered canonically was correctly `Running`. A node re-halted permanently
    /// on a conflict it had already settled, because the pair arrived the other way round.
    ///
    /// Not reachable from bytes -- `wire::decode_fork` always routes through `canonical` --
    /// so this is an API-misuse footgun in a library others embed, and the remedy is to make
    /// the invariant UNNECESSARY rather than to document it. Sorting removes the caller from
    /// the trust path.
    fn fork_key(fork: &CertFork) -> ([u8; 32], [u8; 32]) {
        let (x, y) = (fork.a.tuple.id(), fork.b.tuple.id());
        if x <= y {
            (x, y)
        } else {
            (y, x)
        }
    }

    /// Offer a certificate to this node.
    pub fn observe(&mut self, cert: Certificate, pki: &Pki) -> Result<(), Rejected> {
        if !cert.is_genesis() && !cert.is_valid(pki, self.f) {
            return Err(Rejected::Invalid);
        }
        let r = cert.tuple.round;

        if let Some(existing) = self.certified.get(&r) {
            if existing.tuple == cert.tuple {
                return Ok(()); // idempotent re-delivery
            }
            if let Some(fork) = CertFork::canonical(existing.clone(), cert) {
                if fork.is_valid(pki, self.f) {
                    // Store only what verifies. `check` counts valid signatures rather than
                    // requiring all of them, so junk entries survive validation -- and the
                    // readers below take MEANING from `sigs` without holding a PKI. Prune at
                    // ingest and membership becomes proof again.
                    let fork = fork.pruned(pki);
                    self.record(fork.clone());
                    if !self.reconciled.contains(&Self::fork_key(&fork)) {
                        self.forks.insert(r, fork);
                        return Err(Rejected::ForkedAt(r));
                    }
                    return Err(Rejected::Invalid);
                }
            }
            return Err(Rejected::Invalid);
        }
        self.certified.insert(r, cert);
        Ok(())
    }

    /// Accept a fork observed elsewhere. Evidence merges by union, so a node that never
    /// saw both certificates directly still halts.
    pub fn observe_fork(&mut self, fork: CertFork, pki: &Pki) -> bool {
        if !fork.is_valid(pki, self.f) {
            return false;
        }
        // PRUNE AT INGEST, EXACTLY AS `observe` DOES. This line was missing here and present
        // there, and the asymmetry was the whole defect: `check` counts VALID signatures
        // rather than requiring all of them, so junk entries survive validation, and
        // `attributable()` then takes MEANING from `sigs` membership without holding a PKI.
        //
        // MEASURED, on the unfixed code: node 1 signed only certificate `a`; inserting a
        // 64-ZERO-BYTE entry for node 1 on certificate `b` left `fork.is_valid` TRUE and
        // `attributable()` returning `{1}` while `attributable_verified(pki)` was correctly
        // empty -- and the junk survived into `fork_history()`, so an HONEST node was
        // published as a double-signer on 64 zero bytes.
        //
        // That is worse than a nuisance in this layer specifically: the proposition is that
        // misbehaviour leaves self-authenticating evidence, and this produced
        // self-authenticating evidence AGAINST AN INNOCENT PARTY. Prune here and membership
        // in `sigs` means verified again on BOTH ingest paths.
        let fork = fork.pruned(pki);
        self.record(fork.clone());
        // Only a fork this node has already reconciled is settled. Anything else halts,
        // whatever its round.
        if !self.reconciled.contains(&Self::fork_key(&fork)) {
            self.forks.insert(fork.round(), fork);
        }
        true
    }

    /// Append to the historical record, once. Re-delivery is expected, not exceptional.
    fn record(&mut self, fork: CertFork) {
        // A fork's two halves conflict at the SAME round by construction, so either tuple's
        // round names it. Recording it here -- the single choke point every observed fork
        // passes through, on both the `observe` and `observe_fork` paths -- is what makes the
        // round permanently non-final, and it is recorded the moment the fork is SEEN rather
        // than when it is reconciled, so the taint does not depend on an operator ever calling
        // `resume`.
        self.forked_rounds.insert(fork.a.tuple.round);
        if !self.history.contains(&fork) {
            self.history.push(fork);
        }
    }

    /// The last round certified uniquely and with no fork at or below it.
    ///
    /// A fork at round `r` invalidates finality for `r` and everything after it, so the
    /// reconcile point is the last certified round strictly below the EARLIEST fork --
    /// not below the latest. Taking the latest would leave rounds between two forks
    /// treated as final, which is the subtle version of finalising a forked state.
    pub fn reconcile_point(&self) -> u64 {
        match self.forks.keys().next() {
            None => *self.certified.keys().next_back().unwrap_or(&0),
            Some(&earliest) => *self
                .certified
                .keys()
                .rfind(|&&r| r < earliest)
                .unwrap_or(&0),
        }
    }

    pub fn status(&self) -> Status {
        match self.forks.iter().next() {
            None => Status::Running {
                last_certified: *self.certified.keys().next_back().unwrap_or(&0),
            },
            Some((&r, fork)) => Status::Halted {
                at_round: r,
                reconcile_from: self.reconcile_point(),
                unattributable: fork.is_unattributable(),
            },
        }
    }

    pub fn is_halted(&self) -> bool {
        !self.forks.is_empty()
    }

    /// Is round `r` final on this node?
    ///
    /// Final iff it is uniquely certified, no fork exists at or before it, AND the round
    /// itself never forked.
    ///
    /// The third clause is the safety fix for the post-resume divergence. `self.forks` holds
    /// only the forks currently BLOCKING; a resume clears it. So the first two clauses alone
    /// report a round final again once its fork has been reconciled and cleared -- and an
    /// adversary who re-delivers the two halves in opposite order to two nodes gets each to
    /// certify a different half and both to call the round final, on conflicting states.
    /// `forked_rounds` is never cleared, so a round that ever forked stays non-final on every
    /// honest node, which is exactly the property that stops the divergence.
    pub fn is_final(&self, r: u64) -> bool {
        self.certified.contains_key(&r)
            && self.forks.keys().all(|&fr| fr > r)
            && !self.forked_rounds.contains(&r)
    }

    /// Identities attributed by any observed fork -- the Byzantine-bridging signers.
    /// Excluded from round `r+1` onward.
    pub fn attributed(&self) -> std::collections::BTreeSet<u32> {
        // READ THE PERMANENT RECORD, NOT THE BLOCKING SET. `forks` holds only the forks
        // currently halting the node; `resume` CLEARS it. Reading `forks` here meant that the
        // moment an operator resumed, `attributed()` returned empty -- so a proven
        // double-signer's conviction vanished on the normal recovery path, with no adversary
        // involved. Measured: {3} before resume, {} after. `history` retains every fork across
        // a resume, and both `record` call sites store the PRUNED fork, so membership in a
        // history fork's `sigs` already means verified -- reading it cannot re-introduce the
        // accuse-an-innocent path that pruning closed.
        self.history.iter().flat_map(|f| f.attributable()).collect()
    }

    /// The published evidence. Every observed fork, for onward gossip.
    pub fn evidence(&self) -> Vec<&CertFork> {
        // Also the permanent record. A resumed node must keep gossiping the fork proofs it
        // holds -- the module's whole argument is that evidence unions into every honest node
        // so a violation cannot be suppressed. Reading `forks` meant a resumed node published
        // NOTHING, quietly withdrawing the proof from the network on the recovery path.
        self.history.iter().collect()
    }

    /// Re-establish the timing assumption and resume from the reconcile point.
    ///
    /// EXPLICIT AND OPERATOR-DRIVEN BY DESIGN. The caller asserts that the bound now
    /// holds -- after re-synchronisation, or after raising the round budget to `>= 2tau`.
    /// The forks are NOT deleted: they stay as the historical record that the run was
    /// interrupted and why. What resumes is the ability to certify rounds above the
    /// reconcile point, not a pretence that the fork never happened.
    ///
    /// Refuses while the budget is still under-provisioned, because resuming into an
    /// under-provisioned budget forks the certificate again by construction.
    pub fn resume(&mut self, budget: crate::cut::RoundBudget) -> Result<u64, &'static str> {
        if !budget.is_safe() {
            return Err("round budget below 2tau -- resuming would fork again by construction");
        }
        let from = self.reconcile_point();
        self.certified.retain(|&r, _| r <= from);
        // Record WHICH forks were settled before clearing, so a re-gossiped copy of one of
        // them is recognised as old news while a fork never seen before still halts.
        for f in self.forks.values() {
            if !self.reconciled.contains(&Self::fork_key(f)) {
                self.reconciled.insert(Self::fork_key(f));
            }
        }
        self.forks.clear(); // no longer blocking; `history` keeps the record
        Ok(from)
    }

    pub fn certified_rounds(&self) -> Vec<u64> {
        self.certified.keys().copied().collect()
    }

    /// Every fork ever observed, including those cleared by a resume. This is the
    /// audit record: a run that halted and recovered must not look like a run that
    /// never halted.
    pub fn fork_history(&self) -> &[CertFork] {
        &self.history
    }
}
