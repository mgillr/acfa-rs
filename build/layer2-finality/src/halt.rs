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
use std::collections::BTreeMap;

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
    /// Rounds at or below this have been reconciled by an explicit `resume`, so a fork at
    /// or below it is HISTORY rather than a live halt.
    ///
    /// Without this, resume could not stick. `resume` cleared the blocking set, but any
    /// peer re-gossiping the old fork -- ordinary behaviour, not an attack -- put it
    /// straight back and halted the node again, forever. The evidence is unsuppressible by
    /// design, so a design that halts on every re-delivery of unsuppressible evidence can
    /// never resume. Recording the reconcile point separates "this happened" from "this is
    /// blocking now", and keeps both true.
    reconciled_through: u64,
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

impl Finality {
    pub fn new(f: usize) -> Finality {
        let g = Certificate::genesis();
        let mut certified = BTreeMap::new();
        certified.insert(0u64, g);
        Finality {
            certified,
            forks: BTreeMap::new(),
            history: Vec::new(),
            reconciled_through: 0,
            f,
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
                    self.record(fork.clone());
                    if r > self.reconciled_through {
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
        self.record(fork.clone());
        // A fork at or below the reconcile point is settled history. Re-halting on it would
        // mean the node can never resume, because the evidence is designed to keep arriving.
        if fork.round() > self.reconciled_through {
            self.forks.insert(fork.round(), fork);
        }
        true
    }

    /// Append to the historical record, once. Re-delivery is expected, not exceptional.
    fn record(&mut self, fork: CertFork) {
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
    /// Final iff it is uniquely certified AND no fork exists at or before it. The
    /// "or before" is what stops a later round inheriting finality across a hole.
    pub fn is_final(&self, r: u64) -> bool {
        self.certified.contains_key(&r) && self.forks.keys().all(|&fr| fr > r)
    }

    /// Identities attributed by any observed fork -- the Byzantine-bridging signers.
    /// Excluded from round `r+1` onward.
    pub fn attributed(&self) -> std::collections::BTreeSet<u32> {
        self.forks.values().flat_map(|f| f.attributable()).collect()
    }

    /// The published evidence. Every observed fork, for onward gossip.
    pub fn evidence(&self) -> Vec<&CertFork> {
        self.forks.values().collect()
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
        // Record the point BEFORE clearing, so a re-gossiped copy of the fork we just
        // reconciled is recognised as settled rather than treated as a fresh halt.
        self.reconciled_through = self
            .forks
            .keys()
            .next_back()
            .copied()
            .unwrap_or(from)
            .max(from);
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
