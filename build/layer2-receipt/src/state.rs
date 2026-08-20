// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The product CRDT -- a contribution OR-Set crossed with an equivocation-proof G-Set --
//! and the admission rule over it.
//!
//! Merge is union x union. Both components are grow-only over content-addressed leaves,
//! so merge is commutative, associative and idempotent by construction, and the state
//! converges without agreement on order. That is the "consensus-free" half of ACFA.

use crate::entry::{Contribution, EquivProof};
use crate::hash::merkle_root;
use crate::identity::Pki;
use crate::redact::RedactedContribution;
use std::collections::{BTreeMap, BTreeSet};

/// Product state. `BTreeMap` keyed by leaf: insertion is idempotent, iteration is
/// ordered, and the ordering is by content rather than by arrival.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub c: BTreeMap<[u8; 32], Contribution>,
    pub e: BTreeMap<[u8; 32], EquivProof>,
    /// **Conviction witnesses: pruned contributions, stripped to what still convicts.**
    ///
    /// A replica cannot retain every round's vectors forever -- at n=20, d=1000 that is about
    /// 8 KB per contribution and 1.5 GiB after ten thousand rounds -- but it also cannot simply
    /// DROP them, because equivocation is detected by comparing a new contribution against the
    /// ones already held. Drop round R and an equivocator whose second message for round R
    /// arrives later, or is deliberately withheld until the prune, escapes conviction entirely.
    /// That is the adversary the whole proof machinery exists to catch.
    ///
    /// So pruning keeps the WITNESS and discards only the vector. `(ctx, params, rnd, node_id, tensor_hash,
    /// sig)` is about 149 bytes and is exactly sufficient to both DETECT a conflict -- detection
    /// keys on leaf inequality -- and to FORM the proof, since `EquivProof::canonical` takes
    /// `(tensor_hash, sig)` pairs and never reads a vector. Detection strength after pruning is
    /// therefore unchanged, not merely degraded gracefully.
    ///
    /// It reuses `RedactedContribution` deliberately: redaction and pruning need the same thing
    /// -- everything that authenticates and commits, minus the vector -- and that type is
    /// already proven to produce a leaf BYTE-IDENTICAL to the full contribution's, which is the
    /// property this rests on.
    ///
    /// **Not part of `root()`.** The commitment stays over `c` and `e` alone. Both production
    /// callers of `root()` build fresh states rather than reading a replica's accumulated one
    /// (verified by enumeration), so a detection-only side structure cannot move any root that
    /// crosses replicas.
    ///
    /// **This bounds the CONSTANT, not the growth.** Retention is still linear in rounds, at
    /// ~149 bytes instead of ~8 KB. Truly bounding it needs a conviction horizon -- a round past
    /// which equivocation stops being detectable at all -- which is a policy decision with a
    /// real security cost and is deliberately left open rather than chosen here.
    pub w: BTreeMap<[u8; 32], RedactedContribution>,
}

/// Largest contribution set `merge` will absorb from a peer.
///
/// Mirrors `acfa_aggregate::rules::MAX_CONTRIBUTIONS` and for the same reason one layer
/// down: the receipt carrying a set grows LINEARLY while the work over it grows faster.
/// That bound was recognised and enforced in layer 1 and was never carried across.
pub const MAX_MERGE_CONTRIBUTIONS: usize = 4096;

/// Largest proof set `merge` will produce.
///
/// THIS IS THE ONE THAT MATTERS, because the proof set is QUADRATIC IN THE PEER'S INPUT,
/// not linear. Every contribution sharing a `(rnd, node_id)` with another conflicts with
/// it, and `deliver` derives a proof per pair, so `k` contributions from one signer in one
/// round yield `k(k-1)/2` proofs. MEASURED against the unfixed code: 200 contributions
/// produced 19 900 proofs -- exactly `n(n-1)/2` -- in 2.0 s, with time rising 3.5x to 4.7x
/// per doubling. Extrapolated, 4096 would be 8 386 560 proofs.
///
/// A peer sends `n` and the receiver stores `n^2/2`. That is amplification, not merely
/// unbounded growth, and it is why a contribution cap alone does not close it.
///
/// THE BOUND IS ON TIME, NOT MEMORY, AND THE FIRST VERSION OF THIS CONSTANT GOT THAT WRONG.
///
/// It was originally 2^20, justified purely by storage: 2^20 proofs at the struct's 192
/// bytes (`rnd`, `node_id`, two 32-byte hashes, two 64-byte signatures) is about 201 MB.
/// That reasoning is sound and it bounds the wrong resource. Deriving a proof costs a
/// SIGNATURE VERIFICATION, so the cap also decides how much CPU an ACCEPTED merge may
/// consume, and nothing checked that.
///
/// MEASURED, on accepted merges under the old cap:
///
/// ```text
///   k=200   19 900 proofs    2.48 s
///   k=400   79 800 proofs    9.61 s
///   k=600  179 700 proofs   22.38 s
///   k=800  319 600 proofs   52.67 s     <- accepted, and already a minute of CPU
/// ```
///
/// Derivation runs at roughly 6 000-8 000 proofs/second on the reference host, so the old
/// 2^20 admitted a single merge costing about 130 SECONDS. The memory bound held perfectly
/// while the machine sat unavailable for over two minutes.
///
/// 8192 puts the worst accepted merge at about one second. The number is chosen from that
/// measurement, not from a round binary figure that happens to look tidy.
///
/// IT COSTS LEGITIMATE USE NOTHING, which is what makes the tightening safe rather than a
/// trade: proofs arise ONLY from equivocation, an honest node sends one contribution per
/// round, so an honest merge derives ZERO. 8192 is one node equivocating 128 ways in a
/// single round, which is already far past anything a real deployment produces.
///
/// AND THE TRUE REQUIREMENT IS SMALLER STILL: `convicted` collects `node_id` into a
/// `BTreeSet`, so ONE valid proof per node convicts and every further proof for that node
/// changes no answer this crate returns. The cap is not set at that minimum because the
/// proof set is a G-Set whose union defines the state root -- discarding redundant proofs
/// would change `root()` and therefore the bytes two replicas must agree on. Refusing is
/// available; thinning is not.
pub const MAX_MERGE_PROOFS: usize = 8192;

/// Upper bound on how many equivocation proofs `deliver`-ing `cs` can DERIVE.
///
/// For each `(round, node_id)` group of size `k`, delivery can form at most `k(k-1)/2`
/// pairs, and each pair costs a signature verification. This is the quantity that makes
/// derivation quadratic in a set the sender chooses, so it is the quantity that must be
/// bounded BEFORE any of the work is done.
///
/// EXTRACTED SO THE TWO DOORS SHARE ONE IMPLEMENTATION. `merge` bounded this and
/// `Receipt::verify` did not, which left the untrusted door open while the trusted one
/// was shut -- measured at 81.4 KB of input to 67.4 s of verifier CPU with verdict Ok.
/// A second copy of this arithmetic in `receipt.rs` would drift from this one; a shared
/// function cannot.
pub fn derivable_proof_bound<'a, I>(cs: I) -> usize
where
    I: IntoIterator<Item = &'a Contribution>,
{
    let mut group: BTreeMap<(u64, u32), usize> = BTreeMap::new();
    for c in cs {
        *group.entry((c.rnd, c.node_id)).or_insert(0) += 1;
    }
    group
        .values()
        .map(|&k| k.saturating_mul(k.saturating_sub(1)) / 2)
        .sum()
}

/// Why a merge was refused. Refusing rather than truncating is not a preference: a
/// partially-absorbed merge leaves two honest replicas holding different states from the
/// same inputs, which is the exact property this module exists to provide.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MergeError {
    /// The combined contribution set would exceed `MAX_MERGE_CONTRIBUTIONS`.
    TooManyContributions { would_be: usize, max: usize },
    /// The combined proof set, INCLUDING the proofs this merge would derive, would exceed
    /// `MAX_MERGE_PROOFS`. `would_be` is an upper bound computed before anything is
    /// absorbed, so the state is untouched when this is returned.
    TooManyProofs { would_be: usize, max: usize },
}

impl core::fmt::Display for MergeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MergeError::TooManyContributions { would_be, max } => write!(
                f,
                "merging would hold {would_be} contributions, over the limit of {max}"
            ),
            MergeError::TooManyProofs { would_be, max } => write!(
                f,
                "merging would derive up to {would_be} equivocation proofs, over the limit \
                 of {max}; the proof set is quadratic in a peer's contributions"
            ),
        }
    }
}

impl core::error::Error for MergeError {}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_contribution(&mut self, c: Contribution) {
        self.c.insert(c.leaf(), c);
    }

    pub fn add_proof(&mut self, p: EquivProof) {
        self.e.insert(p.leaf(), p);
    }

    /// Union x union. Idempotent, commutative, associative.
    /// Merge another replica's state, DERIVING equivocation proofs exactly as `deliver`
    /// does.
    ///
    /// WHY THE PKI ARGUMENT EXISTS. An earlier signature took only `&State` and unioned the
    /// two maps, which looked like the textbook CRDT join and was wrong for this state.
    /// `deliver` derives a proof when an arriving contribution conflicts with one already
    /// held; a union does not. So a replica that learned both halves of an equivocation by
    /// GOSSIP ended up holding both contributions and no proof, while a replica that
    /// learned them by DELIVERY held the proof as well.
    ///
    /// That is not a cosmetic difference. Conviction feeds `admit`, so the two replicas
    /// admit different sets and compute different aggregates -- and because the state root
    /// commits to proof leaves as well as contribution leaves, their roots differ too. Two
    /// honest replicas holding an IDENTICAL contribution set would disagree, which is
    /// precisely the strong-eventual-consistency claim this type exists to make.
    ///
    /// Deriving on merge restores it: the proof set becomes a function of the contribution
    /// set rather than of how the contributions arrived.
    /// BOUNDED, AND ALL-OR-NOTHING. Both caps are checked BEFORE anything is absorbed, so a
    /// refusal leaves `self` byte-identical to what it was. Absorbing until a limit trips
    /// would leave a partially-merged state, and two replicas that stopped at different
    /// points hold different roots from the same inputs -- the failure this type exists to
    /// exclude, arrived at by way of a protection.
    ///
    /// The proof bound is an UPPER bound, computed from group sizes rather than by trial:
    /// proofs only ever arise between contributions sharing a `(rnd, node_id)`, so for each
    /// such group of combined size `k` the derivable count is at most `k(k-1)/2`. Summing
    /// those, plus the proofs both sides already hold, bounds the result without doing the
    /// work. It over-estimates when contributions in a group are identical, and refusing on
    /// an over-estimate is the safe direction.
    pub fn merge(&mut self, other: &State, pki: &Pki) -> Result<(), MergeError> {
        // --- contribution bound -------------------------------------------------------
        // Union, not sum: leaves are content-addressed, so anything both sides hold counts
        // once. Summing would refuse an idempotent re-merge of a state already held.
        // LIVE contributions only. A leaf this replica has already pruned to a witness must not
        // count against the live bound -- it is retired, and counting it would make the bound a
        // function of all history again, which is the defect this fix exists to remove.
        let mut union: BTreeSet<&[u8; 32]> = self.c.keys().collect();
        for k in other.c.keys() {
            if !self.w.contains_key(k) {
                union.insert(k);
            }
        }
        let would_be = union.len();
        if would_be > MAX_MERGE_CONTRIBUTIONS {
            return Err(MergeError::TooManyContributions {
                would_be,
                max: MAX_MERGE_CONTRIBUTIONS,
            });
        }

        // --- proof bound --------------------------------------------------------------
        let mut group: BTreeMap<(u64, u32), usize> = BTreeMap::new();
        for leaf in &union {
            let c = self.c.get(*leaf).or_else(|| other.c.get(*leaf));
            if let Some(c) = c {
                *group.entry((c.rnd, c.node_id)).or_insert(0) += 1;
            }
        }
        let derivable: usize = group
            .values()
            .map(|&k| k.saturating_mul(k.saturating_sub(1)) / 2)
            .sum();
        let mut held: BTreeSet<&[u8; 32]> = self.e.keys().collect();
        held.extend(other.e.keys());
        let would_be = held.len().saturating_add(derivable);
        if would_be > MAX_MERGE_PROOFS {
            return Err(MergeError::TooManyProofs {
                would_be,
                max: MAX_MERGE_PROOFS,
            });
        }

        // --- apply, only now that both bounds hold ------------------------------------
        // Deliver rather than insert, so conflicts are detected against everything already
        // held. `EquivProof::canonical` fixes the pair order, so the derived proof does not
        // depend on which half arrived first and merge stays commutative.
        for c in other.c.values() {
            self.deliver(c.clone(), pki);
        }
        // Proofs are grow-only and self-authenticating, so a plain union is correct here.
        for (k, v) in &other.e {
            self.e.insert(*k, v.clone());
        }
        Ok(())
    }

    /// Commitment trace over every leaf in the product state.
    ///
    /// Contributions and proofs go into ONE tree, matching the reference. They are
    /// already domain-separated from each other by their `C|` / `P|` leaf prefixes, so
    /// a proof cannot be presented as a contribution or the reverse.
    pub fn root(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(self.c.len() + self.e.len());
        leaves.extend(self.c.keys().copied());
        leaves.extend(self.e.keys().copied());
        merkle_root(&leaves)
    }

    /// Identities with at least one VALID proof against them.
    ///
    /// Conviction is monotone: the proof set only grows, so an identity once convicted
    /// stays convicted on every replica that has seen the proof. Invalid proofs are
    /// ignored rather than rejected at insert time -- anyone can inject garbage into a
    /// grow-only set, so validity has to be evaluated at read time, not trusted at
    /// write time.
    pub fn convicted(&self, pki: &Pki) -> BTreeSet<u32> {
        self.e
            .values()
            .filter(|p| p.valid(pki))
            .map(|p| p.node_id)
            .collect()
    }

    /// Derive EVERY equivocation proof `new` exposes against what is already held.
    ///
    /// This returns all conflicting pairs, not the first one found. Returning on the first
    /// match made the proof set a SAMPLE of the conflicts rather than their closure, and
    /// which sample you got depended on map iteration against what had already arrived. At
    /// two halves that is invisible -- there is only one pair -- but an identity that
    /// equivocates THREE ways gives three pairs, and two replicas that saw the same
    /// contributions in a different order recorded different ones, so they disagreed on the
    /// state root and on the receipt bytes. That is the strong-eventual-consistency claim
    /// failing: same updates delivered, permanently different observable state.
    ///
    /// The CLOSURE is what makes this order-independent, and it is what the incremental
    /// path actually builds: when the third half arrives it pairs with both halves already
    /// held, and the pair those two formed on their own arrival is already recorded, so
    /// every order ends at the same three proofs. A "star" shape -- pairing the canonical
    /// smallest half with each other half -- is smaller but CANNOT be built incrementally,
    /// because a smaller half arriving later would invalidate the stars already recorded.
    pub fn detect_equivocations(&self, new: &Contribution, pki: &Pki) -> Vec<EquivProof> {
        let nh = new.tensor_hash();
        let nl = new.leaf();
        let mut out = Vec::new();
        // Witnesses first: a pruned round must still convict. This loop is the reason pruning
        // is safe at all -- delete it and an equivocator simply waits for the prune horizon.
        for wc in self.w.values() {
            if wc.ctx == new.ctx
                && wc.params == new.params
                && wc.rnd == new.rnd
                && wc.node_id == new.node_id
                && wc.leaf() != nl
            {
                let p = EquivProof::canonical(
                    new.ctx,
                    new.sig_preimage,
                    new.params,
                    new.rnd,
                    new.node_id,
                    (wc.tensor_hash, wc.sig),
                    (nh, new.sig),
                );
                if p.valid(pki) {
                    out.push(p);
                }
            }
        }
        for c in self.c.values() {
            // Keyed on the LEAF, which covers the signature, because that is what
            // `admit` excludes on. Keying detection on the tensor hash while admission
            // keys on the leaf left a gap exactly the width of the difference: two
            // distinct valid signatures over the SAME content are two leaves, so the
            // identity was excluded, and were one content, so no proof was formed.
            // THE CONTEXT MUST MATCH. Two contributions by one node at one round number in
            // DIFFERENT contexts are not equivocation -- that is a node doing its job in two
            // places, and convicting it for that was #79.
            // THE ROUND PARAMETERS MUST MATCH TOO, for the same reason the context must. A node
            // that contributes to a Krum round and a Bulyan round, or to two rounds run at
            // different fixed-point scales, is doing its job twice -- not equivocating. Pairing
            // those would rebuild #79 one field over.
            if c.ctx == new.ctx
                && c.params == new.params
                && c.rnd == new.rnd
                && c.node_id == new.node_id
                && c.leaf() != nl
            {
                let p = EquivProof::canonical(
                    new.ctx,
                    new.sig_preimage,
                    new.params,
                    new.rnd,
                    new.node_id,
                    (c.tensor_hash(), c.sig),
                    (nh, new.sig),
                );
                if p.valid(pki) {
                    out.push(p);
                }
            }
        }
        out
    }

    /// Deliver a contribution and record every equivocation it exposes, in one step.
    pub fn deliver(&mut self, c: Contribution, pki: &Pki) {
        for p in self.detect_equivocations(&c, pki) {
            self.add_proof(p);
        }
        // A leaf already held as a WITNESS is one this replica has deliberately pruned. Taking
        // its vector back would undo the prune and let a peer re-inflate a replica's live set to
        // the cap by replaying old rounds -- the same permanent stop by another route. Detection
        // above has already run against it, so nothing is lost by declining the body.
        if !self.w.contains_key(&c.leaf()) {
            self.add_contribution(c);
        }
    }

    /// Retire every contribution for rounds at or before `through`, keeping its conviction
    /// witness.
    ///
    /// This is the fix for the permanent gossip stop: `merge`'s contribution bound counts LIVE
    /// contributions, and without a way to retire settled rounds a replica reaches that bound as
    /// a function of elapsed rounds and never recovers, because the set only grows.
    ///
    /// Deterministic and idempotent: it is a function of the round number alone, so two replicas
    /// pruning through the same round hold the same live set. It does NOT touch `e` -- conviction
    /// is permanent, an identity that equivocated in round 1 is still convicted in round 5 -- and
    /// it does not touch `root()`, which is over `c` and `e`.
    ///
    /// Returns how many contributions were retired.
    pub fn prune_through(&mut self, through: u64) -> usize {
        let doomed: Vec<[u8; 32]> = self
            .c
            .iter()
            .filter(|(_, c)| c.rnd <= through)
            .map(|(k, _)| *k)
            .collect();
        for k in &doomed {
            if let Some(c) = self.c.remove(k) {
                self.w.insert(*k, RedactedContribution::from(&c));
            }
        }
        doomed.len()
    }

    /// The admitted set for a round, in hash-canonical order.
    ///
    /// Four filters, and the fourth is the subtle one:
    ///
    /// 1. round must match -- entries from other rounds are not in scope;
    /// 2. the identity must be in the PKI;
    /// 3. the identity must not be convicted;
    /// 4. **the identity must have exactly ONE visible entry this round.**
    ///
    /// Filter 4 is Definition 7's uniqueness clause and it is not the same as filter 3.
    /// An equivocator is excluded the moment both halves are visible, *without waiting
    /// for a proof to be formed or propagated*. Keeping the first-seen entry instead
    /// would make the result depend on arrival order, which is precisely the property
    /// the whole construction exists to remove. Note it also excludes two entries with
    /// the SAME tensor hash but different signatures -- see `Contribution::leaf`.
    pub fn admit(&self, rnd: u64, pki: &Pki) -> Vec<Contribution> {
        let bad = self.convicted(pki);
        let mut per_id: BTreeMap<u32, Vec<&Contribution>> = BTreeMap::new();
        for c in self.c.values() {
            if c.rnd != rnd || bad.contains(&c.node_id) || !pki.contains_key(&c.node_id) {
                continue;
            }
            if !c.signature_valid(pki) {
                continue;
            }
            per_id.entry(c.node_id).or_default().push(c);
        }
        let mut out: Vec<Contribution> = per_id
            .values()
            .filter(|v| v.len() == 1)
            .map(|v| v[0].clone())
            .collect();
        // `sort_by_cached_key`, NOT `sort_by_key`. The key here is `leaf()`, which hashes the whole
        // tensor, and `sort_by_key` recomputes the key on EVERY COMPARISON -- O(n log n) hashes of
        // O(d) bytes each, where O(n) would do. Measured at 2.13x of total verify cost at the
        // shipped default work budget, which matters twice over: it is wasted work on an untrusted
        // door, and DEFAULT_MAX_VERIFY_COORDINATES was calibrated against a path carrying it, so
        // the default admitted less real work than it should have.
        //
        // Order is unchanged -- `sort_by_cached_key` computes each key once and sorts on the same
        // values -- so no root, no admitted set and no fingerprint moves. Verified.
        out.sort_by_cached_key(|c| c.leaf());
        out
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
    use crate::hash::{enc_tensor, h};
    use crate::identity::{contrib_msg, Identity};

    fn ident(n: u32) -> Identity {
        Identity::from_secret(n, &[n as u8; 32])
    }

    fn pki_of(ids: &[&Identity]) -> Pki {
        ids.iter().map(|i| (i.node_id, i.public())).collect()
    }

    /// crdt-08. `merge` absorbed a peer's contribution set with no ceiling at all -- I
    /// grepped the unfixed file for MAX_, length comparisons and TooMany and there was
    /// nothing. This is the cap, and it refuses rather than truncating: a partially
    /// absorbed merge leaves two replicas with different roots from the same inputs.
    #[test]
    fn merge_refuses_a_contribution_set_over_the_cap() {
        let a = ident(1);
        let mut pki: Pki = BTreeMap::new();
        pki.insert(1, a.public());

        let mut peer = State::new();
        for i in 0..(MAX_MERGE_CONTRIBUTIONS + 1) {
            peer.add_contribution(contrib(&a, i as u64, &[i as i64]));
        }
        let mut mine = State::new();
        assert_eq!(
            mine.merge(&peer, &pki),
            Err(MergeError::TooManyContributions {
                would_be: MAX_MERGE_CONTRIBUTIONS + 1,
                max: MAX_MERGE_CONTRIBUTIONS,
            })
        );
        assert!(mine.c.is_empty(), "a refused merge must absorb NOTHING");
    }

    /// crdt-09, and the finding is an AMPLIFICATION rather than unbounded growth. Every
    /// contribution sharing a `(rnd, node_id)` conflicts with every other, and `deliver`
    /// derives a proof per pair, so `k` such contributions yield `k(k-1)/2` proofs. Measured
    /// against the unfixed code: 200 contributions produced exactly 19 900 proofs in 2.0 s,
    /// with time rising 3.5x to 4.7x per doubling. The peer sends `n`; the receiver stores
    /// `n^2/2`. A contribution cap alone does not close that, which is why there are two.
    #[test]
    fn merge_refuses_the_quadratic_proof_amplification() {
        let a = ident(1);
        let mut pki: Pki = BTreeMap::new();
        pki.insert(1, a.public());

        // k(k-1)/2 must exceed MAX_MERGE_PROOFS; 1500 gives 1 124 250 against 8192.
        let k = 1500usize;
        assert!(
            k * (k - 1) / 2 > MAX_MERGE_PROOFS,
            "precondition: this k must trip it"
        );

        let mut peer = State::new();
        for i in 0..k {
            // SAME round, SAME signer, different tensors: every pair conflicts.
            peer.add_contribution(contrib(&a, 7, &[i as i64]));
        }
        let mut mine = State::new();
        match mine.merge(&peer, &pki) {
            Err(MergeError::TooManyProofs { would_be, max }) => {
                assert_eq!(max, MAX_MERGE_PROOFS);
                assert_eq!(
                    would_be,
                    k * (k - 1) / 2,
                    "bound is k(k-1)/2, computed not tried"
                );
            }
            other => panic!("expected a proof-bound refusal, got {other:?}"),
        }
        assert!(
            mine.c.is_empty() && mine.e.is_empty(),
            "refused merge must absorb NOTHING"
        );
    }

    /// WHERE THE PROOF BOUNDARY SITS, pinned so that widening it is a visible act.
    ///
    /// The cap is a TIME bound expressed as a count: derivation costs one signature
    /// verification per proof, measured at roughly 6 000-8 000/second, so 8192 puts the
    /// worst ACCEPTED merge near one second. The original 2^20 admitted about 130 seconds
    /// and its justification never mentioned time at all.
    ///
    /// Asserted on the REFUSAL side because that path costs nothing -- the bound is computed
    /// from group sizes and refuses before any work -- whereas exercising the accepting side
    /// at the boundary would derive 8128 proofs and take about a second in every CI run on
    /// every architecture. The accepting side is covered by
    /// `an_ordinary_merge_still_absorbs_and_still_derives`.
    #[test]
    fn the_proof_bound_sits_exactly_where_the_timing_measurement_puts_it() {
        // k(k-1)/2 is the derivable count for one (rnd, node_id) group of size k.
        let max_k = (1..).find(|k| k * (k - 1) / 2 > MAX_MERGE_PROOFS).unwrap() - 1;
        assert_eq!(
            max_k, 128,
            "the cap admits at most 128 conflicting contributions"
        );
        assert!(max_k * (max_k - 1) / 2 <= MAX_MERGE_PROOFS);
        assert!((max_k + 1) * max_k / 2 > MAX_MERGE_PROOFS);

        // One past the boundary must refuse, and refuse without absorbing anything.
        let a = ident(1);
        let mut pki: Pki = BTreeMap::new();
        pki.insert(1, a.public());
        let mut peer = State::new();
        for i in 0..(max_k + 1) {
            peer.add_contribution(contrib(&a, 7, &[i as i64]));
        }
        let mut mine = State::new();
        match mine.merge(&peer, &pki) {
            Err(MergeError::TooManyProofs { would_be, max }) => {
                assert_eq!(max, MAX_MERGE_PROOFS);
                assert_eq!(would_be, (max_k + 1) * max_k / 2);
            }
            other => panic!("one past the boundary must refuse, got {other:?}"),
        }
        assert!(mine.c.is_empty() && mine.e.is_empty());
    }

    /// THE ALL-OR-NOTHING PROPERTY, asserted on the ROOT rather than on lengths, because
    /// that is the thing two replicas must agree on. A merge that refused after absorbing
    /// part of the peer would leave a state that still looks plausible and no longer matches
    /// a replica that refused earlier or later.
    #[test]
    fn a_refused_merge_leaves_the_state_byte_identical() {
        let a = ident(1);
        let b = ident(2);
        let mut pki: Pki = BTreeMap::new();
        pki.insert(1, a.public());
        pki.insert(2, b.public());

        let mut mine = State::new();
        mine.deliver(contrib(&b, 1, &[10, 20]), &pki);
        let before_root = mine.root();
        let before_len = (mine.c.len(), mine.e.len());

        let mut peer = State::new();
        for i in 0..(MAX_MERGE_CONTRIBUTIONS + 1) {
            peer.add_contribution(contrib(&a, i as u64, &[i as i64]));
        }
        assert!(
            mine.merge(&peer, &pki).is_err(),
            "precondition: this merge must refuse"
        );

        assert_eq!(
            mine.root(),
            before_root,
            "state root moved on a REFUSED merge"
        );
        assert_eq!((mine.c.len(), mine.e.len()), before_len);
    }

    /// The accepting side, so the two refusals above are not satisfied by a merge that
    /// refuses everything. An ordinary merge must still absorb, still derive its proofs,
    /// and still converge.
    #[test]
    fn an_ordinary_merge_still_absorbs_and_still_derives() {
        let a = ident(1);
        let mut pki: Pki = BTreeMap::new();
        pki.insert(1, a.public());

        let mut peer = State::new();
        peer.add_contribution(contrib(&a, 7, &[1]));
        peer.add_contribution(contrib(&a, 7, &[2])); // conflicts: one proof derivable

        let mut mine = State::new();
        mine.merge(&peer, &pki)
            .expect("an ordinary merge must be accepted");
        assert_eq!(mine.c.len(), 2, "contributions absorbed");
        assert_eq!(
            mine.e.len(),
            1,
            "the equivocation proof was derived, not skipped"
        );
        assert!(
            mine.convicted(&pki).contains(&1),
            "the equivocator is convicted"
        );
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
    fn merge_is_commutative_associative_and_idempotent() {
        let (a, b, c) = (ident(1), ident(2), ident(3));
        let pki = pki_of(&[&a, &b, &c]);
        let (x, y, z) = (
            contrib(&a, 1, &[1]),
            contrib(&b, 1, &[2]),
            contrib(&c, 1, &[3]),
        );

        let mut ab = State::new();
        ab.deliver(x.clone(), &pki);
        ab.deliver(y.clone(), &pki);
        let mut ba = State::new();
        ba.deliver(y.clone(), &pki);
        ba.deliver(x.clone(), &pki);
        assert_eq!(ab.root(), ba.root(), "commutative");

        let mut left = ab.clone();
        let mut only_z = State::new();
        only_z.deliver(z.clone(), &pki);
        left.merge(&only_z, &pki).expect("within bounds");
        let mut right = only_z.clone();
        right.merge(&ab, &pki).expect("within bounds");
        assert_eq!(left.root(), right.root(), "associative");

        let before = left.root();
        left.merge(&ab, &pki).expect("within bounds");
        assert_eq!(before, left.root(), "idempotent");
    }

    #[test]
    fn an_equivocator_is_excluded_before_any_proof_propagates() {
        let (a, b) = (ident(1), ident(2));
        let pki = pki_of(&[&a, &b]);
        let mut s = State::new();
        s.add_contribution(contrib(&a, 1, &[1]));
        s.add_contribution(contrib(&a, 1, &[9])); // same round, different content
        s.add_contribution(contrib(&b, 1, &[2]));
        // No proof was inserted; uniqueness alone must exclude node 1.
        let adm = s.admit(1, &pki);
        assert_eq!(adm.len(), 1);
        assert_eq!(adm[0].node_id, 2);
    }

    #[test]
    fn equivocation_is_detected_automatically_on_delivery() {
        let (a, b) = (ident(1), ident(2));
        let pki = pki_of(&[&a, &b]);
        let mut s = State::new();
        s.deliver(contrib(&a, 1, &[1]), &pki);
        s.deliver(contrib(&a, 1, &[9]), &pki);
        assert_eq!(s.e.len(), 1, "replica forms the proof without being told");
        assert!(s.convicted(&pki).contains(&1));
    }

    #[test]
    fn conviction_in_one_round_excludes_the_identity_in_every_round() {
        let (a, b) = (ident(1), ident(2));
        let pki = pki_of(&[&a, &b]);
        let mut s = State::new();
        s.deliver(contrib(&a, 1, &[1]), &pki);
        s.deliver(contrib(&a, 1, &[9]), &pki); // convicted in round 1
        s.deliver(contrib(&a, 2, &[5]), &pki); // single, well-formed, round 2
        s.deliver(contrib(&b, 2, &[6]), &pki);
        let adm = s.admit(2, &pki);
        assert_eq!(
            adm.len(),
            1,
            "conviction is not scoped to the round it happened in"
        );
        assert_eq!(adm[0].node_id, 2);
    }

    #[test]
    fn an_unsigned_or_foreign_entry_never_reaches_the_admitted_set() {
        let (a, b) = (ident(1), ident(2));
        let pki = pki_of(&[&a]); // b is NOT in the PKI
        let mut s = State::new();
        s.add_contribution(contrib(&a, 1, &[1]));
        s.add_contribution(contrib(&b, 1, &[2]));
        let mut forged = contrib(&a, 1, &[7]);
        forged.node_id = 1;
        forged.sig = [0u8; 64];
        s.add_contribution(forged);
        let adm = s.admit(1, &pki);
        // a contributed once validly, but the forged entry is a SECOND visible entry
        // for node 1, so uniqueness excludes it too. The honest count is zero.
        assert!(adm.iter().all(|c| c.signature_valid(&pki)));
        assert!(adm.iter().all(|c| c.node_id != 2));
    }

    #[test]
    fn a_garbage_proof_convicts_nobody() {
        let (a, b) = (ident(1), ident(2));
        let pki = pki_of(&[&a, &b]);
        let mut s = State::new();
        s.add_proof(EquivProof {
            ctx: crate::identity::NO_CONTEXT,
            sig_preimage: crate::identity::PreimageVersion::V2,
            params: PARAMS_DEFAULT,
            rnd: 1,
            node_id: 1,
            h1: [1u8; 32],
            h2: [2u8; 32],
            sig1: [0u8; 64],
            sig2: [0u8; 64],
        });
        assert!(
            s.convicted(&pki).is_empty(),
            "anyone can inject into a G-Set"
        );
        s.add_contribution(contrib(&a, 1, &[1]));
        assert_eq!(
            s.admit(1, &pki).len(),
            1,
            "and it must not exclude the victim"
        );
    }

    /// crdt-02: gossip and delivery must yield the SAME convicted set.
    ///
    /// Before the fix, `merge` unioned the maps without deriving proofs, so a replica that
    /// learned both halves of an equivocation by gossip held both contributions and no
    /// proof, while a replica that learned them by delivery held the proof. Same
    /// contribution set, different convicted set, different aggregate, different state
    /// root -- a strong-eventual-consistency violation with no Byzantine node involved in
    /// the divergence.
    #[test]
    fn gossip_and_delivery_agree_on_conviction() {
        let liar = ident(1);
        let other = ident(2);
        let pki = pki_of(&[&liar, &other]);
        let liar = &liar;

        // DELIVERY: one replica sees both halves arrive.
        let mut delivered = State::new();
        delivered.deliver(contrib(liar, 1, &[1, 1]), &pki);
        delivered.deliver(contrib(liar, 1, &[2, 2]), &pki);

        // GOSSIP: two replicas each hold one half, then merge.
        let mut a = State::new();
        a.deliver(contrib(liar, 1, &[1, 1]), &pki);
        let mut b = State::new();
        b.deliver(contrib(liar, 1, &[2, 2]), &pki);
        a.merge(&b, &pki).expect("within bounds");

        assert_eq!(
            delivered.convicted(&pki),
            a.convicted(&pki),
            "gossip and delivery disagreed about who equivocated"
        );
        assert_eq!(
            delivered.root(),
            a.root(),
            "identical contribution sets produced different state roots"
        );
        assert!(
            !a.convicted(&pki).is_empty(),
            "the equivocation was not detected at all"
        );
    }

    /// The derived proof must not depend on merge order, or merge stops being a CRDT join.
    #[test]
    fn merge_is_commutative_over_derived_proofs() {
        let liar = ident(1);
        let other = ident(2);
        let pki = pki_of(&[&liar, &other]);
        let liar = &liar;
        let mut a = State::new();
        a.deliver(contrib(liar, 1, &[1, 1]), &pki);
        let mut b = State::new();
        b.deliver(contrib(liar, 1, &[2, 2]), &pki);

        let mut ab = a.clone();
        ab.merge(&b, &pki).expect("within bounds");
        let mut ba = b.clone();
        ba.merge(&a, &pki).expect("within bounds");

        assert_eq!(ab.root(), ba.root(), "merge order changed the state root");
        assert_eq!(ab.convicted(&pki), ba.convicted(&pki));

        // Idempotence, since a grow-only join must absorb a repeat.
        let mut twice = ab.clone();
        twice.merge(&b, &pki).expect("within bounds");
        assert_eq!(twice.root(), ab.root(), "merge is not idempotent");
    }
}
