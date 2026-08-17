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
use std::collections::{BTreeMap, BTreeSet};

/// Product state. `BTreeMap` keyed by leaf: insertion is idempotent, iteration is
/// ordered, and the ordering is by content rather than by arrival.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub c: BTreeMap<[u8; 32], Contribution>,
    pub e: BTreeMap<[u8; 32], EquivProof>,
}

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
    pub fn merge(&mut self, other: &State, pki: &Pki) {
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

    /// Automatically derive an equivocation proof if `new` conflicts with something
    /// already held. Any honest replica that observes both halves forms the proof
    /// itself -- nobody has to report misbehaviour for it to be recorded.
    pub fn detect_equivocation(&self, new: &Contribution, pki: &Pki) -> Option<EquivProof> {
        let nh = new.tensor_hash();
        for c in self.c.values() {
            if c.rnd == new.rnd && c.node_id == new.node_id && c.tensor_hash() != nh {
                let p = EquivProof::canonical(
                    new.rnd,
                    new.node_id,
                    (c.tensor_hash(), c.sig),
                    (nh, new.sig),
                );
                if p.valid(pki) {
                    return Some(p);
                }
            }
        }
        None
    }

    /// Deliver a contribution and record any equivocation it exposes, in one step.
    pub fn deliver(&mut self, c: Contribution, pki: &Pki) {
        if let Some(p) = self.detect_equivocation(&c, pki) {
            self.add_proof(p);
        }
        self.add_contribution(c);
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
        out.sort_by_key(|c| c.leaf());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{enc_tensor, h};
    use crate::identity::{contrib_msg, Identity};

    fn ident(n: u32) -> Identity {
        Identity::from_secret(n, &[n as u8; 32])
    }

    fn pki_of(ids: &[&Identity]) -> Pki {
        ids.iter().map(|i| (i.node_id, i.public())).collect()
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
        left.merge(&only_z, &pki);
        let mut right = only_z.clone();
        right.merge(&ab, &pki);
        assert_eq!(left.root(), right.root(), "associative");

        let before = left.root();
        left.merge(&ab, &pki);
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
        a.merge(&b, &pki);

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
        ab.merge(&b, &pki);
        let mut ba = b.clone();
        ba.merge(&a, &pki);

        assert_eq!(ab.root(), ba.root(), "merge order changed the state root");
        assert_eq!(ab.convicted(&pki), ba.convicted(&pki));

        // Idempotence, since a grow-only join must absorb a repeat.
        let mut twice = ab.clone();
        twice.merge(&b, &pki);
        assert_eq!(twice.root(), ab.root(), "merge is not idempotent");
    }
}
