// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The receipt: a re-executable aggregate.
//!
//! A receipt carries everything needed to recompute a round's result offline and check
//! it against what was claimed. It is a **wire format plus a verifier**, not a daemon
//! and not a protocol run -- verification touches no network, no clock, and no other
//! party.
//!
//! WHAT A VALID RECEIPT DOES AND DOES NOT ESTABLISH. It establishes that, given the
//! carried contributions and proofs, the claimed aggregate is exactly what the rule
//! yields -- that the issuer computed honestly over the set it showed you. It does NOT
//! establish that the issuer showed you every contribution it held. Withholding is a
//! separate property that needs the state root to be compared against an independently
//! obtained one, which is why `claimed_state_root` is carried and checked: two parties
//! with the same root saw the same set, and a party that withholds cannot produce a
//! receipt whose root matches the one everyone else converged on.

use crate::entry::{Contribution, EquivProof};
use crate::identity::Pki;
use crate::resolve::{resolve, Resolution, Rule};
use crate::state::State;

/// A self-contained, offline-checkable record of one resolved round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub round: u64,
    pub f: usize,
    pub rule: Rule,
    pub pki: Pki,
    pub contributions: Vec<Contribution>,
    pub proofs: Vec<EquivProof>,
    pub claimed_state_root: [u8; 32],
    pub claimed_output_root: [u8; 32],
    pub claimed_aggregate: Option<Vec<i64>>,
}

/// What the checker independently knows, obtained from somewhere other than the receipt.
///
/// **THIS TYPE IS THE TRUST BOUNDARY, AND WITHOUT IT VERIFICATION IS CIRCULAR.** A receipt
/// carries a PKI and a fault bound `f`, and both are attacker-chosen. Checking a receipt
/// against its own PKI proves only that *somebody* computed honestly over identities
/// *they* invented: mint five fresh keys, sign five contributions, and the result verifies
/// perfectly while corresponding to no real deployment. Likewise `f` -- a three-node
/// receipt declaring `f = 0` satisfies `n >= 2f+3` and reports itself population_bound_met.
///
/// So the security question is never "is this receipt internally consistent?" but "is this
/// receipt internally consistent **and** about the deployment I care about?". The policy is
/// how the caller supplies the second half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The identities the checker independently believes are participating.
    pub pki: Pki,
    /// The fault bound the checker's own robustness argument assumes.
    pub f: usize,
    /// The rule the checker expects, if it cares. `None` accepts either.
    pub rule: Option<Rule>,
}

impl Policy {
    pub fn new(pki: Pki, f: usize) -> Policy {
        Policy { pki, f, rule: None }
    }

    pub fn expecting(mut self, rule: Rule) -> Policy {
        self.rule = Some(rule);
        self
    }
}

/// The result of an internal-consistency check.
///
/// Deliberately carries **no** `population_bound_met` flag and no admitted identities. It is not a
/// security verdict and must not be presented as one: it says the receipt's arithmetic and
/// signatures agree with each other, nothing about whose signatures they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfConsistent {
    pub round: u64,
    pub state_root: [u8; 32],
    pub output_root: [u8; 32],
}

/// Why a receipt failed. Enumerated rather than boolean, because "this receipt is
/// invalid" is not actionable and "the aggregate does not match the admitted set" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// The receipt's identity set is not the one the checker expects. This is the
    /// fabricated-PKI case and it is the most important rejection in the enum.
    PkiMismatch,
    /// The receipt declares a different fault bound than the checker's policy assumes.
    FaultBoundMismatch { policy: usize, receipt: usize },
    /// The receipt used a different aggregation rule than the checker requires.
    RuleMismatch { policy: Rule, receipt: Rule },
    /// A carried contribution is not signed by its claimed author.
    BadContributionSignature { node_id: u32, leaf: [u8; 32] },
    /// A carried proof does not actually demonstrate equivocation.
    BogusProof { node_id: u32, leaf: [u8; 32] },
    /// A contribution is tagged for a different round than the receipt claims.
    WrongRound { expected: u64, found: u64 },
    /// The commitment trace does not cover the carried entries.
    StateRootMismatch { claimed: [u8; 32], actual: [u8; 32] },
    /// The claimed aggregate is not what the rule produces from the admitted set.
    AggregateMismatch {
        claimed: Option<Vec<i64>>,
        actual: Option<Vec<i64>>,
    },
    /// The claimed output root does not commit to the claimed aggregate.
    OutputRootMismatch { claimed: [u8; 32], actual: [u8; 32] },
}

/// What a receipt establishes once it verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub round: u64,
    pub state_root: [u8; 32],
    pub output_root: [u8; 32],
    pub aggregate: Option<Vec<i64>>,
    /// Identities admitted into this round's aggregate.
    pub admitted: Vec<u32>,
    /// Identities excluded by a valid equivocation proof CARRIED in the receipt.
    pub convicted: Vec<u32>,
    /// Identities the receipt PROVES equivocated but does not itself convict.
    ///
    /// The verifier derives this from the carried contributions rather than trusting the
    /// carried proofs. If a receipt holds two conflicting signed contributions from one
    /// identity and no proof against it, the evidence is present and the conviction was
    /// simply never computed. Reporting it separately is what makes withholding LABELLED
    /// instead of invisible: an issuer who never forms the proof produces an internally
    /// consistent receipt, and without this field a checker cannot tell "withheld" from
    /// "unnoticed".
    ///
    /// Non-empty does NOT invalidate the receipt. The aggregate is still correct, because
    /// the per-round uniqueness clause already excludes an identity with two visible
    /// entries. What is wrong is the accountability record, and that is worth naming.
    pub convictable_but_unconvicted: Vec<u32>,
    /// False when the admitted population was below the rule's robustness bound.
    ///
    /// A receipt can be perfectly valid and unpopulation_bound_met at the same time: the arithmetic
    /// is right, the signatures are right, and the result still carries no Byzantine
    /// guarantee because too few identities took part. Surfacing that separately is the
    /// difference between an honest receipt and a reassuring one.
    pub population_bound_met: bool,
}

impl Receipt {
    /// Build a receipt for a round from a state the issuer holds.
    pub fn issue(state: &State, round: u64, pki: &Pki, f: usize, rule: Rule) -> Receipt {
        let r: Resolution = resolve(state, round, pki, f, rule);

        // SCOPE THE CARRIED SET TO THIS ROUND, and commit to the root of what is carried.
        //
        // `recompute` refuses any contribution whose `rnd` differs from the receipt's, so
        // carrying the issuer's whole state made every receipt from a state that had lived
        // through more than one round unverifiable -- `issue` and `verify` disagreed about
        // what a receipt is. Scoping here rather than relaxing the check there is the
        // correct direction: a receipt is a statement about ONE round, and a verifier that
        // accepted foreign-round entries would be checking a commitment over a set it never
        // examined.
        //
        // Proofs are NOT scoped. Conviction is permanent -- the proof set is grow-only, and
        // an identity that equivocated in round 1 is still convicted in round 5 -- so
        // filtering proofs by round would silently un-convict across rounds. `resolve`
        // already takes conviction from the whole proof set, and `recompute` round-checks
        // contributions only, so this is the view both sides already agree on.
        let mut carried = State::new();
        for c in state.c.values().filter(|c| c.rnd == round) {
            carried.add_contribution(c.clone());
        }
        for p in state.e.values() {
            carried.add_proof(p.clone());
        }

        Receipt {
            round,
            f,
            rule,
            pki: pki.clone(),
            contributions: carried.c.values().cloned().collect(),
            proofs: carried.e.values().cloned().collect(),
            claimed_state_root: carried.root(),
            claimed_output_root: r.output_root,
            claimed_aggregate: r.aggregate,
        }
    }

    /// Verify against what the checker independently knows. **This is the security
    /// entry point.**
    ///
    /// The policy check runs FIRST and is not a formality: it is what stops a receipt
    /// certifying itself. A receipt whose PKI the checker does not recognise is rejected
    /// before any signature is examined, because every signature in it would verify
    /// perfectly against the keys the forger chose.
    pub fn verify(&self, policy: &Policy) -> Result<Verified, Invalid> {
        if self.pki != policy.pki {
            return Err(Invalid::PkiMismatch);
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
        self.recompute()
    }

    /// Check that the receipt agrees with itself, against its own carried PKI.
    ///
    /// **NOT A SECURITY VERDICT.** Use [`Receipt::verify`] with a [`Policy`] for that.
    /// This exists for diagnosis -- inspecting a receipt whose deployment you do not know,
    /// or triaging which of several failures is present -- and it returns a type with no
    /// `population_bound_met` flag precisely so its result cannot be reported as a safe one.
    pub fn check_self_consistent(&self) -> Result<SelfConsistent, Invalid> {
        let v = self.recompute()?;
        Ok(SelfConsistent {
            round: v.round,
            state_root: v.state_root,
            output_root: v.output_root,
        })
    }

    /// Recompute everything and check it against what was claimed.
    ///
    /// Order matters: cryptography before arithmetic. Signatures and proofs are checked
    /// first, so a receipt stuffed with forged entries is rejected as forged rather than
    /// as "aggregate mismatch", which would misattribute the fault.
    fn recompute(&self) -> Result<Verified, Invalid> {
        // 1. Every carried contribution must be genuinely signed.
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

        // 2. Every carried proof must genuinely demonstrate equivocation. A receipt
        //    that convicts an identity on a bogus proof is a censorship tool, so this
        //    is a hard failure and not a filter.
        for p in &self.proofs {
            if !p.valid(&self.pki) {
                return Err(Invalid::BogusProof {
                    node_id: p.node_id,
                    leaf: p.leaf(),
                });
            }
        }

        // 3. Rebuild the state from the carried entries and check the commitment trace.
        let mut state = State::new();
        for c in &self.contributions {
            state.add_contribution(c.clone());
        }
        for p in &self.proofs {
            state.add_proof(p.clone());
        }
        let actual_state_root = state.root();
        if actual_state_root != self.claimed_state_root {
            return Err(Invalid::StateRootMismatch {
                claimed: self.claimed_state_root,
                actual: actual_state_root,
            });
        }

        // 4. Re-execute the aggregate. This is the load-bearing step: it is an
        //    independent recomputation, not a check of the issuer's arithmetic.
        let r = resolve(&state, self.round, &self.pki, self.f, self.rule);
        if r.aggregate != self.claimed_aggregate {
            return Err(Invalid::AggregateMismatch {
                claimed: self.claimed_aggregate.clone(),
                actual: r.aggregate,
            });
        }
        if r.output_root != self.claimed_output_root {
            return Err(Invalid::OutputRootMismatch {
                claimed: self.claimed_output_root,
                actual: r.output_root,
            });
        }

        let admitted_leaves: std::collections::BTreeSet<[u8; 32]> =
            r.admitted.iter().copied().collect();
        let mut admitted: Vec<u32> = self
            .contributions
            .iter()
            .filter(|c| admitted_leaves.contains(&c.leaf()))
            .map(|c| c.node_id)
            .collect();
        admitted.sort_unstable();

        // Derive convictions from the carried contributions. `add_contribution` above is
        // a raw insert that runs no detection, so this is information the receipt holds
        // and has not computed.
        let mut derived = State::new();
        for c in &self.contributions {
            derived.deliver(c.clone(), &self.pki);
        }
        let already: std::collections::BTreeSet<u32> = state.convicted(&self.pki);
        let mut convictable: Vec<u32> = derived
            .convicted(&self.pki)
            .into_iter()
            .filter(|n| !already.contains(n))
            .collect();
        convictable.sort_unstable();

        Ok(Verified {
            round: self.round,
            state_root: actual_state_root,
            output_root: r.output_root,
            aggregate: r.aggregate,
            admitted,
            convicted: already.iter().copied().collect(),
            convictable_but_unconvicted: convictable,
            population_bound_met: r.population_bound_met,
        })
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

    fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
        let th = h(&enc_tensor(t));
        Contribution {
            rnd,
            node_id: a.node_id,
            tensor: t.to_vec(),
            sig: a.sign(&contrib_msg(rnd, &th)),
        }
    }

    fn room(n: u32) -> (Vec<Identity>, Pki) {
        let ids: Vec<Identity> = (1..=n).map(ident).collect();
        let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
        (ids, pki)
    }

    fn honest_state(ids: &[Identity], pki: &Pki) -> State {
        let mut s = State::new();
        for (i, id) in ids.iter().enumerate() {
            s.deliver(contrib(id, 1, &[i as i64 * 3, i as i64 + 1]), pki);
        }
        s
    }

    #[test]
    fn an_honestly_issued_receipt_verifies() {
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let v = Receipt::issue(&s, 1, &pki, 1, Rule::Krum)
            .verify(&Policy::new(pki.clone(), 1))
            .unwrap();
        assert_eq!(v.admitted.len(), 5);
        assert!(v.population_bound_met);
        assert!(v.convicted.is_empty());
    }

    #[test]
    fn a_tampered_aggregate_is_caught_by_re_execution() {
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);
        r.claimed_aggregate.as_mut().unwrap()[0] += 1;
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::AggregateMismatch { .. })
        ));
    }

    #[test]
    fn dropping_a_contribution_breaks_the_commitment_trace() {
        // The withholding check. Remove an entry the root committed to; the receipt
        // can no longer reproduce the root anyone else converged on.
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);
        r.contributions.pop();
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::StateRootMismatch { .. })
        ));
    }

    #[test]
    fn a_forged_contribution_is_rejected_as_forged() {
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);
        r.contributions[0].tensor[0] = 4242;
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::BadContributionSignature { .. })
        ));
    }

    #[test]
    fn a_bogus_conviction_cannot_be_smuggled_in() {
        // A receipt that convicts an innocent identity on an unverifiable proof is a
        // censorship tool. It must fail closed.
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, 1, &pki, 1, Rule::Krum);
        r.proofs.push(EquivProof {
            rnd: 1,
            node_id: 2,
            h1: [7u8; 32],
            h2: [8u8; 32],
            sig1: [0u8; 64],
            sig2: [0u8; 64],
        });
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::BogusProof { .. })
        ));
    }

    #[test]
    fn a_receipt_over_an_equivocation_verifies_and_names_the_culprit() {
        let (ids, pki) = room(5);
        let mut s = honest_state(&ids, &pki);
        s.deliver(contrib(&ids[0], 1, &[9999, 9999]), &pki);
        let v = Receipt::issue(&s, 1, &pki, 1, Rule::Krum)
            .verify(&Policy::new(pki.clone(), 1))
            .unwrap();
        assert_eq!(v.convicted, vec![1]);
        assert!(!v.admitted.contains(&1), "the equivocator is not counted");
    }

    #[test]
    fn an_unpopulation_bound_met_round_verifies_but_says_so() {
        let (ids, pki) = room(3);
        let s = honest_state(&ids, &pki);
        // n = 3 < 2f + 3 = 5 at f = 1.
        let v = Receipt::issue(&s, 1, &pki, 1, Rule::Krum)
            .verify(&Policy::new(pki.clone(), 1))
            .unwrap();
        assert!(
            !v.population_bound_met,
            "a valid receipt must not imply a population_bound_met one"
        );
    }

    #[test]
    fn two_replicas_that_saw_the_same_set_issue_identical_receipts() {
        let (ids, pki) = room(5);
        let cs: Vec<Contribution> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| contrib(id, 1, &[i as i64 * 3, i as i64 + 1]))
            .collect();
        let mut a = State::new();
        for c in &cs {
            a.deliver(c.clone(), &pki);
        }
        let mut b = State::new();
        for c in cs.iter().rev() {
            b.deliver(c.clone(), &pki);
        }
        let ra = Receipt::issue(&a, 1, &pki, 1, Rule::Krum);
        let rb = Receipt::issue(&b, 1, &pki, 1, Rule::Krum);
        assert_eq!(ra.claimed_state_root, rb.claimed_state_root);
        assert_eq!(ra.claimed_output_root, rb.claimed_output_root);
        assert_eq!(crate::wire::encode(&ra), crate::wire::encode(&rb));
    }

    /// crypto-05 / crdt-04: a state that has lived through more than one round must still
    /// issue a verifiable receipt.
    ///
    /// `issue` carried the issuer's ENTIRE contribution map while `recompute` refuses any
    /// contribution whose round differs from the receipt's. So the moment a node processed
    /// a second round, every receipt it issued -- for any round, including the current one
    /// -- failed with WrongRound. The two halves of the same type disagreed about what a
    /// receipt contains, and no single-round test could see it.
    #[test]
    fn a_multi_round_state_still_issues_a_verifiable_receipt() {
        let (ids, pki) = room(5);
        let mut st = State::new();

        for (i, id) in ids.iter().enumerate() {
            st.deliver(contrib(id, 1, &[(i as i64 + 1) << 16, 0]), &pki);
        }
        let r1 = Receipt::issue(&st, 1, &pki, 1, Rule::Krum);
        assert!(
            r1.verify(&Policy::new(pki.clone(), 1)).is_ok(),
            "single-round receipt must verify"
        );

        // Second round into the SAME state -- this is ordinary operation, not an attack.
        for (i, id) in ids.iter().enumerate() {
            st.deliver(contrib(id, 2, &[(i as i64 + 7) << 16, 0]), &pki);
        }

        let r1_again = Receipt::issue(&st, 1, &pki, 1, Rule::Krum);
        assert!(
            r1_again.verify(&Policy::new(pki.clone(), 1)).is_ok(),
            "a round-1 receipt issued from a two-round state must still verify"
        );
        let r2 = Receipt::issue(&st, 2, &pki, 1, Rule::Krum);
        assert!(
            r2.verify(&Policy::new(pki.clone(), 1)).is_ok(),
            "a round-2 receipt from the same state must verify"
        );

        // And it must carry only its own round, or the round check is vacuous.
        assert!(
            r2.contributions.iter().all(|c| c.rnd == 2),
            "receipt carried a foreign round's contributions"
        );
        assert_ne!(
            r1_again.claimed_state_root, r2.claimed_state_root,
            "distinct rounds must commit to distinct state roots"
        );
    }
}
