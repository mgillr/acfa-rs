// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Resolution: the pure total function from converged state to aggregate.
//!
//! This is where Layer 2 hands off to Layer 1. Layer 2 decides WHO is admitted; Layer 1
//! decides WHAT their vectors aggregate to. The split is not cosmetic -- Layer 1 never
//! hashes, signs, verifies or reads a clock, so it discloses nothing about the receipt
//! scheme and can be published on its own.
//!
//! The contract Theorem 7 needs is that `resolve` is a pure total function of the
//! converged `(C, E)` product state: same state in, same bytes out, on any machine, with
//! no ambient randomness and no float anywhere on the path.

use crate::hash::{enc_tensor, h};
use crate::identity::Pki;
use crate::state::State;
use acfa_aggregate::{
    bulyan_aggregate, krum_aggregate_certified, Contribution as AggContribution, MarginCertificate,
};

/// Which robust rule to apply to the admitted set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Multi-Krum, then floor-average the selection. Robustness needs `n >= 2f + 3`.
    Krum,
    /// Bulyan: Krum-iterated selection, then the coordinate-wise trimmed stage.
    /// Stricter precondition, `n >= 4f + 3`, and defends the coordinate-concentrated
    /// attack that plain Krum admits.
    Bulyan,
}

impl Rule {
    pub fn as_wire(&self) -> u8 {
        match self {
            Rule::Krum => 0,
            Rule::Bulyan => 1,
        }
    }
    pub fn from_wire(b: u8) -> Option<Rule> {
        match b {
            0 => Some(Rule::Krum),
            1 => Some(Rule::Bulyan),
            _ => None,
        }
    }
    /// The admitted-population bound this rule's robustness argument rests on.
    ///
    /// SATURATES. `f` arrives from an untrusted receipt, and `2*f + 3` in `usize` WRAPPED:
    /// at `f = usize::MAX` the bound came out as **1**, so a receipt declaring a huge fault
    /// bound satisfied the Krum population bound with a SINGLE admitted contribution. That
    /// is the guard failing OPEN -- the larger the claimed adversary budget, the weaker the
    /// requirement became. Saturating makes an unmeetable claim unmeetable: no admitted set
    /// can reach `usize::MAX`, so the bound is reported as not met, which is the honest
    /// answer for a fault bound nobody can satisfy.
    pub fn required_n(&self, f: usize) -> usize {
        let k: usize = match self {
            Rule::Krum => 2,
            Rule::Bulyan => 4,
        };
        k.saturating_mul(f).saturating_add(3)
    }
}

/// The outcome of resolving one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// `None` when nothing was admitted. An empty round is a legitimate, and
    /// committed-to, outcome -- not an error and not a zero vector.
    pub aggregate: Option<Vec<i64>>,
    pub output_root: [u8; 32],
    /// Leaves of the admitted set, in hash-canonical order. Carried so a verifier can
    /// see exactly WHO was counted without re-deriving the filter.
    pub admitted: Vec<[u8; 32]>,
    /// True when the admitted population met the rule's robustness precondition.
    ///
    /// A resolution below the bound is still deterministic and still re-executable --
    /// it is simply UNDEFENDED, and saying so is the honest reporting the whole
    /// construction is for. It is a flag rather than an error precisely so that it
    /// cannot be silently discarded.
    pub population_bound_met: bool,
    /// Lemma 12's no-flip certificate for this round, when the rule and the configuration
    /// admit one.
    ///
    /// **Recomputed, never carried.** It is not on the wire and not in any root: every
    /// verifier derives it independently from the admitted set, so there is nothing here for
    /// an issuer to forge or to omit. That is also why adding it changes no encoding and
    /// cannot move the cross-architecture fingerprint.
    ///
    /// `None` means no certificate is available, which is NOT the same as "not certified" and
    /// must never be reported as a negative result. It arises when the round admitted nothing,
    /// when the kernel refused, when the select-all band fired (no selection boundary exists),
    /// or under Bulyan -- Lemma 12 is stated for multi-Krum's boundary and extending it to
    /// Bulyan's iterated selection is not a change this crate may make on its own authority.
    pub margin: Option<MarginCertificate>,
}

/// Resolve one round against the state.
///
/// Total: every input produces a resolution. The empty-admitted case commits to a
/// distinct sentinel `H("none|" || round)` rather than to the hash of an empty vector,
/// so "nobody contributed" and "everybody contributed zero" are different commitments.
pub fn resolve(state: &State, rnd: u64, pki: &Pki, f: usize, rule: Rule) -> Resolution {
    let adm = state.admit(rnd, pki);
    let admitted: Vec<[u8; 32]> = adm.iter().map(|c| c.leaf()).collect();

    if adm.is_empty() {
        let mut b = Vec::with_capacity(5 + 8);
        b.extend_from_slice(b"none|");
        b.extend_from_slice(&rnd.to_be_bytes());
        return Resolution {
            aggregate: None,
            output_root: h(&b),
            admitted,
            population_bound_met: false,
            margin: None,
        };
    }

    let cs: Vec<AggContribution> = adm
        .iter()
        .map(|c| AggContribution {
            tie_key: c.leaf().to_vec(),
            v: c.tensor.clone(),
        })
        .collect();

    // `cs` is built from `adm` -- the ADMITTED set -- so the certificate below is computed
    // over exactly the set that produces the aggregate, which is what Lemma 12's `|A|` means.
    // Computing it over the raw carried contributions instead would be a different problem
    // instance whenever anything was excluded or convicted. (C, adversarial review.)
    let (agg, margin) = match rule {
        Rule::Krum => match krum_aggregate_certified(&cs, f) {
            Ok((a, cert)) => (Ok(a), cert),
            Err(e) => (Err(e), None),
        },
        Rule::Bulyan => (bulyan_aggregate(&cs, f), None),
    };

    match agg {
        Ok(a) => {
            let mut b = Vec::with_capacity(4 + a.len() * 8);
            b.extend_from_slice(b"agg|");
            b.extend_from_slice(&enc_tensor(&a));
            Resolution {
                output_root: h(&b),
                aggregate: Some(a),
                admitted,
                population_bound_met: adm.len() >= rule.required_n(f),
                margin,
            }
        }
        // Layer 1 refuses rather than guessing on malformed input (dimension mismatch,
        // duplicate tie keys). That refusal is itself a deterministic outcome and is
        // committed to as such, so two replicas agree that the round produced nothing.
        Err(_) => {
            let mut b = Vec::with_capacity(8 + 8);
            b.extend_from_slice(b"refused|");
            b.extend_from_slice(&rnd.to_be_bytes());
            Resolution {
                aggregate: None,
                output_root: h(&b),
                admitted,
                population_bound_met: false,
                // The kernel refused, so there is no selection and therefore no boundary to
                // certify. `None` is "no certificate available", never "not certified".
                margin: None,
            }
        }
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
    use crate::entry::Contribution;
    use crate::identity::{contrib_msg, Identity};

    fn ident(n: u32) -> Identity {
        Identity::from_secret(n, &[n as u8; 32])
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

    fn room(n: u32) -> (Vec<Identity>, Pki) {
        let ids: Vec<Identity> = (1..=n).map(ident).collect();
        let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
        (ids, pki)
    }

    #[test]
    fn an_empty_round_commits_to_a_sentinel_not_to_a_zero_vector() {
        let (_, pki) = room(3);
        let r = resolve(&State::new(), 1, &pki, 1, Rule::Krum);
        assert!(r.aggregate.is_none());
        assert!(!r.population_bound_met);
        let mut b = b"none|".to_vec();
        b.extend_from_slice(&1u64.to_be_bytes());
        assert_eq!(r.output_root, h(&b));
    }

    #[test]
    fn resolution_is_invariant_under_delivery_order() {
        let (ids, pki) = room(5);
        let cs: Vec<Contribution> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| contrib(id, 1, &[i as i64 * 10, i as i64]))
            .collect();

        let mut fwd = State::new();
        for c in &cs {
            fwd.deliver(c.clone(), &pki);
        }
        let mut rev = State::new();
        for c in cs.iter().rev() {
            rev.deliver(c.clone(), &pki);
        }
        let a = resolve(&fwd, 1, &pki, 1, Rule::Krum);
        let b = resolve(&rev, 1, &pki, 1, Rule::Krum);
        assert_eq!(a, b, "resolution must be a function of the SET");
    }

    #[test]
    fn the_population_bound_met_flag_reports_the_bound_honestly() {
        let (ids, pki) = room(5);
        let mut s = State::new();
        for (i, id) in ids.iter().enumerate() {
            s.deliver(contrib(id, 1, &[i as i64]), &pki);
        }
        // n = 5 meets Krum's 2f+3 = 5 at f = 1, but not Bulyan's 4f+3 = 7.
        assert!(resolve(&s, 1, &pki, 1, Rule::Krum).population_bound_met);
        assert!(!resolve(&s, 1, &pki, 1, Rule::Bulyan).population_bound_met);
    }

    #[test]
    fn an_equivocator_changes_the_aggregate_by_being_excluded() {
        let (ids, pki) = room(5);
        let mut honest = State::new();
        for (i, id) in ids.iter().enumerate() {
            honest.deliver(contrib(id, 1, &[i as i64]), &pki);
        }
        let mut cheating = honest.clone();
        cheating.deliver(contrib(&ids[0], 1, &[9999]), &pki); // node 1 equivocates
        let a = resolve(&honest, 1, &pki, 1, Rule::Krum);
        let b = resolve(&cheating, 1, &pki, 1, Rule::Krum);
        assert_ne!(a.admitted, b.admitted);
        assert_eq!(
            b.admitted.len(),
            4,
            "the equivocator is dropped, not counted"
        );
    }

    #[test]
    fn a_dimension_mismatch_resolves_to_a_committed_refusal_rather_than_a_panic() {
        let (ids, pki) = room(5);
        let mut s = State::new();
        s.deliver(contrib(&ids[0], 1, &[1, 2]), &pki);
        s.deliver(contrib(&ids[1], 1, &[1]), &pki); // ragged
        s.deliver(contrib(&ids[2], 1, &[3, 4]), &pki);
        let r = resolve(&s, 1, &pki, 1, Rule::Krum);
        assert!(r.aggregate.is_none());
        let mut b = b"refused|".to_vec();
        b.extend_from_slice(&1u64.to_be_bytes());
        assert_eq!(r.output_root, h(&b));
    }
}
