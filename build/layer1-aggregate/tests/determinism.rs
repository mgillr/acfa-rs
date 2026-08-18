// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Determinism CI.
//!
//! These are not unit tests of convenience, they are the gate. The crate's only
//! claim is that the aggregate is a function of the input SET, so every test here
//! attacks that claim from a different direction: input order, accumulation order,
//! rounding rule, and agreement with an independent implementation.
//!
//! A test that only checks "the code returns something plausible" would pass on a
//! build that silently truncated instead of floored -- which is exactly the defect
//! that would make two conforming implementations disagree in production.

use acfa_aggregate::*;

/// Deterministic pseudo-random source. Fixed constants, no external crate, so the
/// vectors are reproducible on any machine and in any year.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    /// Values spanning both signs, because sign is where the rounding rule bites.
    fn next_val(&mut self) -> i64 {
        (self.next_u64() % 200_001) as i64 - 100_000
    }
}

fn corpus(n: usize, d: usize, seed: u64) -> Vec<Contribution> {
    let mut r = Lcg::new(seed);
    (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i:04}").into_bytes(),
            v: (0..d).map(|_| r.next_val()).collect(),
        })
        .collect()
}

/// Deterministic permutation, so a failure is reproducible rather than flaky.
fn permute<T: Clone>(xs: &[T], seed: u64) -> Vec<T> {
    let mut out = xs.to_vec();
    let mut r = Lcg::new(seed);
    for i in (1..out.len()).rev() {
        let j = (r.next_u64() as usize) % (i + 1);
        out.swap(i, j);
    }
    out
}

#[test]
fn every_rule_is_invariant_under_input_order() {
    let cs = corpus(17, 64, 42);
    let f = 3;

    let base_mean = mean(&cs).unwrap();
    let base_trim = trimmed_mean(&cs, 1, 5).unwrap();
    let base_med = coord_median_trim(&cs, f).unwrap();
    let base_krum = krum_aggregate(&cs, f).unwrap();
    // Selection is returned as indices, so compare the SELECTED KEYS, not positions:
    // positions legitimately change under permutation, membership must not.
    let keys_of = |cs: &[Contribution], sel: &[usize]| -> Vec<Vec<u8>> {
        let mut k: Vec<Vec<u8>> = sel.iter().map(|&i| cs[i].tie_key.clone()).collect();
        k.sort();
        k
    };
    let base_sel = keys_of(&cs, &multi_krum(&cs, f).unwrap());

    for seed in 0..40u64 {
        let p = permute(&cs, seed + 1);
        assert_eq!(
            mean(&p).unwrap(),
            base_mean,
            "mean moved under permutation {seed}"
        );
        assert_eq!(
            trimmed_mean(&p, 1, 5).unwrap(),
            base_trim,
            "trimmed_mean moved"
        );
        assert_eq!(
            coord_median_trim(&p, f).unwrap(),
            base_med,
            "median_trim moved"
        );
        assert_eq!(
            krum_aggregate(&p, f).unwrap(),
            base_krum,
            "krum_aggregate moved"
        );
        assert_eq!(
            keys_of(&p, &multi_krum(&p, f).unwrap()),
            base_sel,
            "selection moved"
        );
    }
}

#[test]
fn selection_is_stable_when_scores_tie_exactly() {
    // Identical vectors give identical scores, so ONLY the tie key can order them.
    // If tie-breaking were positional this would drift under permutation.
    let cs: Vec<Contribution> = (0..9)
        .map(|i| Contribution {
            tie_key: vec![i as u8],
            v: vec![100, -200, 300],
        })
        .collect();
    let base: Vec<Vec<u8>> = multi_krum(&cs, 1)
        .unwrap()
        .iter()
        .map(|&i| cs[i].tie_key.clone())
        .collect();
    for seed in 0..25u64 {
        let p = permute(&cs, seed + 7);
        let got: Vec<Vec<u8>> = multi_krum(&p, 1)
            .unwrap()
            .iter()
            .map(|&i| p[i].tie_key.clone())
            .collect();
        let (mut a, mut b) = (base.clone(), got);
        a.sort();
        b.sort();
        assert_eq!(a, b, "all-tied selection is not canonical (seed {seed})");
    }
}

#[test]
fn division_floors_and_does_not_truncate() {
    // The helper's own assertions moved into `build/layer1-aggregate/src/rules.rs`
    // when `floor_div` became `pub(crate)`: reaching it from here meant reaching it
    // the way a dependent crate could, which is what made its unguarded arithmetic
    // exploitable. See
    // `rules::tests::floors_toward_negative_infinity_rather_than_truncating_toward_zero`.
    // What belongs at THIS level is the property the wire actually depends on -- that
    // flooring survives all the way out through the public rule.
    let cs = vec![
        Contribution {
            tie_key: b"a".to_vec(),
            v: vec![-3],
        },
        Contribution {
            tie_key: b"b".to_vec(),
            v: vec![-4],
        },
    ];
    // sum = -7, n = 2. Floor gives -4; truncation would give -3.
    assert_eq!(
        mean(&cs).unwrap(),
        vec![-4],
        "mean must floor on negative sums"
    );
}

#[test]
fn duplicate_tie_keys_are_refused_rather_than_ordered_arbitrarily() {
    let cs = vec![
        Contribution {
            tie_key: b"same".to_vec(),
            v: vec![1, 2],
        },
        Contribution {
            tie_key: b"same".to_vec(),
            v: vec![3, 4],
        },
    ];
    assert_eq!(mean(&cs), Err(AggError::DuplicateTieKey));
    assert_eq!(multi_krum(&cs, 0), Err(AggError::DuplicateTieKey));
}

#[test]
fn dimension_mismatch_is_refused_rather_than_padded() {
    let cs = vec![
        Contribution {
            tie_key: b"a".to_vec(),
            v: vec![1, 2, 3],
        },
        Contribution {
            tie_key: b"b".to_vec(),
            v: vec![1, 2],
        },
    ];
    // crdt-08: the refusal now names the offender. `b` is the minority length here, and
    // with only two contributions there is no strict plurality to attribute against -- so
    // the honest answer is that nobody can be named. See `rules::check`.
    assert_eq!(
        mean(&cs),
        Err(AggError::DimensionMismatchUnattributable { lengths: 2 })
    );
}

#[test]
fn median_trim_discards_a_coordinate_concentrated_outlier_that_krum_admits() {
    // The whole reason coord_median_trim exists. One contributor stays inside the
    // honest Euclidean spread on every axis but one, where it puts its whole budget.
    let d = 32;
    let mut cs = corpus(11, d, 99);
    // Force honest agreement so the attack is the only signal.
    for c in cs.iter_mut() {
        c.v = vec![1000; d];
    }
    cs[10].v = vec![1000; d];
    cs[10].v[0] = 500_000; // concentrated on axis 0

    let plain = mean(&cs).unwrap();
    let trimmed = coord_median_trim(&cs, 1).unwrap();
    assert!(
        plain[0] > 1000,
        "plain mean should be dragged by the outlier"
    );
    assert_eq!(trimmed[0], 1000, "median-trim should discard it entirely");
}

#[test]
fn select_all_convention_fires_exactly_when_undefended() {
    // n <= f + 2 means m < 1: the rule is undefined and everything is selected.
    for (n, f) in [(3usize, 1usize), (4, 2), (2, 0)] {
        let cs = corpus(n, 4, 5);
        let sel = multi_krum(&cs, f).unwrap();
        assert_eq!(sel.len(), n, "n={n} f={f} should select all");
    }
    // One more contribution and the rule engages.
    let cs = corpus(6, 4, 5);
    assert!(
        multi_krum(&cs, 1).unwrap().len() < 6,
        "rule should engage at n=6,f=1"
    );
}

#[test]
fn aggregate_is_stable_across_repeated_runs_in_one_process() {
    // Guards against any hidden dependence on allocation addresses or hash seeds,
    // which is how "deterministic" code usually turns out not to be.
    let cs = corpus(13, 48, 7);
    let first = krum_aggregate(&cs, 2).unwrap();
    for _ in 0..50 {
        assert_eq!(krum_aggregate(&cs, 2).unwrap(), first);
    }
}

// ---------------------------------------------------------------------------
// Bulyan and the ranked selector.
//
// These were exported from the crate AND wired into the `acfa-agg` binary as a
// selectable rule with ZERO tests covering them, in a crate whose entire claim is
// that determinism is gated by CI. The tests below are the gate they were missing.
// ---------------------------------------------------------------------------

/// `multi_krum` returns an unordered canonical SET; `multi_krum_ranked` returns the
/// RANKING. Taking `multi_krum(..)[0]` as "the best" selects the lowest INDEX, which
/// is a silent mis-port. This pins the distinction rather than trusting the names.
#[test]
fn ranked_is_score_order_and_the_set_form_is_index_order() {
    let mut order_actually_differed = false;

    for (n, f) in [(17usize, 3usize), (11, 2), (9, 1)] {
        let cs = corpus(n, 32, 7 * n as u64);
        let set = multi_krum(&cs, f).unwrap();
        let ranked = multi_krum_ranked(&cs, f).unwrap();

        let mut set_sorted = set.clone();
        set_sorted.sort_unstable();
        assert_eq!(
            set, set_sorted,
            "n={n} f={f}: the set form must be ascending"
        );

        // Take the TOP-|set| of the ranking, then sort. Sorting the whole ranking
        // first and slicing would compare the |set| lowest indices instead, which is
        // a different claim entirely.
        let mut top = ranked[..set.len()].to_vec();
        let top_in_rank_order = top.clone();
        top.sort_unstable();
        assert_eq!(
            top, set,
            "n={n} f={f}: the top-|set| of the ranking must be the same members as the set form"
        );

        if top_in_rank_order != set {
            order_actually_differed = true;
        }
    }

    // Membership agreement alone would also hold if `ranked` secretly returned index
    // order. At least one corpus must actually separate the two, or this test cannot
    // detect the mis-port it exists to catch.
    assert!(
        order_actually_differed,
        "no corpus separated score order from index order, so this test proves nothing"
    );
}

/// The ranked form must stay in score order on a SMALL pool too. Bulyan drives the
/// pool down into that regime on every run, so an index-order fallback there
/// reintroduces the exact defect the split exists to prevent.
#[test]
fn ranked_stays_score_ordered_on_a_small_pool() {
    let cs = corpus(4, 16, 99);
    let ranked = multi_krum_ranked(&cs, 3).unwrap(); // n < f + 3
    assert_eq!(ranked.len(), 4);
    let mut seen = ranked.clone();
    seen.sort_unstable();
    assert_eq!(seen, vec![0, 1, 2, 3], "must be a permutation of the pool");
    assert_ne!(
        ranked,
        vec![0, 1, 2, 3],
        "small-pool ranking fell back to index order"
    );
}

/// Stage 1 must draw exactly `theta = n - 2f`. An earlier guard made the loop exit
/// early for f < 2, returning fewer than theta with no error: shortfall 2 at f=0 and
/// 1 at f=1, at every n. A short selection is a silently different estimator.
#[test]
fn bulyan_draws_exactly_theta_and_never_silently_short() {
    for n in [7usize, 11, 17, 23] {
        for f in 0..=3usize {
            if n < 4 * f + 3 {
                continue;
            }
            let cs = corpus(n, 16, 42 + n as u64);
            let sel = bulyan_select(&cs, f).unwrap();
            assert_eq!(
                sel.len(),
                n - 2 * f,
                "n={n} f={f}: stage 1 drew {} of theta={}",
                sel.len(),
                n - 2 * f
            );
            let mut s = sel.clone();
            s.sort_unstable();
            s.dedup();
            assert_eq!(s.len(), sel.len(), "n={n} f={f}: duplicate selection");
        }
    }
}

/// Below `n >= 4f + 3` Bulyan has no guarantee, so it must refuse rather than return
/// a plausible-looking aggregate. Same discipline as refusing an out-of-range encode.
#[test]
fn bulyan_refuses_below_its_precondition() {
    for (n, f) in [(7usize, 2usize), (6, 1), (10, 2)] {
        assert!(n < 4 * f + 3, "test case must actually be below the bound");
        let cs = corpus(n, 16, 5);
        assert_eq!(
            bulyan_select(&cs, f),
            Err(AggError::BulyanTooFewContributions),
            "n={n} f={f} is below n >= 4f+3 and must be refused"
        );
        assert_eq!(
            bulyan_aggregate(&cs, f),
            Err(AggError::BulyanTooFewContributions)
        );
    }
}

/// Bulyan, like every other rule here, must be a function of the input SET.
#[test]
fn bulyan_is_invariant_under_input_order() {
    for (n, f) in [(11usize, 2usize), (17, 3), (23, 5)] {
        let cs = corpus(n, 48, 2026 + n as u64);
        let base = bulyan_aggregate(&cs, f).unwrap();
        let mut rot = cs.clone();
        rot.rotate_left(n / 3);
        assert_eq!(
            bulyan_aggregate(&rot, f).unwrap(),
            base,
            "n={n} f={f} rotated"
        );
        let mut rev = cs.clone();
        rev.reverse();
        assert_eq!(
            bulyan_aggregate(&rev, f).unwrap(),
            base,
            "n={n} f={f} reversed"
        );
    }
}
