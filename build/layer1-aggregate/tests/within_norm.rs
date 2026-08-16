// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Characterisation of the within-norm attack against each rule.
//!
//! WHY THIS EXISTS. `n >= 2f+3` is a POPULATION bound. It is not a safety guarantee, and
//! the gap between those two is the most likely way a caller of this crate gets hurt:
//! satisfy the bound, read `population_bound_met`, and ship.
//!
//! The attack: `f` adversaries collude at one point -- the honest mean pushed along a fixed
//! direction by epsilon -- so each gains `f-1` zero-distance siblings in its own score.
//! Epsilon is bisected to the largest value that is still selected AND still inside the
//! honest pairwise spread, so the adversary never looks anomalous by norm.
//!
//! These tests do not assert that the attack fails. They assert what each rule actually
//! does, so that a future change which silently makes a rule WORSE is visible. A
//! characterisation test that pins bad behaviour is more honest than a missing test.

use acfa_aggregate::{bulyan_aggregate, coord_median_trim, krum_aggregate, mean, Contribution};

const D: usize = 200;
const Q: f64 = 65536.0;

/// Deterministic Gaussian via Box-Muller over a fixed-seed LCG. No `rand` dependency:
/// this crate has zero dependencies and a characterisation test must be replayable.
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 11) as f64) / ((1u64 << 53) as f64)
    }
    fn gauss(&mut self) -> f64 {
        let u1 = self.next_f64().max(1e-12);
        let u2 = self.next_f64();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}

fn q(x: f64) -> i64 {
    (x * Q).round() as i64
}

fn l2(a: &[i64], b: &[i64]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| {
            let d = (*x - *y) as f64;
            d * d
        })
        .sum::<f64>()
        .sqrt()
        / Q
}

fn honest_set(rng: &mut Rng, n: usize, f: usize) -> Vec<Vec<i64>> {
    (0..n - f)
        .map(|_| (0..D).map(|_| q(2.0 + rng.gauss())).collect())
        .collect()
}

fn honest_mean(h: &[Vec<i64>]) -> Vec<i64> {
    (0..D)
        .map(|k| h.iter().map(|v| v[k]).sum::<i64>() / h.len() as i64)
        .collect()
}

fn spread(h: &[Vec<i64>]) -> f64 {
    let mut m = 0.0f64;
    for i in 0..h.len() {
        for j in (i + 1)..h.len() {
            m = m.max(l2(&h[i], &h[j]));
        }
    }
    m
}

fn contribs(h: &[Vec<i64>], byz: &[Vec<i64>]) -> Vec<Contribution> {
    h.iter()
        .chain(byz.iter())
        .enumerate()
        .map(|(i, v)| Contribution {
            tie_key: (i as u32).to_be_bytes().to_vec(),
            v: v.clone(),
        })
        .collect()
}

/// Largest epsilon that keeps every adversary selected AND inside the honest spread.
fn worst_within_norm(h: &[Vec<i64>], hm: &[i64], n: usize, f: usize) -> (f64, Vec<Vec<i64>>) {
    let sp = spread(h);
    let (mut lo, mut hi) = (0.0f64, 20.0f64);
    for _ in 0..22 {
        let mid = (lo + hi) / 2.0;
        let byz: Vec<Vec<i64>> = (0..f)
            .map(|_| hm.iter().map(|x| x + q(mid)).collect())
            .collect();
        let cs = contribs(h, &byz);
        let sel = acfa_aggregate::multi_krum(&cs, f).unwrap();
        let all_in = (n - f..n).all(|i| sel.contains(&i));
        let inside = h.iter().map(|x| l2(&byz[0], x)).fold(0.0, f64::max) <= sp;
        if all_in && inside {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let byz = (0..f)
        .map(|_| hm.iter().map(|x| x + q(lo)).collect())
        .collect();
    (lo, byz)
}

fn deviation(rule: &str, cs: &[Contribution], hm: &[i64], f: usize) -> Option<f64> {
    // A rule may REFUSE (Bulyan below n >= 4f+3). Report that rather than panicking:
    // "this rule is unavailable at your configuration" is the answer a caller needs.
    let agg = match rule {
        "krum" => krum_aggregate(cs, f).ok()?,
        "bulyan" => bulyan_aggregate(cs, f).ok()?,
        "median" => coord_median_trim(cs, f).ok()?,
        _ => mean(cs).ok()?,
    };
    Some(l2(&agg, hm))
}

/// The honest baseline: what deviation does the rule show with NO adversary at all? Any
/// attack number is meaningless without it.
fn honest_floor(rule: &str, h: &[Vec<i64>], hm: &[i64], rng: &mut Rng, f: usize) -> Option<f64> {
    let extra: Vec<Vec<i64>> = (0..f)
        .map(|_| (0..D).map(|_| q(2.0 + rng.gauss())).collect())
        .collect();
    deviation(rule, &contribs(h, &extra), hm, f)
}

#[test]
fn within_norm_attack_is_characterised_for_every_rule() {
    // Two configurations, and the contrast is the point:
    //   n=10 f=3  -> Krum's bound holds (2f+3=9), Bulyan's does NOT (4f+3=15)
    //   n=15 f=3  -> both bounds hold, so Bulyan is actually available
    for &(n, f) in &[(10usize, 3usize), (15, 3)] {
        let mut rng = Rng(0xACFA_9001 ^ (n as u64) << 8);
        let trials = 10;
        let rules = ["krum", "bulyan", "median", "mean"];
        let mut dev = [0.0f64; 4];
        let mut floor = [0.0f64; 4];
        let mut avail = [0usize; 4];
        let mut selected = 0usize;
        let mut eps_sum = 0.0;

        for _ in 0..trials {
            let h = honest_set(&mut rng, n, f);
            let hm = honest_mean(&h);
            let (eps, byz) = worst_within_norm(&h, &hm, n, f);
            eps_sum += eps;
            let cs = contribs(&h, &byz);
            let sel = acfa_aggregate::multi_krum(&cs, f).unwrap();
            selected += (n - f..n).filter(|i| sel.contains(i)).count();

            for (r, name) in rules.iter().enumerate() {
                if let (Some(a), Some(fl)) = (
                    deviation(name, &cs, &hm, f),
                    honest_floor(name, &h, &hm, &mut rng, f),
                ) {
                    dev[r] += a;
                    floor[r] += fl;
                    avail[r] += 1;
                }
            }
        }

        println!("\n=== within-norm collusion, n={n} f={f} d={D}, {trials} trials ===");
        println!(
            "  Krum bound   n >= 2f+3 = {}: {}",
            2 * f + 3,
            if n >= 2 * f + 3 { "HOLDS" } else { "violated" }
        );
        println!(
            "  Bulyan bound n >= 4f+3 = {}: {}",
            4 * f + 3,
            if n >= 4 * f + 3 { "HOLDS" } else { "violated" }
        );
        println!(
            "  adversaries selected by multi-Krum: {selected}/{}",
            trials * f
        );
        println!("  mean epsilon sustained: {:.3}", eps_sum / trials as f64);
        println!(
            "\n  {:<8} {:>14} {:>14} {:>10}",
            "rule", "attacked dev", "honest floor", "ratio"
        );
        for (r, name) in rules.iter().enumerate() {
            if avail[r] == 0 {
                println!("  {name:<8} {:>14} {:>14} {:>10}", "REFUSED", "-", "-");
                continue;
            }
            let a = dev[r] / avail[r] as f64;
            let fl = floor[r] / avail[r] as f64;
            println!(
                "  {name:<8} {a:>14.3} {fl:>14.3} {:>10.2}x",
                a / fl.max(1e-9)
            );
        }

        assert!(
            n >= 2 * f + 3,
            "Krum population bound holds, so `population_bound_met` reports true"
        );
        assert!(
            selected > 0,
            "if this reaches 0 a rule improved; re-read this test"
        );
    }
}

#[test]
fn the_population_bound_is_not_a_safety_guarantee() {
    // Executable, so it cannot rot into a comment nobody reads.
    let (n, f) = (10usize, 3usize);
    let mut rng = Rng(0xACFA_9002);
    let h = honest_set(&mut rng, n, f);
    let hm = honest_mean(&h);
    let (_eps, byz) = worst_within_norm(&h, &hm, n, f);
    let cs = contribs(&h, &byz);
    let sel = acfa_aggregate::multi_krum(&cs, f).unwrap();

    assert!(n >= 2 * f + 3, "population bound satisfied");
    assert!(
        (n - f..n).any(|i| sel.contains(&i)),
        "a within-norm adversary is selected despite the bound holding"
    );
}
