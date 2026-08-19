// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Load and stress harness for the aggregation kernel.
//!
//! WHAT THIS IS FOR. Every number the project has published so far is about
//! CORRECTNESS -- byte-identity, cross-implementation agreement, absorption. None of it
//! says whether the kernel can be *run* at the sizes a federated deployment implies.
//! A deterministic aggregate nobody can afford to compute is not a product.
//!
//! WHAT IT MEASURES, AND WHY THESE AXES
//!   Multi-Krum scores each contribution against every other, over every coordinate:
//!   an n x n distance matrix, each entry a d-dimensional squared distance. So cost
//!   should go as O(n^2 d) in time and O(n^2) in memory, and Bulyan -- which re-runs
//!   Krum selection theta times on a shrinking pool -- should go as O(n^3 d). Those are
//!   PREDICTIONS. This harness measures the exponents rather than asserting them, by
//!   fitting a straight line through log(size) vs log(time). A predicted exponent that
//!   the measurement contradicts is the finding, not an inconvenience.
//!
//! HONESTY RULES BUILT IN
//!   * Reports ns/element, not just wall time, so a bigger machine cannot flatter it.
//!   * Fits the exponent from the measured points and prints the fit, so the reader can
//!     see the scaling rather than take a summary on trust.
//!   * Projects to a stated production shape and prints the projection EVEN WHEN IT IS
//!     ABSURD. A harness that quietly stops at the last size that finishes quickly
//!     reports a cliff as an absence.
//!   * `--quick` shrinks the grid for CI; the shape of the report is identical so a
//!     quick run cannot be mistaken for a full one -- it says which it was.
//!
//! USAGE
//!   cargo run --release --example stress -- [--quick]

use acfa_aggregate::*;
use std::time::{Duration, Instant};

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
    fn next_val(&mut self) -> i64 {
        (self.next_u64() % 200_001) as i64 - 100_000
    }
}

fn corpus(n: usize, d: usize, seed: u64) -> Vec<Contribution> {
    let mut r = Lcg::new(seed);
    (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i:06}").into_bytes(),
            v: (0..d).map(|_| r.next_val()).collect(),
        })
        .collect()
}

/// Median of repeated runs. A single timing on a shared laptop is noise, and a mean is
/// dragged by exactly the scheduler hiccups a median ignores.
fn time_it(reps: usize, mut f: impl FnMut()) -> Duration {
    let mut runs: Vec<Duration> = (0..reps)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    runs.sort();
    runs[runs.len() / 2]
}

/// Least-squares slope of log(y) against log(x) -- the empirical scaling exponent.
fn log_log_slope(points: &[(f64, f64)]) -> f64 {
    let n = points.len() as f64;
    let (lx, ly): (Vec<f64>, Vec<f64>) = points.iter().map(|&(x, y)| (x.ln(), y.ln())).unzip();
    let mx = lx.iter().sum::<f64>() / n;
    let my = ly.iter().sum::<f64>() / n;
    let num: f64 = lx.iter().zip(&ly).map(|(x, y)| (x - mx) * (y - my)).sum();
    let den: f64 = lx.iter().map(|x| (x - mx).powi(2)).sum();
    if den == 0.0 {
        f64::NAN
    } else {
        num / den
    }
}

fn bytes_h(bytes: f64) -> String {
    const GIB: f64 = (1u64 << 30) as f64;
    const MIB: f64 = (1u64 << 20) as f64;
    const KIB: f64 = 1024.0;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else {
        format!("{:.0} KiB", bytes / KIB)
    }
}

fn human(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 3600.0 {
        format!("{:.1} h", s / 3600.0)
    } else if s >= 60.0 {
        format!("{:.1} min", s / 60.0)
    } else if s >= 1.0 {
        format!("{s:.2} s")
    } else {
        format!("{:.1} ms", s * 1000.0)
    }
}

/// Formats a possibly-refused timing. A `None` is a size the work bound REFUSED, which
/// is the documented ceiling doing its job -- not a missing measurement -- so it reads
/// `refused` rather than being silently dropped or crashing the run.
fn human_opt(d: Option<Duration>) -> String {
    match d {
        Some(d) => human(d),
        None => "refused".to_string(),
    }
}

/// Times an aggregation that the work bound may refuse at large sizes. Returns `None`
/// when the kernel refuses the size: the bound firing (MAX_COORDINATE_OPS /
/// MAX_CONTRIBUTIONS_BULYAN) is the DOCUMENTED ceiling, not a harness failure, so the
/// harness reports it instead of `unwrap()`-panicking on its own published grid.
fn time_agg<T, E>(reps: usize, mut f: impl FnMut() -> Result<T, E>) -> Option<Duration> {
    // One probe: if the size is over a bound the kernel refuses in O(1), and we report
    // the ceiling rather than time -- and then panic on -- a refusal.
    if f().is_err() {
        return None;
    }
    Some(time_it(reps, || {
        let _ = std::hint::black_box(f());
    }))
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    println!("# ACFA Layer 1 -- load and stress");
    println!("# mode: {}", if quick { "QUICK (CI)" } else { "FULL" });
    println!();

    // ---------------------------------------------------------------- scaling in n
    let ns: Vec<usize> = if quick {
        vec![8, 16, 32, 64]
    } else {
        vec![8, 16, 32, 64, 128, 256]
    };
    let d_fixed = if quick { 256 } else { 1024 };
    let reps = if quick { 3 } else { 5 };

    println!("## Scaling in n (contributions), d = {d_fixed} fixed");
    println!(
        "{:>6} {:>12} {:>12} {:>12} {:>12}",
        "n", "mean", "median_trim", "krum", "bulyan"
    );

    let mut krum_pts: Vec<(f64, f64)> = Vec::new();
    let mut bulyan_pts: Vec<(f64, f64)> = Vec::new();

    for &n in &ns {
        let f = n / 8;
        let cs = corpus(n, d_fixed, 42 + n as u64);
        let t_mean = time_agg(reps, || mean(&cs));
        let t_med = time_agg(reps, || coord_median_trim(&cs, f));
        let t_krum = time_agg(reps, || krum_aggregate(&cs, f));
        // Bulyan needs n >= 4f+3; f = n/8 satisfies it for these sizes. Above the
        // coordinate-op ceiling (MAX_COORDINATE_OPS) the kernel REFUSES rather than
        // compute -- the cell reads `refused`, which is the ceiling, not a crash.
        let t_bul = time_agg(reps.min(3), || bulyan_aggregate(&cs, f));

        println!(
            "{:>6} {:>12} {:>12} {:>12} {:>12}",
            n,
            human_opt(t_mean),
            human_opt(t_med),
            human_opt(t_krum),
            human_opt(t_bul)
        );
        if let Some(t) = t_krum {
            krum_pts.push((n as f64, t.as_secs_f64()));
        }
        if let Some(t) = t_bul {
            bulyan_pts.push((n as f64, t.as_secs_f64()));
        }
    }

    let krum_exp = log_log_slope(&krum_pts);
    let bulyan_exp = log_log_slope(&bulyan_pts);
    println!();
    println!("measured exponent in n:  krum {krum_exp:.3}  (predicted 2.000)");
    println!("measured exponent in n:  bulyan {bulyan_exp:.3}  (predicted 3.000)");

    // ---------------------------------------------------------------- scaling in d
    let ds: Vec<usize> = if quick {
        vec![128, 256, 512, 1024]
    } else {
        vec![256, 1024, 4096, 16384, 65536]
    };
    let n_fixed = if quick { 16 } else { 32 };

    println!();
    println!("## Scaling in d (dimension), n = {n_fixed} fixed");
    println!("{:>8} {:>12} {:>16}", "d", "krum", "ns/coordinate");

    let mut d_pts: Vec<(f64, f64)> = Vec::new();
    for &d in &ds {
        let f = n_fixed / 8;
        let cs = corpus(n_fixed, d, 7 + d as u64);
        let t = time_agg(reps.min(3), || krum_aggregate(&cs, f));
        // n^2 pair-coordinates is the work multi-Krum actually does.
        let work = (n_fixed * n_fixed * d) as f64;
        match t {
            Some(t) => {
                println!(
                    "{:>8} {:>12} {:>16.2}",
                    d,
                    human(t),
                    t.as_secs_f64() * 1e9 / work
                );
                d_pts.push((d as f64, t.as_secs_f64()));
            }
            // A refused d row is the coordinate-op ceiling, printed not hidden.
            None => println!("{:>8} {:>12} {:>16}", d, "refused", "--"),
        }
    }
    let d_exp = log_log_slope(&d_pts);
    println!();
    println!("measured exponent in d:  krum {d_exp:.3}  (predicted 1.000)");

    // ---------------------------------------------------------------- memory
    println!();
    println!("## Memory: the n x n distance matrix");
    println!("{:>8} {:>16}", "n", "matrix (i128)");
    for &n in &[64usize, 256, 1_000, 10_000, 100_000] {
        println!("{n:>8} {:>16}", bytes_h((n * n * 16) as f64));
    }
    println!();
    println!("The matrix is allocated in full before any distance is used, so this is a");
    println!("hard floor on resident memory and not an average.");

    // ------------------------------------------------------- i128 overflow headroom
    println!();
    println!("## Overflow headroom in the i128 distance accumulator");
    // Worst case per coordinate: (MAX - MIN)^2 for Q16.16, summed over d coordinates.
    let span = (fixed::MAX as i128) - (fixed::MIN as i128);
    let per_coord = span * span;
    let max_d = i128::MAX / per_coord;
    println!("  Q16.16 span            {span}");
    println!("  worst per-coordinate   {per_coord}  (= span^2)");
    println!("  d before i128 saturates {max_d}");
    println!();
    println!("  Measured, not argued: sq_dist accumulates in i128 and never rescales, so");
    println!("  the dimension would have to exceed that bound before the accumulator could");
    println!("  wrap. No realistic model reaches it, and time and memory bite long first.");

    // ---------------------------------------------------------------- projection
    println!();
    println!("## Projection to a deployment shape");
    let (base_n, base_t) = (
        *krum_pts.last().map(|(n, _)| n).unwrap_or(&1.0),
        krum_pts.last().map(|(_, t)| *t).unwrap_or(0.0),
    );
    // Bulyan is projected too. It is the rule most likely to be unaffordable, so
    // omitting it would report the worst cliff as an absence -- the exact failure the
    // note below warns about.
    // Scale bulyan from its OWN largest measured n: the work bound can hold that below
    // the krum grid's last n, and projecting from a size that was `refused` (never ran)
    // would be an extrapolation from a point that does not exist.
    let (base_bn, base_b) = bulyan_pts
        .last()
        .map(|(n, t)| (*n, *t))
        .unwrap_or((1.0, 0.0));
    for (pn, pd, label) in [
        (100.0, 1e6, "100 nodes, 1M params"),
        (1000.0, 1e6, "1000 nodes, 1M params"),
        (1000.0, 1e8, "1000 nodes, 100M params"),
    ] {
        // Scale from the largest measured point by the MEASURED exponents, not the
        // predicted ones -- projecting with the theory would assume the answer.
        let t_k = base_t * (pn / base_n).powf(krum_exp) * (pd / d_fixed as f64).powf(d_exp);
        let t_b = base_b * (pn / base_bn).powf(bulyan_exp) * (pd / d_fixed as f64).powf(d_exp);
        println!(
            "  {label:<24} krum {:>10}   bulyan {:>10}   matrix {}",
            human(Duration::from_secs_f64(t_k)),
            human(Duration::from_secs_f64(t_b)),
            bytes_h(pn * pn * 16.0)
        );
    }
    println!();
    println!("These projections are printed whatever they say. A harness that stopped at");
    println!("the last size that finished quickly would report a cliff as an absence.");
    println!();
    println!("## How much to trust the projections: ORDER OF MAGNITUDE ONLY");
    // Two full runs on this host projected the same headline to 9 328 h and then
    // 16 313 h - a 1.75x swing - while BOTH printed the d exponent as "1.00" at two
    // decimal places. The sensitivity below shows where that came from, and it is not
    // where I first looked: n is extrapolated ~3.9x (0.6 decades) but d is extrapolated
    // ~97 700x (5.0 decades), so the same error in the d exponent is worth roughly
    // eleven times more. Probing the n axis alone reported the projection as stable,
    // which is exactly how a false precision survives a sensitivity check.
    let n_reach = 1000.0f64 / base_bn;
    let d_reach = 1e8 / d_fixed as f64;
    let headline = base_b * n_reach.powf(bulyan_exp) * d_reach.powf(d_exp);
    println!(
        "  central {:>12}   (n exponent {bulyan_exp:.3}, d exponent {d_exp:.3})",
        human(Duration::from_secs_f64(headline))
    );
    for delta in [-0.05f64, 0.05] {
        let by_n = base_b * n_reach.powf(bulyan_exp + delta) * d_reach.powf(d_exp);
        let by_d = base_b * n_reach.powf(bulyan_exp) * d_reach.powf(d_exp + delta);
        println!(
            "  {delta:+.2} on exponent:  via n {:>10} ({:.2}x)   via d {:>10} ({:.2}x)",
            human(Duration::from_secs_f64(by_n)),
            by_n / headline,
            human(Duration::from_secs_f64(by_d)),
            by_d / headline
        );
    }
    println!();
    println!("  n is extrapolated {n_reach:.1}x, d is extrapolated {d_reach:.0}x, so the d");
    println!("  exponent dominates the uncertainty. A fit that rounds to the same two");
    println!("  decimals in two runs still moved this headline by 1.75x between them.");
    println!("  Quote as ORDERS OF MAGNITUDE - months, not hours - never as an hour count.");
}
