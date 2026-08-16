// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! UC1 -- Byzantine-robust federated learning where pooling is barred.
//!
//! Five hospitals train locally on data they are legally barred from pooling. One is
//! compromised and submits a poisoned update. Nobody may see anyone else's raw gradients.
//!
//! Run:
//!   cargo run -q --release --example uc1_poisoned_fl
//!
//! WHAT THIS DEMONSTRATES:
//!   * FedAvg (a plain mean, what Flower/FLARE/Substra ship by default) is dragged to
//!     the attacker's value by ONE participant in five.
//!   * multi-Krum resists it.
//!   * AND multi-Krum names WHICH participants it kept. That second half is the part no
//!     shipped orchestration framework provides:
//!       - Flower ships Krum/MultiKrum/Bulyan and DISCARDS the contributor identity one
//!         line before selection, in both its legacy and current APIs.
//!       - NVIDIA FLARE keeps contributor identity but ships no robust aggregator.
//!       - Substra/Owkin logs operations but ships no robust aggregator.
//!
//!     Robustness and attribution both exist in the market. Not together.
//!
//! LIMITS:
//!   1. Fixed input. This is one seeded scenario, not a benchmark. It shows the mechanism,
//!      it does not measure attack success rates over a distribution.
//!   2. multi-Krum inherits Blanchard et al.'s statistical hypotheses (i.i.d. honest
//!      contributions, bounded variance) and needs n >= 2f+3. With n=5, f=1: 5 >= 5. It
//!      is at the boundary, which is why `population_bound_met` is worth checking rather than
//!      assuming.
//!   3. Krum-level robustness is NOT coordinate-level. A within-norm attacker that spends
//!      its whole budget on one coordinate is *selected* by Krum and carries a bounded
//!      O(sqrt(d)) bias (Mhamdi et al.). Bulyan restores coordinate robustness and needs
//!      n >= 4f+3, which n=5 does NOT satisfy.
//!      AND BULYAN DOES NOT REACH DEPLOYMENT SCALE. Measured: it scales as
//!      n^2.87, 12.11 s at n=256/d=1024. Extrapolated to 1000 nodes and 100M
//!      parameters it is YEARS per round, not hours. The extrapolation spans
//!      five decades in d, and repeat runs of the harness spread by 2.1x, so
//!      treat the order of magnitude as the result and ignore any point
//!      estimate, including one quoted to four digits.
//!      So "use Bulyan for coordinate robustness" is sound advice about the
//!      ESTIMATOR and unusable advice about the DEPLOYMENT. Coordinate-level
//!      robustness at scale is an open problem, not a solved one.
//!   4. This example proves nothing about *who* the parties are. That is Layer 2's job:
//!      selection here is by index, and binding an index to a signed identity requires
//!      the receipt.

use acfa_aggregate::{contribution, rules};

fn main() {
    // Five hospitals. Each reports a 3-parameter model delta. Honest sites cluster;
    // site 4 is compromised and reports a large negated update.
    let sites: [(&str, [f64; 3]); 5] = [
        ("hosp-A", [0.90, 0.40, 0.10]),
        ("hosp-B", [0.92, 0.38, 0.12]),
        ("hosp-C", [0.88, 0.42, 0.09]),
        ("hosp-D", [0.91, 0.39, 0.11]),
        ("hosp-E", [-45.0, 60.0, -30.0]), // compromised
    ];

    let cs: Vec<_> = sites
        .iter()
        .map(|(name, xs)| contribution(name.as_bytes().to_vec(), xs).expect("in range"))
        .collect();

    println!("UC1 -- five sites, one compromised, raw updates never pooled\n");
    for (name, xs) in sites.iter() {
        let tag = if name == &"hosp-E" {
            "  <-- compromised"
        } else {
            ""
        };
        println!("  {name:8} {xs:?}{tag}");
    }

    let f = 1usize;
    let n = cs.len();

    // What the incumbents do by default.
    let avg = rules::mean(&cs).expect("mean");
    // What ACFA Layer 1 does.
    let kept = rules::multi_krum(&cs, f).expect("krum");
    let krum = rules::krum_aggregate(&cs, f).expect("krum agg");

    let show = |v: &[i64]| -> String {
        let s: Vec<String> = v
            .iter()
            .map(|&x| format!("{:+.3}", acfa_aggregate::decode(x)))
            .collect();
        format!("[{}]", s.join(", "))
    };

    println!(
        "\n  FedAvg (plain mean, the default everywhere)  {}",
        show(&avg)
    );
    println!(
        "  multi-Krum (ACFA Layer 1)                    {}",
        show(&krum)
    );

    println!("\n  ATTRIBUTION -- which contributors entered the aggregate:");
    for (i, (name, _)) in sites.iter().enumerate() {
        let mark = if kept.contains(&i) {
            "SELECTED    "
        } else {
            "not selected"
        };
        println!("    {mark} {name}");
    }
    println!(
        "\n    multi-Krum selects n-f-2 = {} of {n}. NOT SELECTED IS NOT AN ACCUSATION.",
        n - f - 2
    );
    println!(
        "    hosp-B and hosp-C are honest and were simply outside the closest {};",
        n - f - 2
    );
    println!("    the rule keeps the tightest cluster, it does not rank trustworthiness.");
    println!("    The ONLY thing that convicts a participant is a self-authenticating");
    println!("    equivocation proof -- two conflicting signed messages under one key --");
    println!("    and that lives in Layer 2, not here. Selection is not blame.");

    // Preconditions.
    println!("\n  PRECONDITIONS");
    println!("    n = {n}, f = {f}");
    println!(
        "    multi-Krum needs n >= 2f+3 = {}  -> {}",
        2 * f + 3,
        if n >= 2 * f + 3 {
            "SATISFIED (at the boundary)"
        } else {
            "NOT SATISFIED"
        }
    );
    println!(
        "    Bulyan     needs n >= 4f+3 = {}  -> {}",
        4 * f + 3,
        if n >= 4 * f + 3 {
            "SATISFIED"
        } else {
            "NOT SATISFIED -- coordinate-level robustness NOT available at this n"
        }
    );

    println!("\n  WHAT THIS DOES NOT SHOW");
    println!("    Selection here is by INDEX. Binding an index to a signed identity, so a");
    println!("    third party can check who was excluded and why, is Layer 2 (the receipt).");
    println!("    Run: cargo run -q --release --example issue  (in build/layer2-receipt)");
}
