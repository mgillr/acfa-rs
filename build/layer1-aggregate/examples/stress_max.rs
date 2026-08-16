// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! One aggregation at a caller-chosen size, for finding where the kernel ACTUALLY breaks.
//!
//! `stress.rs` measures a fixed grid and EXTRAPOLATES. Extrapolation says where a cliff
//! should be; it cannot say where the process actually dies. This runs a single (n, d)
//! and either finishes or does not, so an escalating driver can run it in a subprocess
//! per size and read the wall off real outcomes -- a non-zero exit or a kill is the
//! answer, not a projection.
//!
//! Deliberately isolates the two walls, because they are different limits:
//!   * MEMORY wall -- the n x n i128 distance matrix, n^2 * 16 bytes, INDEPENDENT of d.
//!     Probe it with a small d so time does not bite first.
//!   * TIME wall -- n^2 * d. Probe it by growing d at a size that already fits.
//!
//! Usage: cargo run --release --example stress_max -- <n> <d> [rule]
//! Prints one line: `n d rule seconds matrix_bytes` on success. Exit 2 on bad args.

use acfa_aggregate::*;
use std::time::Instant;

struct Lcg(u64);
impl Lcg {
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

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: stress_max <n> <d> [krum|bulyan|median|mean|trimmed]");
        return std::process::ExitCode::from(2);
    }
    let n: usize = args[1].parse().expect("n");
    let d: usize = args[2].parse().expect("d");
    let rule = args.get(3).map(|s| s.as_str()).unwrap_or("krum");
    let f = n / 8;

    // Announce BEFORE allocating. If the process is killed building the corpus, the
    // driver still knows which size was being attempted -- a silent death at an unknown
    // size is not a measurement.
    eprintln!(
        "attempting n={n} d={d} rule={rule} matrix={} MiB",
        n * n * 16 / (1 << 20)
    );

    let mut r = Lcg(42);
    let cs: Vec<Contribution> = (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i:08}").into_bytes(),
            v: (0..d).map(|_| r.next_val()).collect(),
        })
        .collect();
    eprintln!("corpus built");

    let t = Instant::now();
    let out = match rule {
        "krum" => krum_aggregate(&cs, f),
        "bulyan" => bulyan_aggregate(&cs, f),
        "median" => coord_median_trim(&cs, f),
        "mean" => mean(&cs),
        "trimmed" => trimmed_mean(&cs, 1, 5),
        other => {
            eprintln!("unknown rule {other}");
            return std::process::ExitCode::from(2);
        }
    };
    let secs = t.elapsed().as_secs_f64();

    match out {
        Ok(v) => {
            println!("{n} {d} {rule} {secs:.3} {}", n * n * 16);
            // Touch the result so nothing is optimised away.
            std::hint::black_box(&v);
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{n} {d} {rule} REFUSED {e:?}");
            std::process::ExitCode::from(1)
        }
    }
}
