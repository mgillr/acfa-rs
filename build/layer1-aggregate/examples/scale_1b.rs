// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! THE SCALE DEMONSTRATION: multi-Krum over a 1B-parameter model, in 80 MB.
//!
//! WHAT THE WALL ACTUALLY WAS. `multi_krum` takes `&[Contribution]`, every one holding its full
//! `Vec<i64>`, so the corpus is `n * d * 8` bytes RESIDENT: 80 GB at n=10, d=1e9. Measured
//! climbing to it -- work 1e9 -> 4.75s, 5e9 -> 34.4s, 1e10 -> 82.3s with 20.3s of SYS time. The
//! superlinearity and the sys time are paging, not arithmetic. The WORK bound was never the
//! barrier: 1e11 coordinate-ops is ~13 minutes.
//!
//! WHY STREAMING IS SAFE HERE AND WOULD NOT BE IN A FLOAT SYSTEM. Krum's score is a function of
//! the pairwise squared distances, and `sq_dist` is an exact `i128` accumulation. Integer
//! addition is associative, so splitting the coordinate range into chunks and summing the partial
//! sums is BIT-IDENTICAL to the single pass -- at every chunk size, not merely at convenient ones.
//! Measured against a float control on the same inputs:
//!
//!     chunk        exact-int identical?   float identical?
//!         1                        true              FALSE
//!         7                        true              FALSE
//!        64                        true              FALSE
//!      1000                        true              FALSE
//!      4096                        true               true
//!
//! In a floating-point aggregator this optimisation silently changes the answer with the chunk
//! size and destroys byte-identity. Here it cannot. THE EXACT-ARITHMETIC PROPERTY THE WHOLE DESIGN
//! RESTS ON IS WHAT MAKES THE MEMORY FIX FREE -- that is specific to this architecture, not a
//! general fact about robust aggregation.
//!
//! Memory becomes O(n*chunk + n^2), INDEPENDENT OF d. The work bound is untouched, so the refusal
//! semantics are exactly as they were.
//!
//! usage: scale_1b <n> <d> [chunk]

use acfa_aggregate::rules::MAX_COORDINATE_OPS;

/// One participant's update, generated on demand rather than stored.
///
/// A real deployment streams these off disk or a socket; the point of the demo is that NOTHING
/// here ever holds `d` coordinates for `n` parties at once. Deterministic and seeded, so the run
/// is reproducible and two runs at different chunk sizes are comparing the same corpus.
fn coord(node: u64, i: u64) -> i64 {
    let mut x = node.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ i.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    // Q16.16 range is +-32768 in whole units; keep well inside so nothing saturates.
    ((x >> 40) as i64 % 200_000) - 100_000
}

/// The n*n squared-distance matrix, accumulated by streaming `d` in chunks.
///
/// This is the whole contribution. `chunk` coordinates of each of the `n` participants are
/// materialised at a time, the partial squared differences are added into an `i128` accumulator
/// per pair, and the buffer is reused. Peak residency is `n * chunk * 8` bytes plus `n^2 * 16`.
fn stream_matrix(n: usize, d: usize, chunk: usize) -> Option<Vec<i128>> {
    let mut acc = vec![0i128; n * n];
    let mut buf: Vec<Vec<i64>> = vec![Vec::with_capacity(chunk); n];
    let mut start = 0usize;
    while start < d {
        let end = (start + chunk).min(d);
        for (node, b) in buf.iter_mut().enumerate() {
            b.clear();
            b.extend((start..end).map(|i| coord(node as u64, i as u64)));
        }
        for i in 0..n {
            for j in (i + 1)..n {
                let mut part: i128 = 0;
                for k in 0..(end - start) {
                    let delta = (buf[i][k] as i128) - (buf[j][k] as i128);
                    part = part.checked_add(delta.checked_mul(delta)?)?;
                }
                acc[i * n + j] = acc[i * n + j].checked_add(part)?;
            }
        }
        start = end;
    }
    for i in 0..n {
        for j in 0..i {
            acc[i * n + j] = acc[j * n + i];
        }
    }
    Some(acc)
}

/// Multi-Krum selection from a precomputed distance matrix. Same rule, same tie-break: score is
/// the sum of the `m` smallest distances to other participants, and the selection is the `m`
/// lowest scores with the index as the tie-break.
fn select_from_matrix(acc: &[i128], n: usize, f: usize) -> Vec<usize> {
    if n < f + 3 {
        return (0..n).collect();
    }
    let m = n - f - 2;
    let mut scored: Vec<(i128, usize)> = (0..n)
        .map(|i| {
            let mut row: Vec<i128> = (0..n).filter(|&j| j != i).map(|j| acc[i * n + j]).collect();
            row.sort_unstable();
            (row[..m].iter().sum(), i)
        })
        .collect();
    scored.sort_unstable();
    let mut out: Vec<usize> = scored[..m].iter().map(|&(_, i)| i).collect();
    out.sort_unstable();
    out
}

fn main() -> std::process::ExitCode {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: scale_1b <n> <d> [chunk]");
        return std::process::ExitCode::from(2);
    }
    let parse = |s: &str, what: &str| -> Option<usize> {
        s.parse().ok().or_else(|| {
            eprintln!("scale_1b: {what} must be a positive integer, got {s:?}");
            None
        })
    };
    let (n, d) = match (parse(&a[1], "n"), parse(&a[2], "d")) {
        (Some(n), Some(d)) => (n, d),
        _ => return std::process::ExitCode::from(2),
    };
    let chunk = match a.get(3) {
        None => 1_000_000,
        Some(s) => match parse(s, "chunk") {
            Some(c) => c,
            None => return std::process::ExitCode::from(2),
        },
    };
    let f = n / 8;

    let work = (n as u128) * (n as u128) * (d as u128);
    let resident = (n as f64) * (chunk.min(d) as f64) * 8.0 / 1e9;
    let materialised = (n as f64) * (d as f64) * 8.0 / 1e9;
    println!("# ACFA scale demonstration -- multi-Krum, streaming");
    println!("  n {n}   d {d}   f {f}   chunk {chunk}");
    println!("  work {work}  (kernel default cap {MAX_COORDINATE_OPS})");
    println!("  corpus if MATERIALISED : {materialised:.1} GB");
    println!("  peak resident STREAMED : {resident:.3} GB");

    let t = std::time::Instant::now();
    let Some(acc) = stream_matrix(n, d, chunk) else {
        eprintln!("scale_1b: arithmetic overflow accumulating the distance matrix");
        return std::process::ExitCode::from(1);
    };
    let build = t.elapsed();
    let sel = select_from_matrix(&acc, n, f);
    let total = t.elapsed();

    // The selection is the thing that must be identical, so print it and a digest of the matrix.
    let mut h: u64 = 1469598103934665603;
    for v in &acc {
        for b in v.to_be_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211);
        }
    }
    println!("  matrix build {:.2}s   total {:.2}s", build.as_secs_f64(), total.as_secs_f64());
    println!("  selected {sel:?}");
    println!("  matrix-digest {h:016x}");
    std::process::ExitCode::SUCCESS
}
