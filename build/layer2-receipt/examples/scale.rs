// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Measured cost of issuing and verifying a receipt.
//!
//! `cargo run --release --example scale`
//!
//! The published paper states plainly that the prototype "validates correctness, not
//! performance: no timing, bandwidth, or large-n measurements are reported." This is that
//! measurement for the Rust implementation, and it is reported with its limits attached
//! rather than as a headline.
//!
//! WHAT DOMINATES, AND WHY THE SHAPE MATTERS MORE THAN THE ABSOLUTE NUMBERS. Verification
//! is `O(n)` signature checks plus the rule's own cost, and multi-Krum is `O(n^2 * d)` in
//! distance work. So `n` is the parameter to watch, not `d`: doubling the dimension
//! doubles the work, doubling the participant count quadruples part of it. Any deployment
//! sizing this should measure its own `n`, not extrapolate from one row here.
//!
//! Absolute figures are machine-specific and are NOT a claim about anyone else's hardware.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{decode, encode, Contribution, Policy, Receipt, Rule, State};
use std::time::Instant;

fn build(n: u32, d: usize) -> (State, Pki) {
    let ids: Vec<Identity> = (1..=n)
        .map(|k| Identity::from_secret(k, &[(k % 251) as u8 + 1; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut state = State::new();
    for (i, id) in ids.iter().enumerate() {
        let t: Vec<i64> = (0..d)
            .map(|k| ((i * 7 + k * 13) as i64 % 2048) - 1024)
            .collect();
        let sig = id.sign(&contrib_msg(1, &h(&enc_tensor(&t))));
        state.deliver(
            Contribution {
                rnd: 1,
                node_id: id.node_id,
                tensor: t,
                sig,
            },
            &pki,
        );
    }
    (state, pki)
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    println!("# ACFA receipt -- measured cost");
    println!("# machine-specific; the SHAPE (O(n) signatures, O(n^2*d) Krum) is the claim");
    println!("# arch {} / {}-bit", std::env::consts::ARCH, usize::BITS);
    println!();
    println!(
        "{:>5} {:>6} {:>10} {:>11} {:>11} {:>11} {:>9}",
        "n", "dim", "wire KiB", "issue ms", "verify ms", "decode ms", "bound met"
    );

    for &(n, d) in &[
        (5u32, 100usize),
        (10, 100),
        (25, 100),
        (50, 100),
        (100, 100),
        (25, 1_000),
        (25, 10_000),
        (50, 1_000),
    ] {
        let (state, pki) = build(n, d);
        let f = 1;

        let t0 = Instant::now();
        let receipt = Receipt::issue(&state, 1, &pki, f, Rule::Krum);
        let issue = t0.elapsed();

        let bytes = encode(&receipt);

        let t1 = Instant::now();
        let back = decode(&bytes).expect("decodes");
        let dec = t1.elapsed();

        let policy = Policy::new(pki, f);
        let t2 = Instant::now();
        let v = back.verify(&policy).expect("verifies");
        let ver = t2.elapsed();

        println!(
            "{:>5} {:>6} {:>10.1} {:>11.2} {:>11.2} {:>11.2} {:>9}",
            n,
            d,
            bytes.len() as f64 / 1024.0,
            ms(issue),
            ms(ver),
            ms(dec),
            v.population_bound_met
        );
    }

    println!();
    println!("Notes:");
    println!("  * wire size is dominated by the tensors: n * d * 8 bytes, plus 96/contribution.");
    println!("    A deployment aggregating large models should send updates, not weights.");
    println!("  * verify re-executes the rule; it is not a signature check bolted onto a");
    println!("    claimed answer, so it costs roughly what issuing costs. That is the price");
    println!("    of the property and it is not reducible without giving up re-execution.");
    println!("  * single-threaded and unoptimised beyond --release. No SIMD, no batching of");
    println!("    signature verification, both of which are available if n grows.");
}
