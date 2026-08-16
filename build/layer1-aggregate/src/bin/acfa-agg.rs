// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `acfa-agg` -- deterministic robust aggregation over stdin.
//!
//! The integration boundary for callers that are not Rust. The aggregation itself stays
//! in this kernel so that every caller, in every language, gets the identical bytes.
//!
//! ## Why the wire carries IEEE-754 BITS and not decimal
//!
//! A float written as decimal and read back has to survive two conversions, and "parse
//! the shortest round-tripping decimal" is a promise about the *reader*, not about the
//! bytes. Sending the raw 64-bit pattern removes the question entirely: there is nothing
//! to round. This matters more here than in most places, because the whole point of the
//! kernel is that two implementations agree exactly, and a caller that quantised its own
//! input slightly differently would produce a different aggregate and look like a fault.
//!
//! ## Input (stdin, line-oriented, LF)
//!
//! ```text
//! rule krum|bulyan|mean|median|trimmed
//! f <usize>
//! [beta <num> <den>]           # trimmed only
//! <tie_key_hex> <bits_hex>...  # one line per contribution
//! ```
//!
//! `tie_key_hex` is an opaque caller-supplied key, used ONLY to break exact ties and
//! never interpreted. `bits_hex` is 16 hex chars per f64, big-endian.
//!
//! ## Output (stdout)
//!
//! ```text
//! ok <q16.16 int>...
//! ```
//! or `refused <reason>` on a rule that declines to guess. Exit 0 on `ok`, 1 on
//! `refused`, 2 on malformed input.

use acfa_aggregate::{
    bulyan_aggregate, coord_median_trim, encode, krum_aggregate, mean, trimmed_mean, Contribution,
};
use std::io::Read;
use std::process::ExitCode;

fn die(code: u8, msg: &str) -> ExitCode {
    eprintln!("acfa-agg: {msg}");
    ExitCode::from(code)
}

fn parse_bits(tok: &str) -> Option<f64> {
    if tok.len() != 16 {
        return None;
    }
    let mut b = [0u8; 8];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&tok[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(f64::from_be_bytes(b))
}

/// Seconds above which the operator is warned. A minute is the point at which a
/// human stops assuming the tool has hung and starts assuming it has.
const WARN_SECS: f64 = 60.0;

/// Estimated single-threaded bulyan runtime, in seconds.
///
/// Extrapolated from ONE measured point -- n=256, d=1024 -> 12.11 s on an Intel i5-6500
/// -- using the exponents fitted in `build/LOAD-AND-STRESS.md` (n^2.87, d^1.00). It is
/// an estimate and is labelled as one wherever it is shown. Its job is to tell an
/// operator that a run is hours rather than seconds, and it does not need to be
/// accurate to do that job; it needs to be right about the order of magnitude.
fn bulyan_estimate_secs(n: usize, d: usize) -> f64 {
    const REF_SECS: f64 = 12.11;
    const REF_N: f64 = 256.0;
    const REF_D: f64 = 1024.0;
    const EXP_N: f64 = 2.87;
    REF_SECS * (n as f64 / REF_N).powf(EXP_N) * (d as f64 / REF_D)
}

fn main() -> ExitCode {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return die(2, "cannot read stdin");
    }

    let mut rule = String::new();
    let mut f: usize = 0;
    let mut beta = (1u32, 4u32);
    let mut cs: Vec<Contribution> = Vec::new();
    let mut dim: Option<usize> = None;

    for (n, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let head = it.next().unwrap();
        match head {
            "rule" => match it.next() {
                Some(r) => rule = r.to_string(),
                None => return die(2, &format!("line {}: rule needs a value", n + 1)),
            },
            "f" => match it.next().and_then(|v| v.parse().ok()) {
                Some(v) => f = v,
                None => {
                    return die(
                        2,
                        &format!("line {}: f needs a non-negative integer", n + 1),
                    )
                }
            },
            "beta" => {
                let (a, b) = (
                    it.next().and_then(|v| v.parse().ok()),
                    it.next().and_then(|v| v.parse().ok()),
                );
                match (a, b) {
                    (Some(a), Some(b)) => beta = (a, b),
                    _ => return die(2, &format!("line {}: beta needs <num> <den>", n + 1)),
                }
            }
            tie_key_hex => {
                if tie_key_hex.len() % 2 != 0 {
                    return die(2, &format!("line {}: tie key must be hex", n + 1));
                }
                let mut tie_key = Vec::with_capacity(tie_key_hex.len() / 2);
                for i in (0..tie_key_hex.len()).step_by(2) {
                    match u8::from_str_radix(&tie_key_hex[i..i + 2], 16) {
                        Ok(b) => tie_key.push(b),
                        Err(_) => return die(2, &format!("line {}: tie key must be hex", n + 1)),
                    }
                }
                let mut v = Vec::new();
                for tok in it {
                    match parse_bits(tok) {
                        Some(x) => match encode(x) {
                            Ok(q) => v.push(q),
                            Err(e) => {
                                return die(
                                    2,
                                    &format!(
                                        "line {}: {e:?} -- value out of Q16.16 range or not finite",
                                        n + 1
                                    ),
                                )
                            }
                        },
                        None => {
                            return die(
                                2,
                                &format!("line {}: expected 16 hex chars per f64", n + 1),
                            )
                        }
                    }
                }
                if v.is_empty() {
                    return die(2, &format!("line {}: contribution has no values", n + 1));
                }
                match dim {
                    None => dim = Some(v.len()),
                    Some(d) if d != v.len() => {
                        return die(
                            2,
                            &format!("line {}: dimension {} differs from {d}", n + 1, v.len()),
                        )
                    }
                    _ => {}
                }
                cs.push(Contribution { tie_key, v });
            }
        }
    }

    if cs.is_empty() {
        return die(2, "no contributions");
    }

    // COST WARNING BEFORE THE WORK, NOT AFTER.
    //
    // Bulyan is the stronger defence -- it resists the coordinate-concentrated attacks
    // Krum admits -- and measurement puts it at n^2.87 * d. At deployment shapes that is
    // months per round. A production tool that offers the option and lets the operator
    // discover the cost by waiting is not a production tool.
    //
    // Estimate only, and labelled as one: extrapolated from a single measured point
    // (n=256, d=1024 -> 12.11 s, single-threaded, Intel i5-6500) using the exponents
    // fitted in build/LOAD-AND-STRESS.md. It scales with the caller's ACTUAL n and d.
    // Goes to stderr so the stdout contract is untouched, and never changes the exit
    // code: this is information, not a refusal. The operator's call, informed.
    if rule == "bulyan" {
        let secs = bulyan_estimate_secs(cs.len(), cs[0].v.len());
        if secs >= WARN_SECS {
            let pretty = if secs >= 3600.0 {
                format!("{:.1} hours", secs / 3600.0)
            } else {
                format!("{:.1} minutes", secs / 60.0)
            };
            eprintln!(
                "acfa-agg: WARNING: bulyan at n={} d={} is estimated at ~{pretty} \
                 single-threaded on this class of machine.",
                cs.len(),
                cs[0].v.len()
            );
            eprintln!(
                "acfa-agg: bulyan costs n^2.87 * d; krum costs n^1.98 * d and is the \
                 cheaper defence. See build/LOAD-AND-STRESS.md for the measurements."
            );
            eprintln!("acfa-agg: estimate extrapolated from one measured point, not a promise.");
        }
    }

    let out = match rule.as_str() {
        "krum" => krum_aggregate(&cs, f),
        "bulyan" => bulyan_aggregate(&cs, f),
        "mean" => mean(&cs),
        "median" => coord_median_trim(&cs, f),
        "trimmed" => trimmed_mean(&cs, beta.0, beta.1),
        "" => return die(2, "no rule given"),
        other => return die(2, &format!("unknown rule {other:?}")),
    };

    match out {
        Ok(v) => {
            let parts: Vec<String> = v.iter().map(|x| x.to_string()).collect();
            println!("ok {}", parts.join(" "));
            ExitCode::SUCCESS
        }
        // Layer 1 refuses rather than guessing. Surfacing the refusal as a distinct exit
        // code keeps a caller from reading "no output" as "zero vector".
        Err(e) => {
            println!("refused {e:?}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_estimate_reproduces_its_own_calibration_point() {
        // If this drifts, the constants and the measurement have diverged.
        let e = bulyan_estimate_secs(256, 1024);
        assert!((e - 12.11).abs() < 0.01, "calibration point moved: {e}");
    }

    #[test]
    fn ordinary_shapes_stay_below_the_warning_threshold() {
        // The warning must not cry wolf: a demo-sized run has to stay quiet or
        // operators learn to ignore it, and an ignored warning is not a warning.
        for (n, d) in [(8usize, 64usize), (32, 256), (64, 1024), (100, 512)] {
            assert!(
                bulyan_estimate_secs(n, d) < WARN_SECS,
                "n={n} d={d} should not warn, estimated {}s",
                bulyan_estimate_secs(n, d)
            );
        }
    }

    #[test]
    fn deployment_shapes_do_trigger_the_warning() {
        // These are the shapes the measurement says are hours-to-months. If the
        // threshold were ever raised past them the warning would be decorative.
        for (n, d) in [(1000usize, 1_000_000usize), (500, 100_000), (1000, 1024)] {
            assert!(
                bulyan_estimate_secs(n, d) >= WARN_SECS,
                "n={n} d={d} should warn, estimated {}s",
                bulyan_estimate_secs(n, d)
            );
        }
    }

    #[test]
    fn the_estimate_is_monotone_in_both_axes() {
        assert!(bulyan_estimate_secs(64, 1024) < bulyan_estimate_secs(128, 1024));
        assert!(bulyan_estimate_secs(64, 1024) < bulyan_estimate_secs(64, 2048));
    }
}
