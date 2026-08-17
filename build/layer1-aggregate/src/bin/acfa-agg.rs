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
    bulyan_aggregate, coord_median_trim, encode, krum_aggregate, mean, trimmed_mean, AggError,
    Contribution,
};
use std::io::Read;
use std::process::ExitCode;

fn die(code: u8, msg: &str) -> ExitCode {
    eprintln!("acfa-agg: {msg}");
    ExitCode::from(code)
}

fn parse_bits(tok: &str) -> Option<f64> {
    // ASCII FIRST, THEN SLICE. `&tok[i..i+2]` indexes a `&str` by BYTES and panics if the
    // boundary lands inside a multi-byte character, so any non-ASCII token aborted the
    // process instead of being rejected as malformed input. A panic reachable from stdin
    // is a denial of service, and hex is ASCII by definition, so the check costs nothing.
    if tok.len() != 16 || !tok.is_ascii() {
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

const USAGE: &str = "\
acfa-agg -- deterministic robust aggregation, stdin to stdout

USAGE:
    acfa-agg < input          reads the request on stdin, writes the aggregate to stdout

INPUT (line-oriented, LF):
    rule krum|bulyan|mean|median|trimmed
    f <usize>
    [beta <num> <den>]           trimmed only
    <tie_key_hex> <bits_hex>...  one line per contribution

    bits_hex is 16 hex chars per f64, big-endian IEEE-754. tie_key_hex is opaque and is
    used only to break exact ties.

EXAMPLE:
    printf 'rule mean\\nf 0\\n01 3ff0000000000000\\n02 4000000000000000\\n' | acfa-agg

EXIT CODES:
    0 ok    1 refused (bound not met, bad input values)    2 unreadable input

Full documentation: https://github.com/mgillr/acfa-rs
";

fn main() -> ExitCode {
    // Answer --help, and refuse an interactive terminal rather than blocking on it.
    //
    // This program's entire interface is stdin, so with no redirect it sat in a blocking
    // read forever. `acfa-agg --help` -- the first thing anyone types, and the first
    // binary the README tells them to install -- produced no output and never returned,
    // which reads as a hang rather than as a program waiting for input. `acfa-verify`
    // already handled --help, so the two CLIs disagreed about the same convention.
    //
    // IsTerminal is std, so this costs the crate's zero-dependency property nothing.
    use std::io::IsTerminal;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if let Some(a) = args.first() {
        eprintln!("acfa-agg: unexpected argument {a:?}; input is read from stdin\n");
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }
    if std::io::stdin().is_terminal() {
        eprintln!("acfa-agg: no input on stdin. Pipe a request in, or --help.\n");
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return die(2, "cannot read stdin");
    }

    // SEEN-FLAGS, BECAUSE A DUPLICATE DIRECTIVE SILENTLY CHANGED THE ANSWER. `rule mean`
    // followed by `rule krum` took the last one and exited 0, as did a repeated `f`. The
    // caller believed one thing and the tool did another with no diagnostic -- the same
    // shape as saturating an out-of-range value, which this program already refuses to do.
    // `f` is unbracketed in USAGE, so it is required; defaulting it to 0 silently ran an
    // undefended aggregation for anyone who forgot the line.
    let mut rule = String::new();
    let mut f: usize = 0;
    let mut beta = (1u32, 4u32);
    let (mut saw_rule, mut saw_f, mut saw_beta) = (false, false, false);
    let mut cs: Vec<Contribution> = Vec::new();
    // Source line of each contribution, parallel to `cs`. crdt-08: the library refusal
    // names an INDEX into `cs`, and an operator holding a file needs a LINE. Keeping the
    // map here is what lets the CLI report the library's attribution without recomputing
    // it -- and recomputing it is exactly what went wrong, see below.
    let mut cs_lines: Vec<usize> = Vec::new();

    for (n, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let head = it.next().unwrap();
        match head {
            "rule" => {
                if saw_rule {
                    return die(2, &format!("line {}: duplicate `rule` directive", n + 1));
                }
                saw_rule = true;
                match it.next() {
                    Some(r) => rule = r.to_string(),
                    None => return die(2, &format!("line {}: rule needs a value", n + 1)),
                }
            }
            "f" => {
                if saw_f {
                    return die(2, &format!("line {}: duplicate `f` directive", n + 1));
                }
                saw_f = true;
                match it.next().and_then(|v| v.parse().ok()) {
                    Some(v) => f = v,
                    None => {
                        return die(
                            2,
                            &format!("line {}: f needs a non-negative integer", n + 1),
                        )
                    }
                }
            }
            "beta" => {
                if saw_beta {
                    return die(2, &format!("line {}: duplicate `beta` directive", n + 1));
                }
                saw_beta = true;
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
                if tie_key_hex.len() % 2 != 0 || !tie_key_hex.is_ascii() {
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
                                // BOTH HALVES OF THE CONTRACT, NOT ONE. An earlier fix
                                // corrected the exit code here from 2 to 1 and left the
                                // stdout token behind, so this binary's two exit-1 paths
                                // disagreed: the rule path prints `refused <reason>` and
                                // this one printed nothing. A machine caller switches on
                                // that leading token, and an empty stdout with exit 1 reads
                                // as an unclassified failure rather than the typed refusal
                                // it is. stderr keeps the line number for a human; stdout
                                // carries the reason for a program.
                                println!("refused {e:?}");
                                // EXIT 1, NOT 2. The documented contract is
                                // "1 refused (bound not met, bad input values)" against
                                // "2 unreadable input". An out-of-range or non-finite value
                                // is perfectly readable -- it parsed as an f64 -- and the
                                // program is REFUSING it rather than failing to understand
                                // it. Reporting it as unreadable told a caller to go looking
                                // for a malformed wire encoding when the real answer was
                                // "rescale your data".
                                return die(
                                    1,
                                    &format!(
                                        "line {}: {e:?} -- value out of Q16.16 range or not finite",
                                        n + 1
                                    ),
                                );
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
                // crdt-08, SECOND SITE. THERE WAS A DIMENSION CHECK HERE AND IT WAS THE
                // FRAMING VECTOR THE LIBRARY WAS JUST FIXED FOR.
                //
                // It compared every contribution against the FIRST one and reported
                // "line N: dimension X differs from d" -- so an adversary sending a short
                // vector as contribution ONE had every honest line named instead, and its
                // own length was reported as the reference. Measured on six honest dim-4
                // and one adversarial dim-1: with the adversary first the message read
                // "line 4: dimension 4 differs from 1", accusing an honest node.
                //
                // It also exited 2, "unreadable input", for a request that parses
                // perfectly. The contract reserves 1 for "refused -- bad input values",
                // and `ee7d221`/`efc785c` already made exactly this correction for
                // out-of-range and non-finite values while leaving this sibling behind.
                //
                // So the check is GONE rather than repaired. `rules::check` already does
                // this correctly, by plurality, on input the CLI is about to hand it -- a
                // second implementation of a security-relevant rule is how the two drift.
                cs_lines.push(n + 1);
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
    // `f` is unbracketed in USAGE, so it is REQUIRED. Defaulting it to 0 silently ran an
    // undefended aggregation for anyone who omitted the line, and reported success.
    if !saw_f {
        return die(
            2,
            "no `f` directive: the fault bound is required, not optional",
        );
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
            // THE REASON MUST BE ONE WHITESPACE-FREE TOKEN AND `{e:?}` NO LONGER IS.
            //
            // Callers split on whitespace and read the reason, so a reason containing a
            // space truncates for every one of them. That held while every variant was a
            // unit, and crdt-08 made `DimensionMismatch` a struct variant whose Debug form
            // is `DimensionMismatch { offender: 0, expected: 4, got: 1 }` -- NINE tokens.
            // I shipped that break in the library commit and the contract test could not
            // see it, because it only ever exercised a unit variant.
            //
            // So the token is the variant NAME, cut at the first space or brace. The values
            // are not lost: they go to stderr on the next line, where a human reads them and
            // no parser does.
            let dbg = format!("{e:?}");
            let token = dbg.split([' ', '{']).next().unwrap_or(&dbg);
            println!("refused {token}");
            eprintln!("acfa-agg: {e}");
            // crdt-08: translate the library's contribution INDEX into the operator's LINE.
            // Without this the refusal names "contribution 0" against a file whose first
            // contribution is on line 3.
            if let AggError::DimensionMismatch { offender, .. } = e {
                if let Some(line) = cs_lines.get(offender) {
                    eprintln!("acfa-agg: that is line {line} of this request.");
                }
            }
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
