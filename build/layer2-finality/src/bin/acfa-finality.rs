// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `acfa-finality` -- observe certificates, detect forks, report halt state.
//!
//! The operational counterpart to `acfa-verify`. `acfa-verify` answers *is this
//! aggregate what the shown set produces*; this answers *was that the whole set, is
//! this round final, and has the timing assumption broken*.
//!
//! ## Why it re-emits evidence
//!
//! `Finality::evidence()` is documented as the published evidence "for onward gossip".
//! This binary is what makes that literally true: it ingests certificates, detects a
//! fork between two valid conflicting ones, and writes the fork back out in canonical
//! wire form. A node that observed a violation can hand those bytes to any other node,
//! which can verify the violation from the two certificates alone without trusting the
//! reporter. Evidence that cannot leave the process is a log line, not a proof.
//!
//! ## Input (stdin, line-oriented, LF; `#` comments and blank lines ignored)
//!
//! ```text
//! f <usize>                    # fault bound; required before any cert
//! pki <node_id> <pubkey_hex>   # repeatable; 32 bytes hex
//! cert <hex>                   # wire-encoded certificate (ACFA-C1)
//! fork <hex>                   # wire-encoded fork evidence (ACFA-K1)
//! ```
//!
//! ## Output (stdout)
//!
//! ```text
//! status running|halted
//! last_certified <round>          # running only
//! at_round <round>                # halted only
//! reconcile_from <round>          # halted only
//! unattributable true|false       # halted only
//! attributed <id>...              # signers a fork names, if any
//! certified <round>...
//! rejected <round> <reason>       # one per refused certificate
//! evidence <hex>                  # one per observed fork, canonical, for gossip
//! ```
//!
//! ## Exit codes -- the contract a monitor scripts against
//!
//! * `0` -- running. No fork observed.
//! * `1` -- HALTED. A fork was observed; nothing past `reconcile_from` is final.
//! * `2` -- malformed input. Says nothing about finality.
//!
//! A halt is a *result*, not a crash: the construction exists so that a synchrony
//! violation is never silent, so the tool reports it deliberately and exits non-zero.

use acfa_finality::wire::{decode_cert, decode_fork, encode_fork};
use acfa_finality::{Finality, Rejected, Status};
use acfa_receipt::identity::{Pki, PubKey};
use std::io::Read;
use std::process::ExitCode;

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bad(line_no: usize, why: &str) -> ExitCode {
    eprintln!("acfa-finality: line {line_no}: {why}");
    ExitCode::from(2)
}

const USAGE: &str = "\
acfa-finality -- observe certificates, detect forks, report halt state

USAGE:
    acfa-finality < input     reads directives on stdin, writes a report to stdout

INPUT (line-oriented, LF; # comments and blank lines ignored):
    f <usize>                    fault bound; required before any cert
    pki <node_id> <pubkey_hex>   repeatable; 32 bytes hex
    cert <hex>                   wire-encoded certificate (ACFA-C1)
    fork <hex>                   wire-encoded fork evidence (ACFA-K1)

OUTPUT:
    status running|halted, plus certified/rejected rounds, and `evidence <hex>` for
    each observed fork -- canonical bytes another node can verify without trusting
    this one.

EXIT CODES:
    0 running, no fork observed
    1 HALTED, a fork was observed; nothing past reconcile_from is final
    2 malformed input; says nothing about finality

    A halt is a result, not a crash: the construction exists so a synchrony violation
    is never silent.

Full documentation: https://github.com/mgillr/acfa-rs
";

fn main() -> ExitCode {
    // Same treatment as acfa-agg, for the same reason and found the same way. This
    // program also reads stdin unconditionally, so `acfa-finality --help` blocked
    // forever and printed nothing. Three binaries ship; acfa-verify handled --help and
    // the other two hung, which meant the convention was inconsistent across a single
    // release. Fixing one and not the others would have left the same trap one command
    // further along.
    use std::io::IsTerminal;
    // rust-04. `std::env::args()` PANICS on an argument that is not valid Unicode. Every
    // one of these binaries documents "2 unreadable input" and all three ABORTED AT 101
    // instead, with a rustc-internal message an operator cannot act on. Measured before
    // this change, one argument of `--pki=\xff\xfe`: acfa-agg 101, acfa-verify 101,
    // acfa-finality 101.
    //
    // `args_os` cannot panic, so the refusal becomes ours to write -- which is the point:
    // an abort is not a refusal, and the contract promised a refusal. Same shape as num-05,
    // where the CLI aborted at 101 on well-typed input its own contract said was exit 1.
    //
    // The message names the POSITION, not the bytes: the argument is by definition not
    // printable, and "argument 2" is what the operator can act on.
    let args: Vec<String> = {
        let mut collected = Vec::new();
        for (i, a) in std::env::args_os().skip(1).enumerate() {
            match a.into_string() {
                Ok(s) => collected.push(s),
                Err(_) => {
                    eprintln!(
                        "acfa-finality: argument {} is not valid UTF-8; refusing rather than \
                         aborting.\n",
                        i + 1
                    );
                    eprint!("{USAGE}");
                    return ExitCode::from(2);
                }
            }
        }
        collected
    };
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if let Some(a) = args.first() {
        eprintln!("acfa-finality: unexpected argument {a:?}; input is read from stdin\n");
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }
    if std::io::stdin().is_terminal() {
        eprintln!("acfa-finality: no input on stdin. Pipe directives in, or --help.\n");
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("acfa-finality: could not read stdin");
        return ExitCode::from(2);
    }

    let mut f: Option<usize> = None;
    let mut pki: Pki = Pki::new();
    let mut fin: Option<Finality> = None;
    let mut rejected: Vec<String> = Vec::new();

    for (n, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(kw) = it.next() else { continue };

        match kw {
            "f" => {
                let Some(v) = it.next().and_then(|v| v.parse::<usize>().ok()) else {
                    return bad(n + 1, "f expects a non-negative integer");
                };
                if fin.is_some() {
                    return bad(n + 1, "f must be set before any cert or fork");
                }
                f = Some(v);
                fin = Some(Finality::new(v));
            }
            "pki" => {
                let (Some(id), Some(pk)) = (it.next(), it.next()) else {
                    return bad(n + 1, "pki expects <node_id> <pubkey_hex>");
                };
                let Ok(id) = id.parse::<u32>() else {
                    return bad(n + 1, "node_id must be a u32");
                };
                let Some(raw) = unhex(pk) else {
                    return bad(n + 1, "pubkey must be hex");
                };
                let Ok(key) = <PubKey>::try_from(raw.as_slice()) else {
                    return bad(n + 1, "pubkey must be 32 bytes");
                };
                if pki.insert(id, key).is_some() {
                    return bad(n + 1, "duplicate node_id in pki");
                }
            }
            "cert" | "fork" => {
                let (Some(fin), Some(_f)) = (fin.as_mut(), f) else {
                    return bad(n + 1, "f must be set before any cert or fork");
                };
                let Some(hexed) = it.next() else {
                    return bad(n + 1, "expects one hex payload");
                };
                let Some(bytes) = unhex(hexed) else {
                    return bad(n + 1, "payload must be hex");
                };

                if kw == "cert" {
                    let c = match decode_cert(&bytes) {
                        Ok(c) => c,
                        Err(e) => return bad(n + 1, &format!("undecodable certificate: {e:?}")),
                    };
                    let round = c.tuple.round;
                    match fin.observe(c, &pki) {
                        Ok(()) => {}
                        // A fork is NOT an input error: both certificates are valid,
                        // which is the entire point. It is recorded, not rejected.
                        Err(Rejected::ForkedAt(r)) => rejected.push(format!("{r} forked")),
                        Err(Rejected::Invalid) => rejected.push(format!("{round} invalid")),
                    }
                } else {
                    let k = match decode_fork(&bytes) {
                        Ok(k) => k,
                        Err(e) => return bad(n + 1, &format!("undecodable fork: {e:?}")),
                    };
                    // A fork we are TOLD about still has to prove itself against our
                    // own PKI. Transferable evidence means verifiable by the recipient,
                    // not believed on the reporter's word.
                    if !fin.observe_fork(k, &pki) {
                        rejected.push("fork unverifiable".to_string());
                    }
                }
            }
            other => return bad(n + 1, &format!("unknown directive {other:?}")),
        }
    }

    let Some(fin) = fin else {
        eprintln!("acfa-finality: no `f` directive, nothing to report");
        return ExitCode::from(2);
    };

    match fin.status() {
        Status::Running { last_certified } => {
            println!("status running");
            println!("last_certified {last_certified}");
        }
        Status::Halted {
            at_round,
            reconcile_from,
            unattributable,
        } => {
            println!("status halted");
            println!("at_round {at_round}");
            println!("reconcile_from {reconcile_from}");
            println!("unattributable {unattributable}");
        }
    }

    let attributed = fin.attributed();
    if !attributed.is_empty() {
        let ids: Vec<String> = attributed.iter().map(|i| i.to_string()).collect();
        println!("attributed {}", ids.join(" "));
    }

    let certified: Vec<String> = fin
        .certified_rounds()
        .iter()
        .map(|r| r.to_string())
        .collect();
    println!("certified {}", certified.join(" "));

    for r in &rejected {
        println!("rejected {r}");
    }

    for k in fin.evidence() {
        println!("evidence {}", hex(&encode_fork(k)));
    }

    if fin.is_halted() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
