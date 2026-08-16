// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! `acfa-verify` -- check an ACFA receipt offline.
//!
//! Re-executes the aggregate and reports what the receipt does and does not establish.
//! No network, no clock, no trusted party.
//!
//! ## Why `--pki` is mandatory for a security verdict
//!
//! A receipt carries its own PKI and its own fault bound, and both are chosen by whoever
//! wrote the receipt. Checked against itself, a receipt forged from five freshly minted
//! keys verifies perfectly -- every signature in it is genuine, for keys the forger owns.
//! So this tool will not print VERIFIED without an independently supplied identity set.
//! Without `--pki` it performs a self-consistency check, labels it as one, and exits 3.
//!
//! Exit codes:
//!   0  verified against the supplied policy
//!   1  invalid
//!   2  unparseable
//!   3  self-consistent only -- NOT a security verdict (no `--pki` given)

use acfa_receipt::identity::{Pki, PubKey};
use acfa_receipt::{decode, Invalid, Policy, Rule, WireError};
use std::io::Read;
use std::process::ExitCode;

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse a PKI file: one `<node_id> <64-hex-char public key>` per line, `#` comments.
fn parse_pki(text: &str) -> Result<Pki, String> {
    let mut pki = Pki::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(id), Some(hex)) = (parts.next(), parts.next()) else {
            return Err(format!("line {}: expected '<node_id> <hex pubkey>'", n + 1));
        };
        if parts.next().is_some() {
            return Err(format!("line {}: trailing content", n + 1));
        }
        let id: u32 = id
            .parse()
            .map_err(|_| format!("line {}: bad node id {id:?}", n + 1))?;
        if hex.len() != 64 {
            return Err(format!(
                "line {}: public key must be 64 hex chars, got {}",
                n + 1,
                hex.len()
            ));
        }
        let mut pk: PubKey = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("line {}: bad hex", n + 1))?;
        }
        if pki.insert(id, pk).is_some() {
            return Err(format!("line {}: duplicate node id {id}", n + 1));
        }
    }
    if pki.is_empty() {
        return Err("no identities in the PKI file".into());
    }
    Ok(pki)
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
        if let Some(rest) = a.strip_prefix(&format!("{name}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

const USAGE: &str = "\
acfa-verify [FILE] --pki <FILE> [--f <N>] [--rule krum|bulyan] [--require-bound]

Verifies an ACFA Layer 2 receipt offline. Reads stdin when FILE is absent.

  --pki <FILE>          identities you independently trust, one per line:
                          <node_id> <64-hex public key>
                        REQUIRED for a security verdict. A receipt checked against
                        its own carried PKI proves nothing: a forger mints keys and
                        every signature verifies.
  --f <N>               the fault bound your robustness argument assumes.
                        Defaults to the receipt's own value, which is only safe if
                        you already know it matches your deployment.
  --rule krum|bulyan    require a specific aggregation rule.
  --require-bound       fail a receipt whose admitted population is below the rule's
                        stated bound. NOTE this is a POPULATION check, not a safety
                        check: meeting the bound does not make a round safe.

Exit: 0 verified, 1 invalid, 2 unparseable, 3 self-consistent only (no --pki).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let require_bound = args.iter().any(|a| a == "--require-bound");
    let pki_path = flag_value(&args, "--pki");
    let f_override = flag_value(&args, "--f");
    let rule_want = flag_value(&args, "--rule");

    let flag_names = ["--pki", "--f", "--rule"];
    let mut consumed: Vec<usize> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if flag_names.contains(&a.as_str()) {
            consumed.push(i);
            consumed.push(i + 1);
        }
    }
    let path = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && !consumed.contains(i))
        .map(|(_, a)| a.clone());

    let mut bytes = Vec::new();
    let read = match &path {
        Some(p) => std::fs::read(p).map(|b| bytes = b),
        None => std::io::stdin().read_to_end(&mut bytes).map(|_| ()),
    };
    if let Err(e) = read {
        eprintln!("acfa-verify: cannot read input: {e}");
        return ExitCode::from(2);
    }

    let receipt = match decode(&bytes) {
        Ok(r) => r,
        Err(e) => {
            let why = match e {
                WireError::BadMagic => "not an ACFA receipt (bad magic)".to_string(),
                WireError::UnsupportedVersion(v) => format!("unsupported receipt version {v}"),
                WireError::Truncated => "truncated, or a length prefix exceeds the input".into(),
                WireError::TrailingBytes => "trailing bytes after the receipt".into(),
                WireError::UnknownRule(b) => format!("unknown aggregation rule {b}"),
                WireError::NotCanonical(w) => format!("not canonically encoded: {w}"),
                WireError::ValueOutOfRange => "a tensor value is outside the Q16.16 range \
(+/-2^31); refusing rather than saturating, because saturating would admit the receipt and \
silently change the aggregate"
                    .to_string(),
            };
            eprintln!("acfa-verify: UNPARSEABLE -- {why}");
            return ExitCode::from(2);
        }
    };

    // ---- no policy: self-consistency only, and say so loudly -----------------
    let Some(pki_path) = pki_path else {
        return match receipt.check_self_consistent() {
            Ok(sc) => {
                println!("SELF-CONSISTENT ONLY -- THIS IS NOT A SECURITY VERDICT");
                println!("  round        {}", sc.round);
                println!("  state root   {}", hex32(&sc.state_root));
                println!("  output root  {}", hex32(&sc.output_root));
                println!();
                println!("The receipt agrees with ITSELF, against the identity set it");
                println!("carries. That set is chosen by whoever wrote the receipt, so a");
                println!("forgery built from freshly minted keys reaches this same result.");
                println!("Supply --pki with identities you independently trust.");
                ExitCode::from(3)
            }
            Err(e) => {
                report_invalid(&e);
                ExitCode::from(1)
            }
        };
    };

    let pki_text = match std::fs::read_to_string(&pki_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("acfa-verify: cannot read --pki {pki_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let pki = match parse_pki(&pki_text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acfa-verify: bad --pki file: {e}");
            return ExitCode::from(2);
        }
    };

    let f = match f_override {
        None => receipt.f,
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("acfa-verify: --f must be a non-negative integer, got {v:?}");
                return ExitCode::from(2);
            }
        },
    };

    let mut policy = Policy::new(pki, f);
    if let Some(r) = rule_want {
        policy.rule = match r.as_str() {
            "krum" => Some(Rule::Krum),
            "bulyan" => Some(Rule::Bulyan),
            other => {
                eprintln!("acfa-verify: --rule must be krum or bulyan, got {other:?}");
                return ExitCode::from(2);
            }
        };
    }

    match receipt.verify(&policy) {
        Ok(v) => {
            println!("VERIFIED");
            println!("  round        {}", v.round);
            println!("  state root   {}", hex32(&v.state_root));
            println!("  output root  {}", hex32(&v.output_root));
            match &v.aggregate {
                None => println!("  aggregate    NONE (no admissible contribution)"),
                Some(a) => println!(
                    "  aggregate    {} values, first {:?}",
                    a.len(),
                    &a[..a.len().min(8)]
                ),
            }
            println!("  admitted     {:?}", v.admitted);
            println!("  convicted    {:?}", v.convicted);
            if !v.convictable_but_unconvicted.is_empty() {
                println!(
                    "  UNCONVICTED  {:?}  <-- this receipt PROVES these equivocated and \
                     does not convict them",
                    v.convictable_but_unconvicted
                );
            }
            println!(
                "  bound n>=req {}",
                if v.population_bound_met {
                    format!(
                        "met ({} admitted, {} required) -- POPULATION only, not a safety verdict",
                        v.admitted.len(),
                        receipt.rule.required_n(f)
                    )
                } else {
                    format!(
                        "NOT MET -- {} admitted, {} required; no Byzantine guarantee applies",
                        v.admitted.len(),
                        receipt.rule.required_n(f)
                    )
                }
            );
            println!();
            println!("Checked against the identities in {pki_path} and f = {f}.");
            println!("This establishes that the issuer computed honestly over the set shown.");
            println!("It does NOT establish that the issuer showed every entry it held --");
            println!("compare the state root against an independently obtained one for that.");
            println!();
            println!("Meeting the population bound is NOT a safety guarantee. A colluding");
            println!("within-norm adversary can be selected while the bound holds and move");
            println!("the aggregate; that is a property of the imported rule. See the");
            println!("within-norm characterisation in the aggregation crate's test suite.");

            if require_bound && !v.population_bound_met {
                eprintln!("\nacfa-verify: FAILED --require-bound");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            report_invalid(&e);
            ExitCode::from(1)
        }
    }
}

fn report_invalid(e: &Invalid) {
    eprintln!("INVALID");
    match e {
        Invalid::PkiMismatch => {
            eprintln!("  the receipt's identity set is NOT the one you supplied");
            eprintln!("  every signature in it may still be genuine -- for keys you do not trust");
        }
        Invalid::FaultBoundMismatch { policy, receipt } => eprintln!(
            "  receipt assumes f = {receipt}, your policy assumes f = {policy}; \
             the robustness bound differs"
        ),
        Invalid::RuleMismatch { policy, receipt } => {
            eprintln!("  receipt used {receipt:?}, your policy requires {policy:?}")
        }
        Invalid::BadContributionSignature { node_id, leaf } => eprintln!(
            "  contribution {} by node {node_id} is not signed by that identity",
            hex32(leaf)
        ),
        Invalid::BogusProof { node_id, leaf } => eprintln!(
            "  proof {} against node {node_id} does not demonstrate equivocation",
            hex32(leaf)
        ),
        Invalid::WrongRound { expected, found } => {
            eprintln!("  contribution tagged round {found}, receipt claims {expected}")
        }
        Invalid::StateRootMismatch { claimed, actual } => {
            eprintln!("  commitment trace does not cover the carried entries");
            eprintln!("    claimed {}", hex32(claimed));
            eprintln!("    actual  {}", hex32(actual));
        }
        Invalid::AggregateMismatch { claimed, actual } => {
            eprintln!("  re-execution does not reproduce the claimed aggregate");
            eprintln!("    claimed {claimed:?}");
            eprintln!("    actual  {actual:?}");
        }
        Invalid::OutputRootMismatch { claimed, actual } => {
            eprintln!("  output root does not commit to the claimed aggregate");
            eprintln!("    claimed {}", hex32(claimed));
            eprintln!("    actual  {}", hex32(actual));
        }
    }
}
