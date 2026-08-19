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

use acfa_receipt::identity::{is_usable_pubkey, Pki, PubKey};
use acfa_receipt::{decode, Invalid, Policy, Rule, WireError};
use std::io::{IsTerminal, Read};
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
        // ASCII before byte-slicing. `&hex[i*2..i*2+2]` indexes a `&str` by BYTES and
        // panics when the boundary falls inside a multi-byte character, so a non-ASCII
        // PKI line aborted the process instead of being reported as a bad line. Hex is
        // ASCII by definition, so this rejects rather than aborts.
        if !hex.is_ascii() {
            return Err(format!("line {}: public key must be hex", n + 1));
        }
        let mut pk: PubKey = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            // Slicing a `&str` by byte index panics on a non-ASCII boundary; hex is
            // ASCII, so reject rather than abort. See acfa-agg for the same guard.
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("line {}: bad hex", n + 1))?;
        }
        // crypto-10, SECOND DOOR. `is_usable_pubkey` says in its own doc that it is
        // "checked where keys ENTER, because by the time `verify` sees one the damage is a
        // policy decision already made" -- and this is an entry. `wire::decode` calls it
        // (wire.rs) and `acfa-finality` calls it at its `pki` directive; this door checked
        // only length, ASCII and hex, so a small-order identity entered the trusted set
        // here and every signature attributed to that node became one anybody could
        // produce, with nothing said to the operator.
        //
        // The file is operator-supplied and therefore less adversarial than the wire, which
        // is an argument about LIKELIHOOD, not about consequence: a weak key in a trusted
        // PKI is exactly the case where nobody is looking.
        if !is_usable_pubkey(&pk) {
            return Err(format!(
                "line {}: node {id} has an unusable public key (malformed or small-order)",
                n + 1
            ));
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
  --expect-state-root <64-hex>
                        the state root you obtained INDEPENDENTLY of this receipt.
                        Refuses (exit 1) if the receipt's root differs. This is the
                        only check that detects WITHHOLDING: verification proves the
                        issuer computed honestly over the set it SHOWED, never that
                        it showed everything it held.

Exit: 0 verified, 1 invalid, 2 unparseable, 3 self-consistent only (no --pki).";

fn main() -> ExitCode {
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
                        "acfa-verify: argument {} is not valid UTF-8; refusing rather than \
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
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    // REJECT UNKNOWN FLAGS. Silently ignoring them turns a failing security check into a
    // passing one: `--require-bounds` (plural, a one-character typo) simply did not match
    // `--require-bound`, so the check the operator asked for was never applied and the tool
    // exited 0. A verifier that ignores what it was asked to do is worse than one that
    // refuses, because the operator has no way to notice.
    const KNOWN: [&str; 7] = [
        "--pki",
        "--f",
        "--rule",
        "--require-bound",
        "--expect-state-root",
        "--help",
        "-h",
    ];
    for a in &args {
        if !a.starts_with('-') {
            continue;
        }
        let name = a.split('=').next().unwrap_or(a);
        if !KNOWN.contains(&name) {
            eprintln!("acfa-verify: unknown option {a:?}\n");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    }

    // THE `=` FORM, AND WHY THIS LINE USED TO BE THE HOLE IN THE FIX ABOVE.
    //
    // `flag_value` accepts BOTH spellings -- it strips a `name=` prefix -- so `--pki=k.txt`,
    // `--f=2` and `--rule=krum` all work. The unknown-flag guard above also accepts both,
    // because it splits on `=` before comparing. This line did NOT: it was
    // `args.iter().any(|a| a == "--require-bound")`, an exact match.
    //
    // So `--require-bound=true` -- the spelling every OTHER flag on this tool supports --
    // passed the unknown-flag check as a KNOWN option and then evaluated to FALSE. The one
    // security gate the verifier has was silently not applied, and the tool exited 0.
    //
    // That is the very defect the guard above was written to close (adv-03 / rust-07: a
    // one-character typo disabling `--require-bound` and exiting 0), reintroduced in a new
    // spelling by the fix itself. Closing the exact input a finding names while the mechanism
    // stays reachable one keystroke sideways is the shape of eleven fixes reviewed today, and
    // two of them were mine.
    //
    // A VALUE IS REFUSED RATHER THAN INTERPRETED. `--require-bound=false` is not treated as
    // "off": guessing wrong in that direction is a silent security downgrade, and guessing
    // wrong in the other ignores what the operator wrote. A boolean switch given a value it
    // does not define should say so.
    let mut require_bound = false;
    for a in &args {
        if a == "--require-bound" {
            require_bound = true;
        } else if let Some(v) = a.strip_prefix("--require-bound=") {
            if v == "true" {
                require_bound = true;
            } else {
                eprintln!(
                    "acfa-verify: --require-bound is a switch, not a setting; {v:?} is not a \
                     value it defines. Write --require-bound to enable it, or omit it entirely.\n"
                );
                eprint!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let pki_path = flag_value(&args, "--pki");
    let f_override = flag_value(&args, "--f");
    let rule_want = flag_value(&args, "--rule");

    // rust-08. THE MITIGATION THIS TOOL DOCUMENTS BUT DID NOT IMPLEMENT. Three places --
    // SECURITY.md, lib.rs and this binary's own closing note -- tell the operator to
    // "compare the state root against an independently obtained one", and there was no way
    // to supply one. Advice a tool gives and cannot accept is not a mitigation.
    //
    // Malformed input is refused rather than interpreted, for the same reason
    // `--require-bound=false` is: a root that is not 32 bytes of hex cannot match anything,
    // so silently failing the comparison would report WITHHOLDING for a typo.
    let expect_root = match flag_value(&args, "--expect-state-root") {
        None => None,
        Some(h) => {
            let h = h.trim().to_ascii_lowercase();
            let ok = h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit());
            if !ok {
                eprintln!(
                    "acfa-verify: --expect-state-root takes 64 hex characters (32 bytes); \
                     got {} character(s). Refusing rather than comparing against a value \
                     that cannot match any root.\n",
                    h.len()
                );
                eprint!("{USAGE}");
                return ExitCode::from(2);
            }
            Some(h)
        }
    };

    let flag_names = ["--pki", "--f", "--rule", "--expect-state-root"];
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

    // Refuse an interactive stdin rather than blocking on it. With no FILE and no pipe this
    // sat in a blocking read forever and printed nothing, which reads as a hang. acfa-agg
    // was given this guard; acfa-verify was not, so the two disagreed about the same case.
    if path.is_none() && std::io::stdin().is_terminal() {
        eprintln!("acfa-verify: no input. Give a FILE, or pipe a receipt in, or --help.\n");
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    // CHECK THE MAGIC BEFORE READING THE REST. `fs::read` pulled the whole file into memory
    // and only then asked whether it was a receipt at all, so pointing this at a 200 MB file
    // that is not an ACFA receipt cost 200 MB of resident memory to reach "bad magic".
    // Anyone can hand a verifier a file, so the cost of REJECTING one should be bounded by
    // the header, not by the attacker's choice of length.
    //
    // Eight bytes is the whole check: it is a fixed-size constant at a fixed offset.
    let mut bytes = Vec::new();
    let read = match &path {
        Some(p) => (|| -> std::io::Result<()> {
            let mut f = std::fs::File::open(p)?;
            let mut head = [0u8; 8];
            match f.read_exact(&mut head) {
                Ok(()) if &head == acfa_receipt::wire::MAGIC => {}
                // Too short to carry a magic, or the magic is wrong. Either way this is not
                // a receipt and there is nothing to gain by reading the remainder.
                _ => {
                    bytes = head.to_vec();
                    return Ok(());
                }
            }
            bytes.extend_from_slice(&head);
            f.read_to_end(&mut bytes)?;
            Ok(())
        })(),
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
                // decode never produces this -- it is an ENCODE-side refusal for a fault bound
                // that does not fit the wire -- but the shared enum makes the match exhaustive.
                WireError::FaultBoundTooLarge { f } => {
                    format!("fault bound f = {f} does not fit the wire (encode-side error)")
                }
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
                if let Some(want) = &expect_root {
                    if &hex32(&sc.state_root) != want {
                        eprintln!();
                        eprintln!(
                            "acfa-verify: STATE ROOT MISMATCH -- the receipt does not describe \
                             the state you expected."
                        );
                        eprintln!("  expected {want}");
                        eprintln!("  receipt  {}", hex32(&sc.state_root));
                        eprintln!(
                            "  This is the withholding check: the issuer may have computed \
                             honestly over a set it chose to show you."
                        );
                        return ExitCode::from(1);
                    }
                    println!("  state root MATCHES the one you supplied.");
                }
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

    let rule_was_pinned = rule_want.is_some();
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
            // rust-08: check BEFORE printing VERIFIED. A mismatch means this is not the
            // receipt you were promised, and printing the success banner first and the
            // refusal after would leave a scrollback where VERIFIED is the eye-catching line.
            if let Some(want) = &expect_root {
                if &hex32(&v.state_root) != want {
                    eprintln!(
                        "acfa-verify: STATE ROOT MISMATCH -- the receipt does not describe the \
                         state you expected."
                    );
                    eprintln!("  expected {want}");
                    eprintln!("  receipt  {}", hex32(&v.state_root));
                    eprintln!(
                        "  Every signature may still be genuine. This is the WITHHOLDING check: \
                         verification proves the issuer computed honestly over the set it \
                         SHOWED, never that it showed everything it held."
                    );
                    return ExitCode::from(1);
                }
            }
            println!("VERIFIED");
            // crypto-08: NAME THE RULE. A receipt's robustness argument is a property of the
            // aggregation rule it used, so a VERIFIED verdict that never says which rule that
            // was leaves the operator unable to tell whether it matches the rule THEY assume.
            println!("  rule         {:?}", receipt.rule);
            if !rule_was_pinned {
                println!(
                    "               NOT PINNED -- verified against the receipt's OWN claimed \
                     rule; pass --rule to require the rule you expect"
                );
            }
            println!("  round        {}", v.round);
            println!("  state root   {}", hex32(&v.state_root));
            if expect_root.is_some() {
                println!("               MATCHES the root you supplied independently.");
            }
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
            // Lemma 12. Reported on its OWN line and never folded into VERIFIED, because it
            // answers a DIFFERENT question: not "did the issuer compute honestly over this
            // set" but "would the selection have been the same in real arithmetic". An
            // operator who cannot see the distinction will assume the strongest reading, so
            // the absent case says so explicitly rather than printing nothing.
            match &v.margin {
                Some(c) if c.certified => {
                    println!("  no-flip      CERTIFIED -- fixed-point selection provably equals");
                    println!("               the real-valued one (Lemma 12)");
                    println!(
                        "               margin {} > threshold {} (4 x beta {})",
                        c.margin, c.threshold, c.beta
                    );
                }
                Some(c) => {
                    println!("  no-flip      NOT CERTIFIED -- the selection boundary is too close");
                    println!(
                        "               margin {} <= threshold {} (4 x beta {})",
                        c.margin, c.threshold, c.beta
                    );
                    println!(
                        "               This is NOT evidence of a flip. It means quantisation"
                    );
                    println!("               COULD have changed who was selected, and the margin");
                    println!(
                        "               condition cannot rule it out. An exact tie (margin 0)"
                    );
                    println!("               is the residual no condition can ever cover.");
                }
                None => {
                    println!("  no-flip      not available for this round");
                    println!("               (empty round, refusal, select-all, or Bulyan --");
                    println!("               Lemma 12 is stated for multi-Krum's boundary)");
                }
            }
            println!();
            println!("Checked against the identities in {pki_path} and f = {f}.");
            println!("This establishes that the issuer computed honestly over the set shown.");
            println!("It does NOT establish that the issuer showed every entry it held --");
            println!("compare the state root against an independently obtained one for that --");
            println!("pass it as --expect-state-root <64-hex> and a mismatch exits 1.");
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
        Invalid::TooMuchDerivableWork { would_be, max } => {
            eprintln!("  this receipt would cost more work to check than it is allowed to");
            eprintln!("  up to {would_be} equivocation proofs derivable, limit {max}");
            eprintln!("  each derivable proof is a signature verification, and the count is");
            eprintln!("  quadratic in how often a single node id repeats -- so a small file");
            eprintln!("  can buy a large amount of your CPU. Refused before doing the work.");
        }
        Invalid::TooManyContributions { would_be, max } => {
            eprintln!("  this receipt carries more contributions than the verifier will scan");
            eprintln!("  {would_be} carried, limit {max}");
            eprintln!("  equivocation detection scans every held contribution, so checking");
            eprintln!("  is quadratic in this count even when the set derives no proofs -- so");
            eprintln!(
                "  a small file can buy a large amount of your CPU. Refused before the scan."
            );
        }
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
