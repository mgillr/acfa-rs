// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! crypto-08 -- the checker's robustness argument is not pinned by default.
//!
//! `Policy::new` leaves `rule: None`, which accepts EITHER aggregation rule. A checker
//! built the default way has therefore not told the receipt which rule its own robustness
//! argument assumes, and `population_bound_met` can only answer for the rule the RECEIPT
//! used. The permissive path is the one spelled `new`, so it is reached by anyone who never
//! thought about the rule at all.
//!
//! MEASURED at n = 5, f = 1, where the two rules genuinely disagree -- Krum requires
//! 2f+3 = 5, Bulyan requires 4f+3 = 7:
//!
//!   Krum receipt vs `Policy::new(pki, 1)`                -> Ok, population_bound_met TRUE
//!   Krum receipt vs `.expecting(Rule::Bulyan)`           -> Err(RuleMismatch)
//!
//! So an operator who assumes Bulyan gets a fully green verdict, INCLUDING the flag whose
//! whole job is to say "was the population large enough", for a deployment that does not
//! meet their assumption.
//!
//! TWO OF THESE TESTS ARE DIFFERENT KINDS OF TEST AND THAT IS DELIBERATE.
//!
//! `expecting_pins_the_rule` is a GUARD. It must never go red.
//!
//! `the_default_policy_is_fail_open_on_the_rule` is a CHARACTERISATION test. It pins
//! behaviour that is currently WRONG, so that the fail-open default cannot be relied upon
//! silently or changed silently. WHEN THE crypto-08 RULING LANDS AND `Policy::new`
//! REQUIRES A RULE, THIS TEST SHOULD BE INVERTED OR DELETED, NOT PATCHED TO KEEP PASSING.
//! Its failure is the intended signal that the fix arrived; read it as good news.

use acfa_receipt::entry::Contribution;
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Invalid, Policy, Receipt, Rule, State};

fn room(n: u32) -> (Vec<Identity>, Pki) {
    let ids: Vec<Identity> = (1..=n)
        .map(|i| Identity::from_secret(i, &[i as u8; 32]))
        .collect();
    let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    (ids, pki)
}

fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            rnd,
            a.node_id,
            &th,
        )),
    }
}

/// n = 5 is the population where the two rules disagree; the test is worthless anywhere
/// the bounds coincide, so assert the premise rather than trusting it.
fn krum_receipt_at_five() -> (Receipt, Pki) {
    assert_eq!(Rule::Krum.required_n(1), 5, "premise: Krum needs 2f+3");
    assert_eq!(Rule::Bulyan.required_n(1), 7, "premise: Bulyan needs 4f+3");

    let (ids, pki) = room(5);
    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        s.deliver(contrib(id, 1, &[i as i64, 0]), &pki);
    }
    (
        Receipt::issue(
            &s,
            acfa_receipt::identity::NO_CONTEXT,
            1,
            &pki,
            1,
            Rule::Krum,
        ),
        pki,
    )
}

#[test]
fn expecting_pins_the_rule() {
    // GUARD. Never let this go red.
    let (receipt, pki) = krum_receipt_at_five();
    assert_eq!(
        receipt
            .verify(&Policy::new(pki, 1).expecting(Rule::Bulyan))
            .err(),
        Some(Invalid::RuleMismatch {
            policy: Rule::Bulyan,
            receipt: Rule::Krum
        }),
        "a checker that states its rule must be able to refuse a receipt using another one; \
         if this is red, the only mechanism a Bulyan operator has to reject a Krum receipt \
         is gone"
    );
}

#[test]
fn the_default_policy_is_fail_open_on_the_rule() {
    // CHARACTERISATION, NOT A GUARD. See the module docs: invert or delete this when
    // `Policy::new` starts requiring a rule. A failure here means the fix landed.
    let (receipt, pki) = krum_receipt_at_five();
    let default_policy = Policy::new(pki, 1);

    assert_eq!(default_policy.rule, None, "Policy::new does not pin a rule");

    let verdict = receipt
        .verify(&default_policy)
        .expect("a Krum receipt passes a policy that pinned no rule");

    assert!(
        verdict.population_bound_met,
        "AND THE BOUND FLAG READS GREEN TOO. It is computed against the RECEIPT's rule \
         (Krum, 5 required, 5 admitted), not against the checker's. An operator whose \
         argument assumes Bulyan needs 7 and is told the population was sufficient."
    );
}

/// crypto-08, the CLI half: `acfa-verify` must NAME the aggregation rule in its VERIFIED
/// output, and must flag when the rule was not pinned -- so an operator can tell whether the
/// verified rule matches the one they assume. Before, VERIFIED never mentioned the rule.
///
/// GUARD-DELETION: remove the `println!("  rule ...")` line from acfa-verify and this goes RED.
#[test]
fn acfa_verify_names_the_rule_and_flags_when_it_is_not_pinned() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let (receipt, pki) = krum_receipt_at_five();
    let dir = std::env::temp_dir().join("acfa_crypto08_cli");
    std::fs::create_dir_all(&dir).unwrap();
    let pki_file = dir.join("pki.txt");
    let mut txt = String::new();
    for (id, pk) in &pki {
        txt.push_str(&format!(
            "{id} {}\n",
            pk.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
    }
    std::fs::write(&pki_file, txt).unwrap();
    let bytes = acfa_receipt::wire::encode(&receipt);

    let run = |extra: &[&str]| -> String {
        let mut c = Command::new(env!("CARGO_BIN_EXE_acfa-verify"));
        c.arg(format!("--pki={}", pki_file.display())).arg("--f=1");
        for a in extra {
            c.arg(a);
        }
        let mut ch = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        ch.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
        let o = ch.wait_with_output().unwrap();
        String::from_utf8_lossy(&o.stdout).to_string()
    };

    // Not pinned: names the rule AND flags that it was not pinned.
    let out = run(&[]);
    assert!(out.contains("rule"), "VERIFIED must name the rule: {out}");
    assert!(
        out.contains("Krum"),
        "the receipt's rule must appear: {out}"
    );
    assert!(
        out.contains("NOT PINNED"),
        "unpinned rule must be flagged: {out}"
    );

    // Pinned to the correct rule: named, no NOT PINNED flag.
    let out = run(&["--rule=krum"]);
    assert!(out.contains("Krum"));
    assert!(
        !out.contains("NOT PINNED"),
        "a pinned rule must not be flagged: {out}"
    );
}
