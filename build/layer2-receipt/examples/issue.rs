// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Issue demo artefacts, for driving `acfa-verify` end to end.
//!
//! ```sh
//! cargo run --example issue                  > receipt.bin   # honest
//! cargo run --example issue -- --pki         > trusted.pki   # the identity set
//! cargo run --example issue -- --equivocate  > equiv.bin     # node 1 equivocates
//! cargo run --example issue -- --tamper      > tampered.bin  # claimed aggregate altered
//! cargo run --example issue -- --forged-pki  > forged.bin    # identities nobody authorised
//! ```
//!
//! Deterministic: same flags in, same bytes out, so the outputs are usable as fixtures.
//!
//! `--forged-pki` is the important one. It is internally flawless -- every signature in it
//! is genuine, for keys the forger owns -- so it is what distinguishes a verifier that
//! checks a receipt against a trusted identity set from one that checks it against itself.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{encode, Contribution, Receipt, Rule, State};
use std::io::Write;

fn build(ids: &[Identity], equivocate: bool) -> (State, Pki) {
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut state = State::new();
    for (i, id) in ids.iter().enumerate() {
        let t = vec![i as i64 * 3, i as i64 + 1, 7 - i as i64];
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
    if equivocate {
        let t = vec![9999, 9999, 9999];
        let sig = ids[0].sign(&contrib_msg(1, &h(&enc_tensor(&t))));
        state.deliver(
            Contribution {
                rnd: 1,
                node_id: ids[0].node_id,
                tensor: t,
                sig,
            },
            &pki,
        );
    }
    (state, pki)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |f: &str| args.iter().any(|a| a == f);

    // The honest deployment: node ids 1..=5, seeds fixed.
    let honest: Vec<Identity> = (1..=5)
        .map(|n| Identity::from_secret(n, &[n as u8; 32]))
        .collect();

    if has("--pki") {
        // The trusted identity set, in the format `acfa-verify --pki` reads.
        let mut out = String::from("# ACFA trusted identities: <node_id> <hex public key>\n");
        for id in &honest {
            let pk: String = id.public().iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!("{} {}\n", id.node_id, pk));
        }
        print!("{out}");
        return;
    }

    let ids: Vec<Identity> = if has("--forged-pki") {
        // Identities nobody ever authorised. Note the node ids deliberately OVERLAP the
        // honest ones (1..=5) -- a forger would not helpfully use distinct numbering, and
        // a verifier that compared only ids rather than KEYS would be fooled.
        (1..=5)
            .map(|n| Identity::from_secret(n, &[0xF0 ^ n as u8; 32]))
            .collect()
    } else {
        honest
    };

    let (state, pki) = build(&ids, has("--equivocate"));
    let mut receipt = Receipt::issue(&state, 1, &pki, 1, Rule::Krum);

    if has("--withhold") {
        // Both halves of an equivocation present, no proof formed: the receipt holds the
        // evidence and never computes the conviction.
        let t = vec![9999, 9999, 9999];
        let sig = ids[0].sign(&contrib_msg(1, &h(&enc_tensor(&t))));
        let mut st2 = state;
        st2.add_contribution(Contribution {
            rnd: 1,
            node_id: ids[0].node_id,
            tensor: t,
            sig,
        });
        let r = Receipt::issue(&st2, 1, &pki, 1, Rule::Krum);
        std::io::stdout()
            .write_all(&encode(&r))
            .expect("write receipt");
        return;
    }

    if has("--tamper") {
        if let Some(a) = receipt.claimed_aggregate.as_mut() {
            a[0] += 1;
        }
    }

    std::io::stdout()
        .write_all(&encode(&receipt))
        .expect("write receipt");
}
