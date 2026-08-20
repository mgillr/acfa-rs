// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! UC2 -- Reproducible multi-party merging: several parties, one byte-identical result.
//!
//! Run:
//!   cargo run -q --release --example uc2_merge_order
//!
//! THE PROBLEM. Five organisations merge model deltas. Each receives the others' updates
//! over a different network path, so each sees them in a DIFFERENT ORDER. If the merged
//! result depends on arrival order, no two parties can sign the same artefact and there is
//! nothing to agree on -- every party has a defensible, different answer.
//!
//! WHAT THIS DEMONSTRATES. The same contributions, delivered in every one of the 120
//! possible orders, produce ONE state root and ONE aggregate, byte for byte.
//!
//! HONEST LIMITS -- this is the half of determinism that runs on your machine:
//!   1. This tests ORDER invariance on ONE machine. It does NOT test cross-architecture
//!      determinism, and order invariance alone would be satisfied by an implementation
//!      that is consistently wrong everywhere.
//!   2. The cross-architecture half is evidence this demo does NOT regenerate: see
//!      build/DETERMINISM-RESULTS.md and the CI matrix, which gates eight architectures
//!      including real ARM64 silicon and big-endian s390x. Those runs are the claim; this
//!      is not. Do not restate a target count here: DETERMINISM-RESULTS says counting each
//!      architecture as its own data model over-counts, and this comment used to do that.
//!   3. 120 orders is 5! exhaustively, not a sample. That is only exhaustive for n=5.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{Contribution, State};
use std::collections::BTreeSet;

/// Krum at `f = 1` on this build's fixed-point scale.
///
/// A NAMED FIXTURE, NOT A DEFAULT. A contribution signed under different round parameters is
/// filtered out of the round by `Receipt::issue`, exactly as a foreign `ctx` is, so a test that
/// needs other parameters has to say so rather than inherit these silently.
const PARAMS_DEFAULT: acfa_receipt::RoundParams = acfa_receipt::RoundParams {
    rule: acfa_receipt::Rule::Krum,
    f: 1,
    frac_bits: acfa_receipt::FRAC_BITS,
};

fn permutations(v: &[usize]) -> Vec<Vec<usize>> {
    if v.len() <= 1 {
        return vec![v.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..v.len() {
        let mut rest = v.to_vec();
        let x = rest.remove(i);
        for mut p in permutations(&rest) {
            p.insert(0, x);
            out.push(p);
        }
    }
    out
}

fn main() {
    let ids: Vec<Identity> = (1..=5)
        .map(|n| Identity::from_secret(n, &[n as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    let contribs: Vec<Contribution> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let t = vec![i as i64 * 3, i as i64 + 1, 7 - i as i64];
            let sig = id.sign(&contrib_msg(
                &acfa_receipt::identity::NO_CONTEXT,
                &PARAMS_DEFAULT,
                1,
                id.node_id,
                &h(&enc_tensor(&t)),
            ));
            Contribution {
                ctx: acfa_receipt::identity::NO_CONTEXT,
                sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
                params: PARAMS_DEFAULT,
                rnd: 1,
                node_id: id.node_id,
                tensor: t,
                sig,
            }
        })
        .collect();

    let idx: Vec<usize> = (0..contribs.len()).collect();
    let orders = permutations(&idx);

    println!("UC2 -- five parties merge, each sees a different arrival order\n");
    println!(
        "  delivering the SAME 5 contributions in all {} possible orders",
        orders.len()
    );

    let mut roots: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut admitted_sets: BTreeSet<Vec<u32>> = BTreeSet::new();

    for ord in &orders {
        let mut st = State::new();
        for &i in ord {
            st.deliver(contribs[i].clone(), &pki);
        }
        roots.insert(st.root());
        admitted_sets.insert(st.admit(1, &pki).iter().map(|c| c.node_id).collect());
    }

    let root = roots.iter().next().expect("at least one");
    println!("\n  DISTINCT state roots  : {}", roots.len());
    println!("  DISTINCT admitted sets: {}", admitted_sets.len());
    println!("  the single root       : {}", hex(root));
    println!(
        "  the single admitted   : {:?}",
        admitted_sets.iter().next().expect("one")
    );
    println!("    (that is HASH-CANONICAL order, not node-id order, and not a bug: the");
    println!("     order is derived from the content so every party computes the same one");
    println!("     without coordinating. Sorting by node id would work too -- what matters");
    println!("     is that it is a function of the DATA and never of arrival.)");

    if roots.len() == 1 && admitted_sets.len() == 1 {
        println!("\n  PASS -- every arrival order produced the identical result, byte for byte.");
        println!("  All five parties can sign the same artefact.");
    } else {
        println!(
            "\n  FAIL -- arrival order changed the result. Nothing here can be signed jointly."
        );
        std::process::exit(1);
    }

    println!("\n  WHAT THIS DOES NOT SHOW");
    println!("    1. Order invariance on ONE machine. It does not test cross-architecture");
    println!("       determinism -- an implementation consistently wrong everywhere would");
    println!("       pass this. That evidence is build/DETERMINISM-RESULTS.md and the CI");
    println!("       matrix, including real ARM64 silicon. This demo does not regenerate it.");
    println!("    2. The property is measured AT THE RECEIPT LAYER. It carries into a");
    println!("       consumer only if that consumer's tie-break is also a function of the");
    println!("       DATA. The Flower adapter's default is content-derived (sha256 of the");
    println!("       update bytes), pinned by a regression test, so omitting tie keys is");
    println!("       safe for distinct updates. The residual case is BYTE-IDENTICAL");
    println!("       updates: indistinguishable to a content-derived key, so the adapter");
    println!("       REFUSES them rather than ordering by arrival. Pass stable per-client");
    println!("       tie keys (a client id) if you expect identical submissions.");
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
