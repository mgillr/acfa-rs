// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Emit the cross-architecture fingerprint of a receipt.
//!
//! `cargo run --release --example digest`
//!
//! This is the artefact the whole stack's claim reduces to: run it on x86_64 and on
//! aarch64 and the lines must be **byte-identical**. Layer 1 proves the aggregate is
//! reproducible; this proves the whole receipt is -- the commitment trace, the signatures,
//! the canonical encoding and the aggregate together.
//!
//! Everything is derived from fixed seeds, so the only variable between two runs is the
//! machine. If a line differs, the difference IS the finding.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{encode, Contribution, Policy, Receipt, Rule, State};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn scenario(n: u32, equivocate: bool, rule: Rule, f: usize) -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=n)
        .map(|k| Identity::from_secret(k, &[k as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        // Deliberately signed, negative and large values: the floor-division path and the
        // fixed-point boundary are where an architecture-dependent bug would hide.
        let t = vec![
            i as i64 * 3 - 7,
            -(i as i64) * 11,
            i as i64 * 65_536 + 1,
            -32_768,
        ];
        let sig = id.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            1,
            id.node_id,
            &h(&enc_tensor(&t)),
        ));
        s.deliver(
            Contribution {
                ctx: acfa_receipt::identity::NO_CONTEXT,
                sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
                rnd: 1,
                node_id: id.node_id,
                tensor: t,
                sig,
            },
            &pki,
        );
    }
    if equivocate {
        let t = vec![9_999, -9_999, 1, -1];
        let sig = ids[0].sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            1,
            ids[0].node_id,
            &h(&enc_tensor(&t)),
        ));
        s.deliver(
            Contribution {
                ctx: acfa_receipt::identity::NO_CONTEXT,
                sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
                rnd: 1,
                node_id: 1,
                tensor: t,
                sig,
            },
            &pki,
        );
    }
    (
        Receipt::issue(&s, acfa_receipt::identity::NO_CONTEXT, 1, &pki, f, rule),
        pki,
    )
}

fn main() {
    println!("# ACFA receipt cross-architecture fingerprint");
    println!("# Every line below must be byte-identical on every target.");
    println!("# arch is printed for context and is NOT part of the comparison.");
    println!("arch                {}", std::env::consts::ARCH);
    println!("pointer-width       {}", usize::BITS);
    println!(
        "endian              {}",
        if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        }
    );
    println!();

    let cases: [(&str, u32, bool, Rule, usize); 5] = [
        ("krum-5-honest", 5, false, Rule::Krum, 1),
        ("krum-5-equivocation", 5, true, Rule::Krum, 1),
        ("bulyan-7-honest", 7, false, Rule::Bulyan, 1),
        ("krum-7-equivocation", 7, true, Rule::Krum, 1),
        ("krum-3-undefended", 3, false, Rule::Krum, 1),
    ];

    for (name, n, equiv, rule, f) in cases {
        let (r, pki) = scenario(n, equiv, rule, f);
        let bytes = encode(&r);
        let v = r
            .verify(&Policy::new(pki, f))
            .expect("issued receipt must verify against its own deployment");
        println!("[{name}]");
        println!("  wire-bytes        {}", bytes.len());
        println!("  wire-sha256       {}", hex(&h(&bytes)));
        println!("  state-root        {}", hex(&v.state_root));
        println!("  output-root       {}", hex(&v.output_root));
        println!(
            "  aggregate         {}",
            match &v.aggregate {
                None => "NONE".to_string(),
                Some(a) => format!("{a:?}"),
            }
        );
        println!("  admitted          {:?}", v.admitted);
        println!("  convicted         {:?}", v.convicted);
        println!("  population_bound_met          {}", v.population_bound_met);
        println!();
    }
}
