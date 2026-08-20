// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Generator for `tests/golden/vectors_wire.json` -- the cross-implementation wire golden.
//!
//! The vectors are chosen to DISCRIMINATE, not to pad a count. See
//! `tests/cross_impl_wire.rs` for what each one pins.
//!
//! Regenerate:
//!   cargo run --release --example wire_vectors > tests/golden/vectors_wire.json

use acfa_receipt::entry::Contribution;
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{encode, Receipt, Rule, State};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let ids: Vec<Identity> = (1..=5)
        .map(|n| Identity::from_secret(n, &[n as u8; 32]))
        .collect();

    // (name, pki size, contributions, rule, f, round)
    let scenarios: [(&str, usize, usize, Rule, usize, u64); 5] = [
        ("empty-krum", 3, 0, Rule::Krum, 0, 1),
        ("three-contribs", 3, 3, Rule::Krum, 0, 1),
        ("five-bulyan", 5, 5, Rule::Bulyan, 1, 7),
        // Exactly 2^32. MEASURED: this and byte-distinct-round are the ONLY two vectors
        // that catch a 32-bit round field -- the mistake a third implementation in a
        // fixed-width language would make. Keep at least one round above 2^32.
        ("high-round", 3, 1, Rule::Krum, 0, 4_294_967_296),
        // Every byte distinct. Added expecting it to be needed for endianness; measurement
        // showed ANY nonzero round catches that, because the harness compares the decoded
        // value rather than only checking that decoding succeeded. It earns its place as a
        // second witness for the 32-bit-round case.
        (
            "byte-distinct-round",
            3,
            2,
            Rule::Krum,
            0,
            0x0102_0304_0506_0708,
        ),
    ];

    let mut out = Vec::new();
    for (name, n, ncon, rule, f, rnd) in scenarios {
        let pki: Pki = ids[..n].iter().map(|i| (i.node_id, i.public())).collect();
        // SIGN UNDER THE SCENARIO'S OWN PARAMETERS, not a shared fixture. `Receipt::issue`
        // filters contributions whose parameters differ from the round's, so signing every
        // scenario under one default silently emptied the Bulyan and f=0 vectors.
        let params = acfa_receipt::RoundParams {
            rule,
            f: f as u32,
            frac_bits: acfa_receipt::FRAC_BITS,
        };
        let mut st = State::new();
        for (i, id) in ids[..ncon].iter().enumerate() {
            let t = vec![(i as i64) * 3, (i as i64) + 1];
            let sig = id.sign(&contrib_msg(
                &acfa_receipt::identity::NO_CONTEXT,
                &params,
                rnd,
                id.node_id,
                &h(&enc_tensor(&t)),
            ));
            st.deliver(
                Contribution {
                    ctx: acfa_receipt::identity::NO_CONTEXT,
                    sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
                    params,
                    rnd,
                    node_id: id.node_id,
                    tensor: t,
                    sig,
                },
                &pki,
            );
        }
        let r = Receipt::issue(&st, acfa_receipt::identity::NO_CONTEXT, rnd, &pki, f, rule);
        let w = encode(&r);
        let agg = match &r.claimed_aggregate {
            Some(v) => format!("{v:?}"),
            None => "null".into(),
        };
        out.push(format!(
            "  {{\"name\":\"{}\",\"round\":{},\"f\":{},\"rule\":\"{:?}\",\"pki_n\":{},\
             \"contribs\":{},\"proofs\":{},\"state_root\":\"{}\",\"output_root\":\"{}\",\
             \"agg\":{},\"bytes\":{},\"wire\":\"{}\"}}",
            name,
            r.round,
            r.f,
            r.rule,
            r.pki.len(),
            r.contributions.len(),
            r.proofs.len(),
            hex(&r.claimed_state_root),
            hex(&r.claimed_output_root),
            agg,
            w.len(),
            hex(&w)
        ));
    }
    println!("[\n{}\n]", out.join(",\n"));
}
