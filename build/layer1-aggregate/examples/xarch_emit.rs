// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Canonical byte emitter for the cross-target determinism run.
//!
//! WHAT THIS IS FOR
//!   The paper (arXiv:2607.10305, limitations) owes one of two things: "a heterogeneous
//!   run OR a fixed-width port with documented overflow semantics". This experiment was
//!   scoped to the second. The CPython prototype cannot test a fixed-width claim because
//!   CPython
//!   `int` has no width at all. THIS crate is the fixed-width port, so it is the
//!   artifact the claim is actually about.
//!
//! WHAT IT EMITS
//!   A canonical byte stream on stdout covering every rule over the same 9-case
//!   corpus the golden vectors use, plus the float->fixed boundary. Hash it
//!   externally (`| shasum -a 256`) and compare across build profiles and targets.
//!   The banner goes to stderr so the digest is of DATA ONLY.
//!
//! DESIGN CONSTRAINTS THAT MAKE THE COMPARISON MEAN ANYTHING
//!   1. NO transcendentals. sin/cos/exp/ln are libm-implementation-defined and DO
//!      differ between platforms, so using them would measure libm, not this kernel.
//!      Float inputs are built from division only, which is IEEE-754 correctly
//!      rounded and therefore identical on every conforming target.
//!   2. Serialization is EXPLICIT big-endian (`to_be_bytes`). Native-endian encoding
//!      here would make every big-endian run differ for a reason that has nothing to
//!      do with the aggregation kernel.
//!   3. The float boundary IS included. `fixed::encode` is the only place in Layer 1
//!      that touches a float, so it is the only place where a target could plausibly
//!      diverge; excluding it would leave the one interesting surface untested.
//!   4. Self-contained: no input file, so a container needs only the crate source.

use acfa_aggregate::*;

/// Byte-identical to the Lcg in tests/determinism.rs and tests/golden/generate.py.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn next_val(&mut self) -> i64 {
        (self.next_u64() % 200_001) as i64 - 100_000
    }
}

fn corpus(n: usize, d: usize, seed: u64) -> Vec<Contribution> {
    let mut r = Lcg::new(seed);
    (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i:04}").into_bytes(),
            v: (0..d).map(|_| r.next_val()).collect(),
        })
        .collect()
}

fn put_tag(out: &mut Vec<u8>, tag: &str) {
    out.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    out.extend_from_slice(tag.as_bytes());
}

fn put_i64s(out: &mut Vec<u8>, tag: &str, vs: &[i64]) {
    put_tag(out, tag);
    out.extend_from_slice(&(vs.len() as u32).to_be_bytes());
    for v in vs {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Deterministic f64s from integer division only -- IEEE-754 exact rounding, no libm.
fn floats(n: usize, seed: u64) -> Vec<f64> {
    let mut r = Lcg::new(seed);
    (0..n)
        .map(|_| {
            let num = r.next_val(); // -100_000 ..= 100_000
            let den = (r.next_u64() % 9_973 + 1) as i64;
            num as f64 / den as f64
        })
        .collect()
}

fn main() {
    const CASES: [(usize, usize, usize, u64); 9] = [
        (17, 64, 3, 42),
        (11, 32, 2, 7),
        (9, 16, 1, 99),
        (23, 8, 5, 1234),
        (7, 128, 1, 5),
        (12, 256, 2, 777),
        (31, 64, 7, 2026),
        (5, 32, 0, 31337),
        (9, 96, 1, 8080),
    ];

    let mut out: Vec<u8> = Vec::new();
    put_tag(&mut out, "ACFA-L1-XARCH-v1");

    for (n, d, f, seed) in CASES {
        let cs = corpus(n, d, seed);
        put_tag(&mut out, "CASE");
        out.extend_from_slice(&(n as u32).to_be_bytes());
        out.extend_from_slice(&(d as u32).to_be_bytes());
        out.extend_from_slice(&(f as u32).to_be_bytes());
        out.extend_from_slice(&seed.to_be_bytes());

        put_i64s(&mut out, "mean", &mean(&cs).unwrap());
        put_i64s(
            &mut out,
            "trimmed_mean_1_5",
            &trimmed_mean(&cs, 1, 5).unwrap(),
        );
        put_i64s(
            &mut out,
            "coord_median_trim",
            &coord_median_trim(&cs, f).unwrap(),
        );
        put_i64s(&mut out, "krum_aggregate", &krum_aggregate(&cs, f).unwrap());

        let sel: Vec<i64> = multi_krum(&cs, f)
            .unwrap()
            .iter()
            .map(|&i| i as i64)
            .collect();
        put_i64s(&mut out, "multi_krum_selected", &sel);
    }

    // The float -> Q16.16 boundary: the only float surface in Layer 1.
    put_tag(&mut out, "FP-BOUNDARY");
    let xs = floats(4096, 20260816);
    let enc: Vec<i64> = xs
        .iter()
        .map(|&x| encode(x).unwrap_or(i64::MIN)) // MIN marks a refusal; never a silent 0
        .collect();
    put_i64s(&mut out, "fp_encode", &enc);
    // Round-trip through decode and back: catches a decode that is not the exact
    // inverse on representable values, which would break replica agreement.
    let round: Vec<i64> = enc
        .iter()
        .map(|&v| {
            if v == i64::MIN {
                i64::MIN
            } else {
                encode(decode(v)).unwrap_or(i64::MIN)
            }
        })
        .collect();
    put_i64s(&mut out, "fp_roundtrip", &round);

    eprintln!("target_arch   {}", std::env::consts::ARCH);
    eprintln!("target_os     {}", std::env::consts::OS);
    eprintln!("pointer_width {} bits", usize::BITS);
    eprintln!(
        "endianness    {}",
        if cfg!(target_endian = "big") {
            "big"
        } else {
            "little"
        }
    );
    eprintln!("payload_bytes {}", out.len());

    use std::io::Write;
    std::io::stdout().write_all(&out).unwrap();
}
