// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Divergence-absorption probe for the FIXED-WIDTH port.
//!
//! WHY THIS EXISTS, AND WHY `xarch_emit` WAS NOT ENOUGH
//!   `xarch_emit` deliberately excludes transcendentals, on the reasoning that
//!   sin/exp/ln are libm-implementation-defined and would measure libm rather than
//!   this kernel. That reasoning isolates the kernel correctly, but a later review
//!   measurement shows it also removes the ONLY genuine cross-architecture
//!   divergence source from the input path:
//!
//!     glibc 2.41, same version both platforms, 60000 doubles through log/cos/exp:
//!       20 values differ between x86_64 and aarch64, every one by exactly 1 ULP
//!       (~1 in 3000 on exp).   musl, same sweep: 0 of 60000.
//!
//!   So an `xarch_emit` pass cannot distinguish "the boundary absorbed a real
//!   divergence" from "nothing diverged in the first place". On musl it is a VACUOUS
//!   PASS that looks exactly like a success. THE LIBC CHOICE DECIDES WHETHER THE RUN
//!   HAS ANY CONTENT AT ALL, so this probe must be run on a glibc image
//!   (rust:1-slim-bookworm), with musl (rust:1-alpine) as the zero-divergence control.
//!
//! WHAT IT MEASURES
//!   The paper's second disjunct (arXiv:2607.10305, limitations) is "a fixed-width port with
//!   documented overflow semantics". This crate IS that port, so running the
//!   absorption test HERE is a stronger result than running it on the widthless
//!   CPython prototype: it shows the property holds for the artifact whose claim is
//!   about width.
//!
//!   Two sections, selected by argv so each can be hashed and diffed independently:
//!     raw -- IEEE-754 bit patterns of exp/cos/ln outputs, big-endian.
//!            EXPECTED TO DIFFER across architectures on glibc. If this matches,
//!            there was nothing to absorb and the `enc` result below is vacuous.
//!     enc -- the same values through fixed::encode into Q16.16, big-endian.
//!            EXPECTED TO MATCH. That is the contraction property.
//!
//!   A pass is only meaningful when `raw` DIFFERS and `enc` MATCHES. Reporting `enc`
//!   alone would be the mirage.
//!
//! PROVENANCE: on this host every non-amd64 row is QEMU user-mode emulation on one
//! Intel i5-6500. The container binaries are genuine target machine code (aarch64 ELF
//! e_machine 0xb7), so the aarch64 SOFTWARE STACK including libm is really exercised;
//! aarch64 SILICON is NOT. Do not write "we ran on aarch64 hardware".

use acfa_aggregate::*;

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
    /// Deterministic double in [-5, 5), built by division only so the INPUTS are
    /// identical on every target; all divergence must come from libm, not the RNG.
    fn next_x(&mut self) -> f64 {
        let n = (self.next_u64() % 10_000_001) as i64 - 5_000_000;
        n as f64 / 1_000_000.0
    }
}

const N: usize = 200_000;
const SEED: u64 = 20260816;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "enc".to_string());

    let mut r = Lcg::new(SEED);
    let xs: Vec<f64> = (0..N).map(|_| r.next_x()).collect();

    // The three functions B measured as divergent on glibc. Ranges are chosen so
    // every result is inside Q16.16 (+/-2^15) and encode never refuses: a refusal
    // would silently drop the very samples the probe exists to compare.
    let mut vals: Vec<f64> = Vec::with_capacity(N * 3);
    for &x in &xs {
        vals.push(x.exp()); // x in [-5,5) => (0.0067, 148.4)
        vals.push(x.cos()); // [-1, 1]
        vals.push((x.abs() + 1.0).ln()); // [0, 1.792)
    }

    let mut out: Vec<u8> = Vec::with_capacity(vals.len() * 8 + 32);
    match mode.as_str() {
        "raw" => {
            out.extend_from_slice(b"ACFA-ABSORB-RAW-v1");
            for v in &vals {
                out.extend_from_slice(&v.to_bits().to_be_bytes());
            }
        }
        "enc" => {
            out.extend_from_slice(b"ACFA-ABSORB-ENC-v1");
            let mut refused = 0usize;
            for v in &vals {
                let e = match encode(*v) {
                    Ok(e) => e,
                    Err(_) => {
                        refused += 1;
                        i64::MIN // marked, never silently zero
                    }
                };
                out.extend_from_slice(&e.to_be_bytes());
            }
            eprintln!("refused       {refused}");
        }
        other => {
            eprintln!("unknown mode {other}, expected raw or enc");
            std::process::exit(2);
        }
    }

    eprintln!("mode          {mode}");
    eprintln!("target_arch   {}", std::env::consts::ARCH);
    eprintln!("samples       {}", vals.len());
    eprintln!("payload_bytes {}", out.len());

    use std::io::Write;
    std::io::stdout().write_all(&out).unwrap();
}
