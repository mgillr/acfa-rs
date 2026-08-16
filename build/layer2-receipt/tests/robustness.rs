// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Robustness sweep over the decoder.
//!
//! The decoder is the only part of this crate that touches bytes an attacker chose, so it
//! is the only part where "it panicked" is a security outcome rather than a bug report.
//! It already shipped one such defect -- an unbounded allocation from a length prefix --
//! and that one was found by luck, on a platform that happened to abort. This sweep is
//! the systematic version.
//!
//! **The contract under test: `decode` may return `Ok` or `Err`, and may never panic,
//! abort, hang, or allocate unboundedly, for ANY input.** Nothing here asserts that a
//! mutated receipt is rejected -- many mutations are legitimately still valid -- only that
//! the decoder survives them and that anything it accepts round-trips.
//!
//! Deterministic by construction: a fixed-seed LCG, no `rand`, no wall clock. A fuzz test
//! that cannot be replayed is a bug report you cannot act on.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{decode, encode, Contribution, Policy, Receipt, Rule, State};

/// Fixed-seed LCG. Same constants as the determinism tests, for the same reason.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() >> 16) as usize % n
        }
    }
}

fn sample(n: u32, rule: Rule) -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=n)
        .map(|k| Identity::from_secret(k, &[k as u8; 32]))
        .collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        let t = vec![i as i64 * 3 - 5, -(i as i64), 1234];
        let sig = id.sign(&contrib_msg(1, &h(&enc_tensor(&t))));
        s.deliver(
            Contribution {
                rnd: 1,
                node_id: id.node_id,
                tensor: t,
                sig,
            },
            &pki,
        );
    }
    (Receipt::issue(&s, 1, &pki, 1, rule), pki)
}

#[test]
fn decoding_arbitrary_bytes_never_panics() {
    let mut rng = Lcg(0xACFA_0001);
    for len in [0usize, 1, 7, 8, 9, 16, 64, 256, 1024] {
        for _ in 0..200 {
            let mut buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            // Half the cases carry the correct magic, so the sweep gets past the first
            // gate and actually exercises the length-prefix and ordering logic.
            if len >= 8 && rng.next().is_multiple_of(2) {
                buf[..8].copy_from_slice(b"ACFA-R1\0");
            }
            let _ = decode(&buf);
        }
    }
}

#[test]
fn single_byte_mutations_of_a_real_receipt_never_panic() {
    for rule in [Rule::Krum, Rule::Bulyan] {
        let (r, pki) = sample(5, rule);
        let bytes = encode(&r);
        let policy = Policy::new(pki, 1);
        for i in 0..bytes.len() {
            for (k, delta) in [0x01u8, 0x7f, 0x80, 0xff].into_iter().enumerate() {
                let mut m = bytes.clone();
                m[i] ^= delta;
                if let Ok(back) = decode(&m) {
                    // Anything accepted must re-encode to exactly what was decoded,
                    // or two byte strings map to one receipt and canonicity is a lie.
                    assert_eq!(encode(&back), m, "accepted a non-canonical encoding");
                    // verify() is Ed25519-bound and dominates the sweep in a debug build.
                    // Decode is what is under test here; sampling the verify path keeps
                    // the sweep exhaustive where it matters and affordable in CI.
                    if (i + k).is_multiple_of(16) {
                        let _ = back.verify(&policy);
                    }
                }
            }
        }
    }
}

#[test]
fn truncations_and_extensions_never_panic() {
    let (r, pki) = sample(6, Rule::Krum);
    let bytes = encode(&r);
    let policy = Policy::new(pki, 1);
    for cut in 0..bytes.len() {
        assert!(decode(&bytes[..cut]).is_err(), "a prefix must not decode");
    }
    let mut rng = Lcg(0xACFA_0002);
    for extra in 1..64usize {
        let mut m = bytes.clone();
        for _ in 0..extra {
            m.push(rng.next() as u8);
        }
        assert!(decode(&m).is_err(), "trailing bytes must be refused");
    }
    // And a real receipt still verifies, so the sweep is testing a live object.
    assert!(decode(&bytes).unwrap().verify(&policy).is_ok());
}

#[test]
fn spliced_receipts_never_panic() {
    // Cut two real receipts together at a random point. This produces inputs that are
    // structurally plausible far deeper than random bytes reach.
    let (a, pki) = sample(5, Rule::Krum);
    let (b, _) = sample(7, Rule::Bulyan);
    let (ba, bb) = (encode(&a), encode(&b));
    let policy = Policy::new(pki, 1);
    let mut rng = Lcg(0xACFA_0003);
    for _ in 0..400 {
        let i = rng.below(ba.len());
        let j = rng.below(bb.len());
        let mut m = ba[..i].to_vec();
        m.extend_from_slice(&bb[j..]);
        if let Ok(back) = decode(&m) {
            assert_eq!(encode(&back), m, "accepted a non-canonical encoding");
            let _ = back.verify(&policy);
        }
    }
}

#[test]
fn every_length_field_at_every_extreme_is_refused_not_allocated() {
    // The generalised form of the shipped defect: walk EVERY 4-byte aligned window in the
    // header region and set it to each extreme, rather than only the counts we know about.
    // If a future field is added without bounding, this catches it.
    let (r, _) = sample(4, Rule::Krum);
    let bytes = encode(&r);
    for off in (8..bytes.len().min(200)).step_by(1) {
        if off + 4 > bytes.len() {
            break;
        }
        for v in [u32::MAX, u32::MAX / 2, 0x7FFF_FFFF, 0x0100_0000] {
            let mut m = bytes.clone();
            m[off..off + 4].copy_from_slice(&v.to_be_bytes());
            // Must terminate and must not abort. A panic or an OOM here fails the test
            // by killing the process, which is exactly the signal we want.
            let _ = decode(&m);
        }
    }
}

#[test]
fn a_receipt_with_many_small_contributions_stays_bounded() {
    // Structural stress rather than adversarial: the largest legitimate shape we expect,
    // to confirm nothing is quadratic enough to look like a hang at showcase scale.
    let (r, pki) = sample(60, Rule::Krum);
    let bytes = encode(&r);
    let back = decode(&bytes).expect("large receipt decodes");
    assert_eq!(back, r);
    assert!(back.verify(&Policy::new(pki, 1)).is_ok());
}
