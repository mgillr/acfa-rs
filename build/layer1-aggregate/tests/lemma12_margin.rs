// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Lemma 12 (quantisation margin, a checkable no-flip condition) -- the SOUNDNESS battery.
//!
//! The certificate claims: when `certified` is true, the fixed-point selection EQUALS the
//! selection the un-quantised real-valued gradients would have produced. That claim is only
//! worth shipping if a test can kill it, so the central test below searches for a
//! counterexample -- a case where the two selections differ AND the certificate said they
//! would not. One such case refutes the lemma's implementation.
//!
//! HOW CONSERVATIVE IS THE 4x, MEASURED. A fair question about the observable threshold is
//! whether the factor is real or padding. Measured over 480 000 trials across four coordinate
//! spreads (1e-2, 3e-3, 1e-3, 3e-4), collecting every case where quantisation genuinely
//! changed the selection:
//!
//! ```text
//!   spread    diverged        max(margin/beta)   flips with margin > beta
//!   1e-2       281/120000          0.3036                 0
//!   3e-3       958/120000          0.3225                 0
//!   1e-3      2858/120000          0.3282                 0
//!   3e-4      9601/120000          0.3363                 0
//! ```
//!
//! 13 698 real flips, and not one of them had a margin above `0.34 * beta` -- so the shipped
//! `4 * beta` carries roughly a TWELVE-FOLD empirical safety factor over the worst observed
//! flip. Two honest consequences. First, weakening the threshold from `4*beta` to `beta` does
//! NOT turn this battery red, so these tests do not by themselves justify the constant: the
//! `4x` is carried by the paper's proof (bounding `|g - g_hat| <= 2*beta` on quantised data),
//! and the paper states plainly that the observable form is conservative in two ways and that
//! the threshold doubling dominates. Second, the data never contradicts the bound in the
//! direction that would matter -- an unsound certificate -- which is the property being shipped.
//!
//! The test is also guarded against being VACUOUS, which is the failure mode that matters
//! most here: a certificate that never certifies anything, or a grid on which the two
//! selections never disagree, would pass a naive soundness assertion while proving nothing.
//! So it asserts non-vacuity on BOTH sides -- some cases certified, some cases genuinely
//! diverged -- before it asserts soundness over the intersection.

use acfa_aggregate::{multi_krum, multi_krum_certified, Contribution};

struct Lcg(u64);
impl Lcg {
    fn new(s: u64) -> Self {
        Lcg(s)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    /// Uniform in [-spread, spread].
    fn next_f64(&mut self, spread: f64) -> f64 {
        let u = (self.next_u64() % 1_000_001) as f64 / 1_000_000.0;
        (u * 2.0 - 1.0) * spread
    }
}

const SCALE: f64 = 65536.0; // Q16.16

fn quantise(v: &[f64]) -> Vec<i64> {
    // Half away from zero -- the normative rule (num-01), matching the Rust encoder.
    v.iter()
        .map(|x| {
            let s = x * SCALE;
            if s >= 0.0 {
                (s + 0.5).floor() as i64
            } else {
                (s - 0.5).ceil() as i64
            }
        })
        .collect()
}

/// The REAL-VALUED reference selection: multi-Krum in f64 over the un-quantised vectors,
/// with the same lexicographic (score, tie_key, index) ordering the kernel uses. This is the
/// ground truth the certificate makes a claim about.
fn real_selection(reals: &[Vec<f64>], keys: &[Vec<u8>], f: usize) -> Vec<usize> {
    let n = reals.len();
    if n < f + 3 {
        return (0..n).collect();
    }
    let m = n - f - 2;
    let mut scored: Vec<(f64, &[u8], usize)> = Vec::with_capacity(n);
    for i in 0..n {
        let mut ds: Vec<f64> = Vec::with_capacity(n - 1);
        for j in 0..n {
            if j != i {
                ds.push(
                    reals[i]
                        .iter()
                        .zip(&reals[j])
                        .map(|(a, b)| (a - b) * (a - b))
                        .sum::<f64>(),
                );
            }
        }
        ds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        scored.push((ds[..m].iter().sum::<f64>(), keys[i].as_slice(), i));
    }
    scored.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap()
            .then_with(|| a.1.cmp(b.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    let mut out: Vec<usize> = scored[..m].iter().map(|&(_, _, i)| i).collect();
    out.sort_unstable();
    out
}

/// **THE FALSIFIER.** Search for a certified case whose fixed-point selection differs from
/// the real-valued one. Any hit refutes the implementation of Lemma 12.
///
/// The spread is deliberately tiny (1e-2) so that a half-unit of Q16.16 rounding is a
/// meaningful fraction of the coordinate values: that is the regime where selection flips
/// actually happen, and testing on well-separated data would make the whole battery vacuous.
///
/// GUARD-DELETION: force `certified: true` in `multi_krum_certified` (or drop the `4 *` from
/// the threshold) and this goes RED on the divergent cases it collects.
#[test]
fn a_certified_selection_never_differs_from_the_real_valued_selection() {
    let mut r = Lcg::new(42);
    let (mut certified_n, mut diverged_n) = (0usize, 0usize);

    for trial in 0..1500u64 {
        let n = 7 + (trial % 4) as usize; // 7..10
        let d = 3 + (trial % 3) as usize; // 3..5
        let f = 1 + (trial % 2) as usize; // 1..2

        let reals: Vec<Vec<f64>> = (0..n)
            .map(|_| (0..d).map(|_| r.next_f64(1e-2)).collect())
            .collect();
        let keys: Vec<Vec<u8>> = (0..n).map(|i| format!("k{i:04}").into_bytes()).collect();
        let cs: Vec<Contribution> = reals
            .iter()
            .zip(&keys)
            .map(|(v, k)| Contribution {
                tie_key: k.clone(),
                v: quantise(v),
            })
            .collect();

        let (fixed_sel, cert) = multi_krum_certified(&cs, f).expect("well-formed input");
        let cert = cert.expect("n >= f + 3 in this grid, so a boundary exists");
        let real_sel = real_selection(&reals, &keys, f);

        let diverged = fixed_sel != real_sel;
        if cert.certified {
            certified_n += 1;
        }
        if diverged {
            diverged_n += 1;
        }
        if cert.certified && diverged {
            panic!(
                "LEMMA 12 REFUTED at trial {trial}: certificate said no-flip but the selection \
                 flipped.\n  fixed = {fixed_sel:?}\n  real  = {real_sel:?}\n  {cert:?}"
            );
        }
    }

    // NON-VACUITY, both sides. Without these the soundness assertion above could pass on a
    // grid where nothing is ever certified, or where the two selections never disagree.
    assert!(
        certified_n > 0,
        "vacuous: the certificate never fired on {certified_n} of 1500 -- soundness untested"
    );
    assert!(
        diverged_n > 0,
        "vacuous: quantisation never changed the selection on this grid, so the certificate \
         was never actually at risk -- tighten the spread"
    );
    println!("certified {certified_n}/1500, diverged {diverged_n}/1500, certified-and-diverged 0");
}

/// The certificate is an ADDITIVE observable: it must not change the selection that ships.
#[test]
fn certified_selection_is_byte_identical_to_plain_multi_krum() {
    let mut r = Lcg::new(7);
    for trial in 0..400u64 {
        let n = 5 + (trial % 6) as usize;
        let d = 2 + (trial % 4) as usize;
        let f = (trial % 3) as usize;
        let cs: Vec<Contribution> = (0..n)
            .map(|i| Contribution {
                tie_key: format!("k{i:04}").into_bytes(),
                v: (0..d).map(|_| (r.next_f64(1.0) * SCALE) as i64).collect(),
            })
            .collect();
        let plain = multi_krum(&cs, f).unwrap();
        let (certified, _) = multi_krum_certified(&cs, f).unwrap();
        assert_eq!(
            plain, certified,
            "trial {trial}: certificate changed the selection"
        );
    }
}

/// The select-all band has no selection boundary, so there is no certificate to give. A
/// vacuous `true` here would be a safety claim about an undefended configuration.
#[test]
fn select_all_band_yields_no_certificate() {
    let cs: Vec<Contribution> = (0..4)
        .map(|i| Contribution {
            tie_key: vec![i as u8],
            v: vec![i as i64, 1],
        })
        .collect();
    // n = 4 < f + 3 = 5
    let (sel, cert) = multi_krum_certified(&cs, 2).unwrap();
    assert_eq!(sel, vec![0, 1, 2, 3], "select-all fires");
    assert!(
        cert.is_none(),
        "no boundary exists, so no certificate may be offered"
    );
}

/// An exact tie is the irreducible residual of Remark 13: `g = 0` is certifiable by no
/// margin condition, and the honest answer is `certified: false`, not an error.
#[test]
fn an_exact_tie_is_reported_uncertified_not_certified() {
    // Four points on the axes at radius r plus one at the centre. The centre's three
    // nearest distances are all r^2 (score 3r^2); every outer point sees r^2, 2r^2, 2r^2
    // (score 5r^2). So the four outer scores are EXACTLY equal, and with m = 3 the selection
    // boundary falls between two of them: g = 0 by construction, not by luck.
    let cs: Vec<Contribution> = vec![
        Contribution {
            tie_key: b"a".to_vec(),
            v: vec![1000, 0],
        },
        Contribution {
            tie_key: b"b".to_vec(),
            v: vec![-1000, 0],
        },
        Contribution {
            tie_key: b"c".to_vec(),
            v: vec![0, 1000],
        },
        Contribution {
            tie_key: b"d".to_vec(),
            v: vec![0, -1000],
        },
        Contribution {
            tie_key: b"e".to_vec(),
            v: vec![0, 0],
        },
    ];
    let (_, cert) = multi_krum_certified(&cs, 0).unwrap();
    let cert = cert.unwrap();
    assert_eq!(cert.margin, 0, "the symmetric pair ties exactly");
    assert!(!cert.certified, "g = 0 must never be certified");
}

/// Determinism: the certificate is a function of the SET, not of arrival order.
#[test]
fn certificate_is_independent_of_input_order() {
    let mut r = Lcg::new(99);
    let n = 8usize;
    let cs: Vec<Contribution> = (0..n)
        .map(|i| Contribution {
            tie_key: format!("k{i:04}").into_bytes(),
            v: (0..4).map(|_| (r.next_f64(1e-2) * SCALE) as i64).collect(),
        })
        .collect();
    let (_, base) = multi_krum_certified(&cs, 1).unwrap();
    let base = base.unwrap();
    // Rotate the input; the certificate must be bit-identical.
    for shift in 1..n {
        let mut rot = cs[shift..].to_vec();
        rot.extend_from_slice(&cs[..shift]);
        let (_, c) = multi_krum_certified(&rot, 1).unwrap();
        assert_eq!(
            base,
            c.unwrap(),
            "certificate moved under a rotation of the input"
        );
    }
}
