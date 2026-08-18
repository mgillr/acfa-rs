// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! num-01, RESOLVED. The Rust encoder and the published reference now round IDENTICALLY.
//!
//! The reference kernel `reference/acfa.py` used `int(round(x * 2^16))` -- Python's `round`
//! is ties-to-even, while `fixed::encode` uses `f64::round`, which is HALF AWAY FROM ZERO.
//! They agreed everywhere except exact midpoints, and at midpoints disagreed on those whose
//! floor is even -- measured at ~13% of rounds on ordinary float32 gradients, invisible
//! because the cross-implementation golden corpus is built from INTEGERS and never calls the
//! float encoder.
//!
//! DECISION (num-01): half-away-from-zero is canonical. It is the wire contract documented in
//! `fixed.rs`, the cross-architecture fingerprint is built on it, and the annihilation
//! threshold argument (`|s| < 0.5` encodes to 0) rests on it. Correcting the reference has no
//! wire or fingerprint impact -- golden generation feeds the kernel integers and never calls
//! `fp_encode` -- whereas changing the implementation would break the fingerprint. So the
//! reference was corrected to the canonical rule (`reference/acfa.py::fp_encode` now rounds
//! half away from zero).
//!
//! These tests were CHARACTERISATION tests pinning the divergence; they are now CONFORMANCE
//! GUARDS asserting agreement, and they cross-check the encoder at the midpoints directly --
//! the exact place the integer golden corpus could not reach.

use acfa_aggregate::encode;

/// The corrected reference rule, replicated INDEPENDENTLY in Rust (floor/ceil, not
/// `f64::round`), so this is a genuine cross-check and not the implementation compared to
/// itself. Mirrors `reference/acfa.py::fp_encode`.
fn reference_encode(x: f64) -> i64 {
    let s = x * 65536.0;
    if s >= 0.0 {
        (s + 0.5).floor() as i64
    } else {
        (s - 0.5).ceil() as i64
    }
}

/// num-01 conformance: the two encoders agree at EVERY midpoint.
///
/// GUARD-DELETION: revert `reference/acfa.py::fp_encode` to `int(round(...))` and this file's
/// `reference_encode` to `s.round_ties_even()`, and this goes RED on the even-floor midpoints.
#[test]
fn the_encoder_agrees_with_the_reference_at_every_midpoint() {
    for k in -1000i64..=1000 {
        let x = (k as f64 + 0.5) / 65536.0;
        let ours = encode(x).expect("midpoints are well inside range");
        let theirs = reference_encode(x);
        assert_eq!(
            ours, theirs,
            "encoder disagrees with the reference at x*65536 = {k}.5 (ours {ours}, ref {theirs})"
        );
    }
}

/// num-01 conformance: reachable from ORDINARY float32, which is what made the divergence a
/// live defect. Every float32 that is an odd multiple of 2^-17 scales to exactly k + 0.5, and
/// the two encoders must now agree on all of them.
#[test]
fn ordinary_float32_midpoints_agree() {
    let mut checked = 0;
    for odd in (1i64..=4001).step_by(2) {
        let x = ((odd as f32) / 131_072.0) as f64; // 2^-17
        assert_eq!(
            encode(x).expect("in range"),
            reference_encode(x),
            "float32 midpoint {odd}/131072 disagrees"
        );
        checked += 1;
    }
    assert!(
        checked > 500,
        "must actually exercise the midpoints, checked {checked}"
    );
}

/// num-01, the reason it survived: the cross-implementation GOLDEN corpus is integer-only, so
/// `fp_encode` was never exercised by the existing cross-check. That gap is now covered NOT by
/// changing the golden corpus (which would move nothing, since the divergence is at the float
/// boundary the corpus does not use) but by the two conformance tests above, which cross-check
/// the encoder at the midpoints directly. This test documents that the golden corpus remains
/// integer-based BY DESIGN, so the encoder coverage lives here rather than there.
#[test]
fn the_encoder_is_now_cross_checked_at_the_float_boundary() {
    // A midpoint that ties-to-even would round DOWN and half-away rounds UP: x*65536 = 2.5.
    let x = 2.5 / 65536.0;
    assert_eq!(encode(x).unwrap(), 3, "half-away rounds 2.5 up to 3");
    assert_eq!(reference_encode(x), 3, "the corrected reference agrees");
    // and the negative twin.
    let x = -2.5 / 65536.0;
    assert_eq!(encode(x).unwrap(), -3);
    assert_eq!(reference_encode(x), -3);
}
