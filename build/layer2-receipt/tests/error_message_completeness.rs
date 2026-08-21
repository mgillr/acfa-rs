// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! #98 -- every error variant's message is checked, and the check cannot silently fall behind.
//!
//! `error_traits.rs::every_variant_has_a_real_message` says in its own comment that "a match arm
//! added later without a message is the failure this catches". IT CANNOT CATCH THAT. It iterates a
//! HAND-WRITTEN array, so a new variant is simply absent from it and every assertion still passes.
//! That is a gate that cannot fail, and it had already drifted. Measured on this tree:
//!
//! | enum         | variants | covered by the array | missing |
//! |--------------|----------|----------------------|---------|
//! | `Invalid`    | 14       | 8                    | `TooMuchDerivableWork`, `TooManyContributions`, `TooMuchCoordinateWork`, `RuleMismatch`, `ScaleMismatch`, `ContextMismatch` |
//! | `WireError`  | 10       | 7                    | `FaultBoundTooLarge`, `ParamsDisagreeWithHeader`, `PreimageDisagreesWithMagic` |
//! | `MergeError` | 2        | 0                    | the whole enum |
//!
//! THE GUARD FIRED ON ITS OWN INTEGRATION, WHICH IS THE ONLY EVIDENCE WORTH HAVING FOR IT. This
//! file was written against a tree where `WireError` had 9 variants. A concurrent change added a
//! tenth, `PreimageDisagreesWithMagic` (#105), and the first `cargo test --test
//! error_message_completeness` did not run a single assertion -- it stopped at
//! `error[E0004]: non-exhaustive patterns: `&WireError::PreimageDisagreesWithMagic { .. }` not
//! covered`, pointing at the match below. `error_traits.rs`, on the same tree, still passes:
//! its hand-written array simply does not mention the new variant. That is the entire difference
//! between the two files, observed rather than argued.
//!
//! WHAT WAS ALREADY GUARANTEED, so this file does not claim credit for it. Every `Display` impl in
//! the crate is an exhaustive match with NO wildcard arm -- `Invalid` 14 of 14, `WireError` 10 of
//! 10, `MergeError` 2 of 2. Adding a variant ALREADY fails to compile until it is given a message. The
//! missing guarantee was never "it has a message"; it is that the message is a REAL one -- non-empty,
//! not a `Debug` passthrough -- and that the check covers every variant.
//!
//! EVERY ASSERTION HERE HAS BEEN SHOWN TO FAIL, because a green check that was never made to go
//! red is not evidence. Measured on integration, each mutation applied alone and then reverted:
//!
//!   * A `DummyProbeVariant` added to `Invalid`, `WireError` and `MergeError` in turn, each given
//!     a `Display` arm so a missing message could not be what failed, stopped this file at
//!     `error[E0004]` on lines 77, 97 and 113 respectively (`cargo test --no-run --test
//!     error_message_completeness` exit 101 in all three).
//!
//!     The three probes are NOT equally clean and saying otherwise would overstate them. For
//!     `Invalid` a matching arm was added to `bin/acfa-verify.rs` too: `cargo build` exit 0, and
//!     `error_traits.rs` on that same tree still reported `3 passed; 0 failed` -- the whole
//!     finding, side by side, on one tree. `MergeError` is the same picture with no bin change:
//!     `cargo build` exit 0, `error_traits.rs` `3 passed; 0 failed`. The `WireError` probe is
//!     weaker: `bin/acfa-verify.rs:405` matches `WireError` exhaustively as well, so `cargo build`
//!     exited 101, two `E0004`s were reported, only the one at line 97 is this file's guard, and
//!     `error_traits.rs` could not be BUILT on that tree (exit 101) rather than passing on it.
//!     The real-tree case above covers what that probe cannot: `PreimageDisagreesWithMagic` is a
//!     `WireError` variant that production DOES handle, so the crate builds, `error_traits.rs`
//!     passes, and this file alone refuses.
//!   * Deleting `WireError::ValueOutOfRange` from `every_wire()`: RED, "expected 10
//!     representatives, found 9".
//!   * Replacing it with a second `WireError::BadMagic` instead, so the count still reads 10:
//!     RED on the discriminant check, "representatives 0 and 6 are the SAME variant".
//!   * `every_merge()` returning `vec![]`: RED, "expected 2 representatives, found 0" -- the
//!     count is asserted BEFORE the per-variant loop, so an empty list cannot pass vacuously.
//!   * `MergeError::TooManyProofs`'s message shortened to `"nope"`: RED on the length floor.
//!   * `MergeError`'s whole `Display` replaced by `write!(f, "{self:?}")`: RED on the
//!     Debug-passthrough check.
//!
//! HOW THIS FILE CANNOT DRIFT. Each enum gets an exhaustive `match` whose only purpose is to fail
//! compilation when a variant appears, sitting immediately beside the representative list, plus a
//! pinned count and a distinct-discriminant assertion so the list cannot be padded to satisfy the
//! count. Adding a variant therefore breaks the BUILD here, not a run somewhere else.
use acfa_receipt::state::MergeError;
use acfa_receipt::wire::WireError;
use acfa_receipt::Invalid;
use std::mem::discriminant;

const INVALID_VARIANTS: usize = 14;
const WIRE_VARIANTS: usize = 10;
const MERGE_VARIANTS: usize = 2;

/// Never called. Exists so a new `Invalid` variant fails to COMPILE here until the author adds a
/// representative to `every_invalid()` below and bumps `INVALID_VARIANTS`.
#[allow(dead_code)]
fn _invalid_is_exhaustively_listed(e: &Invalid) {
    match e {
        Invalid::TooMuchDerivableWork { .. } => (),
        Invalid::TooManyContributions { .. } => (),
        Invalid::TooMuchCoordinateWork { .. } => (),
        Invalid::PkiMismatch => (),
        Invalid::FaultBoundMismatch { .. } => (),
        Invalid::RuleMismatch { .. } => (),
        Invalid::BadContributionSignature { .. } => (),
        Invalid::BogusProof { .. } => (),
        Invalid::WrongRound { .. } => (),
        Invalid::StateRootMismatch { .. } => (),
        Invalid::AggregateMismatch { .. } => (),
        Invalid::OutputRootMismatch { .. } => (),
        Invalid::ScaleMismatch { .. } => (),
        Invalid::ContextMismatch { .. } => (),
    }
}

#[allow(dead_code)]
fn _wire_is_exhaustively_listed(e: &WireError) {
    match e {
        WireError::BadMagic => (),
        WireError::UnsupportedVersion(_) => (),
        WireError::Truncated => (),
        WireError::TrailingBytes => (),
        WireError::UnknownRule(_) => (),
        WireError::NotCanonical(_) => (),
        WireError::ValueOutOfRange => (),
        WireError::FaultBoundTooLarge { .. } => (),
        WireError::ParamsDisagreeWithHeader { .. } => (),
        WireError::PreimageDisagreesWithMagic { .. } => (),
    }
}

#[allow(dead_code)]
fn _merge_is_exhaustively_listed(e: &MergeError) {
    match e {
        MergeError::TooManyContributions { .. } => (),
        MergeError::TooManyProofs { .. } => (),
    }
}

/// A message must be informative and must not be the `Debug` rendering. Applied to EVERY variant.
fn assert_real_message<E: std::fmt::Display + std::fmt::Debug>(e: &E) {
    let shown = e.to_string();
    assert!(
        shown.len() > 12,
        "message too short to be informative for {e:?}: {shown:?}"
    );
    assert_ne!(
        shown,
        format!("{e:?}"),
        "Display forwards to Debug for {e:?} -- that is not a message, it is a struct dump"
    );
    assert!(!shown.trim().is_empty(), "empty message for {e:?}");
}

/// The list is complete and honest: one representative per variant, no duplicates padding it out.
fn assert_complete<E>(all: &[E], expected: usize, name: &str) {
    assert_eq!(
        all.len(),
        expected,
        "{name}: expected {expected} representatives, found {}. If a variant was added, add a \
         representative here and bump the constant -- the exhaustive match above will already \
         have failed to compile.",
        all.len()
    );
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i < j {
                assert_ne!(
                    discriminant(a),
                    discriminant(b),
                    "{name}: representatives {i} and {j} are the SAME variant -- the list has been \
                     padded rather than completed, so the count check passes while a variant is \
                     still untested"
                );
            }
        }
    }
}

fn every_invalid() -> Vec<Invalid> {
    vec![
        Invalid::TooMuchDerivableWork {
            would_be: 5,
            max: 4,
        },
        Invalid::TooManyContributions {
            would_be: 9,
            max: 8,
        },
        Invalid::TooMuchCoordinateWork {
            coordinates: 7,
            max: 6,
        },
        Invalid::PkiMismatch,
        Invalid::FaultBoundMismatch {
            policy: 1,
            receipt: 7,
        },
        Invalid::RuleMismatch {
            policy: acfa_receipt::Rule::Krum,
            receipt: acfa_receipt::Rule::Bulyan,
        },
        Invalid::BadContributionSignature {
            node_id: 3,
            leaf: [0xab; 32],
        },
        Invalid::BogusProof {
            node_id: 4,
            leaf: [0xcd; 32],
        },
        Invalid::WrongRound {
            expected: 1,
            found: 2,
        },
        Invalid::StateRootMismatch {
            claimed: [1; 32],
            actual: [2; 32],
        },
        Invalid::AggregateMismatch {
            claimed: None,
            actual: None,
        },
        Invalid::OutputRootMismatch {
            claimed: [1; 32],
            actual: [2; 32],
        },
        Invalid::ScaleMismatch {
            policy: 16,
            receipt: 24,
        },
        Invalid::ContextMismatch {
            policy: acfa_receipt::identity::NO_CONTEXT,
            receipt: [7u8; 32],
        },
    ]
}

fn every_wire() -> Vec<WireError> {
    vec![
        WireError::BadMagic,
        WireError::UnsupportedVersion(2),
        WireError::Truncated,
        WireError::TrailingBytes,
        WireError::UnknownRule(9),
        WireError::NotCanonical("pki reuses a public key"),
        WireError::ValueOutOfRange,
        WireError::FaultBoundTooLarge { f: 99 },
        WireError::ParamsDisagreeWithHeader { node_id: 5 },
        WireError::PreimageDisagreesWithMagic { node_id: 6 },
    ]
}

fn every_merge() -> Vec<MergeError> {
    vec![
        MergeError::TooManyContributions {
            would_be: 9,
            max: 8,
        },
        MergeError::TooManyProofs {
            would_be: 5,
            max: 4,
        },
    ]
}

#[test]
fn every_invalid_variant_has_a_real_message() {
    let all = every_invalid();
    assert_complete(&all, INVALID_VARIANTS, "Invalid");
    for e in &all {
        assert_real_message(e);
    }
}

#[test]
fn every_wire_error_variant_has_a_real_message() {
    let all = every_wire();
    assert_complete(&all, WIRE_VARIANTS, "WireError");
    for e in &all {
        assert_real_message(e);
    }
}

/// `MergeError` had a `Display` impl and NO test at all. It is a public error type reached by
/// `State::merge`, so a caller meets it the same way they meet the other two.
#[test]
fn every_merge_error_variant_has_a_real_message() {
    let all = every_merge();
    assert_complete(&all, MERGE_VARIANTS, "MergeError");
    for e in &all {
        assert_real_message(e);
    }
}

// WHAT THIS FILE DOES NOT COVER:
//
//   * It does not check that a message is CORRECT -- only that it is present, long enough, and not
//     a Debug dump. A variant whose message names the wrong field would pass.
//   * `Rule` and `Status` are deliberately excluded, for the reason `error_traits.rs` already
//     gives: they are ordinary enums, not errors.
//   * The pinned counts are a backstop, not the primary guard. The primary guard is the exhaustive
//     match, which fails at COMPILE time; the counts catch the narrower case of someone adding a
//     match arm and forgetting the representative.
//   * It does not cover `layer2-finality`'s own error enums. That crate has its own
//     `error_traits.rs` with the same hand-written-array shape, so it can drift the same way --
//     but it has NOT drifted yet, and the draft of this file that said it "very likely" had was
//     guessing. Counted on this tree: `ChainError` 4 variants, `WireError` 6, `Rejected` 2,
//     `CertError` 3, and every one of the 15 is named somewhere in that file. What is missing
//     there is the compile-time guarantee, not the coverage; the fix is the same shape as this
//     file and belongs to whoever owns that crate.
//
// The three `error[E0004]` line numbers in the header are cited against THIS file as committed,
// re-run after formatting rather than carried over from the draft the probe first fired on. They
// are recorded down here for the same reason: a note added above a line number moves it.
