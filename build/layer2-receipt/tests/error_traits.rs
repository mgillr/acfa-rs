// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! audit #2 -- the public error types are usable as errors.
//!
//! Before this, every public enum in the crate implemented neither `Display` nor
//! `std::error::Error`. A caller could not use `?` to lift one into `Box<dyn Error>`,
//! could not put one in an error chain, and got `Debug` formatting or nothing when
//! printing. That is a usability defect in the surface a stranger meets first.
//!
//! THE COMPILE-TIME HALF IS THE LOAD-BEARING HALF. `boxed_via_question_mark` does not
//! assert anything interesting at runtime -- it exists because it DOES NOT COMPILE unless
//! `std::error::Error` is implemented. Deleting the impl turns this into a build failure,
//! which is a louder signal than an assertion.
//!
//! `Rule` and `Status` are deliberately NOT covered. They are ordinary enums, not errors:
//! `Rule` names an aggregation rule and `Status` names a finality state. Implementing
//! `std::error::Error` for them would be wrong, and a blanket "every public enum" reading
//! of the finding would have done exactly that.

use acfa_receipt::wire::WireError;
use acfa_receipt::Invalid;
use std::error::Error;

fn boxed(e: impl Error + 'static) -> Box<dyn Error> {
    Box::new(e)
}

/// This test is its own point: it fails to COMPILE if the `Error` impls are removed.
#[test]
fn boxed_via_question_mark() {
    fn lift() -> Result<(), Box<dyn Error>> {
        Err(WireError::BadMagic)?;
        Ok(())
    }
    assert!(lift().is_err());
    let _: Box<dyn Error> = boxed(Invalid::PkiMismatch);
}

/// A `Display` that merely forwards to `Debug` would satisfy "it prints", so require that
/// the two differ and that the message carries the operand values a caller needs.
#[test]
fn display_is_not_debug_and_carries_the_numbers() {
    let e = Invalid::FaultBoundMismatch {
        policy: 1,
        receipt: 7,
    };
    let shown = e.to_string();
    assert_ne!(
        shown,
        format!("{e:?}"),
        "Display must not just forward to Debug"
    );
    assert!(
        shown.contains('1') && shown.contains('7'),
        "both bounds must appear: {shown}"
    );

    let w = WireError::UnsupportedVersion(9);
    let shown = w.to_string();
    assert_ne!(shown, format!("{w:?}"));
    assert!(
        shown.contains('9'),
        "the offending version must appear: {shown}"
    );
}

/// Every variant must produce a non-empty message that is not the Debug rendering. A
/// match arm added later without a message is the failure this catches.
#[test]
fn every_variant_has_a_real_message() {
    let invalid = [
        Invalid::PkiMismatch,
        Invalid::FaultBoundMismatch {
            policy: 1,
            receipt: 2,
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
    ];
    for e in &invalid {
        let s = e.to_string();
        assert!(s.len() > 12, "message too short to be informative: {s:?}");
        assert_ne!(s, format!("{e:?}"), "Display forwards to Debug for {e:?}");
    }

    let wire = [
        WireError::BadMagic,
        WireError::UnsupportedVersion(2),
        WireError::Truncated,
        WireError::TrailingBytes,
        WireError::UnknownRule(9),
        WireError::NotCanonical("pki reuses a public key"),
        WireError::ValueOutOfRange,
    ];
    for e in &wire {
        let s = e.to_string();
        assert!(s.len() > 12, "message too short to be informative: {s:?}");
        assert_ne!(s, format!("{e:?}"), "Display forwards to Debug for {e:?}");
    }
}
