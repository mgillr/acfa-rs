// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! audit #2 -- the public error types are usable as errors.
//!
//! See the sibling file in `acfa-receipt` for the reasoning. In short: these types
//! implemented neither `Display` nor `std::error::Error`, so a caller could not use `?`
//! to lift one into `Box<dyn Error>`, could not chain them, and got `Debug` or nothing
//! when printing.
//!
//! `boxed_via_question_mark` is the load-bearing test and it asserts almost nothing at
//! runtime: it FAILS TO COMPILE if the `Error` impls are removed.
//!
//! `Status` is deliberately NOT covered. It names a finality state (running / forked),
//! not a failure, and implementing `std::error::Error` for it would be wrong.

use acfa_finality::wire::WireError;
use acfa_finality::{CertError, ChainError, Rejected};
use std::error::Error;

/// Fails to COMPILE without the `Error` impls.
#[test]
fn boxed_via_question_mark() {
    fn lift() -> Result<(), Box<dyn Error>> {
        Err(WireError::BadMagic)?;
        Ok(())
    }
    assert!(lift().is_err());
    let _: Vec<Box<dyn Error>> = vec![
        Box::new(CertError::UnknownSigner(3)),
        Box::new(ChainError::RepeatedSigner(4)),
        Box::new(Rejected::ForkedAt(9)),
        Box::new(WireError::NotAFork),
    ];
}

#[test]
fn display_is_not_debug_and_carries_the_numbers() {
    let e = CertError::Insufficient { have: 2, need: 3 };
    let s = e.to_string();
    assert_ne!(
        s,
        format!("{e:?}"),
        "Display must not just forward to Debug"
    );
    assert!(
        s.contains('2') && s.contains('3'),
        "both counts must appear: {s}"
    );

    let c = ChainError::TooShort { have: 1, need: 4 };
    let s = c.to_string();
    assert!(
        s.contains('1') && s.contains('4'),
        "both counts must appear: {s}"
    );

    let r = Rejected::ForkedAt(42);
    assert!(r.to_string().contains("42"), "the forked round must appear");
}

#[test]
fn every_variant_has_a_real_message() {
    let mut msgs: Vec<(String, String)> = Vec::new();
    for e in [
        CertError::Insufficient { have: 1, need: 2 },
        CertError::UnknownSigner(1),
        CertError::BadSignature(2),
    ] {
        msgs.push((e.to_string(), format!("{e:?}")));
    }
    for e in [
        ChainError::TooShort { have: 1, need: 2 },
        ChainError::RepeatedSigner(1),
        ChainError::UnknownSigner(2),
        ChainError::BadHop {
            depth: 1,
            node_id: 3,
        },
    ] {
        msgs.push((e.to_string(), format!("{e:?}")));
    }
    for e in [Rejected::Invalid, Rejected::ForkedAt(1)] {
        msgs.push((e.to_string(), format!("{e:?}")));
    }
    for e in [
        WireError::BadMagic,
        WireError::UnsupportedVersion(2),
        WireError::Truncated,
        WireError::TrailingBytes,
        WireError::NotCanonical("certificate signers not ascending"),
        WireError::NotAFork,
    ] {
        msgs.push((e.to_string(), format!("{e:?}")));
    }

    assert_eq!(
        msgs.len(),
        15,
        "every variant of all four enums must be covered"
    );
    for (shown, dbg) in &msgs {
        assert!(
            shown.len() > 12,
            "message too short to be informative: {shown:?}"
        );
        assert_ne!(shown, dbg, "Display forwards to Debug for {dbg}");
    }
}
