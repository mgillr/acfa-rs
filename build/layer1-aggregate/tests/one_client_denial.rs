// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! fl-01. ONE CLIENT DENIES THE ROUND FOR EVERYONE, AND THE REFUSAL NAMES NOBODY.
//!
//! Canonical text: *"One Byzantine client stops every round: refusing out-of-range values
//! turns bounded influence into unconditional denial of service."*
//!
//! Measured on the shipped library, seven honest contributions plus ONE client whose single
//! coordinate is one unit outside the Q16.16 range: `mean`, `krum_aggregate`, `multi_krum`,
//! `coord_median_trim`, `trimmed_mean` and `bulyan_select` all return
//! `Err(ValueOutOfRange)`. The same set without that one client returns `Ok([10,20,30,40])`.
//! One participant, one coordinate, and the round is gone for the other seven.
//!
//! THE REFUSAL ITSELF IS CORRECT AND IS NOT THE DEFECT. `SECURITY.md` states the position
//! deliberately: out-of-range values are refused rather than saturated, because saturating
//! would let a value the caller never sent become the aggregate. That reasoning holds. What
//! it does not do is give the caller any way to CONTINUE.
//!
//! THE DEFECT IS THAT `ValueOutOfRange` IS UNATTRIBUTABLE -- exactly the state
//! `DimensionMismatch` was in before crdt-08:
//!
//!     Debug   : ValueOutOfRange
//!     Display : a raw value lies outside the Q16.16 range [-2147483648, 2147483647]
//!     names a node, index or tie_key: NO
//!
//! So an operator holding a denied round cannot say who denied it, cannot exclude them, and
//! cannot retry. crdt-08 was fixed by carrying `offender` and `expected`, which makes
//! exclusion a one-line filter at the layer that owns policy. fl-01 is the same defect with
//! a different trigger and it has NOT had that fix.
//!
//! AND IT IS EASIER THAN crdt-08 WAS, because there is no framing vector here. A short
//! vector is only "wrong" relative to what the others sent, so naming an offender required
//! a plurality rule to stop the adversary choosing the accused by arriving first. Out of
//! range is OBJECTIVE -- a value either is or is not inside `[MIN, MAX]` -- so the offender
//! can be named directly with nothing to get wrong.
//!
//! WHY THE FIX IS NOT IN THIS COMMIT. `ValueOutOfRange` is referenced 31 times across both
//! crates, and FIVE of those are in `layer2-receipt` (`wire.rs`, `acfa-verify.rs`,
//! `tests/error_traits.rs`) which is not this seat's file and is currently dirty in the
//! shared clone. Turning a unit variant into a struct variant is a cross-crate API break,
//! so it needs the owner's agreement rather than a unilateral edit. This file pins the
//! defect so it cannot go quiet while that is decided.

use acfa_aggregate::*;

fn honest(n: u8) -> Vec<Contribution> {
    (0..n)
        .map(|i| Contribution {
            tie_key: vec![i],
            v: vec![10, 20, 30, 40],
        })
        .collect()
}

/// fl-01, ATTRIBUTION HALF LANDED; THE DENIAL ITSELF REMAINS AND REMAINS PINNED.
///
/// This began as a characterisation of two defects sharing one symptom: the round is
/// denied, and the refusal names nobody. The ATTRIBUTION half is now fixed -- every arm
/// below asserts the exact offender, coordinate and value -- so this is a GUARD for that
/// half. The DENIAL half is unchanged and deliberate (SECURITY.md: refuse, never
/// saturate); whether a layer above should EXCLUDE the named offender and retry is the
/// refuse-or-exclude policy question, still open, and the offender field is what makes
/// that a one-line filter when it is ruled on.
#[test]
fn one_out_of_range_client_denies_the_round_for_every_rule() {
    let mut cs = honest(7);
    cs.push(Contribution {
        tie_key: vec![99],
        v: vec![10, 20, 30, fixed::MAX + 1],
    });

    assert_eq!(
        mean(&cs),
        Err(AggError::ValueOutOfRange {
            offender: 7,
            coord: 3,
            value: fixed::MAX + 1,
        }),
        "mean"
    );
    assert_eq!(
        krum_aggregate(&cs, 1),
        Err(AggError::ValueOutOfRange {
            offender: 7,
            coord: 3,
            value: fixed::MAX + 1,
        }),
        "krum_aggregate"
    );
    assert_eq!(
        multi_krum(&cs, 1).map(|_| ()),
        Err(AggError::ValueOutOfRange {
            offender: 7,
            coord: 3,
            value: fixed::MAX + 1,
        }),
        "multi_krum"
    );
    assert_eq!(
        coord_median_trim(&cs, 1),
        Err(AggError::ValueOutOfRange {
            offender: 7,
            coord: 3,
            value: fixed::MAX + 1,
        }),
        "coord_median_trim"
    );
    assert_eq!(
        trimmed_mean(&cs, 1, 4),
        Err(AggError::ValueOutOfRange {
            offender: 7,
            coord: 3,
            value: fixed::MAX + 1,
        }),
        "trimmed_mean"
    );
    assert_eq!(
        bulyan_select(&cs, 1).map(|_| ()),
        Err(AggError::ValueOutOfRange {
            offender: 7,
            coord: 3,
            value: fixed::MAX + 1,
        }),
        "bulyan_select"
    );

    // POSITIVE CONTROL. Without this one client the same seven aggregate fine, so the
    // refusal above is caused by the single participant and by nothing else about the set.
    assert_eq!(
        mean(&honest(7)),
        Ok(vec![10, 20, 30, 40]),
        "the honest set alone must aggregate"
    );
}

/// fl-01, ACCOUNTABILITY HALF -- **INVERTED, NOT REPAIRED.**
///
/// This was a characterisation test asserting the refusal named NOBODY, and its own
/// docstring said that red meant the fix had arrived and to invert it rather than patch it
/// back to green. The fix arrived. So it is inverted: it now asserts the refusal DOES name
/// its offender, which makes it a GUARD.
///
/// Recording the transition rather than silently rewriting it, because the failure mode
/// this repo keeps hitting is a characterisation test meeting a later editor as a broken
/// guard and being "fixed" -- restoring the defect and adding a test that defends it. The
/// opposite happened here and it should be visible: red was correct, and red was the
/// signal to delete the old assertion.
#[test]
fn the_out_of_range_refusal_names_its_offender() {
    let mut cs = honest(3);
    cs.push(Contribution {
        tie_key: vec![0xAB],
        v: vec![10, 20, 30, fixed::MAX + 1],
    });

    // The offender is the fourth contribution, index 3, at coordinate 3.
    assert_eq!(
        mean(&cs),
        Err(AggError::ValueOutOfRange {
            offender: 3,
            coord: 3,
            value: fixed::MAX + 1,
        }),
        "the refusal must identify which contribution and which coordinate"
    );

    // And the operator-facing message must carry the values, not just the variant: a
    // refusal a caller cannot act on is the whole of fl-01.
    let rendered = mean(&cs).unwrap_err().to_string();
    for needle in ["3", &(fixed::MAX + 1).to_string()] {
        assert!(
            rendered.contains(needle),
            "the message drops {needle}, so it cannot be acted on: {rendered}"
        );
    }

    // ATTRIBUTION MUST NOT DEPEND ON ARRIVAL ORDER. Out of range is a property of the value
    // against a constant bound, so unlike the short-vector case there is no plurality to
    // compute and no framing vector -- but that is worth pinning rather than assuming.
    for position in 0..4usize {
        let mut set = honest(3);
        set.insert(
            position,
            Contribution {
                tie_key: vec![0xAB],
                v: vec![10, 20, 30, fixed::MAX + 1],
            },
        );
        assert_eq!(
            mean(&set),
            Err(AggError::ValueOutOfRange {
                offender: position,
                coord: 3,
                value: fixed::MAX + 1,
            }),
            "the accused must be the out-of-range client wherever it arrives (position \
             {position})"
        );
    }
}
