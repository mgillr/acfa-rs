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

/// fl-01. **CHARACTERISATION TEST -- IT PINS A DEFECT, IT IS NOT A GUARD.**
///
/// When this goes red, a single out-of-range client no longer denies the round -- the
/// exclusion policy landed. Invert or delete it; do not repair it back to green, because
/// that would restore the denial and add a test defending it.
#[test]
fn one_out_of_range_client_denies_the_round_for_every_rule() {
    let mut cs = honest(7);
    cs.push(Contribution {
        tie_key: vec![99],
        v: vec![10, 20, 30, fixed::MAX + 1],
    });

    assert_eq!(mean(&cs), Err(AggError::ValueOutOfRange), "mean");
    assert_eq!(
        krum_aggregate(&cs, 1),
        Err(AggError::ValueOutOfRange),
        "krum_aggregate"
    );
    assert_eq!(
        multi_krum(&cs, 1).map(|_| ()),
        Err(AggError::ValueOutOfRange),
        "multi_krum"
    );
    assert_eq!(
        coord_median_trim(&cs, 1),
        Err(AggError::ValueOutOfRange),
        "coord_median_trim"
    );
    assert_eq!(
        trimmed_mean(&cs, 1, 4),
        Err(AggError::ValueOutOfRange),
        "trimmed_mean"
    );
    assert_eq!(
        bulyan_select(&cs, 1).map(|_| ()),
        Err(AggError::ValueOutOfRange),
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

/// fl-01, the half that is actually fixable without a policy decision.
///
/// **CHARACTERISATION TEST.** When this goes red the refusal started naming its offender
/// and fl-01's accountability half is closed -- which is the crdt-08 fix applied here.
#[test]
fn the_out_of_range_refusal_names_nobody() {
    let mut cs = honest(3);
    cs.push(Contribution {
        tie_key: vec![0xAB],
        v: vec![10, 20, 30, fixed::MAX + 1],
    });

    let e = mean(&cs).expect_err("must refuse");
    let rendered = format!("{e:?} {e}");

    // The offender is at index 3 and carries tie key 0xAB. Neither appears anywhere in the
    // refusal, so a caller cannot exclude it and retry.
    assert!(
        !rendered.contains("171") && !rendered.contains("ab") && !rendered.contains("AB"),
        "the refusal now identifies the offending contribution: {rendered}"
    );
    assert!(
        !rendered.contains(" 3 ") && !rendered.ends_with(" 3"),
        "the refusal now carries an offender index: {rendered}"
    );
}
