// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! # acfa-aggregate -- Layer 1
//!
//! A deterministic robust-aggregation engine. Given a set of fixed-point vectors it
//! returns an aggregate that is **bit-identical regardless of input order,
//! accumulation order, or target architecture**.
//!
//! ## Why determinism is the product
//!
//! Robust aggregation rules are not new; multi-Krum, coordinate median and trimmed
//! mean are all standard. What is missing from the deployed stack is that two honest
//! parties running the same rule on the same inputs cannot demonstrate they agree.
//! Float aggregation is order-dependent, so a mismatch between replicas is
//! indistinguishable from misbehaviour by one of them -- which means no accountability
//! mechanism can be layered on top, because the base case is already ambiguous.
//!
//! Making the aggregate an exact function of the input SET removes that ambiguity.
//! Any disagreement is then necessarily a difference in inputs or in conduct, never
//! an artefact of arithmetic.
//!
//! ## What this crate deliberately does NOT do
//!
//! No hashing, signing, verification, timing, networking, or persistence. It does not
//! know what a round is, who a participant is, or how contributions arrived. Where a
//! canonical tie-break is needed it accepts an opaque caller-supplied key and never
//! interprets it. Those concerns belong to layers above and keeping them out is what
//! makes this layer independently useful -- and independently publishable.
//!
//! ## Numerical contract
//!
//! - Values are Q16.16 (`fixed`), a **deployment parameter**: +/-2^15 range, 2^-16
//!   resolution. Components below resolution quantise to zero.
//! - Distances are computed in exact raw units as `i128` and never rescaled.
//! - Division rounds toward **negative infinity** (floor), never toward zero.
//!   See `rules::floor_div` -- this is the single most portable-looking place where
//!   two conforming implementations can silently diverge.
//! - Out-of-range and non-finite inputs are **refused**, not saturated. Saturation
//!   would make the aggregate depend on which party saturated first.

pub mod fixed;
pub mod rules;

pub use fixed::{decode, decode_vec, encode, encode_vec, FixedError, FRAC_BITS, SCALE};
pub use rules::{
    bulyan_aggregate, bulyan_select, coord_median_trim, krum_aggregate, mean, multi_krum,
    multi_krum_ranked, trimmed_mean, AggError, Contribution,
};

/// Convenience constructor for a contribution from float input.
pub fn contribution(tie_key: impl Into<Vec<u8>>, xs: &[f64]) -> Result<Contribution, FixedError> {
    let v = encode_vec(xs).map_err(|(_, e)| e)?;
    Ok(Contribution {
        tie_key: tie_key.into(),
        v,
    })
}
