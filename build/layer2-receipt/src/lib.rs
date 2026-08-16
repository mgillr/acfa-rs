// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! # ACFA Layer 2 -- the receipt
//!
//! A **wire format plus a verifier**: signed contributions, a self-authenticating
//! equivocation proof, a Merkle commitment trace, and a re-executable aggregate that
//! any third party can recheck offline with no network, no clock, and no trusted party.
//!
//! ## Provenance -- read this before claiming novelty for anything here
//!
//! The constructions in this crate are the author's own **published** work:
//! **arXiv:2607.10305**, *Accountable Consensus-Free Aggregation*, public since
//! 11 July 2026. The signed contribution, the self-authenticating misbehaviour proof,
//! the re-executable aggregate, and the Merkle/content-addressing commitment trace are
//! all described there, and are cited to it rather than presented as new.
//!
//! ## Scope -- what this crate does NOT do
//!
//! It answers *"is this aggregate what the shown set produces?"*. It does **not** answer
//! *"was that the whole set, and is this round final?"*. Round finality, and the
//! admission semantics that would make a round's membership uniform across replicas
//! under a synchrony assumption, are deliberately out of scope here and are not
//! implemented in this crate.
//!
//! That is a real limitation and it bounds what a receipt can be used for: a receipt
//! establishes honest computation over a shown set, and a caller who needs finality must
//! obtain it elsewhere. See "What a valid receipt does and does not prove" below.
//!
//! ## The split, and why Layer 1 is separate
//!
//! Layer 1 (`acfa-aggregate`) decides WHAT a set of vectors aggregates to. Layer 2
//! decides WHO is in that set. Layer 1 never hashes, signs, verifies or reads a clock,
//! so it discloses nothing about the receipt scheme and ships independently. Layer 2
//! passes contribution leaves into Layer 1 as an **opaque tie-break key** that Layer 1
//! never interprets, so the coupling runs one way only.
//!
//! ## What a valid receipt does and does not prove
//!
//! **Verification requires a [`Policy`] and this is not ceremony.** A receipt carries its
//! own PKI and its own fault bound, both chosen by whoever wrote it, so checking a receipt
//! against itself is circular: mint five keys, sign five contributions, and the forgery
//! verifies perfectly because every signature in it is genuine for keys the forger owns.
//! [`Receipt::verify`] therefore takes the identity set and fault bound the checker
//! obtained independently, and rejects a receipt that is about anyone else.
//!
//! Given a policy, a valid receipt proves the issuer computed honestly **over the set it
//! showed you**. It does not by itself prove the issuer showed you everything it held --
//! that requires comparing `state_root` against an independently obtained root. And a
//! receipt can be valid and `population_bound_met == false` at the same time: correct arithmetic over
//! too small a population to carry any Byzantine guarantee.
//!
//! ```
//! use acfa_receipt::{Identity, Pki, Policy, Receipt, Rule, State, Contribution};
//! use acfa_receipt::hash::{h, enc_tensor};
//! use acfa_receipt::identity::contrib_msg;
//!
//! let ids: Vec<Identity> = (1..=5).map(|n| Identity::from_secret(n, &[n as u8; 32])).collect();
//! let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
//!
//! let mut state = State::new();
//! for (i, id) in ids.iter().enumerate() {
//!     let t = vec![i as i64 * 3, i as i64 + 1];
//!     let sig = id.sign(&contrib_msg(1, &h(&enc_tensor(&t))));
//!     state.deliver(Contribution { rnd: 1, node_id: id.node_id, tensor: t, sig }, &pki);
//! }
//!
//! let receipt = Receipt::issue(&state, 1, &pki, 1, Rule::Krum);
//!
//! // The checker supplies the identities it independently trusts.
//! let policy = Policy::new(pki.clone(), 1);
//! let verified = receipt.verify(&policy).expect("honest receipt verifies");
//! assert_eq!(verified.admitted.len(), 5);
//! assert!(verified.population_bound_met);
//! ```

pub mod entry;
pub mod hash;
pub mod identity;
pub mod receipt;
pub mod resolve;
pub mod state;
pub mod wire;

pub use entry::{Contribution, EquivProof};
pub use identity::{Identity, Pki, PubKey, Sig};
pub use receipt::{Invalid, Policy, Receipt, SelfConsistent, Verified};
pub use resolve::{resolve, Resolution, Rule};
pub use state::State;
pub use wire::{decode, encode, WireError};
