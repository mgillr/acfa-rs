// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! # ACFA finality -- round certificates and fail-visible halting
//!
//! `acfa-receipt` answers *"is this aggregate what the shown set produces?"*. It cannot
//! answer *"was that the whole set, and is this round final?"*. This crate does.
//!
//! | Module | Construction | Answers |
//! |---|---|---|
//! | [`cut`] | ERC deadline cut, Dolev-Strong authenticated broadcast | which contributions are in, uniformly |
//! | [`certificate`] | round certificate, certificate-level equivocation | is the round certified, and did it fork |
//! | [`halt`] | halt-and-reconcile | what to do when it forked |
//!
//! ## The thesis, in one paragraph
//!
//! Under a known synchrony bound, a round's admitted set is pinned by authenticated
//! broadcast and `f+1` signatures certify it uniquely. If the bound breaks -- **or if the
//! round budget is under-provisioned below `2tau` while the bound holds** -- two disjoint
//! honest groups can each certify a different cut. At `n >= 3f+2` this needs no Byzantine
//! participation, so there is **nobody to blame**. A naive design fails *silently* there.
//!
//! The answer is that the **fork is itself the evidence**: two valid conflicting
//! certificates cannot coexist under ERC, so their coexistence proves ERC failed -- a
//! decidable check on the two signed objects, needing no knowledge of who was slow.
//! Honest nodes halt, publish the pair, and reconcile from the last uniquely-certified
//! round. **Fail-visible-and-halt, never fail-silent.**
//!
//! ## Honest limits
//!
//! - The `>= 2tau` round budget is a **safety** parameter, not a performance knob. An
//!   under-provisioned budget forks the certificate *even when the delivery bound holds*.
//!   [`RoundBudget::is_safe`] reports it; nothing enforces it, because a deployment that
//!   knowingly runs under-provisioned should record that its certificates are fork-prone
//!   rather than have someone patch the check out.
//! - Honest signing is the **caller's** obligation. [`Certificate::sign`] cannot verify
//!   that your completeness predicate held, because completeness is a property of what you
//!   observed, not of the tuple. Signing an incomplete cut is how an honest-but-hasty node
//!   forks the certificate.
//! - Resuming after a halt is **explicit and operator-driven**. There is deliberately no
//!   timeout-based automatic resume: it would re-enter the regime that produced the fork
//!   and convert a visible failure back into a silent one on the next lap.
//!
//! ## Provenance
//!
//! Round certificate, the ERC assumption (deadline completeness via authenticated
//! broadcast), the `>= 2tau` round-budget remark, certificate-level equivocation, and the
//! halt-and-reconcile rule. The accountability model these build on is arXiv:2607.10305;
//! the finality constructions themselves are implemented here and are not in that paper.

pub mod certificate;
pub mod cut;
pub mod halt;
pub mod wire;

pub use certificate::{CertError, CertFork, CertTuple, Certificate};
pub use cut::{ChainError, DeadlineCut, RelayChain, RoundBudget};
pub use halt::{Finality, Rejected, Status};
pub use wire::{decode_cert, decode_fork, encode_cert, encode_fork, WireError};
