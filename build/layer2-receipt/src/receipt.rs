// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The receipt: a re-executable aggregate.
//!
//! A receipt carries everything needed to recompute a round's result offline and check
//! it against what was claimed. It is a **wire format plus a verifier**, not a daemon
//! and not a protocol run -- verification touches no network, no clock, and no other
//! party.
//!
//! WHAT A VALID RECEIPT DOES AND DOES NOT ESTABLISH. It establishes that, given the
//! carried contributions and proofs, the claimed aggregate is exactly what the rule
//! yields -- that the issuer computed honestly over the set it showed you. It does NOT
//! establish that the issuer showed you every contribution it held. Withholding is a
//! separate property that needs the state root to be compared against an independently
//! obtained one, which is why `claimed_state_root` is carried and checked: two parties
//! with the same root saw the same set, and a party that withholds cannot produce a
//! receipt whose root matches the one everyone else converged on.

use crate::entry::{Contribution, EquivProof};
use crate::identity::Context;
use crate::identity::Pki;
use crate::identity::RoundParams;
use crate::resolve::{resolve, Resolution, Rule};
use crate::state::State;
use acfa_aggregate::MarginCertificate;

/// A self-contained, offline-checkable record of one resolved round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// **What this receipt is ABOUT** -- an opaque, caller-defined commitment the protocol never
    /// parses. Every contribution and proof in the receipt shares it, and it is inside each
    /// signature, so a receipt cannot be replayed into another context and an honest node in two
    /// contexts cannot be framed by its own signatures (#79).
    pub ctx: Context,
    pub round: u64,
    pub f: usize,
    pub rule: Rule,
    /// **The fixed-point scale this receipt's numbers are expressed in (#77).**
    ///
    /// Carried so a checker built at a different scale refuses BY NAME instead of producing a
    /// confidently wrong comparison. Two builds at different `FRAC_BITS` compute different
    /// aggregates from the same real-valued inputs, and before this field both receipts verified,
    /// both were internally consistent, and nothing on the wire said they disagreed.
    pub frac_bits: u32,
    pub pki: Pki,
    pub contributions: Vec<Contribution>,
    pub proofs: Vec<EquivProof>,
    pub claimed_state_root: [u8; 32],
    pub claimed_output_root: [u8; 32],
    pub claimed_aggregate: Option<Vec<i64>>,
}

/// Default ceiling on the tensor COORDINATES a verifier will do work over: the sum of
/// `tensor.len()` across the carried contributions, i.e. the `n * d` product.
///
/// THE OTHER TWO BOUNDS CAP INPUTS; THIS ONE CAPS WORK, AND THAT IS THE WHOLE POINT.
/// `MAX_MERGE_PROOFS` bounds the derivable-proof count and `MAX_MERGE_CONTRIBUTIONS` bounds
/// `n`. Verification cost is a PRODUCT of `n` and `d`, and `d` was bounded by nothing at all
/// except `filesize / 8`. Bounding one factor of a product bounds nothing -- the same
/// sentence `MAX_COORDINATE_OPS` one layer down already says about `MAX_CONTRIBUTIONS`.
///
/// MEASURED ON THE SHIPPED CODE, RELEASE, WITH EVERY EXISTING GUARD PASSING AND THE VERDICT
/// `Ok`. CPU time (`getrusage`, user+sys), because the calibration host was shared and its
/// wall clock moved 4x under load while CPU did not:
///
/// ```text
///   n      d       receipt      verify CPU   peak RSS   derivable   carried   kernel
///    256     64      0.15 MiB      0.11 s        3 MiB    0/8192    256/4096  ran
///    256   1024      2.04 MiB      1.11 s       19 MiB    0/8192    256/4096  ran
///    256   8192     16.09 MiB      8.72 s      114 MiB    0/8192    256/4096  ran
///    256  16384     32.03 MiB     11.78 s      194 MiB    0/8192    256/4096  REFUSED
///   1024   1024      8.11 MiB      3.58 s       65 MiB    0/8192   1024/4096  REFUSED
///   4096   1024     32.45 MiB     16.18 s      217 MiB    0/8192   4096/4096  REFUSED
///   4096   2048     64.45 MiB     31.54 s      401 MiB    0/8192   4096/4096  REFUSED
/// ```
///
/// Every row returned `Ok`. Read the `n = 256` rows first: the contribution count is at
/// SIXTEENTH of its cap and the derivable-proof bound is ZERO, so neither existing guard is
/// anywhere near firing, and 32 MiB still buys 11.8 seconds. The count cap is not a
/// near-miss here; it is irrelevant here.
///
/// AND THE KERNEL'S OWN BOUND DOES NOT SAVE THE VERIFIER. `MAX_COORDINATE_OPS` fires on the
/// four rows marked REFUSED -- and `resolve` treats a kernel refusal as a legitimate
/// DETERMINISTIC OUTCOME (`Err(_) =>` a `"refused|"` output root), which is correct for
/// determinism and useless as a DoS guard: the refusal arrives after the work, not instead
/// of it. Worse, the `n = 256, d = 8192` row shows the kernel bound cannot be reused here
/// even in principle -- its quantity is `n^2 * d = 5.4e8`, comfortably UNDER the `1e9` cap,
/// while the verifier burned 8.7 s. The kernel's number is small exactly where the
/// verifier's is large.
///
/// WHY 262 144. Two independent constraints meet there, and it is picked from measurement
/// rather than from a tidy binary figure:
///
///   * it is about **one second** of verify CPU on the calibration host (measured 153k-290k
///     coordinates/second across the grid above), which is the same budget
///     `MAX_MERGE_PROOFS` was set against ("8192 puts the worst accepted merge at about one
///     second"); and
///   * it is the smallest power of two that still admits every shape this crate's own
///     `examples/scale.rs` treats as legitimate -- the largest being `n = 25, d = 10 000`
///     at 250 000 coordinates.
///
/// The headroom over that example is 5%, which is thin, and that thinness is the argument
/// for the budget being caller-supplied rather than the argument for a bigger constant.
///
/// THIS WILL REFUSE REAL FEDERATED SHAPES AND THAT IS WHY IT IS A DEFAULT AND NOT A LAW.
/// `n = 10` clients at a 10M-parameter model is `1e8` coordinates, 380x this. That
/// deployment must raise the budget -- [`Policy::with_max_coordinates`], or `acfa-verify
/// --max-coordinates` -- and the refusal names the exact number to raise it to, so the
/// figure an operator needs is in the error rather than in this file.
///
/// WHAT IT DOES NOT BOUND. It bounds the term that was UNBOUNDED. It does not tighten the
/// kernel's own `MAX_COORDINATE_OPS` allowance, so a receipt with a small `n * d` and a
/// large `n^2 * d` can still buy the seconds that ceiling already grants (measured:
/// `n = 2048, d = 64` is 131 072 coordinates, inside this budget, and 2.31 s). It does not
/// bound `decode`, which does its own linear pass before `verify` is ever called (measured
/// 0.91 s on the 32 MiB receipt). And it does not bound the CARRIED PROOF count, which is a
/// separate unbounded quantity on this same door.
pub const DEFAULT_MAX_VERIFY_COORDINATES: u128 = 262_144;

/// What the checker independently knows, obtained from somewhere other than the receipt.
///
/// **THIS TYPE IS THE TRUST BOUNDARY, AND WITHOUT IT VERIFICATION IS CIRCULAR.** A receipt
/// carries a PKI and a fault bound `f`, and both are attacker-chosen. Checking a receipt
/// against its own PKI proves only that *somebody* computed honestly over identities
/// *they* invented: mint five fresh keys, sign five contributions, and the result verifies
/// perfectly while corresponding to no real deployment. Likewise `f` -- a three-node
/// receipt declaring `f = 0` satisfies `n >= 2f+3` and reports itself population_bound_met.
///
/// So the security question is never "is this receipt internally consistent?" but "is this
/// receipt internally consistent **and** about the deployment I care about?". The policy is
/// how the caller supplies the second half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The identities the checker independently believes are participating.
    pub pki: Pki,
    /// The fault bound the checker's own robustness argument assumes.
    pub f: usize,
    /// The rule the checker expects, if it cares. `None` accepts either.
    pub rule: Option<Rule>,
    /// **The event the checker is asking about. `None` accepts whatever the receipt claims.**
    ///
    /// `None` is deliberately permitted and deliberately loud: a checker may genuinely not know
    /// the context, and requiring one would put a restriction on deployments that this protocol
    /// exists to stay out of. But an unset pin must never be mistaken for a satisfied one, so
    /// `acfa-verify` prints NOT PINNED when it is `None`, exactly as it does for `rule`.
    pub ctx: Option<Context>,
    /// **The fixed-point scale the checker itself reads numbers in (#77).**
    ///
    /// Defaults to this build's `acfa_aggregate::FRAC_BITS` via [`Policy::new`]. A receipt on a
    /// different grid is refused by name, never silently compared.
    pub frac_bits: u32,
    /// **The checker's WORK budget, in tensor coordinates.** See
    /// [`DEFAULT_MAX_VERIFY_COORDINATES`] for the measurements behind the default.
    ///
    /// WHY THIS IS CALLER-SUPPLIED AND NOT A CONSTANT. Every other bound in this crate is a
    /// compile-time number, and that is right for them: they are properties of the FORMAT
    /// (what a receipt may contain) and every checker agrees about them. This one is a
    /// property of the CHECKER (how much of its own CPU it will spend on a file from a
    /// stranger), and checkers genuinely disagree: a public paste-a-receipt endpoint wants
    /// tens of milliseconds, an operator batch-checking their own deployment's rounds wants
    /// minutes. `MAX_COORDINATE_OPS` is the worked example of one constant failing to serve
    /// both -- it sits EXACTLY at `n = 10` clients on a 10M-parameter model and refuses
    /// ResNet-18 at the same `n` by 17%, while simultaneously granting an untrusted receipt
    /// several seconds. The number belongs beside `pki` and `f`, which are already the
    /// checker's own knowledge rather than the receipt's claims.
    ///
    /// Raising it is an explicit, greppable act. Leaving it alone is safe, which is the
    /// property `Policy::new` must have and the reason the constant does not simply
    /// disappear into an argument.
    pub max_coordinates: u128,
}

impl Policy {
    /// THIS DEFAULT IS FAIL-OPEN ON THE RULE, and it is the constructor everyone reaches
    /// for. `rule: None` accepts EITHER aggregation rule, so a checker built this way has
    /// not pinned the robustness argument it believes it is checking. See
    /// `SelfConsistent::population_bound_met` for the measured consequence: a Krum receipt
    /// at n = 5 verifies Ok with the bound flag TRUE against an operator who assumes
    /// Bulyan and needs n = 7.
    ///
    /// Use `.expecting(rule)` unless you genuinely accept both. Making that mandatory is a
    /// public API change and is with B (crypto-08).
    ///
    /// FAIL-CLOSED ON WORK, unlike the rule. The work budget defaults to
    /// [`DEFAULT_MAX_VERIFY_COORDINATES`] rather than to "unlimited", so a checker built
    /// this way -- which is every checker that never thought about it -- has a bounded door.
    /// The two defaults point in opposite directions ON PURPOSE: an unpinned rule weakens a
    /// verdict the caller still gets, an unbounded work budget denies the caller service
    /// altogether, and only one of those is recoverable by reading the output.
    pub fn new(pki: Pki, f: usize) -> Policy {
        Policy {
            pki,
            f,
            rule: None,
            ctx: None,
            frac_bits: acfa_aggregate::FRAC_BITS,
            max_coordinates: DEFAULT_MAX_VERIFY_COORDINATES,
        }
    }

    /// Read a receipt written at a DIFFERENT fixed-point scale than this build uses.
    ///
    /// Only meaningful for a checker that genuinely knows how to interpret the other grid. The
    /// default is this build's own scale, and that is the safe answer.
    pub fn at_scale(mut self, frac_bits: u32) -> Policy {
        self.frac_bits = frac_bits;
        self
    }

    /// Pin the event this checker is asking about.
    pub fn about(mut self, ctx: Context) -> Policy {
        self.ctx = Some(ctx);
        self
    }

    pub fn expecting(mut self, rule: Rule) -> Policy {
        self.rule = Some(rule);
        self
    }

    /// Raise (or lower) the work budget this checker will spend on one receipt.
    ///
    /// The unit is tensor COORDINATES -- the `n * d` product -- because that is the quantity
    /// the door's cost is proportional to and the quantity nothing else bounds. It is not
    /// bytes and not seconds: bytes are a decoder's concern, and seconds cannot be used
    /// because the verdict must be a function of the receipt and not of machine load.
    /// [`Invalid::TooMuchCoordinateWork`] reports the count it refused, so the value to pass
    /// here comes out of the refusal.
    pub fn with_max_coordinates(mut self, max_coordinates: u128) -> Policy {
        self.max_coordinates = max_coordinates;
        self
    }
}

/// The result of an internal-consistency check.
///
/// Deliberately carries **no** `population_bound_met` flag and no admitted identities. It is not a
/// security verdict and must not be presented as one: it says the receipt's arithmetic and
/// signatures agree with each other, nothing about whose signatures they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfConsistent {
    pub round: u64,
    pub state_root: [u8; 32],
    pub output_root: [u8; 32],
}

/// Why a receipt failed. Enumerated rather than boolean, because "this receipt is
/// invalid" is not actionable and "the aggregate does not match the admitted set" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// The carried contributions could derive more equivocation proofs than the verifier
    /// will do work for. Each derivable proof costs a signature verification and the count
    /// is quadratic in how often one node id repeats, so an unbounded verify is a remote
    /// denial of service on a door that accepts input from anyone.
    TooMuchDerivableWork { would_be: usize, max: usize },
    /// The carried contribution set is larger than the verifier will scan.
    /// `deliver` runs equivocation detection against everything held, so `recompute`
    /// is QUADRATIC in the carried count. `TooMuchDerivableWork` bounds only the PROOF
    /// half -- a set of all-DISTINCT node ids derives zero proofs (bound 0) yet still
    /// forces n(n-1)/2 leaf comparisons -- so this is the contribution half of the
    /// bound. `State::merge` caps this exact quantity on the trusted door; verify
    /// carries the SAME cap on the untrusted one.
    TooManyContributions { would_be: usize, max: usize },
    /// The carried contributions total more tensor coordinates than the checker's work
    /// budget allows.
    ///
    /// THE THIRD BOUND, AND THE ONLY ONE ON A PRODUCT. `TooMuchDerivableWork` bounds the
    /// proof count and `TooManyContributions` bounds `n`; verification cost is `n * d` and
    /// `d` was bounded by nothing but `filesize / 8`. A set of all-DISTINCT node ids derives
    /// zero proofs (proof bound 0) and can sit at a sixteenth of the contribution cap while
    /// still carrying an arbitrary `d`: measured, `n = 256, d = 16384` is 32.03 MiB of
    /// receipt, 11.78 s of verifier CPU, both other guards nowhere near firing, verdict
    /// `Ok`.
    ///
    /// `coordinates` is the sum of `tensor.len()` over the carried set, computed in `O(n)`
    /// from the lengths alone -- BEFORE any coordinate is read, hashed or cloned. It is the
    /// number to pass to [`Policy::with_max_coordinates`] to admit this receipt.
    TooMuchCoordinateWork { coordinates: u128, max: u128 },
    /// The receipt's identity set is not the one the checker expects. This is the
    /// fabricated-PKI case and it is the most important rejection in the enum.
    PkiMismatch,
    /// The receipt declares a different fault bound than the checker's policy assumes.
    FaultBoundMismatch { policy: usize, receipt: usize },
    /// The receipt used a different aggregation rule than the checker requires.
    RuleMismatch { policy: Rule, receipt: Rule },
    /// **The receipt's numbers are on a different fixed-point grid than the checker's (#77).**
    ///
    /// Refused BY NAME rather than compared anyway. Two builds at different `FRAC_BITS` produce
    /// different aggregates from identical real-valued inputs, each internally consistent, so a
    /// silent comparison yields a confidently wrong answer -- the precise failure this crate
    /// exists to exclude.
    ScaleMismatch { policy: u32, receipt: u32 },
    /// **The receipt is about a different event than the checker asked about (#79 follow-on).**
    ///
    /// A receipt cannot lie about its own `ctx` -- every signature commits to it. What it CAN do
    /// is be presented to a verifier that never asked. Two deployments sharing a PKI, an `f` and
    /// a rule would otherwise each verify the other's receipts as `VERIFIED`, with nothing shown
    /// to say the receipt belongs to another context.
    ContextMismatch { policy: Context, receipt: Context },
    /// A carried contribution is not signed by its claimed author.
    BadContributionSignature { node_id: u32, leaf: [u8; 32] },
    /// A carried proof does not actually demonstrate equivocation.
    BogusProof { node_id: u32, leaf: [u8; 32] },
    /// A contribution is tagged for a different round than the receipt claims.
    WrongRound { expected: u64, found: u64 },
    /// The commitment trace does not cover the carried entries.
    StateRootMismatch { claimed: [u8; 32], actual: [u8; 32] },
    /// The claimed aggregate is not what the rule produces from the admitted set.
    AggregateMismatch {
        claimed: Option<Vec<i64>>,
        actual: Option<Vec<i64>>,
    },
    /// The claimed output root does not commit to the claimed aggregate.
    OutputRootMismatch { claimed: [u8; 32], actual: [u8; 32] },
}

fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

impl core::fmt::Display for Invalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Invalid::TooMuchDerivableWork { would_be, max } => write!(
                f,
                "the carried contributions could derive up to {would_be} equivocation \
                 proofs, over the limit of {max}; each costs a signature verification and \
                 the count is quadratic in how often one node id repeats"
            ),
            Invalid::TooManyContributions { would_be, max } => write!(
                f,
                "the receipt carries {would_be} contributions, over the limit of {max}; \
                 equivocation detection scans every held contribution, so checking is \
                 quadratic in this count even when the set derives no proofs"
            ),
            // NAMES THE NUMBER TO RAISE, not just the number exceeded. A refusal that reports
            // only "over the limit" leaves an operator with a legitimate large receipt
            // guessing; `coordinates` IS the value that admits this receipt, so it is printed
            // as the argument to pass rather than left to be inferred.
            Invalid::TooMuchCoordinateWork { coordinates, max } => write!(
                f,
                "the carried contributions total {coordinates} tensor coordinates, over this \
                 checker's work budget of {max}; verification does work proportional to that \
                 product (contributions x values each) and nothing in a receipt bounds the \
                 vector length, so the budget is the bound. If you meant to check this \
                 receipt, raise the budget to {coordinates}: \
                 Policy::with_max_coordinates({coordinates}), or acfa-verify \
                 --max-coordinates {coordinates}"
            ),
            Invalid::PkiMismatch => write!(
                f,
                "the receipt's PKI is not the checker's trust file: it describes a different \
                 deployment"
            ),
            Invalid::FaultBoundMismatch { policy, receipt } => write!(
                f,
                "fault bound mismatch: the checker assumes f={policy}, the receipt claims \
                 f={receipt}"
            ),
            Invalid::ContextMismatch { policy, receipt } => write!(
                f,
                "context mismatch: the checker asked about {}, the receipt is about {}",
                hex32(policy),
                hex32(receipt)
            ),
            Invalid::ScaleMismatch { policy, receipt } => write!(
                f,
                "fixed-point scale mismatch: the checker reads FRAC_BITS={policy}, the receipt \
                 was written at FRAC_BITS={receipt}. These are different grids; the values are \
                 not comparable and were NOT compared"
            ),
            Invalid::RuleMismatch { policy, receipt } => write!(
                f,
                "aggregation rule mismatch: the checker requires {policy:?}, the receipt \
                 used {receipt:?}"
            ),
            Invalid::BadContributionSignature { node_id, leaf } => write!(
                f,
                "contribution {}.. claims node {node_id} but carries no valid signature by it",
                hex8(leaf)
            ),
            Invalid::BogusProof { node_id, leaf } => write!(
                f,
                "equivocation proof {}.. does not convict node {node_id}",
                hex8(leaf)
            ),
            Invalid::WrongRound { expected, found } => {
                write!(
                    f,
                    "round mismatch: expected {expected}, receipt is for {found}"
                )
            }
            Invalid::StateRootMismatch { claimed, actual } => write!(
                f,
                "state root mismatch: receipt claims {}.., re-execution gives {}..",
                hex8(claimed),
                hex8(actual)
            ),
            Invalid::AggregateMismatch { .. } => write!(
                f,
                "the claimed aggregate is not what the rule produces from the admitted set"
            ),
            Invalid::OutputRootMismatch { claimed, actual } => write!(
                f,
                "output root mismatch: receipt claims {}.., re-execution gives {}..",
                hex8(claimed),
                hex8(actual)
            ),
        }
    }
}

impl core::error::Error for Invalid {}

/// What a receipt establishes once it verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub round: u64,
    pub state_root: [u8; 32],
    pub output_root: [u8; 32],
    pub aggregate: Option<Vec<i64>>,
    /// Identities admitted into this round's aggregate.
    pub admitted: Vec<u32>,
    /// Identities excluded by a valid equivocation proof CARRIED in the receipt.
    pub convicted: Vec<u32>,
    /// Identities the receipt PROVES equivocated but does not itself convict.
    ///
    /// The verifier derives this from the carried contributions rather than trusting the
    /// carried proofs. If a receipt holds two conflicting signed contributions from one
    /// identity and no proof against it, the evidence is present and the conviction was
    /// simply never computed. Reporting it separately is what makes withholding LABELLED
    /// instead of invisible: an issuer who never forms the proof produces an internally
    /// consistent receipt, and without this field a checker cannot tell "withheld" from
    /// "unnoticed".
    ///
    /// Non-empty does NOT invalidate the receipt. The aggregate is still correct, because
    /// the per-round uniqueness clause already excludes an identity with two visible
    /// entries. What is wrong is the accountability record, and that is worth naming.
    pub convictable_but_unconvicted: Vec<u32>,
    /// False when the admitted population was below the robustness bound OF THE RECEIPT'S
    /// OWN RULE -- which is NOT necessarily the rule the checker's robustness argument
    /// assumes. READ THE NEXT PARAGRAPH BEFORE TREATING `true` AS REASSURANCE.
    ///
    /// crypto-08, MEASURED. `Policy::new` leaves `rule: None`, meaning "accepts either",
    /// so a checker who never calls `.expecting()` has not told the receipt which rule it
    /// wanted, and this flag can only answer for the rule the receipt used. At n = 5,
    /// f = 1, a Krum receipt against a default policy gives:
    ///
    ///   verify              -> Ok
    ///   population_bound_met -> TRUE   (Krum requires 2f+3 = 5, and 5 were admitted)
    ///
    /// An operator whose own argument assumes BULYAN needs 4f+3 = 7. They get a fully
    /// green verdict, including this flag, for a deployment that does not meet their
    /// assumption -- because the flag answers the RECEIPT's question, not theirs. The
    /// permissive default is spelled `new`, so it is reached by anyone who never thought
    /// about the rule at all.
    ///
    /// `Policy::new(pki, f).expecting(rule)` closes it and returns `RuleMismatch`. Making
    /// that the DEFAULT means changing `Policy::new`'s signature, which is a public API
    /// break and therefore a ruling rather than a tidy-up; it is with B.
    ///
    /// A receipt can be perfectly valid and short of the bound at the same time: the
    /// arithmetic is right, the signatures are right, and the result still carries no
    /// Byzantine guarantee because too few identities took part. Surfacing that separately
    /// is the difference between an honest receipt and a reassuring one.
    pub population_bound_met: bool,
    /// **Lemma 12's no-flip certificate: did fixed-point arithmetic change WHO was selected?**
    ///
    /// This is the question byte-identity does not answer. Determinism says every replica
    /// computed the same selection; it does not say that selection is the one the
    /// un-quantised gradients would have produced. `Some(c)` with `c.certified` true means it
    /// provably is -- a per-round, third-party-checkable statement about a counterfactual.
    ///
    /// **Recomputed by the verifier, never carried on the wire**, so there is nothing here an
    /// issuer can forge or suppress; two verifiers of the same receipt derive the same
    /// certificate, and it costs no encoding change.
    ///
    /// `None` means no certificate is available -- empty round, kernel refusal, the select-all
    /// band, or Bulyan -- and is NOT a negative result. `Some(c)` with `c.certified` false is
    /// the honest negative: the boundary was too close to certify, which by Remark 13 includes
    /// an irreducible exact-tie residual no margin condition can ever cover.
    ///
    /// Independent of `population_bound_met`: a certified selection can still be undefended,
    /// and a defended round can be uncertified. Neither implies the other.
    pub margin: Option<MarginCertificate>,
}

impl Receipt {
    /// Build a receipt for a round from a state the issuer holds.
    pub fn issue(
        state: &State,
        ctx: Context,
        round: u64,
        pki: &Pki,
        f: usize,
        rule: Rule,
    ) -> Receipt {
        let params = RoundParams {
            rule,
            f: f as u32,
            frac_bits: acfa_aggregate::FRAC_BITS,
        };

        // SCOPE THE CARRIED SET TO THIS ROUND AND TO VALID SIGNATURES, and commit to the
        // root of what is carried.
        //
        // `recompute` refuses any contribution whose `rnd` differs from the receipt's, or
        // that is not signed by its claimed author, so carrying the issuer's whole state
        // made a receipt unverifiable the moment the state held a foreign-round OR an
        // unsigned entry -- `issue` and `verify` disagreed about what a receipt is. Scoping
        // here rather than relaxing the check there is the correct direction: a receipt is a
        // statement about ONE round, and a verifier that accepted foreign-round or
        // unauthenticated entries would be checking a commitment over a set it never
        // examined.
        //
        // The SIGNATURE half of this scope closes a composition defect: `admit` (the
        // read-time path the aggregate is taken over) already SKIPS a contribution with a
        // bad signature (`if !c.signature_valid(pki) { continue }`), but `issue` carried the
        // raw state, so one unauthenticated contribution merged into a replica's state made
        // every receipt it issued for that round fail `recompute`'s step-1 signature check
        // everywhere -- an availability defect, and a receipt whose committed state root and
        // whose aggregate were taken over DIFFERENT sets. Carrying exactly what `recompute`
        // accepts (`rnd == round && signature_valid`) makes issue and verify agree and puts
        // the state root over the same set the aggregate is. On an HONEST state every
        // contribution is valid, so this filter drops nothing and the golden vectors and the
        // cross-architecture fingerprint are byte-for-byte unchanged.
        //
        // Proofs are NOT scoped. Conviction is permanent -- the proof set is grow-only, and
        // an identity that equivocated in round 1 is still convicted in round 5 -- so
        // filtering proofs by round would silently un-convict across rounds. `resolve`
        // already takes conviction from the whole proof set, and `recompute` round-checks
        // contributions only, so this is the view both sides already agree on.
        let mut carried = State::new();
        for c in state
            .c
            .values()
            // THE ROUND PARAMETERS MUST MATCH, for the same reason the context must. A
            // contribution offered under a different rule, fault bound, or fixed-point scale was
            // not offered to THIS round, and carrying it would record a node as having taken part
            // in an aggregation it never consented to. Filtered here rather than rejected later so
            // a mismatch produces an obviously empty round instead of a subtly wrong one.
            .filter(|c| {
                c.ctx == ctx && c.params == params && c.rnd == round && c.signature_valid(pki)
            })
        {
            carried.add_contribution(c.clone());
        }
        for p in state.e.values() {
            carried.add_proof(p.clone());
        }

        // RESOLVE OVER THE CARRIED SET, NOT THE RAW STATE.
        //
        // This is the whole point of the block above and it was briefly lost. `resolve` used to
        // run on `state`, so once the filter learned to drop foreign CONTEXTS (#79) and then
        // foreign round PARAMETERS, the receipt committed a state root over the filtered set and
        // an aggregate over the unfiltered one -- two commitments covering two different sets,
        // which is verbatim the defect the signature half of this filter was added to close.
        // Measured while it was broken: a state signed at f=1 issued at f=0 carried ZERO
        // contributions and still published `claimed_aggregate = Some([1, 0])`.
        //
        // Resolving over `carried` keeps issue and verify looking at one set by construction
        // rather than by two filters being kept in step by hand. Conviction is unaffected:
        // `carried` holds the ENTIRE proof set, so `resolve` still takes conviction from all of
        // it, across rounds, exactly as before.
        let r: Resolution = resolve(&carried, round, pki, f, rule);

        Receipt {
            ctx,
            round,
            f,
            rule,
            frac_bits: acfa_aggregate::FRAC_BITS,
            pki: pki.clone(),
            contributions: carried.c.values().cloned().collect(),
            proofs: carried.e.values().cloned().collect(),
            claimed_state_root: carried.root(),
            claimed_output_root: r.output_root,
            claimed_aggregate: r.aggregate,
        }
    }

    /// Verify against what the checker independently knows. **This is the security
    /// entry point.**
    ///
    /// The policy check runs FIRST and is not a formality: it is what stops a receipt
    /// certifying itself. A receipt whose PKI the checker does not recognise is rejected
    /// before any signature is examined, because every signature in it would verify
    /// perfectly against the keys the forger chose.
    ///
    /// THE EQUALITY BELOW IS LOAD-BEARING FOR TWO SEPARATE FINDINGS, and relaxing it
    /// reopens both. It compares the WHOLE map -- ids AND keys -- so an operator's trust
    /// file can only be USED if it is identical to the one the receipt carries, and the
    /// carried one has already been through `wire::decode`. That is what extends two
    /// decode-time guards to the CLI, which reads its PKI from a text file that never
    /// touches the decoder:
    ///
    ///   crypto-03  `decode` refuses a PKI that reuses one public key for two identities.
    ///              Without that extension, a cloned trust file would let an attacker
    ///              replay one node's signed bytes under extra identities -- the clones sit
    ///              at distance zero and multi-Krum selects the tightest cluster, moving a
    ///              measured aggregate from [10, 9] to [750002, 750001].
    ///   crypto-02  `decode` refuses a PKI containing a small-order key, for which
    ///              `R = identity, S = 0` verifies without any secret.
    ///
    /// The dangerous edit is the plausible local one: accepting a SUPERSET trust file, or
    /// comparing only the id sets to support a rekeying story. Either silently detaches the
    /// CLI from both guards while every test still passes. See
    /// `tests/crypto02_key_strength.rs` and `tests/key_binding.rs`.
    pub fn verify(&self, policy: &Policy) -> Result<Verified, Invalid> {
        if self.pki != policy.pki {
            return Err(Invalid::PkiMismatch);
        }
        // BEFORE the arithmetic, not after: comparing numbers from two different grids produces a
        // confidently wrong answer rather than an error, so the grid is checked first.
        if let Some(want) = policy.ctx {
            if want != self.ctx {
                return Err(Invalid::ContextMismatch {
                    policy: want,
                    receipt: self.ctx,
                });
            }
        }
        if self.frac_bits != policy.frac_bits {
            return Err(Invalid::ScaleMismatch {
                policy: policy.frac_bits,
                receipt: self.frac_bits,
            });
        }
        if self.f != policy.f {
            return Err(Invalid::FaultBoundMismatch {
                policy: policy.f,
                receipt: self.f,
            });
        }
        if let Some(want) = policy.rule {
            if want != self.rule {
                return Err(Invalid::RuleMismatch {
                    policy: want,
                    receipt: self.rule,
                });
            }
        }
        self.recompute(policy.max_coordinates)
    }

    /// Check that the receipt agrees with itself, against its own carried PKI.
    ///
    /// **NOT A SECURITY VERDICT.** Use [`Receipt::verify`] with a [`Policy`] for that.
    /// This exists for diagnosis -- inspecting a receipt whose deployment you do not know,
    /// or triaging which of several failures is present -- and it returns a type with no
    /// `population_bound_met` flag precisely so its result cannot be reported as a safe one.
    ///
    /// WORK BUDGET: this entry point has no [`Policy`], so it uses
    /// [`DEFAULT_MAX_VERIFY_COORDINATES`] and can return
    /// [`Invalid::TooMuchCoordinateWork`]. Diagnosis is still a door that accepts a file from
    /// a stranger -- `acfa-verify` reaches this path whenever `--pki` is omitted -- so it
    /// gets the bound rather than an exemption. A caller who needs a larger budget here has
    /// a `Policy` available and should use `verify`.
    pub fn check_self_consistent(&self) -> Result<SelfConsistent, Invalid> {
        let v = self.recompute(DEFAULT_MAX_VERIFY_COORDINATES)?;
        Ok(SelfConsistent {
            round: v.round,
            state_root: v.state_root,
            output_root: v.output_root,
        })
    }

    /// Recompute everything and check it against what was claimed.
    ///
    /// Order matters: cryptography before arithmetic. Signatures and proofs are checked
    /// first, so a receipt stuffed with forged entries is rejected as forged rather than
    /// as "aggregate mismatch", which would misattribute the fault.
    fn recompute(&self, max_coordinates: u128) -> Result<Verified, Invalid> {
        // 0. BOUND THE CARRIED SET BEFORE ANY PER-CONTRIBUTION WORK. The derivation
        //    loop near the end calls `deliver`, which scans everything held, so
        //    `recompute` is QUADRATIC in the carried count. `TooMuchDerivableWork`
        //    further down bounds the PROOF half -- but a set of all-DISTINCT node ids
        //    derives zero proofs (bound 0) and still forces n(n-1)/2 leaf comparisons,
        //    so that guard passes while the scan runs unbounded. Measured end to end:
        //    12 000 all-distinct contributions verify Ok in 2.4 s, cost unbounded in n.
        //    `State::merge` caps this exact quantity (`MAX_MERGE_CONTRIBUTIONS`) on the
        //    trusted door; verify MUST carry the SAME cap or the untrusted door is a
        //    remote DoS. This is the contribution half the note near the derivation
        //    loop promised; before this guard only the proof half was carried across.
        let carried = self.contributions.len();
        if carried > crate::state::MAX_MERGE_CONTRIBUTIONS {
            return Err(Invalid::TooManyContributions {
                would_be: carried,
                max: crate::state::MAX_MERGE_CONTRIBUTIONS,
            });
        }

        // 0b. BOUND THE WORK, NOT ONLY THE INPUTS. Step 0 above bounds `n`; the derivable
        //     -proof check further down bounds the proof count. Neither bounds `d`, and the
        //     cost of every step below this one is proportional to the PRODUCT `n * d`:
        //     step 1 hashes each tensor to check its signature, step 3 clones and re-hashes
        //     it into the leaf, step 4 hashes it again inside `admit` and clones it again
        //     for the kernel, and the derivation loop hashes it twice more. Bounding one
        //     factor of a product bounds nothing -- the sentence `MAX_COORDINATE_OPS` one
        //     layer down already writes about `MAX_CONTRIBUTIONS`.
        //
        //     MEASURED, on the unfixed code, release, EVERY EXISTING GUARD PASSING and the
        //     verdict `Ok`: `n = 256, d = 16384` is 32.03 MiB of receipt and 11.78 s of
        //     verifier CPU with the contribution count at 256 of 4096 and the derivable
        //     -proof bound at 0. `n = 4096, d = 2048` is 64.45 MiB and 31.54 s. The cost is
        //     LINEAR in `d` (fitted exponent 0.99) and `d` is bounded only by `filesize / 8`.
        //
        //     THE KERNEL'S BOUND IS NOT A SUBSTITUTE FOR THIS ONE, TWICE OVER. `resolve`
        //     treats a layer-1 refusal as a legitimate deterministic OUTCOME -- correctly,
        //     because two replicas must agree the round produced nothing -- so
        //     `MAX_COORDINATE_OPS` firing changes the answer and not the cost; it arrives
        //     after the work rather than instead of it. And its quantity is the wrong one:
        //     at `n = 256, d = 8192` the kernel's `n^2 * d` is 5.4e8, comfortably inside its
        //     1e9 cap, while this door burned 8.7 s. Small kernel number, large verifier
        //     number, same receipt.
        //
        //     THE CHECK ITSELF IS `O(n)` AND TOUCHES NO COORDINATE: `Vec::len` is a field
        //     read, and `n` is already capped by step 0 immediately above. So this is
        //     genuinely BEFORE the expensive work rather than merely early in the function.
        //     `u128` and saturating, because the sum of attacker-chosen lengths must not
        //     wrap into a small number and pass -- that is `required_n`'s failure mode
        //     (see `Rule::required_n`) and it fails OPEN.
        let coordinates: u128 = self
            .contributions
            .iter()
            .fold(0u128, |acc, c| acc.saturating_add(c.tensor.len() as u128));
        if coordinates > max_coordinates {
            return Err(Invalid::TooMuchCoordinateWork {
                coordinates,
                max: max_coordinates,
            });
        }

        // 1. Every carried contribution must be genuinely signed.
        for c in &self.contributions {
            if !c.signature_valid(&self.pki) {
                return Err(Invalid::BadContributionSignature {
                    node_id: c.node_id,
                    leaf: c.leaf(),
                });
            }
            if c.rnd != self.round {
                return Err(Invalid::WrongRound {
                    expected: self.round,
                    found: c.rnd,
                });
            }
        }

        // 2. Every carried proof must genuinely demonstrate equivocation. A receipt
        //    that convicts an identity on a bogus proof is a censorship tool, so this
        //    is a hard failure and not a filter.
        for p in &self.proofs {
            if !p.valid(&self.pki) {
                return Err(Invalid::BogusProof {
                    node_id: p.node_id,
                    leaf: p.leaf(),
                });
            }
        }

        // 3. Rebuild the state from the carried entries and check the commitment trace.
        let mut state = State::new();
        for c in &self.contributions {
            state.add_contribution(c.clone());
        }
        for p in &self.proofs {
            state.add_proof(p.clone());
        }
        let actual_state_root = state.root();
        if actual_state_root != self.claimed_state_root {
            return Err(Invalid::StateRootMismatch {
                claimed: self.claimed_state_root,
                actual: actual_state_root,
            });
        }

        // 4. Re-execute the aggregate. This is the load-bearing step: it is an
        //    independent recomputation, not a check of the issuer's arithmetic.
        let r = resolve(&state, self.round, &self.pki, self.f, self.rule);
        if r.aggregate != self.claimed_aggregate {
            return Err(Invalid::AggregateMismatch {
                claimed: self.claimed_aggregate.clone(),
                actual: r.aggregate,
            });
        }
        if r.output_root != self.claimed_output_root {
            return Err(Invalid::OutputRootMismatch {
                claimed: self.claimed_output_root,
                actual: r.output_root,
            });
        }

        let admitted_leaves: std::collections::BTreeSet<[u8; 32]> =
            r.admitted.iter().copied().collect();
        let mut admitted: Vec<u32> = self
            .contributions
            .iter()
            .filter(|c| admitted_leaves.contains(&c.leaf()))
            .map(|c| c.node_id)
            .collect();
        admitted.sort_unstable();

        // THE UNTRUSTED DOOR. `deliver` runs detection against everything accumulated so
        // far, so this loop is QUADRATIC in a contribution set the SENDER chooses. Measured
        // before the bound: 81.4 KB of receipt to 67.4 s of verifier CPU, verdict Ok, wire
        // linear while work quadrupled per doubling. `State::merge` bounds BOTH halves on
        // the trusted door -- the contribution count AND the derivable-proof count. Verify
        // now carries both: the count at step 0 at the top of `recompute`, the proof count
        // here. The proof bound alone is a hole an all-distinct-id set walks through (it
        // derives zero proofs), which is why the count cap above is not redundant with it.
        let derivable = crate::state::derivable_proof_bound(&self.contributions);
        if derivable > crate::state::MAX_MERGE_PROOFS {
            return Err(Invalid::TooMuchDerivableWork {
                would_be: derivable,
                max: crate::state::MAX_MERGE_PROOFS,
            });
        }

        // Derive convictions from the carried contributions. `add_contribution` above is
        // a raw insert that runs no detection, so this is information the receipt holds
        // and has not computed.
        let mut derived = State::new();
        for c in &self.contributions {
            derived.deliver(c.clone(), &self.pki);
        }
        let already: std::collections::BTreeSet<u32> = state.convicted(&self.pki);
        let mut convictable: Vec<u32> = derived
            .convicted(&self.pki)
            .into_iter()
            .filter(|n| !already.contains(n))
            .collect();
        convictable.sort_unstable();

        Ok(Verified {
            round: self.round,
            state_root: actual_state_root,
            output_root: r.output_root,
            aggregate: r.aggregate,
            admitted,
            convicted: already.iter().copied().collect(),
            convictable_but_unconvicted: convictable,
            population_bound_met: r.population_bound_met,
            margin: r.margin,
        })
    }
}

fn hex32(b: &Context) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    /// Krum at `f = 1` on this build's scale. A NAMED fixture, not a default -- `Receipt::issue`
    /// filters contributions whose parameters differ, so a test needing others must say so.
    const PARAMS_DEFAULT: crate::identity::RoundParams = crate::identity::RoundParams {
        rule: crate::resolve::Rule::Krum,
        f: 1,
        frac_bits: acfa_aggregate::FRAC_BITS,
    };

    use super::*;
    use crate::hash::{enc_tensor, h};
    use crate::identity::{contrib_msg, Identity};

    fn ident(n: u32) -> Identity {
        Identity::from_secret(n, &[n as u8; 32])
    }

    fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
        let th = h(&enc_tensor(t));
        Contribution {
            ctx: crate::identity::NO_CONTEXT,
            sig_preimage: crate::identity::PreimageVersion::V2,
            params: PARAMS_DEFAULT,
            rnd,
            node_id: a.node_id,
            tensor: t.to_vec(),
            sig: a.sign(&contrib_msg(
                &crate::identity::NO_CONTEXT,
                &PARAMS_DEFAULT,
                rnd,
                a.node_id,
                &th,
            )),
        }
    }

    fn room(n: u32) -> (Vec<Identity>, Pki) {
        let ids: Vec<Identity> = (1..=n).map(ident).collect();
        let pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
        (ids, pki)
    }

    fn honest_state(ids: &[Identity], pki: &Pki) -> State {
        let mut s = State::new();
        for (i, id) in ids.iter().enumerate() {
            s.deliver(contrib(id, 1, &[i as i64 * 3, i as i64 + 1]), pki);
        }
        s
    }

    #[test]
    fn an_honestly_issued_receipt_verifies() {
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let v = Receipt::issue(&s, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum)
            .verify(&Policy::new(pki.clone(), 1))
            .unwrap();
        assert_eq!(v.admitted.len(), 5);
        assert!(v.population_bound_met);
        assert!(v.convicted.is_empty());
    }

    #[test]
    fn a_tampered_aggregate_is_caught_by_re_execution() {
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        r.claimed_aggregate.as_mut().unwrap()[0] += 1;
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::AggregateMismatch { .. })
        ));
    }

    #[test]
    fn dropping_a_contribution_breaks_the_commitment_trace() {
        // The withholding check. Remove an entry the root committed to; the receipt
        // can no longer reproduce the root anyone else converged on.
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        r.contributions.pop();
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::StateRootMismatch { .. })
        ));
    }

    #[test]
    fn a_forged_contribution_is_rejected_as_forged() {
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        r.contributions[0].tensor[0] = 4242;
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::BadContributionSignature { .. })
        ));
    }

    #[test]
    fn a_bogus_conviction_cannot_be_smuggled_in() {
        // A receipt that convicts an innocent identity on an unverifiable proof is a
        // censorship tool. It must fail closed.
        let (ids, pki) = room(5);
        let s = honest_state(&ids, &pki);
        let mut r = Receipt::issue(&s, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        r.proofs.push(EquivProof {
            ctx: crate::identity::NO_CONTEXT,
            sig_preimage: crate::identity::PreimageVersion::V2,
            params: PARAMS_DEFAULT,
            rnd: 1,
            node_id: 2,
            h1: [7u8; 32],
            h2: [8u8; 32],
            sig1: [0u8; 64],
            sig2: [0u8; 64],
        });
        assert!(matches!(
            r.verify(&Policy::new(pki.clone(), 1)),
            Err(Invalid::BogusProof { .. })
        ));
    }

    #[test]
    fn a_receipt_over_an_equivocation_verifies_and_names_the_culprit() {
        let (ids, pki) = room(5);
        let mut s = honest_state(&ids, &pki);
        s.deliver(contrib(&ids[0], 1, &[9999, 9999]), &pki);
        let v = Receipt::issue(&s, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum)
            .verify(&Policy::new(pki.clone(), 1))
            .unwrap();
        assert_eq!(v.convicted, vec![1]);
        assert!(!v.admitted.contains(&1), "the equivocator is not counted");
    }

    #[test]
    fn an_unpopulation_bound_met_round_verifies_but_says_so() {
        let (ids, pki) = room(3);
        let s = honest_state(&ids, &pki);
        // n = 3 < 2f + 3 = 5 at f = 1.
        let v = Receipt::issue(&s, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum)
            .verify(&Policy::new(pki.clone(), 1))
            .unwrap();
        assert!(
            !v.population_bound_met,
            "a valid receipt must not imply a population_bound_met one"
        );
    }

    #[test]
    fn two_replicas_that_saw_the_same_set_issue_identical_receipts() {
        let (ids, pki) = room(5);
        let cs: Vec<Contribution> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| contrib(id, 1, &[i as i64 * 3, i as i64 + 1]))
            .collect();
        let mut a = State::new();
        for c in &cs {
            a.deliver(c.clone(), &pki);
        }
        let mut b = State::new();
        for c in cs.iter().rev() {
            b.deliver(c.clone(), &pki);
        }
        let ra = Receipt::issue(&a, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        let rb = Receipt::issue(&b, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        assert_eq!(ra.claimed_state_root, rb.claimed_state_root);
        assert_eq!(ra.claimed_output_root, rb.claimed_output_root);
        assert_eq!(crate::wire::encode(&ra), crate::wire::encode(&rb));
    }

    /// crypto-05 / crdt-04: a state that has lived through more than one round must still
    /// issue a verifiable receipt.
    ///
    /// `issue` carried the issuer's ENTIRE contribution map while `recompute` refuses any
    /// contribution whose round differs from the receipt's. So the moment a node processed
    /// a second round, every receipt it issued -- for any round, including the current one
    /// -- failed with WrongRound. The two halves of the same type disagreed about what a
    /// receipt contains, and no single-round test could see it.
    #[test]
    fn a_multi_round_state_still_issues_a_verifiable_receipt() {
        let (ids, pki) = room(5);
        let mut st = State::new();

        for (i, id) in ids.iter().enumerate() {
            st.deliver(contrib(id, 1, &[(i as i64 + 1) << 16, 0]), &pki);
        }
        let r1 = Receipt::issue(&st, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        assert!(
            r1.verify(&Policy::new(pki.clone(), 1)).is_ok(),
            "single-round receipt must verify"
        );

        // Second round into the SAME state -- this is ordinary operation, not an attack.
        for (i, id) in ids.iter().enumerate() {
            st.deliver(contrib(id, 2, &[(i as i64 + 7) << 16, 0]), &pki);
        }

        let r1_again = Receipt::issue(&st, crate::identity::NO_CONTEXT, 1, &pki, 1, Rule::Krum);
        assert!(
            r1_again.verify(&Policy::new(pki.clone(), 1)).is_ok(),
            "a round-1 receipt issued from a two-round state must still verify"
        );
        let r2 = Receipt::issue(&st, crate::identity::NO_CONTEXT, 2, &pki, 1, Rule::Krum);
        assert!(
            r2.verify(&Policy::new(pki.clone(), 1)).is_ok(),
            "a round-2 receipt from the same state must verify"
        );

        // And it must carry only its own round, or the round check is vacuous.
        assert!(
            r2.contributions.iter().all(|c| c.rnd == 2),
            "receipt carried a foreign round's contributions"
        );
        assert_ne!(
            r1_again.claimed_state_root, r2.claimed_state_root,
            "distinct rounds must commit to distinct state roots"
        );
    }
}
