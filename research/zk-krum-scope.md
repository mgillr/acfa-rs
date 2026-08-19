# ZK-Krum — verifiable Byzantine-robust aggregation without disclosure

**Status: a scope, not a result. Nothing here is implemented and nothing here is measured.**
Published at this stage deliberately — see [Open development](#7-open-development) — but it is a
research direction with an unverified novelty claim, and it should be read as one. If you are
looking for what ACFA actually does today, see the [README](../README.md); everything below is
prospective.

---

## 1. Why this exists

An independent review of this repository scored it 4, 5 and 4 out of ten on novelty and converged
on one sentence: *exceptional engineering discipline around a small idea.* Two specific gaps sat
behind that score, and this proposal is the one move that addresses both at once.

- **Privacy.** The audit artefact used to carry every participant's raw update in plaintext.
  v0.3.0's [redacted receipts](../build/layer2-receipt/src/redact.rs) remove the plaintext from
  the *artefact*, but the aggregator still sees everything and redaction gives **no formal privacy
  guarantee at all**. That is an honest improvement to an adoption blocker, not a research result.
- **Novelty over prior art.** PeerReview (SOSP'07) established determinism-as-evidence nineteen
  years ago. Shipping this project's own Lemma 12 closed a gap between the paper's claims and its
  code — good hygiene, no new mathematics.

## 2. The claim

> Prove, in zero knowledge, that a multi-Krum aggregate was computed correctly over *committed*
> contributions, without revealing any contribution.

A verifier learns that the aggregate is the honest multi-Krum output over a set of committed,
signed contributions under fault bound `f`. It learns nothing else — not the vectors, not the
distances, not the scores.

## 3. The load-bearing insight: exact arithmetic is the precondition for provability

**Krum over IEEE floats is not soundly arithmetizable**, and not only for the obvious reason.

1. Float operations are not field operations. There is no exact circuit for an
   implementation-defined rounding mode, and FMA contraction makes results compiler-dependent.
   This is the same divergence documented in
   [`xarch-libm-divergence.md`](xarch-libm-divergence.md).
2. **Selection is discontinuous, which closes the tolerance route.** The usual escape — prove the
   result to within ε — is unavailable *by construction*: arbitrarily near a score tie, a bounded
   perturbation flips the selection by Θ(1). This is the paper's Lemma 3(b), and it is why exact
   arithmetic is an obligation here rather than a preference.

ACFA's kernel is already what a circuit needs: every operation in `multi_krum` is `+`, `−`, `×`
and integer comparison over Q16.16 raw integers, with `i128` accumulators that never rescale.
That maps onto R1CS / AIR / sumcheck with no approximation step.

> **So the determinism this project already has is not merely a reproducibility property — it is
> the enabling substrate for a zero-knowledge proof of robust aggregation.** That composition is
> the novelty claim, and it is one no float-based aggregator can make.

## 4. Feasibility: the decomposition

Naively this is `O(n²·d)` constraints — at n=20, d=10⁶ that is `4×10⁸`, past what general-purpose
SNARKs handle comfortably. But the computation decomposes so that **`d` enters only through
sumcheck-native inner products**:

| Layer | Proves | Cost in `d` | Shape |
|---|---|---|---|
| **A** | the `n²` squared distances `‖vᵢ − vⱼ‖²` | `O(n²d)` prover, `O(d + n²)` verifier | degree-2 multilinear — native sumcheck/GKR |
| **B** | scores (sum of the `m` smallest distances per row), then the `m` lowest scores with lexicographic tie-break | **independent of `d`** | permutation / sorting argument over `n²` then `n` values |
| **C** | mean of the selected set, floor division | **independent of `d`** | range checks |

Layer A is the entire `d` dependence and it is a sum of squares — exactly what sumcheck proves in
linear prover time with a logarithmic verifier. Layers B and C touch `n²` and `n` values only. So
**the expensive part of Krum (dimension) and the awkward part (selection) never meet.**

Order-of-magnitude estimate: n=20, d=10⁶ → ~4×10⁸ field multiplications for Layer A.

> ⚠️ **This estimate is INFERRED from structure and has not been measured.** No implementation
> exists. Treat §4 as a hypothesis about feasibility, not a performance claim.

## 5. Prior art — unverified, and the novelty claim depends on it

**The claim in §3 is not yet defensible**, because the search has not been done. This repository's
own paper was criticised for citing no secure-aggregation literature, and it would be a poor
answer to that criticism to assert novelty again without checking. Candidates to clear:

- **ELSA (S&P'23)** — secure aggregation *with robustness*. Closest known; determine whether it
  covers a **selection** rule or only norm-bounding.
- **RoFL (S&P'23)** — robustness and secrecy via norm bounds, not Krum selection.
- **Bonawitz et al. (CCS'17)** — practical secure aggregation. Sum only. Masks cancel under a sum
  and **do not cancel under a selection**, which is exactly why this problem is open.
- **Prio / Prio+** — private robust statistics, not Krum.
- **VerifyNet / VeriFL** — verifiable federated learning over sums and means.
- **zkCNN / zkML** — ZK for inference; different shape, useful for circuit technique.

**If ELSA or a successor already covers selection rules, the claim collapses to an efficiency
argument, and this scope should be rewritten rather than quietly re-framed.**

## 6. Method

Following the same route the paper used, so the failure modes are the ones already understood:

1. **Anchor** — a reproducible instance already exists: five participants' vectors reconstructed
   from a published receipt in about forty lines of Python, no keys required.
2. **Impossibility lemma** — *float Krum admits no sound ZK arithmetization*, composing
   non-determinism with Lemma 3(b)'s discontinuity. This is what *forces* the exact-arithmetic
   construction rather than merely motivating it.
3. **Construction and converse** — the three-layer decomposition, plus a characterisation: which
   robust rules admit it? Conjecture: exactly those whose score is a sum of order statistics over
   exactly-computed pairwise distances.
4. **Falsifier drives the design** — an adversary who produces an *accepted* proof for a wrong
   aggregate. Surfaces to attack: the binding between commitments and the sumcheck claim; the
   lexicographic tie-break on `tie_key`, which is the least obviously arithmetizable step; the
   select-all band; and `f = 0`.
5. **Checkable** — the proof is the artefact, and it composes with the redacted receipt already
   shipped: that carries `(rnd, node_id, tensor_hash, sig)` and commits to the set without
   disclosing it, which is the commitment layer such a proof needs.
6. **Honest open item, stated up front** — the sorting/selection argument's cost at large `n`, and
   whether the lexicographic tie-break admits an efficient argument at all. If it does not, the
   fallback is to prove selection *up to* tie-break and carry the tie-break as public data, which
   leaks a little and must be stated rather than hidden.
7. **Prior art anchor** — position as the generalisation of verifiable-**sum** aggregation to
   verifiable-**selection** aggregation, with exact fixed point as the enabling condition.

## 7. Open development

This is developed in the open under the same Apache-2.0 licence as the rest of the repository.
There is no patent strategy and none is planned.

Publishing a scope this early is a deliberate choice with a specific benefit: **a public,
timestamped description is defensive**. It establishes prior art, so the direction cannot later be
enclosed by someone else, and it invites the prior-art corrections in §5 from people who know that
literature better than we do. If the answer to §5 is "ELSA already does this", the fastest way to
find out is to say so publicly and be told.

## 8. First deliverable

**A probe, not more design.** Layer A only: a sumcheck argument for the `n²` squared distances over
committed Q16.16 vectors, benchmarked at n=20 with d=10⁴ and d=10⁶, reporting prover time,
verifier time and proof size. That measurement either supports §4 or refutes it. Until it exists,
§4 is inference and this document rests on structure rather than evidence.
