# Audit record

An independent adversarial review of this codebase was run across six lenses -- distributed
systems, Rust robustness, cryptography, Byzantine ML, numerics, and an adversarial engineer
reading it as an attacker. It produced **fifty-nine** findings: 2 critical, 5 high, 14 medium,
36 low, and 2 rated none. By lens: crdt 11, rust 13, crypto 9, fl 9, num 7, adv 10.

That count was previously given here as "sixty", and the correction is worth stating rather
than quietly applying. The number was carried from memory instead of read off the list, and it
travelled into this file, the issue tracker and the working notes before anyone reconciled it
against the source. Four of the findings below are about a claim in a shipped document being
wrong; this file was making a fifth.

The real total is 59 identifiers, contiguous with no gaps and no duplicates, which collapses to
**55 distinct defects** once four confirmed alias pairs are merged -- crypto-01 = crdt-06,
crypto-05 = crdt-04, adv-03 = rust-07, adv-04 = rust-06. The last of those is recorded by the
source itself, at `build/layer1-aggregate/tests/value_range.rs`.

This file records the ones that are **fixed**. A note on provenance, because the reviewer was
right to probe it: the short commit hashes cited inline below are from the PRE-EXTRACTION
private history and DO NOT RESOLVE in this public repository -- the shipped history was re-rooted
at `8caa65da` when the publishable subset was extracted, collapsing many private commits. So an
inline hash here is a historical marker, not a `git show` target for a stranger. The CHECKABLE
public record of every finding is its **GitHub issue**, labelled `audit`, each closed with the
mechanism, the public commit, a guarding test, and confirmation that test FAILS on the unfixed
code (the guard-deletion proof). The machine-checkable anchors are the cross-architecture
fingerprint (below) and `tools/regression-guard.sh`, a CI job that fails if any fix, guard test,
or the fingerprint is reverted. Read the issues for provenance; the inline hashes are kept for
internal traceability only. **Three** of the fifty-nine were refuted outright -- crdt-10,
adv-07 and num-07 -- and a refuted finding is kept rather than deleted, because a report that
was investigated and found wrong is a result, and the next person to notice the same thing
deserves to find the answer instead of repeating the work. Several more were partly confirmed
and are recorded here at their real scope rather than as reported.

Findings that are still open are tracked as GitHub issues, labelled `audit`. A small number are held back
until they are closed, because publishing an unfixed weakness in a system people may be
running hands an attacker a recipe. That set is deliberately not enumerated here; its
existence is stated rather than hidden, which is the honest half of that decision.

Nothing in this file changed the cross-architecture receipt fingerprint
(`4664c321388267507c825b8e1b5ef6c2c082879bb871d2c0fff557d514b2fedf`) or any golden vector.
A guard that moves the product is not a fix.

---

## Critical

### An integer overflow reachable from untrusted wire bytes

`encode()` bounds values to the Q16.16 range on the float path, but a contribution built
directly from raw `i64` -- which is what decoding a receipt does -- reached the aggregator's
`i128` accumulators unbounded. `rules::check` validated emptiness, dimensions and tie keys,
and never magnitudes.

The failure had two stages, and the first hid the second. At `+/-2^62` each squared coordinate
difference is `2^125` and still fits, so the distance function returned cleanly; the **score**
accumulator then summed four of them past `i128::MAX`. Measured before the fix: `sq_dist`
Ok, `multi_krum` panic, `bulyan_select` panic, in both debug and release. Guarding the
distance function alone would have moved the fault one line down and made it look like a
different bug.

Worse, the score-summing block was duplicated byte-for-byte in the Bulyan path. A hand patch
to one copy yields a guard covering Krum and not Bulyan, with the whole suite still green
because nothing exercised the second copy at an overflowing magnitude.

**Fixed** by bounding raw values at both entry points -- `rules::check` for a contribution
assembled by any route, and `wire::decode` at the untrusted door -- which makes every
accumulator on the path safe by construction rather than by audit. The duplicate block was
deleted rather than patched twice. A panic here is a denial of service; under a consumer
build with overflow checks disabled it would instead have been a silently wrong selection.

---

## High

### A receipt from a multi-round state could never verify

`Receipt::issue` carried the issuer's entire contribution map while verification refuses any
contribution whose round differs from the receipt's. So the moment a node processed a second
round, every receipt it issued -- including for the current round -- failed. Two halves of one
type disagreeing about what a receipt contains, and no single-round test could see it.

**Fixed** in `60e6bb8` (public `c985616`) by scoping the carried contributions to the round
and committing to the root of what is carried. Proofs are deliberately not scoped: conviction
is permanent, so filtering them by round would silently un-convict across rounds.

### Merge lost convictions, breaking strong eventual consistency

`deliver` derives an equivocation proof when an arriving contribution conflicts with one
already held. `merge` unioned the two maps and derived nothing. A replica that learned both
halves of an equivocation by **gossip** held both contributions and no proof; one that learned
them by **delivery** held the proof too.

Conviction feeds admission, so the replicas admitted different sets and computed different
aggregates -- and because the state root commits to proof leaves as well as contribution
leaves, their roots differed. Two honest replicas holding an identical contribution set
disagreed, which is exactly the property the type exists to provide.

**Fixed** in `60e6bb8` (public `c985616`). Merge now delivers rather than inserts, so the
proof set is a function of the contribution set rather than of arrival path.

### The decoder's bound was linear and the work was quadratic

The wire decoder bounds a claimed element count against the bytes actually present, so a
length prefix cannot invent elements. That bound is linear. The distance matrix is `n` by `n` of
`i128`. A receipt small enough to pass the wire check could still ask a verifier to allocate
gigabytes: hardening the decoder moved the amplification one layer up rather than removing it.

**Fixed** in `afd6d77` (public `294fc75`). `MAX_CONTRIBUTIONS = 4096`, checked *before* the
allocation, since the allocation is the amplification.

### One wire byte selected a cubic code path

The rule byte selects Bulyan, which re-runs the quadratic selection `theta` times: `O(n^3 * d)`.
The per-call guard inside the selection is not enough there, because Bulyan buys `n` of them.

**Fixed** in `afd6d77` (public `294fc75`). `MAX_CONTRIBUTIONS_BULYAN = 512` at entry, taken
from the measured stress table rather than from taste: n=256 is 11.55 s on the reference host,
so the cube law puts 1024 beyond ten minutes.

### Halt-and-reconcile could not terminate, and its record was not a union

Two bugs sharing a root: the design says evidence is unsuppressible and keeps propagating, and
the implementation treated every arrival as news.

`resume` cleared the blocking fork set, but any peer re-gossiping the reconciled fork put it
straight back and halted the node again. That is ordinary operation, not an attack -- so a node
that re-halts on re-delivery can never resume at all. Separately, the historical record was a
`Vec` with an unconditional push, so fifty deliveries of one fork stored fifty copies.

**Fixed** in `6d5f48e`, then **corrected twice more**, and the correction history is the useful
part. The first fix suppressed re-delivery by *round*, which closed the denial of service and
opened a worse hole: a fork never seen before, at an earlier round, is not old news -- it
invalidates that round and everything after it. An adversary could withhold a fork until after
a resume and have it ignored permanently. The second fix (`c934256`) keyed on certificate
identity, which was defeated in review: `CertFork` derives equality over the signature map, so
re-signing the same conflict with a different valid quorum produces a byte-different,
semantically identical fork that slips the check. The record is now keyed on the **conflict**
itself -- the ordered pair of certificate tuple ids -- which is immune to signature variation by
construction.

---

## Medium and low

| Finding | What it was | Fixed in |
|---|---|---|
| A typo disabled a security check | `acfa-verify` ignored unrecognised flags, so `--require-bounds` (plural, one character) never matched `--require-bound`, the check was never applied, and the tool exited 0 | `ee7d221` / `efc785c` |
| A CLI blocked forever on a terminal | `acfa-verify` read stdin with no guard and no message; `acfa-agg` had the guard and it did not | `ee7d221` / `efc785c` |
| `assert!` in library code aborted the process | `beta_den = 0` exited 101 where the documented contract promises a typed refusal | `ee7d221` / `efc785c` |
| The exit contract was wrong in the code | Out-of-range and non-finite values exited 2 ("unreadable") when the contract says 1 ("refused -- bad input values"). They parse fine; the program is refusing them | `ee7d221` / `efc785c` |
| All three CLIs aborted on non-ASCII input | `&s[i..i+2]` indexes a `&str` by bytes and panics off a character boundary. A tie key of `0` followed by any multi-byte character gave exit 101 | `ee7d221` / `efc785c` |
| A false claim in a shipped document | `DETERMINISM-RESULTS` sec. 4 asserted the build-profile axis was "closed by construction". It was false for every downstream consumer, and it was live in both trees | `4ac0d76` / `0a21f11` |
| The overflow-headroom figure was derived under an unstated assumption | It used the Q16.16 span, which is only the span if every value went through `encode` -- and nothing enforced that on the `i64` path | `da72f09` |

---

## How these were fixed, since the method is the part worth copying

Every fix in this file was **reproduced before being written**. Two findings were already
stale by the time they were reached and three were refuted outright, so patching on the report
would have produced changes with nothing behind them.

Every regression test was verified to **fail on the unfixed code** before it was kept. A test
that only passes on fixed code is not evidence of anything, and this project found eleven
separate cases of checks that could not fail -- including a linter that reported a clean tree
after enumerating zero files, and a coverage checker that reported eight architectures
enforced while four were.

Three of the fixes above were themselves wrong on the first attempt and were caught in
review. That is recorded rather than tidied away, because a review process that never
overturns its own author is not doing anything.

---

## Findings status -- ALL CLOSED

Every one of the 59 findings is now closed on GitHub (labelled `audit`), each with the closure
detail above. There are **no open audit findings**. A production sweep after the audit raised and
closed a further set, including a remote verify-path denial of service the audit had missed.

What remains are not open defects but **documented limitations and roadmap** -- the honest
envelope of the system, closed at their real scope rather than left as bugs:

- **Q16.16 resolution vs realistic gradient magnitudes** (#6). A parameter-choice trade, now
  measured and documented on both sides (the exactness and the cost). Rescale upstream by a
  power of two, which is exact and reversible.
- **"Drop-in for FedAvg" on non-IID data** (#8). Distance-based rules exclude
  minority-distribution clients even with zero adversaries -- inherent to Krum/Bulyan, now
  caveated where the claim is made.
- **ASCII-over-stdin at model scale** (#9). The single-implementation guarantee is deliberate;
  its constant-factor cost is now documented rather than implied away.
- **no-std (#1), MSRV (#3), Display/Error (#2)** -- CLOSED. The `no-std` category claim was
  removed, an MSRV CI job now builds at the declared floor and proves it bites, and every public
  error enum implements `Display` and `std::error::Error`.

Two roadmap items an adopter should weigh, named because the system's honesty about its envelope
is the point: it is a **wire format plus a verifier**, not a daemon -- there is no network layer
and finality state is in-memory (not persisted across a restart) -- and it has had **no accredited
security review**. Run it today as a reproducibility and provenance tool for small-model,
small-cohort, accountability-first deployments, which is the envelope its guarantees actually fit.

## MASTER LEDGER

Every finding from audit round 3 onward, with its GitHub issue and its status. **The count must
reconcile:** a finding that was fixed but never filed reads exactly like a finding that was never
found, which is why this table exists in the repository rather than only on GitHub.

`area` distinguishes where the defect lives, because that governs how bad it is. **rust** is the
implementation. **reference** is `reference/acfa.py` — pinned by hash and the executable spec a
third party implements from, so a defect there ships a spec that contradicts the code. **gate** is
a test, guard or CI step that cannot fail: a green check that verified nothing.

| # | status | area | finding |
|---|---|---|---|
| [#99](https://github.com/mgillr/acfa-rs/issues/99) | **OPEN** | reference | LOW: demos/run.sh always reports exit 0 and its verdicts are hardcoded prose; not referenced by CI |
| [#98](https://github.com/mgillr/acfa-rs/issues/98) | **OPEN** | gate | MEDIUM: error_traits covers 8 of 14 Invalid variants and 7 of 9 WireError variants -- both new variants are outside the array |
| [#97](https://github.com/mgillr/acfa-rs/issues/97) | **OPEN** | gate | MEDIUM: claim-caveat-check.py self-test passes while 5 of 6 pairings go unevaluated -- fl-06 re-entering through the tool built to stop it |
| [#96](https://github.com/mgillr/acfa-rs/issues/96) | **OPEN** | gate | HIGH: layer1-aggregate -- Lemma 12 constants are unasserted and the certificate check recomputes the production comparison |
| [#95](https://github.com/mgillr/acfa-rs/issues/95) | **OPEN** | gate | HIGH: layer2-finality -- five guards in halt.rs and certificate.rs survive deletion of the behaviour they name |
| [#94](https://github.com/mgillr/acfa-rs/issues/94) | **OPEN** | gate | HIGH: the golden CI job regenerates 2 of 4 vector files; vectors_cert.json can be replaced with garbage and CI stays green |
| [#93](https://github.com/mgillr/acfa-rs/issues/93) | **OPEN** | gate | CRITICAL: regression-guard.sh greps for the fingerprint instead of computing it, and its test floor counts #[test] attributes |
| [#92](https://github.com/mgillr/acfa-rs/issues/92) | **OPEN** | reference | MEDIUM: reference trimmed_mean silently returns the plain mean where Rust refuses (adv-05), and divides by zero |
| [#91](https://github.com/mgillr/acfa-rs/issues/91) | **OPEN** | reference | MEDIUM: four inputs where Rust commits a refusal root and the reference computes an aggregate or crashes |
| [#90](https://github.com/mgillr/acfa-rs/issues/90) | **OPEN** | reference | MEDIUM: reference merkle_root accepts duplicate leaves and returns the ambiguous colliding root (CVE-2012-2459 shape) |
| [#89](https://github.com/mgillr/acfa-rs/issues/89) | **OPEN** | reference | HIGH: the v1 preimage/leaf path is absent from the reference -- ACFA-R1 receipts are unverifiable from the spec |
| [#88](https://github.com/mgillr/acfa-rs/issues/88) | **OPEN** | reference | HIGH: reference fp_encode uses floor(s+0.5) -- the exact idiom fixed.rs documents as wrong -- and its guard test replicates the bug so it cannot fail |
| [#87](https://github.com/mgillr/acfa-rs/issues/87) | **OPEN** | reference | HIGH: reference verify() is not strict -- accepts small-order-key forgeries Rust rejects (622/2000 measured) |
| [#86](https://github.com/mgillr/acfa-rs/issues/86) | **OPEN** | reference | HIGH: reference State.merge is a plain dict union -- no proof derivation, crdt-02 live in the spec |
| [#85](https://github.com/mgillr/acfa-rs/issues/85) | **OPEN** | reference | HIGH: reference _auto_proof returns after the first conflicting pair -- its state root is delivery-order dependent |
| [#84](https://github.com/mgillr/acfa-rs/issues/84) | **OPEN** | reference | CRITICAL: reference EquivProof.valid refuses on h1==h2 alone, making the crypto-04 leaf-keying fix inert |
| [#83](https://github.com/mgillr/acfa-rs/issues/83) | closed | rust | ctx cannot be pinned by a checker: Policy has no context field and acfa-verify has no --ctx |
| [#82](https://github.com/mgillr/acfa-rs/issues/82) | **OPEN** | reference | CRITICAL: #79 and crypto-04 are both still live in the vendored Python reference -- the normative artefact contradicts the fix |
| [#81](https://github.com/mgillr/acfa-rs/issues/81) | closed | rust | CRITICAL: EquivProof::valid ignores sig_preimage -- every pre-v0.4.0 conviction silently stops validating |
| [#80](https://github.com/mgillr/acfa-rs/issues/80) | closed | rust | v1 receipts stopped decoding: leaf() folded ctx in unconditionally, reordering and re-rooting every pre-v0.4.0 receipt |
| [#79](https://github.com/mgillr/acfa-rs/issues/79) | closed | rust | CRITICAL: an honest node in two contexts is permanently convictable -- the signed preimage does not name the context |
| [#78](https://github.com/mgillr/acfa-rs/issues/78) | **OPEN** | rust | f semantics are unstated: population_bound_met compares a post-conviction set to an unadjusted fault bound |
| [#77](https://github.com/mgillr/acfa-rs/issues/77) | closed | rust | FRAC_BITS is not on the wire and not versioned -- two builds at different scales silently disagree |
| [#76](https://github.com/mgillr/acfa-rs/issues/76) | closed | rust | State::admit sorts with sort_by_key, hashing every tensor once per comparison -- 2.13x of verify at the shipped default budget |
| [#75](https://github.com/mgillr/acfa-rs/issues/75) | closed | rust | acfa-agg: a stdin-supplied fault bound near usize::MAX panics (exit 101) after printing an answer |
| [#74](https://github.com/mgillr/acfa-rs/issues/74) | closed | rust | verify_derivable_work_bound: timing-ratio test flakes on pristine main under host load (2/6) |
| [#73](https://github.com/mgillr/acfa-rs/issues/73) | closed | rust | acfa-verify: the --pki-less self-consistency path does unbounded work and takes no policy (second door, no trust argument at all) |
| [#72](https://github.com/mgillr/acfa-rs/issues/72) | closed | rust | layer1-aggregate: one rejected contribution denies the Lemma 12 certificate for the whole round (l1_max is a global max) |
| [#71](https://github.com/mgillr/acfa-rs/issues/71) | closed | rust | verify: work is unbounded in d -- 32 MiB receipt buys 19s of CPU with every guard passing (second door) |
| [#70](https://github.com/mgillr/acfa-rs/issues/70) | closed | rust | merge: global cross-round contribution cap kills gossip permanently at round ~4096/n (n=20 -> round 205) |
| [#69](https://github.com/mgillr/acfa-rs/issues/69) | closed | rust | composition: one unsigned contribution nullifies a round's receipts (issue carried junk admit ignores) |
| [#68](https://github.com/mgillr/acfa-rs/issues/68) | closed | rust | verify-dos: contribution-count scan is unbounded for all-distinct ids (the half #57 missed) |

**32 findings recorded, 14 closed, 18 open**
(6 gate, 11 reference, 1 rust).

Nothing in the Rust implementation is known-broken at `5110657`. Every open item is either a
divergence in the vendored reference or a gate that cannot fail — and the two are related, because
what made the reference divergences invisible for so long is that **not one of them is exercised by
any golden vector**, so the cross-implementation suite compared the two implementations only on
inputs they agree about.

