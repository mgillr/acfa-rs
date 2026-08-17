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

This file records the ones that are **fixed**, with the commit that fixed each so the claim
is checkable rather than asserted. **Three** of the fifty-nine were refuted outright -- crdt-10,
adv-07 and num-07 -- and a refuted finding is kept rather than deleted, because a report that
was investigated and found wrong is a result, and the next person to notice the same thing
deserves to find the answer instead of repeating the work. Several more were partly confirmed
and are recorded here at their real scope rather than as reported.

Findings that are still open are tracked as GitHub issues, labelled `audit`. A small number are held back
until they are closed, because publishing an unfixed weakness in a system people may be
running hands an attacker a recipe. That set is deliberately not enumerated here; its
existence is stated rather than hidden, which is the honest half of that decision.

Nothing in this file changed the cross-architecture receipt fingerprint
(`bd13ba3209a940b2025368a63c546ffd59e2580a1b8aa7128cc9b423d1957e40`) or any golden vector.
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

## Open findings

Tracked as issues labelled [`audit`](https://github.com/mgillr/acfa-rs/issues?q=is%3Aissue+is%3Aopen+label%3Aaudit).
The ones worth naming here because they bear on whether the system suits a given deployment:

- **Q16.16 resolution may be unfit for realistic gradient magnitudes** (#6). The most
  consequential open item, and a parameter-choice question rather than a bug. Exactness and
  dynamic range are a trade, and this repository has documented the exactness side and not
  the cost side. Being measured; the result will be published whichever way it falls.
- **"Drop-in for FedAvg" is not accurate on non-IID data** (#8). Minority-distribution
  clients are excluded with zero adversaries present -- expected for a distance-based rule,
  and not what "drop-in" tells a reader.
- **The ASCII-over-stdin integration path is impractical at model scale** (#9). The
  single-implementation guarantee is deliberate; the constant factor it costs is not
  documented.
- **The `no-std` crate category is false** (#1), the **MSRV is declared but never exercised**
  (#3), and **public error enums implement neither `Display` nor `Error`** (#2).

Not listed: a small number of security findings, held until they are closed.