# Changelog

Every release of this repository, what it contains, and how to identify the one you are
running. Newest first.

**How releases are identified.** A release is a signed annotated git tag `vMAJOR.MINOR.PATCH`
on `main`, a GitHub Release carrying the same notes, and — from v0.3.0 — the same version in
all three Rust crate manifests and in the Python adapter. Before v0.3.0 the crate manifests did
not track the tag; see the note under v0.2.0.

**The identifier that matters most is not the version.** It is the cross-architecture receipt
fingerprint, printed by `cargo run --release --example digest` in `build/layer2-receipt`:

```
4664c321388267507c825b8e1b5ef6c2c082879bb871d2c0fff557d514b2fedf
```

This value is byte-identical on every supported architecture including big-endian s390x. A change
to it is a wire-format change and may only happen with a deliberate, documented wire-version bump
— never as a side effect. That has happened once: v0.1.0–v0.3.0 printed
`bd13ba3209a940b2025368a63c546ffd59e2580a1b8aa7128cc9b423d1957e40`, and v0.4.0 moved it for the
`ACFA-R1` → `ACFA-R2` context bump. If your build prints neither value, you are not running a
released tree.

---

## v0.4.0 — 2026-08-20

The context release. It closes #79 — a cross-context forgery that let two *honest*
contributions be assembled into a valid-looking equivocation proof against their author — and it
is the first release in which the cross-architecture fingerprint moves.

### The defect (#79)

A signature covered `contrib_msg(round, tensor_hash)` and nothing else. It did not say **what the
contribution was about**. An honest node participating in two concurrent contexts — two studies,
two cohorts, two tenants of the same deployment — signs one vector in each, in the same round.
Those are two valid signatures by one key over different content in one round, which is precisely
the definition `EquivProof` uses. Anyone holding both receipts could pair them and produce a
proof that verified against the honest node's own key.

The consequence was the exact inversion of the system's proposition: conviction is permanent and
offline-verifiable, so a node could be permanently and unappealably convicted **for behaving
correctly**, by evidence that authenticated perfectly.

### Fixed

- **The signed preimage now binds the context and the node id.**
  `ACFA-CONTRIB2|ctx|rule|f|frac_bits|round|node_id|tensor_hash` (99 bytes), replacing
  `ACFA-CONTRIB|round|tensor_hash` (54). `ctx` is an opaque, caller-defined 32-byte commitment
  the protocol never parses — a study id, a tenant id, a cohort hash, whatever the deployment
  means by "about". Equivocation detection is scoped to a single context, so two contributions
  made under different `ctx` values can no longer be paired.
- **The preimage also binds the round parameters — rule, fault bound, and fixed-point scale
  (closes #77).** `FRAC_BITS` was a compile-time constant carried nowhere, so two builds at
  different scales produced different aggregates from identical real-valued inputs, both
  internally consistent, both verifying, with nothing on the wire saying they disagreed. The
  scale is now on the receipt and in every signature, and `Policy` refuses a mismatch **by name**
  as `ScaleMismatch` rather than comparing numbers from two different grids. `rule` and `f` are
  bound for the adjacent reason: without them an issuer can present contributions offered for one
  aggregation in a round running another, and the signer is recorded as having consented to
  something it never saw.
- **A checker can now pin the context.** `Policy.ctx`, `Invalid::ContextMismatch`, and a `--ctx`
  flag on `acfa-verify`. #79 made the ISSUER commit to a context and gave the CHECKER no way to
  say which one it expected, so a receipt from another deployment sharing a PKI verified as
  VERIFIED with nothing shown. `None` is still accepted — a checker may genuinely not know the
  context — but it now prints NOT PINNED, exactly as an unpinned rule does.
- **A new wire magic rather than a version bump.** `ACFA-R1` → `ACFA-R2` (and `ACFA-X1` →
  `ACFA-X2` for redacted receipts). v1 and v2 differ in what their signatures *mean*, not merely
  in layout, so the decoder must never be one branch away from applying v2 rules to v1 bytes.
  Distinct magics make that a decode dispatch instead of a conditional a maintainer can collapse.
- **The leaf derivation is versioned too.** The leaf is what `admit` sorts by and what the state
  root commits to, so folding `ctx` into a v1 contribution's leaf would both reorder a v0.3.0
  receipt and change the state root it already published. A v1 entry hashes the v1 way forever.

### The fingerprint moved, deliberately and for the first time

```
v0.1.0 - v0.3.0   bd13ba3209a940b2025368a63c546ffd59e2580a1b8aa7128cc9b423d1957e40
v0.4.0            4664c321388267507c825b8e1b5ef6c2c082879bb871d2c0fff557d514b2fedf
```

This is the only circumstance in which that value is permitted to move: a deliberate, documented
wire-version bump. Within each era it remains byte-identical on all eight supported
architectures, big-endian s390x included.

### Compatibility

Receipts written by v0.1.0–v0.3.0 still decode, still verify, and still reproduce their state
roots byte for byte. Reading v1 is not deprecated and has no sunset.

That promise was previously **unfalsifiable**: deleting the v1 decode arm outright left the entire
suite green. `tests/compat_v1_receipts.rs` now pins it against real v0.3.0 receipts — the fixtures
are the `wire_vectors` output of the v0.3.0 tag itself, produced by code that never knew v2 would
exist — and asserts decode, v1 signature verification, state-root reproduction, and a negative
control that a v1 receipt relabelled `ACFA-R2` never verifies. Building that test is what revealed
the leaf-versioning defect above; without it, v0.4.0 would have shipped silently breaking every
receipt v0.3.0 ever wrote.

### Known open

- **#78** — every conviction shrinks the admitted set, which enlarges Lemma 12's `beta` and so
  makes certification harder. Honest-majority rounds with a convicted node may decline to certify.

## v0.3.0 — 2026-08-20

The frontier release: it ships the paper's Lemma 12, which had never been implemented, and
closes the verifier-bound and composition defects found in round-3 review.

### Added
- **Lemma 12 — the quantisation-margin no-flip certificate** (`multi_krum_certified`,
  `krum_aggregate_certified`, `MarginCertificate`). Answers the question byte-identity does
  not: *did fixed-point arithmetic change **who** was selected?* In raw Q16.16 units the grid
  step is exactly 1, so the paper's observable form reduces to pure integer arithmetic —
  `delta_star = 2*l1_max + 3*d`, `beta = (|A|-f-2)*delta_star`, certified iff
  `margin > 4*beta`. No float, no rescale, exact `i128`.
  - Sound, not complete: it may decline to certify a stable configuration but can never certify
    an unstable one. An adversary inflating a contribution enlarges `beta` and so *denies*
    certification — the failure mode of hostile input is a withheld certificate, never a false
    one.
  - Soundness battery searches for a counterexample (a certified case whose fixed-point
    selection differs from the real-valued f64 selection) and asserts non-vacuity on both
    sides. A wider search — 480,000 trials, 13,698 genuine quantisation-induced flips — put
    `max(margin/beta)` on any flipped case at 0.336, a ~12× empirical safety factor.
- **The certificate surfaced on `Verified` and in `acfa-verify`.** Recomputed by the verifier,
  never carried on the wire: nothing for an issuer to forge or suppress, and no encoding
  change. Computed over the **admitted** set — the paper's `|A|` — not a receipt's raw carried
  contributions, which is a superset whenever anything was excluded or convicted.
- `CHANGELOG.md` (this file) and a Releases section in the README.
- **Redacted receipts — full accountability, zero plaintext.** The audit artefact carried every
  participant's raw update in the clear, which is why it could not be shown to anyone the
  participants did not already trust with their gradients. Redaction turns out to be *lossless*
  for verification, because of a property the crypto already had: a signature is over
  `contrib_msg(rnd, tensor_hash)` and a leaf hashes the tensor *hash*, never the tensor, and
  `EquivProof` was already plaintext-free. A redacted receipt therefore still establishes, at
  full strength, that every contribution is genuinely signed, that the state root commits to
  exactly this set, who was admitted, and who equivocated — with the same answers as the
  unredacted receipt. It cannot re-execute the aggregate, which genuinely needs the vectors.
  - **This is redaction. It is NOT secure aggregation and NOT differential privacy.** It gives
    no formal privacy guarantee; `tensor_hash` is a binding commitment, not a hiding one, so a
    recipient who can guess a plausible update can confirm it by hashing. Bonawitz-style masking
    does not straightforwardly apply to this rule at all — masks cancel under a *sum*, and
    multi-Krum is a *selection* on pairwise distances.
  - Its own wire format and magic (`ACFA-X1`), so neither decoder can accept the other's
    artefact. The redacted decoder repeats every guard the full one carries — it is a narrower
    door, not a weaker one.
  - Size note: replacing `4 + 8d` tensor bytes with a fixed 32-byte hash shrinks the artefact
    only for `d >= 4`, and grows it slightly below that. At real model widths the reduction is
    the point (a 1M-parameter update collapses from 8 MB to 32 bytes per contributor).

### Fixed
- **Verify bounded by contribution count** (#68). `State::merge` capped both the derivable-proof
  count *and* the contribution count on the trusted door; verify carried only the proof half. A
  carried set of all-distinct node ids derives zero proofs, so that guard passed while work grew
  unbounded in a sender-chosen count.
- **A single unsigned contribution no longer nullifies a round's receipts** (#69). `admit`
  skips a bad-signature contribution but `issue` carried the raw state and `recompute`
  hard-failed on it, so one junk gossip message made every receipt a replica issued for that
  round fail verification everywhere. `issue` now carries exactly what `recompute` accepts.
- **The suite is runnable against a PyPI install.** A test located its module by path arithmetic
  from the tests directory, which fails for anyone without a source tree beside it.
- Round-3 review corrections: the reference spec described the superseded ties-to-even rounding
  rule and an old file hash; `AUDIT.md` cited commit hashes absent from the re-rooted public
  history and listed closed findings as open; the stress example panicked on its own documented
  grid by unwrapping a now-expected `TooMuchWork` refusal.

### Adversarial review of Lemma 12, and what it changed
- An exhaustive **preimage** search — fixing the quantised point and enumerating the whole
  `|x - X| <= 1/2` box it could have come from, which is the freedom the lemma exists to bound —
  found **0 forged certificates over 812,500 preimages**, including instances certified by as
  little as 0.9% over the line. Flips ceased to exist ~13× below where certification begins.
- A proposal to halve the threshold from `4*beta` to `2*beta` on the strength of that slack was
  **refuted and rejected**. The 4 is 2 + 2 with both terms load-bearing: both boundary endpoints
  move in opposite directions (real condition `g > 2*beta`), and each rank can sit `beta_hat`
  from its real counterpart under a 1-Lipschitz transport (`g >= g_hat - 2*beta_hat`). Halving
  yields only `g > 0`, certifying configurations that can still flip — **but the diagnosis given
  at the time was wrong.** A direct argument on the observed gap, which pays no transport cost,
  shows `2*beta_hat` is the true soundness floor; it was verified step by step and searched over
  1,781,100 preimages in the contested band with zero flips. The paper's `4*beta_hat` is
  therefore twice what soundness requires. It ships anyway because the code must not enforce a
  threshold the published lemma does not state — paper first, then code. **The claim that
  tightening "doubles the certification rate" was also wrong and unmeasured**: measured, the gain
  is 1.00x–11.75x depending on the margin distribution, and zero in the realistic
  high-dimensional clustered case. The constant is pinned by a numeric test and by
  `tools/regression-guard.sh`.
- `l1_max` remains a **global** maximum over all pairs, and this is load-bearing rather than
  cautious: a Krum score is a min over m-subsets, so the perturbation can change which pairs are
  the `m` nearest, and a bound over the currently-minimising set bounds a set the adversary can
  walk out of.

### Also fixed
- **Verifier work is bounded by a caller-supplied coordinate budget** (#71, #73). Neither the
  contribution-count cap nor the derivable-proof bound bounded the `n*d` product they multiply
  into: measured, a 32 MiB receipt bought 16 s of CPU and returned `Ok` with every guard passing,
  and at `n=256` the count guard sat at a *sixteenth* of its cap. Ships a fail-closed default plus
  `Policy::with_max_coordinates`; the refusal names the count it declined. `check_self_consistent`
  takes the same default, which is #73.
- **Gossip no longer stops permanently** (#70). `State::merge` unioned contribution keys across
  *all* rounds against a global cap, so gossip died at round ~4096/n — measured n=20 at round 205 —
  and never recovered. `prune_through` retires settled rounds to conviction witnesses
  `(rnd, node_id, tensor_hash, sig)`, ~108 bytes, which still detect **and still prove**
  equivocation, so detection strength is unchanged rather than traded.
- **A stdin fault bound near `usize::MAX` no longer panics** (#75). It printed `undefended 0` and
  then aborted at 101 — a panic reachable from an untrusted door, and an exit code outside the
  documented contract. Now refused at parse time with exit 2.
- **A timing test no longer flakes on pristine code** (#74). It failed 2 of 6 runs with no patch
  applied. Now the minimum over interleaved repetitions, resting on the fact that contention can
  only make a run *slower*.

### Verification work
- **All 11 Tier 1 crypto guards witnessed**, each test proven to fail on its mutant. One of them —
  `identity.rs` — could be mutated so `verify()` accepted **any** signature against a malformed
  public key while the whole suite stayed green.
- **All 21 Tier 2 untrusted-door sites addressed**: 19 witnessed, **2 shown to be equivalent
  mutants** (not guards at all), written by one agent and independently re-proven by a second.
- **Two real verifier holes found and closed**: `recompute`'s round binding and its output-root
  check. The first is the *verifier* half of a composition defect whose issuer half was already
  fixed and witnessed.
- **A negative control was run on the mutation sweep, and it returned a negative result worth
  recording**: a non-guard cannot be distinguished from a genuinely unwitnessed guard by
  "changed, compiles, suite green" — both present identically. So a survivor count is an **upper
  bound** on unwitnessed guards, not a count of them.

### Known open

- ~~#70 — gossip stops permanently~~ — **fixed, see above**. `State::merge` unions contribution keys
  across *all* rounds against a global cap with no round scoping and no prune API. Measured:
  n=20 dies at round 205, n=100 at round 41, no recovery. Note that the naive fix is **not**
  semantically inert — pruning preserves convictions already made but destroys the ability to
  convict an equivocator whose second message arrives after the prune.
- **#72 — one outlier denies the Lemma 12 certificate for the whole round.** Because `l1_max`
  is a global maximum, a single contribution with large raw magnitude enlarges `beta` for
  everybody and can push every configuration out of the certified tier. **Availability-only: it
  can deny a certificate but never forge one.** The obvious fix is unsound (see above), so this
  is documented rather than patched.
- ~~#71 — verifier work unbounded in `d`~~ — **fixed, see above**. At n=4096, d=1024 a 32.45 MiB receipt buys
  19.00s of CPU and returns `Ok` with every guard passing. The guards bound inputs; what needs
  bounding is work.

### Unchanged
Cross-architecture fingerprint `bd13ba32…`. No wire-format change in this release.

---

## v0.2.0 — 2026-08-19

First production-signed release, after a full independent audit (59 findings, all closed with
guard-deletion proofs) and a round-2 production sweep (remote verify DoS, crypto-10 both PKI
doors, adapter hardening, previously-unwitnessed guards).

- 0 open issues at tag time.
- All CI green including `fingerprints-agree` (byte-identical receipt across 8 architectures
  including big-endian s390x) and `readme-commands-live`.
- Python adapter published to PyPI as `acfa-flower` 0.2.0; an installed-from-PyPI acceptance
  run passed 67 tests with end-to-end Byzantine robustness verified.

**Version-identification caveat, recorded rather than quietly corrected.** At v0.2.0 the three
Rust crate manifests still read `version = "0.1.0"` while the tag read `v0.2.0`, so the crate
version could not be used to identify the release. The install path is `cargo install --git`,
so no published artifact was mislabelled — but a reader inspecting `Cargo.toml` would have been
misled. From v0.3.0 the manifests track the tag.

**Acceptance caveat, found later and recorded here because it changes what that green meant.**
The adapter's test suite inserted a checkout's package at the front of `sys.path`, so running
the suite from the repository tested the *repository copy* even inside a virtualenv with the
wheel installed. The v0.2.0 "67 tests against the PyPI install" claim was therefore not evidence
about the wheel. Fixed in v0.3.0; a from-PyPI acceptance run is now only valid from a directory
with no source tree beside it.

## v0.1.0 — 2026-08-17

First public tag of the extracted, public-only tree.
