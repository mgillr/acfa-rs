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
bd13ba3209a940b2025368a63c546ffd59e2580a1b8aa7128cc9b423d1957e40
```

This value is byte-identical on every supported architecture including big-endian s390x, and it
has not changed across any release to date. A change to it is a wire-format change and may only
happen with a deliberate, documented wire-version bump — never as a side effect. If your build
prints something else, you are not running a released tree.

---

## v0.3.0 — unreleased

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

### Known open at time of writing
- **#70 — gossip stops permanently at round ~4096/n.** `State::merge` unions contribution keys
  across *all* rounds against a global cap with no round scoping and no prune API. Measured:
  n=20 dies at round 205, n=100 at round 41, no recovery. Note that the naive fix is **not**
  semantically inert — pruning preserves convictions already made but destroys the ability to
  convict an equivocator whose second message arrives after the prune.
- **#71 — verifier work is unbounded in `d`.** At n=4096, d=1024 a 32.45 MiB receipt buys
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
