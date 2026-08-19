# Reference implementation

`acfa.py` is the reference kernel released with
[arXiv:2607.10305](https://arxiv.org/abs/2607.10305), vendored here with ONE documented
correction (the `fp_encode` rounding rule, num-01 -- see below). It is not byte-identical to
the paper's release; the correction and the reason it was made to the file rather than only
noted are recorded here.

## Why it is vendored rather than linked

The golden vectors in `build/*/tests/golden/` are generated from this file. A golden
nobody can rebuild is a number with no provenance, so the check that matters is not
"do the committed vectors match the committed Rust" but "can anyone regenerate the
vectors from the reference and get the same bytes". That check needs the reference
present, and CI cannot clone something that is not here.

Without the file present the regeneration job can only skip with a warning. A
load-bearing check that never executes is worse than one that fails, because the warning
gets read as noise.

## Provenance

Verify the copy is unmodified:

```sh
cd reference && shasum -a 256 -c SHA256SUMS
```

`43e45bfa...` is the pinned hash of this file (`SHA256SUMS`, checked in CI). If you change it, the goldens change, the
cross-implementation tests fail, and that is the intended behaviour: the whole point of
this file is to be a second, independently written implementation that the Rust must
agree with byte for byte. Do not edit it to make a test pass.

## What agreement with it does and does not prove

Agreement proves the Rust and this Python compute the same bytes. It does not prove
either is correct. Order invariance within one implementation only shows that
implementation agrees with itself; agreement with a second one is the stronger claim,
and it is the one the test suite makes.

Divergences are recorded rather than hidden. There are two.

**Bulyan stage-1 shortfall.** This reference's stage-1 loop draws at most `n-f-2`
candidates while `theta = n-2f`, which differ exactly when `f < 2`. The Rust refuses below
`n >= 4f+3` and otherwise draws exactly theta. The suite asserts that divergence and
asserts it is still present, so a corrected reference fails CI rather than sliding into
unexamined agreement.

**`fp_encode` rounding -- RESOLVED (num-01).** This was a real divergence and it is fixed.
`fp_encode` originally used `int(round(...))`, and Python's `round` is ties-to-even, while the
Rust `fixed::encode` specifies and implements half-away-from-zero -- so they disagreed at
exactly half the half-integers (those whose floor is even): `0.5 -> 0` here versus `1` in Rust,
`2.5 -> 2` versus `3`, and so on. `fp_encode` now rounds **half away from zero explicitly**
(`floor(s+0.5)` for `s >= 0`, `ceil(s-0.5)` for `s < 0`), so it agrees with the Rust encoder at
every tie. Re-run it: `0.5/65536` encodes to `1`, matching Rust. The correction is guarded by
`build/layer1-aggregate/tests/reference_rounding.rs`, which cross-checks the encoders at the
midpoints directly.

WHICH RULE IS NORMATIVE: HALF-AWAY-FROM-ZERO (num-01). The paper and the crate's docstring
both specify it, the cross-architecture fingerprint is built on it, and the annihilation
threshold argument (`|s| < 0.5` encodes to 0) rests on it. So the reference was corrected TO
the file rather than only in prose -- an earlier version of this README left `acfa.py`
ties-to-even and documented the divergence here, on the theory that a vendored reference should
not be edited. That theory loses to a sharper hazard the reviewer named: this file's STATED
PURPOSE is to be the specification, and a third-party implementer reading a spec that rounds
ties-to-even would produce a kernel that disagrees with every deployed one at every rounding
boundary -- exactly the failure the fixed-point design exists to prevent. A spec that is wrong
is worse than a vendored file that is edited. Correcting `acfa.py` (and re-pinning it) makes the
spec, the implementation, and the fingerprint say one thing. Golden generation feeds the kernel
integers and never calls `fp_encode`, so the correction moved no golden and no fingerprint.
