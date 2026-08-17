# Reference implementation

`acfa.py` is the reference kernel released with
[arXiv:2607.10305](https://arxiv.org/abs/2607.10305), vendored here verbatim.

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

`377cfa60...` is the file as released. If you change it, the goldens change, the
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

**`fp_encode` rounds by a different rule than the crate.** `fp_encode` is
`int(round(x * (1 << Q_FRAC_BITS)))`, and Python's `round` is ties-to-even; the Rust
`fixed::encode` specifies and implements half-away-from-zero. They do not disagree at
every tie -- they disagree at exactly half of them, the half-integers whose floor is even.
Measured: `0.5 -> 0` here against `1` in Rust, `2.5 -> 2` against `3`, `4.5 -> 4` against
`5`, and symmetrically for negatives; `1.5`, `3.5` and `5.5` agree.

Two things bound what that means, and both are worth stating because each alone would
mislead. It is not a live interop break: `fp_encode` has no call site inside this file --
its own docstring says the kernel never sees floats -- the goldens are generated from
integer inputs, and the Rust encoder is the only encoder on every documented path. But it
is also not harmless, because the hazard here is a READER: anyone who takes this file as
the specification and writes a third implementation from it will round the other way at
those points and produce a different aggregate from the same inputs, which is exactly the
failure the determinism property exists to exclude.

WHICH RULE IS NORMATIVE IS AN OPEN QUESTION AND IS NOT ANSWERED HERE. The paper and the
crate's docstring both specify half-away-from-zero; this file is the artifact as released
and is deliberately left byte-identical to it, warts included, because a vendored
reference that has been edited is no longer evidence of anything. That is why the
correction lives in this README, which is not pinned, and not in `acfa.py`, which is.
