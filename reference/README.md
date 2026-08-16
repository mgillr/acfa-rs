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

One deliberate divergence is recorded rather than hidden: this reference's Bulyan
stage-1 loop draws at most `n-f-2` candidates while `theta = n-2f`, which differ exactly
when `f < 2`. The Rust refuses below `n >= 4f+3` and otherwise draws exactly theta. The
suite asserts that divergence and asserts it is still present, so a corrected reference
fails CI rather than sliding into unexamined agreement.
