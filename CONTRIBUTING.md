# Contributing

## The one rule that matters

**Publish the probe, not the verdict.** A claim in an issue, a PR description, or a code
comment should carry the command that produced it and that command's exact output. "This
is faster" is not reviewable; a benchmark invocation and its numbers are.

Corollaries the project actually enforces on itself:

- **A status code is not a payload.** Discriminate on content. Probe a deliberately
  impossible input first, so you know what failure looks like before you trust a success.
- **State the sample power behind a null.** "0 divergences in 60,000 samples" is not
  evidence of "never" if the rate is 1 in 120,000. That exact mistake was made here and
  corrected: see the musl row in `build/DETERMINISM-RESULTS.md`.
- **The honest null is a complete result.** A change that measures nothing and says so is
  worth more than one that finds something by relaxing the test.

## Before you open a PR

```sh
# in each of build/layer1-aggregate, build/layer2-receipt and build/layer2-finality
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings

# the Flower adapter, against real Flower
cd adapters/flower && python -m pytest tests/ -q

# the documentation is tested too, and CI runs both of these
python3 -m pip install pyyaml            # the only dependency either check has
python3 tools/readme-commands.py         # every command the README documents
python3 tools/coverage-claim-check.py    # the architecture table vs the workflow
```

CI additionally requires that **eight** architectures produce a byte-identical receipt:
four on real silicon (x86_64 Linux, aarch64 Linux, Apple Silicon, x86_64 Windows) and four
under emulation (i386 and armv7 for 32-bit pointer width, ppc64le, and s390x for
big-endian). If your change makes them diverge, that is not a CI failure to be worked
around -- it is a finding, and we want to hear about it before it is fixed.

## Changes that need extra care

- **Anything touching the wire format or a hash preimage** is a compatibility break: old
  receipts stop verifying. Say so explicitly in the PR.
- **Anything touching rounding, division, or ordering.** The kernel matches a published
  reference byte for byte; `cargo test` will tell you if you broke that, and the goldens
  are regenerable rather than magic numbers.
- **New `unsafe`.** There is none today. Adding some needs a reason in the PR body.
- **New dependencies in `acfa-aggregate`.** It has zero, deliberately, and that is a
  feature for anyone vendoring it.

## Style

Match the surrounding code. Comments explain *why*, especially where the obvious
implementation is wrong -- most comments in this codebase exist because a plausible
alternative silently breaks determinism, and the comment is there to stop the next person
"simplifying" it back.
