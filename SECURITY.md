# Security

## Please attack this

This project makes a security claim, so an unexamined implementation is worth very little.
Three soundness bugs have already been found and fixed **by the authors, in their own code**:

1. **A self-certifying receipt.** A receipt carries its own identity set, and verification
   originally checked it against that set. Anyone could mint keys, sign contributions, and
   produce a receipt that verified perfectly. Fixed by requiring an independently supplied
   PKI; the tool now refuses to give a verdict without one.
2. **Unbounded allocation from a length prefix.** The decoder allocated on counts read
   straight from untrusted input, so a few dozen hostile bytes could abort the verifier
   before a single signature was checked. Fixed by bounding every count against the bytes
   actually present.
3. **A tie-break key derived from arrival order.** The default tie key came from the order
   contributions arrived, so two replicas holding the same set could break an exact score
   tie differently and produce different aggregates. That defeats the whole point: the
   result has to be a function of the set. Tie keys are now caller-supplied and stable, and
   a call that cannot obtain one refuses rather than guessing.

Finding your own bugs is not the same as being audited. **There has been no independent
security review.** If you are considering this for anything that matters, please assume
there are more and go looking.

## Reporting

Open a GitHub security advisory, or a public issue if the finding is not sensitive. There
is no bug bounty. Expect an acknowledgement and an honest assessment, including "you are
right and we shipped that" where it applies -- the project's own discipline is that a
confirmed defect is published as loudly as a result.

## What is in scope

- The verifier reaching **VERIFIED** on a receipt it should reject.
- Any input causing a panic, abort, hang, or unbounded allocation in `decode` or `verify`.
- Any divergence in the aggregate across architectures, compilers, or optimisation levels.
  A single reproducible instance refutes the central claim and is the most valuable thing
  you could send.
- Attribution failures: a participant that misbehaves without the receipt recording it, or
  a proof that convicts an honest participant.

## What is explicitly NOT claimed

Reporting these is welcome but they are known scope limits, documented in the README:

- **Sybil resistance** is delegated to whatever issues the PKI.
- **Withholding.** A valid receipt proves honest computation over the set it showed you,
  not that it showed you everything it held. Detecting withholding requires comparing the
  state root against an independently obtained one.
- **Round finality** is provided by `acfa-finality` and is IN scope: a certificate that
  verifies on evidence it should reject, or a synchrony violation that does not produce
  transferable evidence, are both reportable. What is NOT claimed is liveness under an
  adversarial network -- the design halts visibly instead of proceeding.
- **Krum admits coordinate-concentrated attacks** that stay inside the honest spread. That
  is a property of the imported rule; use `bulyan`, which needs `n >= 4f+3`.
- **Values outside Q16.16 range are refused, not handled.** That is deliberate: saturating
  would make the result depend on which replica saturated first.

## Threat model in one paragraph

Up to `f` of `n` participants are Byzantine and may send anything, to anyone, in any order,
including different values to different parties. The network may reorder and duplicate.
Verification assumes the checker independently knows which public keys belong to the
deployment and what `f` is; supplying either from the receipt itself is circular and the
tooling refuses to do it.
