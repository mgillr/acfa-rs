# Compatibility policy

This file exists because of one sentence in what this project is for: **a receipt must be
verifiable years later by a third party who was never online.** That is not a property of a
codebase, it is a promise about a format, and a promise that lives only as prose in a README is not
one anyone can build on. This is the promise, stated so it can be held against us.

## What is promised

**A receipt written by any released version of this software verifies under every later version
that speaks the same wire magic and version.** Concretely:

| Format | Magic | Version | Meaning |
|---|---|---|---|
| Receipt | `ACFA-R1\0` | 1 | full receipt, carries contributions |
| Redacted receipt | `ACFA-X1\0` | 1 | no plaintext vectors; see the redaction section of the README |

Neither has changed since the format was introduced, and the cross-architecture fingerprint
`bd13ba3209a940b2025368a63c546ffd59e2580a1b8aa7128cc9b423d1957e40` has been byte-identical across
every release to date, on every supported architecture including big-endian s390x.

**The fingerprint is the compatibility test, not the version number.** It is a hash of a receipt
built from a fixed input, so it moves if and only if the encoding, the kernel arithmetic, or the
canonical ordering moves. CI computes it on eight targets and refuses any push where they disagree.
A reader who wants to know whether two builds will agree about a receipt should compare that value,
not the tag.

## What a format change requires

A change to what a receipt's bytes mean is a **wire-version event**, never a side effect. It
requires all of:

1. a new `MAGIC` **or** an incremented `VERSION` — the old bytes must remain unambiguously
   identifiable;
2. the previous decoder retained, so receipts written before the change still verify;
3. an entry in [`CHANGELOG.md`](CHANGELOG.md) stating what changed and why;
4. the new fingerprint recorded, with the old one kept in the history rather than overwritten.

**A silent fingerprint change is a defect, not a release.** `tools/regression-guard.sh` pins the
current value and CI fails the build if it moves, precisely so that this cannot happen by accident
during a refactor.

## What is NOT promised

Stated plainly, because a compatibility promise that quietly covers less than it appears to is
worse than none:

- **The Rust API is not frozen.** It follows ordinary semver: additive changes in minor releases,
  breaking changes in a major. v0.x means the API may still move. The *wire format* promise above
  is independent of this and is the stronger of the two.
- **CLI human-readable output is not a contract.** The **exit codes** are (`0` ok, `1` refused,
  `2` unreadable input), and they are witnessed by tests. The prose on stdout and stderr may be
  reworded.
- **Performance is not a contract.** Work bounds and their defaults may change; they are safety
  parameters, not compatibility surface. A refusal always names the quantity it declined so an
  operator can raise it.
- **The Python adapter tracks the Rust crates** and carries the same version, but its own API is
  v0.x and may move.

## Verifying an old receipt

Everything a verifier needs is either in the receipt or supplied by the verifier — never fetched.
Verification touches no network, no clock and no other party, which is what makes "years later"
meaningful rather than aspirational.

```sh
acfa-verify receipt.acfa --pki trusted.pki --f 1
```

The PKI must be one you obtained **independently**. A receipt carries the identity set it was
issued against, and a forgery built from freshly minted keys verifies perfectly against its own —
so a verdict is only as strong as the trust file you brought with you. `acfa-verify` refuses to
print `VERIFIED` without one, and reports self-consistency separately and in different words.
