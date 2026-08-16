# Determinism -- measured results

Every number here came from a run, with the command that produced it. Nothing is inferred
from another number.

## Two kinds of evidence, and they cover different things

**Real hardware, every push.** CI runs the full test suites on x86_64 Linux, aarch64 Linux
(`ubuntu-24.04-arm`), Apple Silicon (`macos-latest`) and x86_64 Windows, and gates on all
four emitting a byte-identical receipt fingerprint. That is genuine silicon, not emulation.

**Emulated targets, every push.** The wide matrix below covers targets no hosted runner
offers: 32-bit (`386`, `arm/v7`), big-endian (`s390x`), and `ppc64le`. These were first
measured locally under QEMU user-mode on a single Intel i5-6500; they now run in CI on
every push alongside the hosted rows, and the fingerprint gate spans all eight. They remain
emulation: the target backend, data model and software stack are exercised, the silicon is
not.

What the emulated rows do and do not establish:

- The container binaries are **genuine target machine code** (the aarch64 `python3` ELF
  header carries `e_machine 0xb7`), so the target compiler backend, data model and software
  stack are exercised. `uname -m` reports `aarch64` while `/proc/cpuinfo` in the same
  container reports `GenuineIntel`.
- **Silicon is not tested** on those rows. Hardware FPCR defaults and errata are out of
  scope for them. The four CI targets above cover real hardware.

## Why the fixed-width port is the artefact under test

The paper states the limitation as *a heterogeneous run **or a fixed-width port with
documented overflow semantics** is owed*. The second is the one that matters here, because
the CPython reference cannot exhibit the failure the claim is about: CPython `int` has no
width, every reduction is `//` on arbitrary precision, and every serialization is already
explicit big-endian. Byte identity there follows from the language specification, not from
the artefact.

## 1. Kernel and data-model determinism -- `examples/xarch_emit.rs`

All 9 golden cases through every rule, plus the float->Q16.16 boundary, emitted as a
canonical big-endian payload and hashed externally.

```
docker run --rm --platform linux/<TARGET> -v <crate>:/src:ro rust:1-slim-bookworm \
  sh -c 'cp -r /src/{Cargo.toml,src,examples} /tmp/b && cd /tmp/b &&
         cargo run --quiet --release --example xarch_emit' | sha256sum
```

| row | arch | width | endian | rustc | digest |
|---|---|---|---|---|---|
| host macOS, debug | x86_64 | 64 | little | 1.96.1 | `4ad9f106...` |
| host macOS, release | x86_64 | 64 | little | 1.96.1 | `4ad9f106...` |
| linux/amd64 | x86_64 | 64 | little | 1.97.1 | `4ad9f106...` |
| linux/arm64 | aarch64 | 64 | little | 1.97.1 | `4ad9f106...` |
| linux/386 | x86 | **32** | little | 1.97.1 | `4ad9f106...` |
| linux/arm/v7 | arm | **32** | little | 1.97.1 | `4ad9f106...` |
| linux/ppc64le | powerpc64 | 64 | little | 1.97.1 | `4ad9f106...` |
| linux/amd64 (Ubuntu control) | x86_64 | 64 | little | **1.75.0** | `4ad9f106...` |
| linux/s390x | s390x | 64 | **big** | 1.75.0 | `4ad9f106...` |

Full digest, identical on every row, over an 89 794-byte payload:

```
4ad9f106ef8840073b09c7babff21f0cd3ac6de149993042b17cf24c95d83850
```

Coverage: **9 rows over 7 distinct targets**, **3 compiler versions** spanning
Dec 2023 -> Jul 2026, **2 operating systems**.

On a strict *(pointer width, endianness)* dedup those 7 targets collapse to **3 data
model classes**: LP64-LE (amd64, arm64, ppc64le), ILP32-LE (386, arm/v7), and LP64-BE
(s390x). Counting each architecture as its own data model would over-count. The
architectures still differ in codegen backend, which is why all 7 are worth running, but
the
data-model claim is 3, not 5.

### What this row does and does not buy

- The 32-bit rows are the only ones with a real prior chance of failure. The crate
  description claims bit-identity "regardless of ... target architecture" *unqualified*,
  while `trimmed_mean` in `build/layer1-aggregate/src/rules.rs` does `usize` arithmetic --
  so an LP64 assumption was
  live. Both
  32-bit rows came back identical, which retires that concern **on this corpus**.
- The s390x row does **not** test Layer 1. Layer 1 never serializes and emits no bytes
  at all; endianness lives in Layer 2. This row tests the harness and the toolchain,
  and is labelled as nothing more.
- The float-boundary section of this payload is a **vacuous pass** -- see sec.2.

## 2. Divergence absorption -- `examples/xarch_absorb.rs`

`xarch_emit` excludes transcendentals so that it measures this kernel rather than libm.
That isolates the kernel correctly, but it removes the only genuine cross-architecture
divergence source from the input path -- so its float-boundary section cannot
distinguish *"the boundary absorbed a real divergence"* from *"nothing diverged in the
first place"*. This probe fixes that.

200 000 deterministic doubles (built by division only, so inputs are bit-identical on
every target), each through `exp`, `cos`, `ln` -> 600 000 samples. Two independently
hashable sections:

- `raw` -- IEEE-754 bit patterns. **Must differ** across architectures.
- `enc` -- the same values through `fixed::encode` into Q16.16. **Must match.**

**A pass counts only if `raw` DIFFERS and `enc` MATCHES.** Reporting `enc` alone is the
mirage.

| libc | image | raw (amd64 vs arm64) | rate | enc | refusals |
|---|---|---|---|---|---|
| **glibc** | `rust:1-slim-bookworm` | **293 / 600 000 differ** | 1 in 2 047 | **0 / 600 000 -- identical** | 0 |
| musl | `rust:1-alpine` | 5 / 600 000 differ | 1 in 120 000 | 0 / 600 000 -- identical | 0 |

Every divergence, on both libcs, is **exactly 1 ULP** in integer encoding space -- none
larger. Example (glibc, `exp`, index 936): amd64 `3f8aa7263dfa19b2` vs arm64
`3f8aa7263dfa19b1` (0.013014124647509149 vs 0.013014124647509147).

**Result:** absorption is **demonstrated on the tested corpus and tested functions** --
not proved as a property. The boundary absorbed 293 real divergences rather than
absorbing nothing.

### The full environment matrix -- and the axis that actually dominates

Running all five environments (macOS libSystem, glibc, musl x x86_64, aarch64) and
comparing every pair:

| pair | raw differing | exp | cos | ln | max ULP | enc |
|---|---|---|---|---|---|---|
| macOS libSystem vs glibc-amd64 | 37 721 | 396 | 37 120 | 205 | 1 | identical |
| macOS libSystem vs glibc-arm64 | 37 788 | 459 | 37 127 | 202 | 1 | identical |
| macOS libSystem vs musl-amd64 | 36 934 | 396 | 36 333 | 205 | 1 | identical |
| macOS libSystem vs musl-arm64 | 36 931 | 396 | 36 333 | 202 | 1 | identical |
| glibc-amd64 vs musl-amd64 | 6 009 | 0 | 6 009 | 0 | 1 | identical |
| glibc-arm64 vs musl-amd64 | 6 142 | 137 | 6 000 | 5 | 1 | identical |
| glibc-arm64 vs musl-arm64 | 6 137 | 137 | 6 000 | 0 | 1 | identical |
| glibc-amd64 vs musl-arm64 | 6 014 | 0 | 6 009 | 5 | 1 | identical |
| **glibc-amd64 vs glibc-arm64** | **293** | 137 | 151 | 5 | 1 | identical |
| musl-amd64 vs musl-arm64 | 5 | 0 | 0 | 5 | 1 | identical |

**5 distinct raw streams out of 5 environments. 1 distinct encoded stream out of 5.**
Every divergence in all ten pairs is exactly 1 ULP; none larger.

The headline follows: **the libm implementation, not the architecture, is the dominant
divergence axis.** macOS libSystem vs glibc diverges ~128x more than glibc-x86_64 vs
glibc-aarch64 does, and glibc vs musl on the *same* architecture diverges ~20x more.
Cross-architecture-within-one-libc -- the axis the experiment originally targeted -- is
the *weakest* of the three measured. Absorption holds across all of them.

Digests (first 16 hex, 4 800 018 bytes each):

```
                 raw               enc
host macOS       b1b75ce5407317a5  c9e60aaed6659f09
glibc-amd64      551af3715f9368ae  c9e60aaed6659f09
glibc-arm64      e7986890099dc794  c9e60aaed6659f09
musl-amd64       e2fe6dd0ec559a64  c9e60aaed6659f09
musl-arm64       e08241792a50bdfc  c9e60aaed6659f09
```

The host raw/enc digests reproduce an independently computed reference exactly.

### Deviations from the pre-registered shape

Acceptance criteria were locked before these rows landed. Reporting the misses:

- **`ln` was pre-registered as expected-zero. It fired 5** (glibc cross-arch, and again
  musl cross-arch). `ln` does diverge; the prediction was wrong.
- **`exp` and `cos` were predicted at ~65-130 each per 200 000 samples; measured 137 and
  151** -- both modestly above the band.
- **The musl control was pre-registered as expected-identical cross-arch; it differed
  (5 / 600 000).** The prediction was registered before the run, and a registered
  prediction that misses is a result rather than noise to bury, which is how it is
  reported here.
- Compliant: no divergence anywhere exceeded 1 ULP (the halt condition), `exp` and `cos`
  were not both null (the harness-fault signature), and no encoded value differed
  anywhere (a single one would have been a FAIL and a major result).

### Divergence profile differs by libc -- and it is not just a rate

| libc | exp | cos | ln |
|---|---|---|---|
| glibc | 137 | 151 | 5 |
| musl | 0 | 0 | 5 |

musl diverges **only in `ln`**. So a musl-only test does not merely have a weaker rate;
it never touches the `exp` or `cos` surface at all. Both facts point the headline at
glibc.

**Why the sample size is 600 000 and not 60 000.** A 60 000-sample musl sweep returns
zero divergences, and zero invites the reading that on musl the float layer never
diverges. At a rate of 1 in 120 000, a 60 000-sample run *expects half an event*, so
zero is the more likely outcome whether the true rate is zero or one in 120 000. That
sample cannot distinguish *never* from *rarely*; this one can, and it finds *rarely*.
musl is a **low**-divergence control, ~59x weaker than glibc -- not a zero-divergence
one, and not vacuous: it absorbed 5 real divergences.

## 3. Cross-implementation agreement

The claim that matters operationally is that an *independent* implementation computes
the same aggregate. Order-invariance within one implementation only proves that
implementation is self-consistent.

`tests/golden/vectors.json` was regenerated from the published Python reference
(the reference implementation released with arXiv:2607.10305) and byte-compared against the committed file:

```
sha256  e570481d498f64eddb7ce4cfe72d3e89713fadc89df2ce7c6e096539e186b0fd   (both)
```

So the goldens are genuinely reproducible from a second implementation, not numbers
written to match. Measured corpus: **9 cases, 2 784 output components, 1 397 negative**
-- so the floor-vs-truncate divergence is genuinely exercised.

## 4. Build-profile axis -- closed by construction

Integer overflow panics in debug and wraps in release, which is a real
"two conforming implementations disagree" hazard in general. In this crate it cannot
occur: `Cargo.toml` sets `[profile.release] overflow-checks = true`, so both profiles
panic. Measured anyway -- debug and release digests are identical (sec.1, rows 1-2).

## 5. Still owed

- **Real aarch64 silicon.** Would convert sec.1 and sec.2 from an emulation caveat into the
  heterogeneous run the paper describes as owed. Nice-to-have rather than a blocker,
  since the software-stack divergence in sec.2 is real and measured.
- The unqualified "regardless of target architecture" wording is supported by sec.1 on
  this corpus, but it remains a claim about tested targets, not a proof over all of
  them.
