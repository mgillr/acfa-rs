# Cross-architecture float divergence and Q16.16 absorption -- measured

**Date:** 16 August 2026
**Status:** measured, reproducible on this host. Not a claim about aarch64 silicon -- see Provenance.

## Why this exists

arXiv:2607.10305 records in its own limitations:

> *Cross-architecture byte-identity is argued, not measured*: the integer kernel is exact under a
> fixed width contract, but the prototype runs one architecture; a heterogeneous run (or a
> fixed-width port with documented overflow semantics) is owed.

The obvious objection to running it is that byte-identity across architectures is **trivially true**
for a pure-integer kernel, and therefore uninformative. That objection is correct about the kernel
and wrong about the pipeline. This note establishes where the informative content actually lives,
and measures it.

## The kernel half is tautological

The reference implementation released with the paper states it directly at line 11 of
its kernel module: *"The kernel touches NO floats and NO ambient randomness."*
Supporting structure:

| Property | Location | Consequence |
|---|---|---|
| Boundary-only float conversion | reference kernel, l.26-31 (`fp_encode`/`fp_decode`) | no float reaches the kernel |
| Explicit big-endian serialization | reference kernel, l.58, 62, 89, 103-104, 119-120 | no native-endianness dependence |
| Reductions on arbitrary-precision `int` | reference kernel, l.231, 242, 248 (`//`) | no native width, floor by language spec |
| Hash-canonical leaf ordering | reference kernel, l.46, 175 | no iteration-order dependence |

Under CPython these four properties make byte-identity follow from the *language specification*, not
from the artifact. Running the kernel alone on two architectures confirms that CPython conforms to
CPython.

## The informative half is the float->fixed boundary

The harness deliberately routes inputs along the realistic path --
`float -> fp_encode -> integer tensor` -- so the boundary is exercised rather than bypassed. That
boundary is where architecture can actually bite, because `random.gauss` is built on `math.log`,
`math.sqrt` and `math.cos`, and libm is not bit-identical across architectures.

### Probe 1 -- glibc, libc version held constant

`python:3.12-slim` on `linux/amd64` and `linux/arm64`, **glibc 2.41 on both**. 20,000 doubles swept
across `log`, `cos`, `exp` -- 60,000 comparisons -- as raw big-endian bit patterns.

```
differing values : 20 / 60,000
by function      : 19 exp, 1 cos
magnitude        : every one exactly 1 ULP
example          : exp[2970]  aarch64 3fefe7b4b2e428ed
                              x86_64  3fefe7b4b2e428ec
raw exp rate     : 19 / 20,000 = ~1 in 1,050
```

### Probe 2 -- musl control

Identical sweep on `python:3.12-alpine`:

```
differing values : 0 / 60,000
```

> **CORRECTED -- this observation was right, the inference drawn from it was wrong.**
> A larger sample refutes the inference: at 600,000 samples musl diverges **5 times
> (~1 in 120,000), all exactly 1 ULP**. At that rate a 60,000-sample run expects half an event, so a
> zero was the *likely* outcome and this probe could never have distinguished *never* from *rarely*.
> musl is a **low-divergence control, roughly 59x weaker than glibc -- not a zero-divergence
> control**, and a musl pass is therefore not vacuous; it absorbs real divergences.
>
> The sharper fact, which the first pass did not look for: **the divergence sits in different
> functions on the two libcs.** glibc spreads across `exp`, `cos` and `ln`; musl diverges **only in
> `ln`** -- zero in `exp`, zero in `cos`. So a musl-only test does not merely have a weaker rate, it
> never touches the `exp`/`cos` surface at all.

The headline instruction below is unchanged, but the reason is **rate and function coverage, not
existence**, and alpine is **demoted, not disqualified**.

### Probe 3 -- does Q16.16 absorb it?

1,000,000 samples pushed through the fixed-point boundary, `int(round(x * 65536))`, glibc on both
platforms:

```
differing encoded values : 0 / 1,000,000
```

**CORRECTION (num-02): THIS PROBE CANNOT PRODUCE ANY OTHER NUMBER.** `0 / 1,000,000` is what
this corpus returns whether quantisation absorbs anything or not, so it is not evidence of
absorption.

An encoding changes only if the scaled value lies within **half a ULP** of a rounding
boundary, and every divergence measured here is *exactly 1 ULP*. Measured over the 600,000
-sample corpus that `examples/xarch_absorb.rs` builds:

```
closest sample to a rounding boundary : 20,472 ULPs
samples a 1-ULP divergence could flip : 0 of 600,000
expected flips                        : 8.7e-06
samples needed for ONE expected flip  : 6.9e10  (about 114,000x this corpus)
```

The corpus never comes near the only place the two rules can disagree, so `enc` matches
whatever libm does. To give the probe power the inputs must be *boundary-adjacent* -- see
`build/layer1-aggregate/tests/quantisation_power.rs`, which carries both the measurement and
a corpus that can fail. That change is not made here because `xarch_absorb`'s output is
hashed and compared across eight architectures, so it moves a published fingerprint and may
legitimately turn that job red -- which would be the experiment finally working.

## Result

Cross-architecture byte-identity is **not** a tautology inherited from CPython. The float layer
genuinely diverges across architectures -- measured, same libc version, 1 ULP, ~1 in 1,050 on `exp`.
Quantisation did **not** absorb it, and this section previously said it did.

Byte-identity here is **not** a demonstrated contraction property: no sample in the corpus is
within 20,472 ULPs of a rounding boundary, so a 1-ULP divergence could not have changed any
encoding and `0` was forced. Worse, the property as stated is false in the other direction --
quantisation does not absorb a 1-ULP divergence, it makes one **rare and total**. At a
boundary one ULP of input produces a FULL Q16.16 unit of output. Verified against the shipped
encoder rather than a re-implementation of it:

```
encode(2.2888183593749997e-5) = 1      encode(nextafter(v)) = 2
encode(5.340576171874999e-5)  = 3      encode(nextafter(v)) = 4
encode(1.1444091796874999e-4) = 7      encode(nextafter(v)) = 8
```

What survives is the *first* half of this section, which is sound and was always the harder
measurement: the float layer genuinely diverges across architectures. The cross-architecture
determinism claim rests on the eight-way fingerprint agreement, not on absorption.

A matching root alone cannot distinguish *absorbed a real divergence* from *nothing diverged
in the first place*. That sentence was right, and the control built from it checked the wrong
side: it verified that the **input** diverged, never that the **output could have**. Only the
second question is about power, and it was not asked.

## Consequence for how the headline run must be executed

1. **Run on `python:3.12-slim` (glibc). Alpine is demoted as the headline image.** Two independent
   reasons, both measured: glibc's divergence rate is ~59x musl's, and musl never exercises the
   `exp`/`cos` surface at all. Alpine remains useful as a low-divergence control.
2. Publish `INPUT_DIGEST`, `STATE_ROOT` and `OUTPUT_ROOT` **alongside the libm divergence count for
   the same image pair**, so the record shows the pass absorbed a real divergence.
3. Printing the input digest separately from the output root is what
   makes a failure attributable. Keep it.

## Provenance -- read before citing

The aarch64 container runs **genuine aarch64 machine code**: the ELF `e_machine` field of
`/usr/local/bin/python3` reads `0xb7` (aarch64) inside the arm64 container and `0x3e` (x86-64)
inside the amd64 container. The entire aarch64-compiled libc/libm code path is real.

The **processor is emulated** (QEMU user-mode, Docker Desktop, single Intel i5-6500 host --
`/proc/cpuinfo` inside the arm64 container reads `GenuineIntel ... i5-6500`). QEMU TCG softfloat is
IEEE-754 conformant for basic operations, so the software-stack result stands.

**In scope:** the aarch64 software stack. **Out of scope:** aarch64 silicon, hardware FPCR defaults,
hardware errata. Do not describe this as having been run on aarch64 hardware.

## Reproduce

```sh
# Probe 1 / 2 -- libm sweep (swap python:3.12-slim for python:3.12-alpine for the musl control)
for P in arm64 amd64; do
  docker run --rm --platform linux/$P python:3.12-slim python3 -c '
import math,struct
def b(x): return struct.pack(">d",x).hex()
o=[]
for i in range(20000):
    o.append("log %d %s"%(i,b(math.log(1.0+i*1e-7))))
    o.append("cos %d %s"%(i,b(math.cos(i*1e-5))))
    o.append("exp %d %s"%(i,b(math.exp(-i*1e-6))))
print("\n".join(o))' > sweep_$P.txt
done
diff sweep_arm64.txt sweep_amd64.txt

# Probe 3 -- Q16.16 absorption
for P in arm64 amd64; do
  docker run --rm --platform linux/$P python:3.12-slim python3 -c '
import math
Q=1<<16
o=[]
for i in range(1000000):
    x=math.exp(-i*1e-8)*1.7 + math.cos(i*1e-6)
    o.append("%d %d"%(i,int(round(x*Q))))
print("\n".join(o))' > enc_$P.txt
done
diff enc_arm64.txt enc_amd64.txt

# Provenance -- ELF e_machine and host CPU
docker run --rm --platform linux/arm64 python:3.12-slim python3 -c \
  'b=open("/usr/local/bin/python3","rb").read(20); print(hex(b[18]|(b[19]<<8)))'
docker run --rm --platform linux/arm64 python:3.12-slim head -6 /proc/cpuinfo
```
