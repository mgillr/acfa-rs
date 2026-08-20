# Architecture coverage

The central claim is that the aggregate and the receipt are byte-identical on every target.
This is where that is tested.

## Enforced on every push

CI blocks any push where these fail to produce an identical receipt fingerprint. The
fingerprint covers five receipt scenarios end to end: wire bytes, wire SHA-256, state root,
output root, aggregate, admitted set, convicted set.

| Target | Bits | Endian | How |
|---|---|---|---|
| x86_64 Linux | 64 | little | hosted runner, real hardware |
| aarch64 Linux | 64 | little | hosted runner, real hardware |
| aarch64 macOS (Apple Silicon) | 64 | little | hosted runner, real hardware |
| x86_64 Windows | 64 | little | hosted runner, real hardware |
| i386 | **32** | little | QEMU, `rust:1-slim-bookworm` |
| armv7 | **32** | little | QEMU, `rust:1-slim-bookworm` |
| ppc64le | 64 | little | QEMU, `rust:1-slim-bookworm` |
| s390x | 64 | **big** | QEMU, `s390x/rust:slim` |

Four hosted targets run on real silicon. The other four cover what no hosted runner offers:
32-bit pointer width, and a big-endian machine.

## The big-endian result

The case most likely to break byte-identity is a machine that lays out integers the other
way round. Measured directly, x86_64 little-endian against s390x big-endian, over the full
five-scenario fingerprint:

```
x86_64   sha256 4664c321388267507c825b8e1b5ef6c2c082879bb871d2c0fff557d514b2fedf
s390x    sha256 4664c321388267507c825b8e1b5ef6c2c082879bb871d2c0fff557d514b2fedf
```

Identical. Per-scenario wire digests, the same on both:

```
krum-5-honest         39de77f583331f498460c849927c3740a6208525fcc7f65cfeeeef39352602dd
krum-5-equivocation   7ac5087c089ae154eb238aab3639278b62d7870b3ab28efed1529c9e1fbec209
bulyan-7-honest       e5d336abb0406730ae6049f7e4a094fc8e6038a1e8a3c8e8125eb9f35d6042e7
krum-7-equivocation   2fb759345fae728b607ce373b5dc1b82933bd872477a86aaa9485a7cff821552
krum-3-undefended     05e4909007812d9395eea78ec8c76b9077bce93855f782c091588ce35a686d6c
```

Both were measured directly, not inferred: `linux/amd64` and `linux/s390x` under QEMU,
same commit, same command. The value is the SHA-256 of the comparable fingerprint, the
digest output with the three context lines removed.

Reproduce it:

```sh
cd build/layer2-receipt
cargo run -q --release --example digest | grep -v -E '^(arch|pointer-width|endian) ' > local.txt

docker run --rm --platform linux/s390x -v "$PWD/../..":/w -w /w s390x/rust:slim \
  bash -c 'cd build/layer2-receipt && cargo run -q --release --example digest' \
  | grep -v -E '^(arch|pointer-width|endian) ' > s390x.txt

diff local.txt s390x.txt
```

The three context lines are stripped because architecture, pointer width and endianness are
*expected* to differ. Everything else must not.

## Why this is the load-bearing test

Order invariance within one implementation proves that implementation agrees with itself. It
says nothing about a second machine. Two honest replicas that disagree are indistinguishable
from one replica misbehaving, so attribution needs byte-identity first, and byte-identity is
only a claim once it has been tested somewhere the layout genuinely differs.

## Choosing images, if you extend the matrix

`rust:1-slim-bookworm` publishes manifests for `386`, `amd64`, `arm/v7`, `arm64` and
`ppc64le`. It does **not** publish `s390x`. Pointing the matrix at it for big-endian fails
with `no matching manifest`, which is a job failure that looks nothing like a test failure
and is easy to misread as a divergence. Big-endian uses the architecture-specific
`s390x/rust:slim` instead, and the image is an explicit matrix field for that reason.

`riscv64` runs under QEMU locally but has no official Rust image; it is not in the matrix.

## What is not covered

- Real 32-bit or big-endian **silicon**. Those four rows are emulation: the target compiler
  backend, data model and software stack are exercised, the hardware is not. The four hosted
  rows cover real hardware, all of it 64-bit little-endian.
- Hardware floating-point mode differences (FPCR defaults, errata) on the emulated rows. The
  kernel is integer-only, so this is out of scope by construction rather than by luck, but it
  is untested on those targets.
