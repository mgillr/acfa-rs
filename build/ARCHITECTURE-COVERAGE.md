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
x86_64   sha256 701a05a332a539697b5415c6d35ca70ca327992a09a80e5c628081b3f890c287
s390x    sha256 701a05a332a539697b5415c6d35ca70ca327992a09a80e5c628081b3f890c287
```

Identical. Per-scenario wire digests, the same on both:

```
krum-5-honest         fc9d36d26cfb3203a7aee4e92b1a8bf0649351116c8a610475084f308e44504f
krum-5-equivocation   08fc61d1d781a6e5e63478510e9c028b0ba817c34c1e13f397fd94082afc45ce
bulyan-7-honest       5179712bd7baa601ada5fa3faccfbef47fb48f2605d8c8b758e308b1434726d7
krum-7-equivocation   6a092b7263eebcfe72005ff24aa8b2d956e6f215d6811261f9f0db069e3cec95
krum-3-undefended     c3d59e63be0fbc36ca92b5882c6387ea1ed271ef213a4540190b70cd9ed996ce
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
