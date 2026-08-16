# Layer 1 -- load and stress

Every prior number in this project is about **correctness**: byte-identity,
cross-implementation agreement, divergence absorption. None of it says whether the
kernel can be *run* at the sizes a federated deployment implies. A deterministic
aggregate nobody can afford to compute is not a product.

Reproduce with `cargo run --release --example stress`. Add `-- --quick` for a smaller grid
with an identical report shape; the `--` separator is required or cargo consumes the flag.
No CI job runs this: it is a measurement you run yourself, not a gate.
Host: Intel i5-6500, single-threaded, release profile with `overflow-checks = true`.

## Measured scaling

Exponents are **fitted from the measured points** (least squares on log size vs log
time), not asserted from the theory. The predictions come from the structure -- an
`n x n` matrix of `d`-dimensional distances for Krum, and Krum re-run `theta` times on
a shrinking pool for Bulyan.

### In `n` (contributions), `d = 1024`

| n | mean | median_trim | krum | bulyan |
|---|---|---|---|---|
| 8 | 0.0 ms | 0.3 ms | 0.1 ms | 0.6 ms |
| 16 | 0.0 ms | 0.6 ms | 0.5 ms | 3.3 ms |
| 32 | 0.1 ms | 1.0 ms | 2.5 ms | 23.3 ms |
| 64 | 0.1 ms | 2.3 ms | 8.6 ms | 179.4 ms |
| 128 | 0.2 ms | 4.7 ms | 35.8 ms | 1.46 s |
| 256 | 0.5 ms | 10.2 ms | 135.7 ms | **11.55 s** |

**krum 1.974** (predicted 2.000) . **bulyan 2.856** (predicted 3.000)

### In `d` (dimension), `n = 32`

| d | krum | ns / pair-coordinate |
|---|---|---|
| 256 | 0.5 ms | 2.09 |
| 1 024 | 2.1 ms | 2.05 |
| 4 096 | 8.2 ms | 1.95 |
| 16 384 | 38.6 ms | 2.30 |
| 65 536 | 152.7 ms | 2.27 |

**krum 1.021** (predicted 1.000).

The per-pair-coordinate cost sits near 2 ns across a 256x range of `d`, drifting from
2.09 to 2.27 ns at the top end, so there is no cache cliff inside the range but the
constant is not perfectly flat either.

**Every number on this page comes from one run.** Figures from different runs are
never placed in the same table.

## Memory: the `n x n` distance matrix

| n | matrix (i128) |
|---|---|
| 64 | 64 KiB |
| 256 | 1.0 MiB |
| 1 000 | 15.3 MiB |
| 10 000 | 1.5 GiB |
| 100 000 | 149.0 GiB |

The matrix is allocated **in full** before any distance is used, so this is a hard
floor on resident memory, not an average.

## Overflow headroom -- CORRECTED, and the original claim here was wrong

**An earlier revision of this section was wrong and this is the correction.** It read:

> Computed rather than argued: the Q16.16 span is 4 294 967 295, worst per-coordinate
> contribution is span^2 = 1.84e19, so `d` would have to exceed **9.2e18** before the
> i128 accumulator could wrap. [...] Time and memory bite many orders of magnitude first.

**That figure was derived from the Q16.16 *span*, which is only the span if every value
went through `fixed::encode`.** At the time it was written, nothing enforced that on the
`i64` path: `rules::check` validated emptiness, dimension and tie-key uniqueness and no
range, and `wire::decode` accepted any `i64`. So a signed contribution off the wire could
carry values eighteen orders of magnitude outside the assumed span, and the real bound
was `d >= 1`, not `d >= 9.2e18`.

The label is the worst part. "Computed rather than argued" was meant to say *this has
been checked*; it had been **derived under an unstated assumption**, and the label is
exactly what stops the next reader checking it. A calculation that assumes the property
whose absence is the vulnerability is not a bound, it is a restatement of the assumption.

### What was measured, once the assumption was tested

There are **two** accumulators on this path, not one, and the second binds first:

| accumulator | overflows at |
|---|---|
| `sq_dist`, per-coordinate sum of `d^2` | `d >= 1` when `f >= 2` (adversary supplies both `i64::MAX` and `i64::MIN`, overflowing on the *multiply*); `d >= 2` at `f = 1` against a worst-case legal peer at `-2^31`; `d >= 3` against a zero peer |
| the Krum score, summing the `m` smallest distances | **sooner than any of those** — each distance is already up to 1.7e38, so it overflows at `m = 2` and panics where `sq_dist` alone returns `Ok` |

With `overflow-checks = true` (as this crate pins) these panic; without it, which is what
a downstream consumer gets by default, they **wrap silently** and selection proceeds on
garbage.

### Current state

Fixed. The Q16.16 range is now enforced wherever a raw `i64` enters — `rules::check` for
a `Contribution` assembled by any route, and `wire::decode` at the untrusted door — so
values are bounded to `+/-2^31`, `d <= 2^32`, `d^2 <= 2^64`, and the score to `m * 2^64`.
Every accumulator is then unreachable **by construction** rather than by an argument
about realistic inputs. The score sum also carries a `checked_add`, so behaviour cannot
depend on the caller's overflow-checks profile.

The headroom argument in the quoted paragraph is sound *only* under the enforced
invariant. It is now true because the invariant is enforced, not because the arithmetic
was ever the point.

## Projection to deployment shapes

Extrapolated using the **measured** exponents, not the predicted ones -- projecting
with the theory would assume the answer.

| shape | krum | bulyan | matrix |
|---|---|---|---|
| 100 nodes, 1M params | ~24 s | ~15 min | 156 KiB |
| 1000 nodes, 1M params | ~38 min | **~180 h** | 15.3 MiB |
| 1000 nodes, 100M params | ~69 h | **~20 000 h** | 15.3 MiB |

These are printed whatever they say. A harness that stopped at the last size that
finished quickly would report a cliff as an absence.

### These are orders of magnitude, not measurements

Repeat runs of the same projection on the same host give 9 328 h, 16 313 h and 19 523 h:
a **2.1x spread**, while every run prints the `d` exponent as `1.00` to two decimals. A
four-digit hour count from a five-point fit extrapolated across three decades is false
precision, so the figures above are rounded to the order of magnitude they support.

The sensitivity is printed next to the projection by the harness, and it is **not** on
the axis I first probed:

| perturbation | via the `n` exponent | via the `d` exponent |
|---|---|---|
| -0.05 | 0.93x | **0.56x** |
| +0.05 | 1.07x | **1.78x** |

`n` is extrapolated 3.9x (0.6 decades); `d` is extrapolated ~97 700x (5.0 decades). The
same error in the `d` exponent is therefore worth about eleven times more. Probing only
the `n` axis reported the projection as stable -- which is exactly how false precision
survives a sensitivity check.

## What this means

- **Bulyan does not scale past small cohorts.** At 1000 nodes and 100M parameters it
  projects to **years, not hours, for a single round** -- the point is the order of
  magnitude, not the figure. It is the strictly
  stronger defence -- it is the one that resists coordinate-concentrated attacks Krum
  admits -- and it is unaffordable at deployment scale on one core. Anyone selecting
  `rule bulyan` in production needs to know this before they choose it, not after.
- **Krum is borderline and cadence-dependent.** Tens of minutes per round at 1000 nodes
  and 1M parameters is plausible for a daily federated cadence and impossible for an
  interactive one. Days per round at 100M parameters is not viable on one core.
- **Memory bounds the cohort, not the model.** Cost in `n` is quadratic in memory but
  the matrix stays small until ~10 000 nodes; `d` costs nothing in memory. Large models
  are cheap to hold and expensive to compare.

## The obvious lever, and why it is safe here specifically

All of the above is **single-threaded**. The `n x n` pair matrix and the per-coordinate
reduction are both embarrassingly parallel.

What makes parallelising this safe is the property the project already sells:
the aggregate is an **exact integer function of the input set**. Parallel reduction
over i128 sums is associative and exact, so splitting the work cannot change a single
output bit. In a float pipeline the same change would alter the result -- non-associativity
is precisely what makes parallel float reduction non-reproducible.

So determinism is not only the correctness story; it is what makes the performance fix
free of consequences. That is worth stating plainly, because it is the one place where
the property pays for itself twice.

**Not implemented here** -- it is a change to the kernel's execution model and belongs
in its own reviewed change, not smuggled in with a measurement.

## Where it ACTUALLY breaks (escalation, not extrapolation)

Everything above extrapolates from n <= 256. Extrapolation says where a cliff should
be; it cannot say where the process dies. `examples/stress_max.rs` runs ONE (n, d) so a
driver can escalate in a subprocess per size and read the wall off real outcomes.

Escalated with `d = 64` to isolate the MEMORY wall from the time wall (the matrix is
n^2 * 16 bytes, independent of d). Host: 24 GiB, ~10-12 GiB free, load ~6 on 4 cores
because the machine was under other load at the time.

| n | matrix | krum | local exponent |
|---|---|---|---|
| 1 000 | 15 MiB | 0.172 s | |
| 2 000 | 61 MiB | 0.743 s | 2.11 |
| 4 000 | 244 MiB | 2.928 s | 1.98 |
| 8 000 | 976 MiB | 15.298 s | 2.39 |
| 12 000 | 2.1 GiB | 35.007 s | 2.04 |
| 16 000 | 3.8 GiB | 61.740 s | 1.97 |
| 20 000 | 6.0 GiB | 112.336 s | **2.68** |
| 24 000 | 8.6 GiB | 242.308 s | **4.22** |

**NOTHING BROKE.** No refusal, no panic, no kill, up to n = 24 000 with an 8.6 GiB
distance matrix. I stopped there deliberately: the next step (n = 32 000) needs
15.3 GiB against ~12 GiB free, on a host that was busy with other work. That is a
stopping decision, not a measured wall, and it is reported as one.

### The quadratic model is optimistic exactly where it matters

The exponent holds near 2.0 up to n ~ 16 000 and then degrades sharply -- 2.68, then
4.22. Fitted over segments: 2.14 (1k-8k), 2.02 (8k-16k), **3.35 (16k-24k)**.

Consequence for the projections in the previous section, which used `n^1.97` fitted at
n <= 256: **at n = 24 000 that fit predicts 90 s and the measured value is 242 s, 2.69x
more.** The deployment projections are therefore OPTIMISTIC, not conservative, and the
error grows with n.

The likely cause is memory pressure rather than the algorithm -- an 8.6 GiB working set
against ~12 GiB free, with contention from other processes. That makes the top two rows
noisy, and they should not be quoted as clean numbers. But the direction is consistent
and large, and the honest conclusion is the conservative one: **a cost model fitted on
small n understates large n, so treat the earlier projections as lower bounds.**
