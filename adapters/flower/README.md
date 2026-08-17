# acfa-flower

Byzantine-robust, bit-reproducible aggregation for [Flower](https://flower.ai).

```python
from acfa_flower import AcfaStrategy, Rule

strategy = AcfaStrategy(rule=Rule.KRUM, f=1, min_fit_clients=5)
```

Drop-in for `FedAvg`. Sampling, configuration and evaluation are inherited unchanged. Two
things differ: a minority of adversarial clients cannot drag the aggregate, and the result
is byte-identical on every machine.

**A third thing differs, and it is not a bug -- read "Non-IID data" below before you treat
this as a transparent swap.** A robust rule cannot tell an adversary from a client whose data
simply looks different, because both are far from the majority. On non-IID data that costs
you the minority client's contribution, with no adversary present.

`num_examples` is ignored. FedAvg weights by it, it is an unverifiable self-report, and
weighting a robust rule by it hands back the guarantee.

## Install

The aggregation itself runs in a Rust kernel, so that every caller in every language gets
identical bytes. Build it once:

```sh
# from adapters/flower. The subshell matters: without it the cd persists and the two
# commands below run inside the Rust crate.
( cd ../../build/layer1-aggregate && cargo build --release --bin acfa-agg )
pip install -e ".[dev]"
pytest tests/ -q
```

The package finds the binary automatically, or set `ACFA_AGG_BIN`.

There is deliberately no pure-Python fallback. A second implementation could silently
disagree, which is the failure the fixed-point kernel exists to remove.

## Rules

| Rule | Bound | Notes |
|---|---|---|
| `Rule.KRUM` | `n >= 2f+3` | default |
| `Rule.BULYAN` | `n >= 4f+3` | defends coordinate-concentrated attacks; refuses below the bound |
| `Rule.MEDIAN_TRIMMED` | - | median-**centred trimmed mean** -- see below. `Rule.MEDIAN` is an alias |
| `Rule.TRIMMED` | - | coordinate-wise trimmed mean |
| `Rule.MEAN` | - | no robustness; for A/B against FedAvg |

### `MEDIAN_TRIMMED` is not the coordinate-wise median

It keeps the `max(n - 2f, 1)` values closest to each coordinate's median and **averages
them**. At `n=7, f=1` that averages 5 of 7 values; a median would take 1. It is a
median-centred trimmed mean, not the coordinate-wise median of Yin et al., which is what
selecting a rule called "median" would normally get you.

The gap is not a rounding artefact. Against a true coordinate-wise median, `n=7, f=1,
d=64`, 40 trials per row, Gaussian honest updates:

| honest spread | mean max abs difference | as a fraction of the spread |
|---|---|---|
| 0.01 | 0.00495 | 49.5% |
| 0.10 | 0.05377 | 53.8% |
| 1.00 | 0.50709 | 50.7% |
| 5.00 | 2.68790 | 53.8% |

About **half the honest spread at every scale** -- it grows with heterogeneity rather than
washing out. Federated data is heterogeneous by definition, so this rule diverges from a
median most where you would reach for one, and behaves well in the IID toy case you would
try first.

`MEDIAN_TRIMMED` is the accurate name and is canonical; `Rule.MEDIAN` is kept as an alias,
so the wire value, `Rule("median")` and `Rule.MEDIAN` all still work. Only `.name` and
`repr` change.

## Tie keys

Pass stable per-client `tie_keys`, as `str` or `bytes` -- client ids work, and a `str` is
encoded as UTF-8. They break exact score ties and are never interpreted. `AcfaStrategy`
uses the Flower client id automatically, so this only matters when calling `aggregate()`
yourself.

Calling `aggregate()` directly without `tie_keys` derives them from update content, which is
still a function of the set. Two clients sending byte-identical updates are then
indistinguishable and the call refuses rather than guessing an order.

## Resolution, and when this format does not suit your gradients

Q16.16 has a step of `2^-16`, so it rounds to the nearest multiple of `1.5e-5` and a
coordinate is lost only below **half a step, `7.6e-6`**. Smaller than that and it quantises
to **zero** -- not rounded, gone -- and the aggregate is then computed perfectly from an
update that no longer carries the signal.

Measured at n=10, d=256 with Gaussian updates. The middle column is the fraction genuinely
destroyed; the third is what an earlier version of this table reported, using a whole-step
floor instead of a half-step one, and it is kept so the correction is visible rather than
quietly swapped:

| gradient sigma | non-zero coords lost | previously reported | Krum agrees with float |
|---|---|---|---|
| 1e-1 | 0.01% | 0.01% | 100% |
| 1e-2 | 0.06% | 0.11% | 100% |
| 1e-3 | 0.61% | 1.24% | 99.5% |
| 1e-4 | 6.01% | 12.14% | 92.5% |
| 1e-5 | 55.4% | 87.4% | 41.5% |

The loss column is 60 trials; the agreement column is carried over unchanged from the
200-trial run, because it is measured through the kernel and does not depend on the
predicate that was corrected.

So the format suits gradients around `1e-3` and above, and does not suit them much below
`1e-4`. `aggregate()` refuses rather than returning a confident number when more than half
of the non-zero coordinates would be destroyed -- which is reached near sigma `1.1e-5`.

If your updates are smaller, rescale upstream by a factor both parties already hold --
multiplying by a fixed power of two is exact and reversible -- rather than lowering the
threshold.

## Model size: this path is for small models, and here is where it stops

fl-08. Values cross to the kernel as **hex ASCII over stdin** -- 16 characters plus a
separator per `f64`, against 8 bytes binary. That is a **2.13x wire cost, and it is
structural**: it is arithmetic on the format, not an implementation detail to be tuned away.
Measured at n=10 clients, and the ratio is constant at every size, as it must be:

| parameters | binary | ASCII | wire | Python peak | heap vs binary | ms / 1k params |
|---|---|---|---|---|---|---|
| 1,000 | 80 KB | 171 KB | 2.13x | 1.1 MB | 13.2x | 53.1 |
| 5,000 | 400 KB | 851 KB | 2.13x | 3.4 MB | 8.6x | 44.4 |
| 20,000 | 1.6 MB | 3.4 MB | 2.13x | 12.4 MB | 7.8x | 30.9 |
| 50,000 | 4.0 MB | 8.5 MB | 2.13x | 30.4 MB | 7.6x | 30.9 |

**The heap multiplier is not a constant -- it FALLS with size**, 13.2x down to 7.6x, toward
the structural floor. Quoting a single blow-up figure would mislead in both directions: it is
worse than 7.6x for small models and better than 13x for large ones.

Extrapolating the flat 30.9 ms per 1,000 parameters, at **n=10 clients**:

| model | parameters | per round | peak |
|---|---|---|---|
| ResNet-18 | 11.7M | **~6 minutes** | ~0.7 GB |
| BERT-base | 110M | **~57 minutes** | ~6.7 GB |

**So this integration path suits models up to roughly a hundred thousand parameters, and does
not suit realistic vision or language models.** That is minutes-to-an-hour per round on a
model that is small by current standards, with only ten clients -- and the cost grows with
the client count too. If you are aggregating a real network, the ASCII-over-stdin boundary is
the wrong interface and you want the kernel called directly rather than through this adapter.

This is a property of the INTERFACE, not of the aggregation: the Rust kernel itself is fast,
and the determinism guarantee is unaffected. What you are paying for here is a text boundary
chosen for auditability and cross-language reproducibility.

## Non-IID data: a minority client is excluded, with zero adversaries

fl-06. Every rule here selects by DISTANCE from the other clients. A client whose data is
drawn from a different distribution is far from the majority for the same reason an attacker
is, and the rule cannot distinguish the two -- so it excludes the honest minority. **This is
inherent to distance-based robust aggregation, not a defect in this implementation**, and it
is the cost of the guarantee rather than a bug to be fixed.

Measured with **zero adversaries**: one client drawn from `N(3,1)`, the rest from `N(0,1)`,
50 rounds per row. "Retained" is how much of that client's proportional share of the
aggregate survives. `MEAN` excludes nobody, so it is the control -- it should read ~100%,
and does:

| clients | MEAN | KRUM | MEDIAN_TRIMMED | TRIMMED |
|---|---|---|---|---|
| 10 | 102% | **3%** | 42% | 48% |
| 20 | 103% | **-0%** | 23% | 41% |
| 40 | 98% | **0%** | 32% | 56% |

**KRUM removes the minority client almost entirely at every size**, and the coordinate-wise
rules remove between half and three quarters of it. The effect does not wash out as the
cohort grows.

What this means for you: if your clients are non-IID -- which is the usual reason to run
federated learning at all -- the robust rules will systematically down-weight the clients
whose data differs most, and those are often the ones the model most needs to see. `KRUM` is
the strongest exclusion and `TRIMMED` the mildest, so the choice of rule is also a choice
about how much minority signal you are willing to lose. `MEAN` keeps everything and defends
nothing; that trade is the whole point of the table.

## The aggregate is biased DOWNWARD, and it accumulates

fl-03. The kernel floor-divides when it averages, so every round loses a fraction of an LSB
and **always in the same direction**. Round-to-nearest would cancel over many rounds; floor
does not. The size is `(n-1)/2n` LSB per round -- measured against the closed form at
400 trials per row, and it is the aggregation kernel that is being measured, not a model of
it:

| clients | predicted | measured |
|---|---|---|
| 2 | -0.250 | -0.231 |
| 3 | -0.333 | -0.333 |
| 5 | -0.400 | -0.396 |
| 8 | -0.438 | -0.432 |
| 16 | -0.469 | -0.472 |

**It accumulates linearly over training**, because it never cancels. At `n=5`:

| rounds | drift |
|---|---|
| 100 | 6.1e-4 |
| 600 | 3.7e-3 |
| 5000 | 3.1e-2 |

Against a typical post-clipping gradient scale of `1e-3`, **600 rounds of drift is about 3.7x
one gradient** -- larger than the signal being aggregated, and in one direction. This is not
rounding noise and you should not treat it as such.

**What you can do about it, and it is the same lever as the resolution trade above.** The
bias is a constant number of LSBs, so it is a property of the grid rather than of your data
-- measured at gradient scales `1e-3` through `1.0`, the absolute bias stays at about -0.4
LSB while the relative bias falls from `6.3e-3` to `6.1e-6`. **Scaling your updates up before
aggregation shrinks the bias relative to the signal**, exactly as it lifts coordinates off
the resolution floor.

**What is NOT available**, so nobody proposes it as an easy fix: error feedback (carrying the
discarded remainder into the next round) cancels this completely and is the textbook remedy,
and it is **barred** -- it makes the aggregate a function of the delivery *history*, so two
replicas given the same set in a different order produce different bytes. That is the exact
property this stack exists to provide. Stochastic or dithered rounding is out for the same
reason. Round-half-to-even would be both deterministic and unbiased, but the rounding rule is
a **wire contract**: the vendored reference implementation floors, and changing it costs the
reference pin and an erratum against a published artifact.

## Limits

`n >= 2f+3` is a population bound, not a safety guarantee. See the limitations section of
the [top-level README](https://github.com/mgillr/acfa-rs).
