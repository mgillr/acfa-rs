# acfa-flower

Byzantine-robust, bit-reproducible aggregation for [Flower](https://flower.ai).

```python
from acfa_flower import AcfaStrategy, Rule

strategy = AcfaStrategy(rule=Rule.KRUM, f=1, min_fit_clients=5)
```

Drop-in for `FedAvg`. Sampling, configuration and evaluation are inherited unchanged. Two
things differ: a minority of adversarial clients cannot drag the aggregate, and the result
is byte-identical on every machine.

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
| `Rule.MEDIAN` | - | coordinate-wise, trimmed toward the median |
| `Rule.TRIMMED` | - | coordinate-wise trimmed mean |
| `Rule.MEAN` | - | no robustness; for A/B against FedAvg |

## Tie keys

Pass stable per-client `tie_keys`, as `str` or `bytes` -- client ids work, and a `str` is
encoded as UTF-8. They break exact score ties and are never interpreted. `AcfaStrategy`
uses the Flower client id automatically, so this only matters when calling `aggregate()`
yourself.

Calling `aggregate()` directly without `tie_keys` derives them from update content, which is
still a function of the set. Two clients sending byte-identical updates are then
indistinguishable and the call refuses rather than guessing an order.

## Resolution, and when this format does not suit your gradients

Q16.16 resolves `2^-16`, about `1.5e-5`. A coordinate smaller than that quantises to **zero**
-- not rounded, gone -- and the aggregate is then computed perfectly from an update that no
longer carries the signal. Measured over 200 trials at n=10, d=256 with Gaussian updates:

| gradient sigma | non-zero coords lost | Krum agrees with float |
|---|---|---|
| 1e-1 | 0.02% | 100% |
| 1e-2 | 0.12% | 100% |
| 1e-3 | 1.2% | 99.5% |
| 1e-4 | 12.1% | 92.5% |
| 1e-5 | 87.3% | 41.5% |

So the format suits gradients around `1e-3` and above, and does not suit them much below
`1e-4`. `aggregate()` refuses rather than returning a confident number when more than half
of the non-zero coordinates would be destroyed.

If your updates are smaller, rescale upstream by a factor both parties already hold --
multiplying by a fixed power of two is exact and reversible -- rather than lowering the
threshold.

## Limits

`n >= 2f+3` is a population bound, not a safety guarantee. See the limitations section of
the [top-level README](https://github.com/mgillr/acfa-rs).
