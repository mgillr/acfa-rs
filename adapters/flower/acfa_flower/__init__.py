# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""ACFA aggregation for Flower.

Drops the deterministic, Byzantine-robust ACFA kernel into a Flower deployment in place
of FedAvg's weighted mean.

Two things this changes, and the second is the one that is hard to get elsewhere:

1. **Byzantine robustness.** Multi-Krum, Bulyan, coordinate median and trimmed mean
   select or trim rather than average, so a minority of adversarial updates cannot drag
   the aggregate.

2. **Bit-exact reproducibility.** The aggregate is computed in integer fixed point by the
   Rust kernel, so it is byte-identical on every machine. Float aggregation is not: the
   same updates summed in a different order give different bytes, and two honest servers
   then disagree. Without an aggregate that re-executes exactly, no downstream party can
   prove *which* participant misbehaved -- attribution needs re-execution.
"""

from .strategy import AcfaStrategy, AcfaAggregationError, Rule, aggregate

__all__ = ["AcfaStrategy", "AcfaAggregationError", "Rule", "aggregate"]
