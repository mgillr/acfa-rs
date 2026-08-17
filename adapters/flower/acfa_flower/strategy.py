# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""ACFA aggregation strategy for Flower."""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional, Sequence, Union

import numpy as np


class Rule(str, Enum):
    """Which robust rule to apply.

    The population bound is the caller's responsibility and is NOT enforced here: a rule
    run below its bound still returns a number, it simply carries no Byzantine guarantee.
    Refusing outright would be worse -- callers would patch the check out -- so
    :meth:`AcfaStrategy.aggregate_fit` reports it in the metrics instead.
    """

    KRUM = "krum"        # needs n >= 2f + 3
    BULYAN = "bulyan"    # needs n >= 4f + 3, defends coordinate-concentrated attacks
    MEDIAN = "median"    # coordinate-wise, trimmed toward the median
    TRIMMED = "trimmed"  # coordinate-wise trimmed mean
    MEAN = "mean"        # NO robustness; present for A/B against FedAvg only

    def required_n(self, f: int) -> int:
        if self is Rule.KRUM:
            return 2 * f + 3
        if self is Rule.BULYAN:
            return 4 * f + 3
        return f + 1


class AcfaAggregationError(RuntimeError):
    """The kernel refused, or could not be run.

    Raised rather than silently falling back to a mean. A silent fallback would turn a
    Byzantine-robust deployment into an unprotected one at exactly the moment something
    unusual happened, which is the worst possible time to lose the property.
    """


def _find_binary(explicit: Optional[str] = None) -> str:
    """Locate the `acfa-agg` kernel binary."""
    for cand in (
        explicit,
        os.environ.get("ACFA_AGG_BIN"),
        shutil.which("acfa-agg"),
    ):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    here = os.path.dirname(os.path.abspath(__file__))
    for rel in (
        "../../../build/layer1-aggregate/target/release/acfa-agg",
        "../../../build/layer1-aggregate/target/debug/acfa-agg",
    ):
        p = os.path.normpath(os.path.join(here, rel))
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    raise AcfaAggregationError(
        "acfa-agg not found. Build it with\n"
        "  cargo build --release --bin acfa-agg\n"
        "in build/layer1-aggregate, or set ACFA_AGG_BIN to its path.\n"
        "There is deliberately no pure-Python fallback: a Python reimplementation would "
        "be a second implementation that could silently disagree, which is the exact "
        "failure the fixed-point kernel exists to remove."
    )


def _bits(x: float) -> str:
    """Exact IEEE-754 big-endian hex. No decimal round-trip, so nothing is lost."""
    return struct.pack(">d", float(x)).hex()


@dataclass(frozen=True)
class _Flat:
    """A client update flattened to one vector, with the shapes needed to rebuild it."""

    values: np.ndarray
    shapes: tuple
    dtypes: tuple


def _flatten(arrays: Sequence[np.ndarray]) -> _Flat:
    return _Flat(
        values=np.concatenate([np.asarray(a, dtype=np.float64).ravel() for a in arrays]),
        shapes=tuple(np.asarray(a).shape for a in arrays),
        dtypes=tuple(np.asarray(a).dtype for a in arrays),
    )


def _unflatten(flat: np.ndarray, shapes: tuple, dtypes: tuple) -> list:
    out, i = [], 0
    for shape, dtype in zip(shapes, dtypes):
        n = int(np.prod(shape)) if shape else 1
        out.append(flat[i : i + n].reshape(shape).astype(dtype))
        i += n
    return out


Q_FRAC_BITS = 16
Q_SCALE = 1 << Q_FRAC_BITS
Q_MAX = (1 << 31) - 1
Q_MIN = -(1 << 31)

#: Refuse when more than this fraction of coordinates quantise to zero. At 50% the majority
#: of the update has been destroyed before the kernel ever sees it; measured Krum/float
#: selection agreement is already below 60% there and falls to 41% by 87% annihilation.
ANNIHILATION_REFUSE_ABOVE = 0.5


def aggregate(
    updates: Iterable[Sequence[np.ndarray]],
    *,
    rule: Rule = Rule.KRUM,
    f: int = 1,
    tie_keys: Optional[Sequence[Union[bytes, str]]] = None,
    beta: tuple = (1, 4),
    binary: Optional[str] = None,
) -> list:
    """Aggregate client updates with the ACFA kernel.

    `tie_keys` are opaque per-client bytes used ONLY to break exact ties. They matter:
    without a stable key, two exactly-tied contributions would be ordered by whichever
    arrived first, and the aggregate would stop being a function of the SET. Pass
    something stable and client-specific -- a client id, or a contribution leaf.
    """
    updates = [list(u) for u in updates]
    if not updates:
        raise AcfaAggregationError("no updates to aggregate")

    flats = [_flatten(u) for u in updates]
    ref = flats[0]
    for i, fl in enumerate(flats[1:], start=1):
        if fl.values.shape != ref.values.shape:
            raise AcfaAggregationError(
                f"client {i} sent {fl.values.size} values, client 0 sent {ref.values.size}; "
                "padding one would let a short update shift the result"
            )

    # adv-02. REFUSE integer dtypes rather than truncating the aggregate to fit them.
    #
    # `_unflatten` casts the result back to each input's ORIGINAL dtype. An aggregate of
    # integer updates is generally fractional, so that cast DISCARDS the fractional part
    # of a value the kernel computed correctly -- the adapter then disagrees with the
    # binary it shells out to, silently. Measured on the unfixed path: MEAN of three 0s
    # and two 1s returned 0 where the float path returned 0.3999939, i.e. the entire
    # aggregate annihilated; Krum returned 11 against 11.5. The cast truncates toward
    # zero, so the error is a systematic BIAS toward zero, not rounding noise, and it is
    # invisible to every caller.
    #
    # Refusing is the standing rule -- a value error must not become an order error --
    # and it is deterministic. Refusing only when the result happens not to be exactly
    # representable would work for months and then reject, which is worse.
    for i, fl in enumerate(flats):
        for dt in fl.dtypes:
            if np.dtype(dt).kind in "iub":
                raise AcfaAggregationError(
                    f"client {i} sent an array of dtype {dt}; integer and boolean dtypes "
                    "are refused because the aggregate is generally fractional and "
                    "casting it back would silently truncate toward zero, disagreeing "
                    "with the kernel that computed it. Convert updates to a float dtype "
                    "before aggregating and quantise afterwards if you need integers."
                )

    if tie_keys is None:
        # CONTENT-DERIVED, NOT POSITIONAL. A positional default (0..n-1 by arrival) makes
        # the tie key a function of ARRIVAL ORDER, so two exactly-tied contributions break
        # in whichever order they happened to arrive and the aggregate stops being a
        # function of the SET -- the precise property this whole stack exists to provide.
        # The bug is invisible until an exact tie occurs, which is why it survived review
        # and was caught only by a constructed mirror-pair probe.
        tie_keys = [
            hashlib.sha256(fl.values.tobytes()).digest() for fl in flats
        ]
    else:
        # Accept str as well as bytes. The documentation says "client ids work" and a
        # Flower client id is a str, so the documented usage went straight into
        # `bytes(key)` and raised "string argument without an encoding" from deep inside
        # the payload builder -- an error that names neither tie keys nor the caller's
        # mistake. Encoding here is also what makes the duplicate check below correct:
        # normalising after it would let "a" and b"a" count as two distinct keys.
        tie_keys = [k.encode() if isinstance(k, str) else k for k in tie_keys]
        for i, k in enumerate(tie_keys):
            if not isinstance(k, (bytes, bytearray)):
                raise AcfaAggregationError(
                    f"tie_keys[{i}] is {type(k).__name__}; pass bytes or str. Tie keys are "
                    "opaque and are never interpreted, but they must be byte-comparable."
                )

    if len(tie_keys) != len(flats):
        raise AcfaAggregationError("tie_keys length does not match the number of updates")
    if len(set(tie_keys)) != len(tie_keys):
        raise AcfaAggregationError(
            "tie keys must be distinct; duplicates leave no total order and the aggregate "
            "would depend on input order. If you are relying on the content-derived "
            "default, two clients submitted BYTE-IDENTICAL updates and are therefore "
            "indistinguishable to it -- pass explicit, stable per-client tie_keys "
            "(a client id works) so the order is a function of identity, not arrival."
        )

    for fl in flats:
        bad = ~np.isfinite(fl.values)
        if bad.any():
            raise AcfaAggregationError(
                f"{int(bad.sum())} non-finite value(s) in an update; NaN and inf have no "
                "fixed-point image and no sensible default"
            )
        scaled = fl.values * Q_SCALE
        if (scaled > Q_MAX).any() or (scaled < Q_MIN).any():
            raise AcfaAggregationError(
                "a value is outside Q16.16 dynamic range (+/-2^15). Saturating would make "
                "the aggregate depend on WHICH replica saturated first; rescale upstream "
                "with a factor both parties already hold."
            )

    # fl-02. MEASURE WHAT THE QUANTISATION DESTROYS, AND REFUSE WHEN IT DESTROYS THE UPDATE.
    #
    # Q16.16 resolves 2^-16 ~= 1.5e-5. A gradient coordinate smaller than that quantises to
    # ZERO -- not rounded, gone. Measured over 200 trials at n=10, d=256, Gaussian updates
    # (probe in the project's research notes):
    #
    #   sigma    coords annihilated    Krum agrees with float
    #   1e-1     0.02%                 100%
    #   1e-2     0.12%                 100%
    #   1e-3     1.2%                  99.5%
    #   1e-4     12.1%                 92.5%
    #   1e-5     87.3%                 41.5%
    #
    # So the format is fit for gradients around 1e-3 and above, and unfit below about 1e-4 --
    # and NOTHING in the stack said so. A user with small gradients got an aggregate computed
    # perfectly from an input that had already been destroyed, with the determinism property
    # fully intact and completely beside the point. Exactness and dynamic range are a trade;
    # this side of it was undocumented.
    #
    # Refusing above a threshold rather than warning, because a mostly-zero update produces a
    # confidently wrong aggregate and the caller has no way to see it. The threshold is
    # deliberately generous: below it the aggregate degrades, above it there is no signal left
    # to aggregate. Rescaling upstream is the fix, and the message says so.
    # Count only coordinates the QUANTISATION destroyed: non-zero in float, zero after.
    # A first version counted every zero, which flagged genuinely-zero coordinates as
    # destroyed and refused a legitimate sparse update -- caught by an existing test that
    # aggregates mostly-zero vectors. The metric has to measure loss, not sparsity.
    annihilated = sum(
        int(((fl.values != 0.0) & (np.trunc(fl.values * Q_SCALE) == 0)).sum())
        for fl in flats
    )
    nonzero = sum(int((fl.values != 0.0).sum()) for fl in flats)
    frac = annihilated / nonzero if nonzero else 0.0
    if frac > ANNIHILATION_REFUSE_ABOVE:
        raise AcfaAggregationError(
            f"{frac:.1%} of NON-ZERO update coordinates are below the Q16.16 resolution "
            f"floor (2^-16 ~= 1.5e-5) and would quantise to zero, so the aggregate would be "
            f"computed from an update that no longer carries the signal. Rescale upstream "
            f"by a factor both parties already hold -- multiplying gradients by a fixed "
            f"power of two is exact and reversible -- or aggregate at a coarser step. "
            f"Refusing rather than returning a confident number over destroyed input."
        )

    lines = [f"rule {rule.value}", f"f {int(f)}"]
    if rule is Rule.TRIMMED:
        lines.append(f"beta {int(beta[0])} {int(beta[1])}")
    for key, fl in zip(tie_keys, flats):
        lines.append(bytes(key).hex() + " " + " ".join(_bits(v) for v in fl.values))
    payload = "\n".join(lines) + "\n"

    proc = subprocess.run(
        [_find_binary(binary)],
        input=payload.encode(),
        capture_output=True,
        check=False,
    )
    out = proc.stdout.decode().strip()
    if proc.returncode == 0 and out.startswith("ok "):
        ints = np.array([int(t) for t in out[3:].split()], dtype=np.int64)
        return _unflatten(ints.astype(np.float64) / Q_SCALE, ref.shapes, ref.dtypes)
    if out.startswith("refused "):
        raise AcfaAggregationError(f"kernel refused: {out[8:]}")
    raise AcfaAggregationError(
        f"kernel failed (exit {proc.returncode}): {proc.stderr.decode().strip() or out}"
    )


try:  # pragma: no cover - exercised only when Flower is installed
    from flwr.common import (
        FitRes,
        Parameters,
        ndarrays_to_parameters,
        parameters_to_ndarrays,
    )
    from flwr.server.client_proxy import ClientProxy
    from flwr.server.strategy import FedAvg

    _HAVE_FLOWER = True
except Exception:  # pragma: no cover
    _HAVE_FLOWER = False
    FedAvg = object  # type: ignore


class AcfaStrategy(FedAvg):  # type: ignore[misc]
    """FedAvg with the aggregation step replaced by the ACFA kernel.

    Everything else -- client sampling, configuration, evaluation -- is inherited
    unchanged, so this is a drop-in swap:

    ```python
    strategy = AcfaStrategy(rule=Rule.KRUM, f=1, min_fit_clients=5)
    ```

    `num_examples` is deliberately IGNORED. FedAvg weights by it, which hands an attacker
    a free amplifier: claim a large `num_examples` and your update dominates, with no way
    for the server to check the claim. A robust rule that then weighted by an unverifiable
    self-report would give the guarantee back with one hand and take it with the other.
    """

    def __init__(
        self,
        *args,
        rule: Rule = Rule.KRUM,
        f: int = 1,
        beta: tuple = (1, 4),
        binary: Optional[str] = None,
        **kwargs,
    ) -> None:
        if not _HAVE_FLOWER:  # pragma: no cover
            raise ImportError("flwr is required for AcfaStrategy; `pip install flwr`")
        super().__init__(*args, **kwargs)
        self.rule = Rule(rule)
        self.f = int(f)
        self.beta = beta
        self.binary = binary

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"AcfaStrategy(rule={self.rule.value}, f={self.f})"

    def aggregate_fit(self, server_round, results, failures):
        if not results:
            return None, {}
        if failures and not self.accept_failures:
            return None, {}

        updates, tie_keys = [], []
        for proxy, fit_res in results:
            updates.append(parameters_to_ndarrays(fit_res.parameters))
            # The client id is stable and client-specific, which is what a tie key must be.
            # NOT the loop index: that would be arrival order and would reintroduce the
            # exact non-determinism the kernel's tie-break exists to remove.
            tie_keys.append(str(proxy.cid).encode())

        aggregated = aggregate(
            updates,
            rule=self.rule,
            f=self.f,
            tie_keys=tie_keys,
            beta=self.beta,
            binary=self.binary,
        )

        n = len(updates)
        need = self.rule.required_n(self.f)
        population_bound_met = n >= need
        metrics = {
            "acfa_rule": self.rule.value,
            "acfa_f": self.f,
            "acfa_n": n,
            "acfa_required_n": need,
            # Surfaced on EVERY round, not only when it fails. A deployment that quietly
            # drops below its bound would otherwise look identical to a healthy one.
            "acfa_population_bound_met": population_bound_met,
        }
        return ndarrays_to_parameters(aggregated), metrics
