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

    # fl-05. NOT the coordinate-wise median of Yin et al., which is what someone selecting
    # a rule called "median" will believe they are getting. The kernel's `coord_median_trim`
    # keeps the `max(n - 2f, 1)` values CLOSEST TO each coordinate's median and then
    # floor-averages them -- a median-CENTRED TRIMMED MEAN. At n=7, f=1 that averages 5 of
    # 7 values; a median would take 1.
    #
    # The difference is not a rounding artefact. Measured against a true coordinate-wise
    # median, n=7, f=1, d=64, 40 trials per row, Gaussian honest updates:
    #
    #   honest spread    mean max|difference|    as a fraction of the spread
    #   0.01             0.00495                 49.5%
    #   0.10             0.05377                 53.8%
    #   1.00             0.50709                 50.7%
    #   5.00             2.68790                 53.8%
    #
    # It is ~50% of the honest spread at EVERY scale -- it grows with heterogeneity rather
    # than washing out. Federated data is heterogeneous by definition, so the rule labelled
    # "median" diverges most from a median exactly where a practitioner reaches for one, and
    # is well behaved in the IID toy case they would test first. See fl-06, same root cause.
    #
    # MEDIAN_TRIMMED is the accurate name and is canonical. MEDIAN is kept as an ALIAS so no
    # caller breaks: same wire value, `Rule("median")` still resolves, `Rule.MEDIAN` still
    # works. What changes is that `.name` and `repr` now say what the rule does.
    MEDIAN_TRIMMED = "median"
    MEDIAN = "median"    # alias of MEDIAN_TRIMMED, kept for compatibility

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
#: of the update has been destroyed before the kernel ever sees it, and measured Krum/float
#: selection agreement is 41% by the time annihilation reaches 55% (sigma 1e-5).
#: The threshold is unchanged from the first version; what changed is WHERE it bites, since
#: the predicate that feeds it was over-counting by roughly 2x -- see `annihilated_mask`.
ANNIHILATION_REFUSE_ABOVE = 0.5


def annihilated_mask(values: np.ndarray) -> np.ndarray:
    """Which coordinates `fixed::encode` will quantise to zero.

    A NAMED PREDICATE ON PURPOSE. This is a MODEL of the kernel, and the first version
    modelled it wrongly -- np.trunc, the whole-unit floor, where `fixed::encode` is
    `(x * SCALE).round()`, half away from zero. Everything in [7.63e-6, 1.53e-5) was
    reported destroyed and is in fact encoded to +/-1.

    It lives here rather than inline in :func:`aggregate` so a test can bind to THIS
    expression and compare it against the shipped binary. Inlined, the only available test
    was one that re-derived the arithmetic and compared it to the kernel -- which passes
    whatever `aggregate` actually does, and is therefore a check that cannot fail.

    `< 0.5` on the scaled magnitude rather than `np.round(...) == 0`: numpy rounds half to
    even, so it breaks the exact-0.5 tie the opposite way from the kernel.
    """
    return np.abs(values * Q_SCALE) < 0.5


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

    # fl-11. THERE ARE TWO THRESHOLDS ON `f`, NOT ONE, AND ONLY THE FIRST IS DOCUMENTED.
    #
    #   n >= 2f + 3     sound. The population bound in `Rule.required_n`.
    #   f + 3 <= n      the rule STILL SELECTS, with no Byzantine guarantee. This is the
    #                   case the class docstring describes -- "still returns a number, it
    #                   simply carries no Byzantine guarantee" -- and it is left alone.
    #   n < f + 3       `multi_krum` returns EVERY index by its select-all convention, so
    #                   the aggregate is the PLAIN MEAN. The rule did not run at all.
    #
    # The third band is not a weakened guarantee, it is an ABSENT one, and nothing in this
    # adapter said so. Measured at n=7 with six honest values near 1.0 and one adversary at
    # 500.0, where the plain mean is 72.29:
    #
    #   f=1  -> 1.0050    f=2  -> 1.0000    f=3  -> 1.0050    (selects; f=3 is band two)
    #   f=5  -> 72.2900   f=99 -> 72.2900                     (select-all: FedAvg exactly)
    #
    # Refusing here does NOT contradict the docstring's reasoning. That argument -- refuse
    # and callers patch the check out -- is about a REDUCED guarantee, which still does the
    # work asked of it. This is the rule silently not running, which is the one outcome a
    # caller cannot detect and would never choose.
    #
    # KRUM only, measured per rule rather than assumed: BULYAN already refuses below its own
    # bound, MEDIAN_TRIMMED and TRIMMED still exclude the adversary at every f tested (their
    # `keep` floors at 1), and MEAN is documented as carrying no robustness at all.
    if float(f) != int(f):
        raise AcfaAggregationError(
            f"f={f!r} is not an integer. Flooring it would silently change the assumed "
            "adversary count, and f is what every population bound is computed from."
        )
    f = int(f)
    # NOT REFUSED HERE. `test_strategy_reports_bound_unmet_without_failing` constructs
    # exactly this case -- n=3, f=1 -- and asserts it works and reports. That is a deliberate
    # design decision with a test behind it, and the docstring argument (refuse, and callers
    # patch the check out) states a project position that an adapter-level guard should not
    # silently reverse. What was missing was not a refusal but VISIBILITY: band two and
    # band three were reported
    # identically, as `acfa_population_bound_met: False`, and they are not the same event.
    # `AcfaStrategy.aggregate_fit` now distinguishes them. The open question I am NOT
    # deciding: the direct `aggregate()` path has no metrics channel, so on that path band
    # three remains undisclosed at runtime and is documented only here.

    flats = [_flatten(u) for u in updates]
    ref = flats[0]
    for i, fl in enumerate(flats[1:], start=1):
        if fl.values.shape != ref.values.shape:
            raise AcfaAggregationError(
                f"client {i} sent {fl.values.size} values, client 0 sent {ref.values.size}; "
                "padding one would let a short update shift the result"
            )
        # fl-12. THE FLATTENED LENGTH WAS THE ONLY THING COMPARED, AND THE RESULT IS
        # RECONSTRUCTED FROM CLIENT ZERO -- SO THE OUTPUT DEPENDED ON ARRIVAL ORDER.
        #
        # `_unflatten` rebuilds using `ref.shapes` and `ref.dtypes`, and `ref` is `flats[0]`,
        # i.e. whichever client happened to arrive first. Two clients can flatten to the same
        # LENGTH while disagreeing on STRUCTURE or DTYPE, and that passed the check above.
        #
        # MEASURED, same five updates, one client differing, permuted:
        #   structure: [array([1.]), array([2.])] vs [array([1., 2.])]
        #       that client first -> shapes [(1,), (1,)]
        #       that client last  -> shapes [(2,)]
        #   dtype: one float32 client among float64
        #       float32 first -> dtype float32, bytes 0000c03f00002040
        #       float32 last  -> dtype float64, bytes 000000000000f83f0000000000000440
        #
        # THE SAME SET IN A DIFFERENT ORDER PRODUCED DIFFERENT BYTES. That is the exact
        # property this adapter exists to provide, contradicted by the reconstruction step
        # rather than by the aggregation -- the kernel's answer was identical both times.
        # `test_aggregate_is_a_function_of_the_set_not_the_order` cannot see it because every
        # client there shares one structure.
        #
        # Refusing rather than picking a canonical structure: with clients disagreeing there
        # is no principled choice, and any rule for choosing (majority, first, smallest) is a
        # policy the caller should set upstream where the model definition lives.
        if fl.shapes != ref.shapes:
            raise AcfaAggregationError(
                f"client {i} sent parameter shapes {fl.shapes}, client 0 sent {ref.shapes}. "
                "They flatten to the same length, so the aggregate is well defined -- but the "
                "result is rebuilt with client 0's structure, which would make the OUTPUT "
                "SHAPE depend on arrival order. Refusing rather than picking one."
            )
        if fl.dtypes != ref.dtypes:
            raise AcfaAggregationError(
                f"client {i} sent dtypes {tuple(str(d) for d in fl.dtypes)}, client 0 sent "
                f"{tuple(str(d) for d in ref.dtypes)}. The result is cast back to client 0's "
                "dtypes, so a lower-precision client arriving first silently downcasts the "
                "aggregate -- the same set in a different order returns different BYTES."
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
    # THE FLOOR IS HALF A RAW UNIT, NOT A WHOLE ONE. `fixed::encode` is `(x * SCALE).round()`
    # and `f64::round` is HALF AWAY FROM ZERO -- the kernel's own doc calls that "the
    # contract" and warns against composing one. So a coordinate is annihilated iff
    # |x| < 0.5/2^16 = 7.63e-6, NOT |x| < 2^-16 = 1.53e-5. The first version of this guard
    # predicted with np.trunc, which is the whole-unit floor, so everything in
    # [7.63e-6, 1.53e-5) was reported destroyed when the kernel in fact encodes it to +/-1.
    # Confirmed against the shipped binary, not against a model of it: 7.62e-6 -> 0, but
    # 8.0e-6 -> 1, 1.0e-5 -> 1, 1.4e-5 -> 1. The flip is at x*SCALE == 0.5 exactly.
    #
    # Annihilation re-measured with the correct predicate (60 trials, n=10, d=256, Gaussian);
    # the trunc column is kept to show the size of the error, which is roughly a doubling:
    #
    #   sigma    annihilated (round)   was reported (trunc)   Krum agrees with float
    #   1e-1     0.01%                 0.01%                  100%
    #   1e-2     0.06%                 0.11%                  100%
    #   1e-3     0.61%                 1.24%                  99.5%
    #   1e-4     6.01%                 12.14%                 92.5%
    #   1e-5     55.36%                87.36%                 41.5%
    #
    # The agreement column is NOT re-derived here. It is measured through the kernel and does
    # not depend on this predicate, so the fix does not move it. What the fix moves is WHERE
    # the threshold bites: 50% annihilation was being reached near sigma 2.2e-5 and is
    # actually reached near 1.1e-5. The guard now fires where 41% agreement lives rather than
    # where 92% does, which is where it was aimed in the first place.
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
        int(((fl.values != 0.0) & annihilated_mask(fl.values)).sum()) for fl in flats
    )
    nonzero = sum(int((fl.values != 0.0).sum()) for fl in flats)
    frac = annihilated / nonzero if nonzero else 0.0
    if frac > ANNIHILATION_REFUSE_ABOVE:
        raise AcfaAggregationError(
            f"{frac:.1%} of NON-ZERO update coordinates are below the Q16.16 resolution "
            f"floor (half a raw unit, 2^-17 ~= 7.6e-6) and would quantise to zero, so the "
            f"aggregate would be "
            f"computed from an update that no longer carries the signal. Rescale upstream "
            f"by a factor both parties already hold -- multiplying gradients by a fixed "
            f"power of two is exact and reversible -- or aggregate at a coarser step. "
            f"Refusing rather than returning a confident number over destroyed input."
        )

    lines = [f"rule {rule.value}", f"f {int(f)}"]
    if rule is Rule.TRIMMED:
        # fl-10. A BETA THAT CANNOT TRIM SILENTLY TURNS THIS RULE INTO A PLAIN MEAN.
        #
        # The kernel trims `t = min(floor(n * num / den), n)` from each end and trims AT ALL
        # only when `n > 2t`. So there are TWO silent-no-trim regions, one at EACH end, and
        # in both the rule labelled TRIMMED returns exactly the FedAvg mean it exists to
        # replace -- with no error, no warning and no metric.
        #
        # Measured at n=7 against 6 honest values near 1.0 and one adversary at 500.0, where
        # the plain mean is 72.29 and a trimming run gives 1.01:
        #
        #   beta 1/8  -> t=0        n>2t true    72.29   PLAIN MEAN, adversary through
        #   beta 1/4  -> t=1        n>2t true     1.01   trims
        #   beta 1/2  -> t=3        n>2t true     1.01   trims
        #   beta 3/4  -> t=5        n>2t FALSE   72.29   PLAIN MEAN, adversary through
        #   beta 9/4  -> t=7        n>2t FALSE   72.29   PLAIN MEAN, adversary through
        #
        # `beta=(0.5, 4)` reaches the small end by a second route: `int(0.5)` is 0, so a
        # caller asking for a 12.5% trim silently asks for 0/4. Non-integral components are
        # refused rather than floored, because flooring a fraction to zero is precisely how
        # that case became a plain mean.
        #
        # The band is n-DEPENDENT, so this is computed rather than declared: my first guess
        # was that `beta >= 1/2` never trims, and 1/2 trims fine at n=7. The condition is
        # checked exactly as the kernel computes it.
        if len(beta) != 2:
            raise AcfaAggregationError(
                f"beta must be a (numerator, denominator) pair; got {len(beta)} values. "
                "Extra values were previously ignored silently."
            )
        for part, name in zip(beta, ("numerator", "denominator")):
            if float(part) != int(part):
                raise AcfaAggregationError(
                    f"beta {name} {part!r} is not an integer. Truncating it toward zero "
                    "would silently change the trim fraction -- (0.5, 4) becomes (0, 4), "
                    "which trims NOTHING and returns a plain mean with no diagnostic."
                )
        beta_num, beta_den = int(beta[0]), int(beta[1])
        if beta_den > 0:
            n_updates = len(flats)
            t = min((n_updates * beta_num) // beta_den, n_updates)
            if beta_num >= 0 and (t == 0 or n_updates <= 2 * t):
                why = "rounds down to trimming 0 values" if t == 0 else (
                    f"trims {t} from each end of {n_updates}, so nothing is left to keep"
                )
                raise AcfaAggregationError(
                    f"beta {beta_num}/{beta_den} at n={n_updates} {why}, so TRIMMED would "
                    f"return exactly the plain mean -- the aggregate an adversary is trying "
                    f"to move. Refusing rather than silently dropping the robustness. Pick a "
                    f"beta with 1 <= floor(n*num/den) < n/2 (at n={n_updates}: "
                    f"1/{n_updates} up to just under 1/2)."
                )
        lines.append(f"beta {beta_num} {beta_den}")
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

    INHERITED PARAMETERS THAT DO NOT APPLY. `inplace` selects between FedAvg's two
    implementations of `num_examples`-weighted averaging, and this class replaces that step
    entirely, so BOTH settings produce the identical ACFA result. It is accepted and ignored
    because it defaults to `True` -- refusing it would break every default construction --
    and because it is inapplicable rather than dropped: nothing the caller supplied is lost.
    That is the distinction from fl-09, where `fit_metrics_aggregation_fn` carried the
    caller's own data and discarding it lost something. Found by sweeping all 13 FedAvg
    constructor parameters for the accept-store-ignore shape; `inplace` was the only other
    hit, and on measurement it is not one.
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

        # fl-09. CALL THE CALLER'S fit_metrics_aggregation_fn.
        #
        # FedAvg.__init__ STORES it -- it reaches super() through **kwargs -- and this
        # override replaced the method that consumes it. So the constructor accepted the
        # callable, nothing raised, and every client-reported training metric was silently
        # discarded. Constructor accepts, parent stores, override ignores.
        #
        # `evaluate_metrics_aggregation_fn` is NOT affected and never was: aggregate_evaluate
        # is inherited unchanged, so the evaluate side has always worked. fl-09 is the fit
        # side only.
        #
        # num_examples IS passed through here, even though the aggregate deliberately ignores
        # it. Those are different uses. Weighting the MODEL by an unverifiable self-report
        # hands an attacker a free amplifier, which is why the rule refuses to; this is the
        # caller's own callback over the caller's own metrics, and Flower's signature carries
        # the count. Withholding it would silently change the meaning of every metrics
        # function ever written against that signature.
        metrics = {}
        fit_metrics_fn = getattr(self, "fit_metrics_aggregation_fn", None)
        if fit_metrics_fn is not None:
            metrics = dict(
                fit_metrics_fn([(res.num_examples, res.metrics) for _, res in results]) or {}
            )

        n = len(updates)
        need = self.rule.required_n(self.f)
        population_bound_met = n >= need
        # fl-11. BAND TWO AND BAND THREE WERE REPORTED IDENTICALLY AND ARE NOT THE SAME
        # EVENT. `acfa_population_bound_met: False` covered both "the rule selected, with no
        # Byzantine guarantee" and "multi-Krum returned EVERY contribution, so this is the
        # plain mean and no rule ran". An operator watching the first metric cannot tell a
        # degraded round from an undefended one. Measured at n=7: f=3 selects and excludes an
        # adversary at 500.0; f=5 returns 72.29, which is FedAvg exactly.
        selected_all = self.rule is Rule.KRUM and n < self.f + 3
        acfa_metrics = {
            "acfa_rule": self.rule.value,
            "acfa_f": self.f,
            "acfa_n": n,
            "acfa_required_n": need,
            # True means NO ROBUST RULE RAN -- strictly worse than an unmet bound.
            "acfa_rule_selected_all": selected_all,
            # Surfaced on EVERY round, not only when it fails. A deployment that quietly
            # drops below its bound would otherwise look identical to a healthy one.
            "acfa_population_bound_met": population_bound_met,
        }

        # `acfa_` is a RESERVED PREFIX and a collision is refused rather than resolved.
        # Overwriting the caller's key would be the same silent-drop defect this fix exists
        # to remove, and overwriting ours would let a client's self-reported metric forge
        # `acfa_population_bound_met` -- the one field that tells an operator the Byzantine
        # guarantee is live. Refusing is deterministic: it fires on the first round rather
        # than the first round where the values happen to differ.
        clash = sorted(set(metrics) & set(acfa_metrics))
        if clash:
            raise AcfaAggregationError(
                f"fit_metrics_aggregation_fn returned reserved key(s) {clash}; `acfa_` is "
                "reserved for this strategy's own diagnostics. Rename the metric -- "
                "silently overwriting either side would hide one of them."
            )
        metrics.update(acfa_metrics)
        return ndarrays_to_parameters(aggregated), metrics
