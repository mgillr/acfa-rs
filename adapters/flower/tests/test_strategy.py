# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Tests for the ACFA Flower adapter.

The two that matter are `test_a_byzantine_client_cannot_move_the_aggregate` -- the
property the adapter exists to provide -- and `test_aggregate_is_a_function_of_the_set`,
which is the determinism claim at the adapter level rather than in the kernel.
"""

import struct
import subprocess
import sys
from pathlib import Path

import numpy as np
import importlib.util

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from acfa_flower import AcfaAggregationError, Rule, aggregate  # noqa: E402
from acfa_flower.strategy import (  # noqa: E402
    _find_binary,
    annihilated_mask,
    output_dtype_holds_q16_16,
)


def upd(*vals):
    """One client update: two small arrays, so flatten/unflatten is exercised."""
    a = np.array(vals[:2], dtype=np.float64)
    b = np.array([list(vals[2:4])], dtype=np.float64)
    return [a, b]


def honest_set():
    return [
        upd(1.00, 2.00, 3.00, 4.00),
        upd(1.01, 2.01, 3.01, 4.01),
        upd(0.99, 1.99, 2.99, 3.99),
        upd(1.02, 2.02, 3.02, 4.02),
        upd(0.98, 1.98, 2.98, 3.98),
    ]


def test_the_kernel_binary_is_present():
    assert Path(_find_binary()).is_file()


def test_shapes_and_dtypes_are_preserved():
    out = aggregate(honest_set(), rule=Rule.KRUM, f=1)
    assert len(out) == 2
    assert out[0].shape == (2,)
    assert out[1].shape == (1, 2)


def test_an_honest_aggregate_lands_among_the_honest_updates():
    out = aggregate(honest_set(), rule=Rule.KRUM, f=1)
    flat = np.concatenate([o.ravel() for o in out])
    assert np.allclose(flat, [1.0, 2.0, 3.0, 4.0], atol=0.05)


def test_a_byzantine_client_cannot_move_the_aggregate():
    """THE PROPERTY THE ADAPTER EXISTS FOR.

    One client sends a wildly out-of-distribution update. FedAvg's mean would be dragged
    by roughly attacker/n; multi-Krum must select it out entirely.
    """
    honest = honest_set()
    attacked = honest + [upd(500.0, -500.0, 400.0, -400.0)]

    robust = np.concatenate(
        [o.ravel() for o in aggregate(attacked, rule=Rule.KRUM, f=1)]
    )
    plain_mean = np.concatenate(
        [o.ravel() for o in aggregate(attacked, rule=Rule.MEAN, f=1)]
    )

    assert np.allclose(robust, [1.0, 2.0, 3.0, 4.0], atol=0.05), robust
    # And confirm the attack WOULD have worked without the robust rule, so the test is
    # not passing because the attack was too weak to matter.
    assert abs(plain_mean[0] - 1.0) > 10.0, plain_mean


def test_bulyan_defends_a_coordinate_concentrated_attack():
    """Krum is Euclidean, so an attacker can stay close overall and push one coordinate.

    Bulyan needs n >= 4f+3, so this runs at n=7, f=1. Below that the kernel REFUSES
    rather than returning an undefended aggregate -- see the next test.
    """
    honest = honest_set() + [upd(1.03, 2.03, 3.03, 4.03)]      # n=6 honest
    sneaky = honest + [upd(1.0, 2.0, 3.0, 60.0)]               # n=7 total, f=1
    out = np.concatenate([o.ravel() for o in aggregate(sneaky, rule=Rule.BULYAN, f=1)])
    assert abs(out[3] - 4.0) < 1.0, out


def test_bulyan_refuses_below_its_population_bound():
    """Refusing beats returning a plausible aggregate with no guarantee behind it."""
    sneaky = honest_set() + [upd(1.0, 2.0, 3.0, 60.0)]         # n=6 < 4f+3 = 7
    with pytest.raises(AcfaAggregationError, match="refused|Bulyan"):
        aggregate(sneaky, rule=Rule.BULYAN, f=1)


def test_no_rule_defends_a_within_norm_colluding_adversary():
    """CHARACTERISATION, and it is why `acfa_population_bound_met` is named that way.

    Adversaries that collude at one point NEAR the honest mean stay inside the honest
    spread, get selected, and shift the result. Meeting the population bound does not
    prevent it. This test pins the behaviour rather than claiming it is defended.
    """
    honest = honest_set() + [upd(1.03, 2.03, 3.03, 4.03)]
    # two colluding adversaries just off the honest centroid
    byz = [upd(1.6, 2.6, 3.6, 4.6), upd(1.6, 2.6, 3.6, 4.6)]
    attacked = honest + byz
    # The colluders are byte-identical by design, so they need explicit keys -- a real
    # deployment has per-client identities and would supply them.
    keys = [bytes([i]) for i in range(len(attacked))]
    out = np.concatenate([o.ravel() for o in
                          aggregate(attacked, rule=Rule.KRUM, f=1, tie_keys=keys)])
    clean = np.concatenate([o.ravel() for o in
                            aggregate(honest, rule=Rule.KRUM, f=1, tie_keys=keys[:len(honest)])])
    shift = float(np.max(np.abs(out - clean)))
    assert shift > 0.0, "the colluding pair moved the aggregate; that is the point"


def test_aggregate_is_a_function_of_the_set_not_the_order():
    """Determinism at the adapter level: permuting clients must not move a bit."""
    ups = honest_set()
    keys = [bytes([i]) for i in range(len(ups))]
    a = aggregate(ups, rule=Rule.KRUM, f=1, tie_keys=keys)
    order = [3, 0, 4, 1, 2]
    b = aggregate([ups[i] for i in order], rule=Rule.KRUM, f=1,
                  tie_keys=[keys[i] for i in order])
    for x, y in zip(a, b):
        assert np.array_equal(x, y), (x, y)


def test_repeated_runs_are_bit_identical():
    a = aggregate(honest_set(), rule=Rule.KRUM, f=1)
    b = aggregate(honest_set(), rule=Rule.KRUM, f=1)
    for x, y in zip(a, b):
        assert x.tobytes() == y.tobytes()


def test_floats_cross_the_boundary_as_exact_bits():
    """A value with an awkward decimal expansion must survive exactly."""
    x = 0.1 + 0.2  # 0.30000000000000004
    ups = [[np.array([x])] for _ in range(5)]
    # Byte-identical updates: the content-derived default cannot tell them apart, so
    # explicit per-client keys are required. That is the API working as intended.
    keys = [bytes([i]) for i in range(len(ups))]
    out = aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)[0][0]
    # Q16.16 quantises, but the ERROR must be bounded by the grid, not by a decimal
    # round-trip that could differ between writer and reader.
    assert abs(out - x) <= 1.0 / (1 << 16)


# ---------------------------------------------------------------- refusals

def test_non_finite_values_are_refused():
    ups = honest_set()
    ups[0][0][0] = np.nan
    with pytest.raises(AcfaAggregationError, match="non-finite"):
        aggregate(ups, rule=Rule.KRUM, f=1)


def test_out_of_range_values_are_refused_rather_than_saturated():
    ups = honest_set()
    ups[0][0][0] = 1e9
    with pytest.raises(AcfaAggregationError, match="dynamic range"):
        aggregate(ups, rule=Rule.KRUM, f=1)


def test_mismatched_shapes_are_refused_rather_than_padded():
    ups = honest_set()
    ups[0] = [np.array([1.0]), np.array([[1.0, 2.0]])]
    with pytest.raises(AcfaAggregationError, match="padding one"):
        aggregate(ups, rule=Rule.KRUM, f=1)


def test_duplicate_tie_keys_are_refused():
    ups = honest_set()
    with pytest.raises(AcfaAggregationError, match="distinct"):
        aggregate(ups, rule=Rule.KRUM, f=1, tie_keys=[b"same"] * len(ups))


def test_no_updates_is_refused():
    with pytest.raises(AcfaAggregationError, match="no updates"):
        aggregate([], rule=Rule.KRUM, f=1)


def test_there_is_no_silent_python_fallback(monkeypatch):
    """A fallback would drop robustness exactly when something unusual happened."""
    monkeypatch.setenv("ACFA_AGG_BIN", "/nonexistent/acfa-agg")
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr(
        "acfa_flower.strategy.os.path.isfile", lambda p: False
    )
    with pytest.raises(AcfaAggregationError, match="no pure-Python fallback"):
        aggregate(honest_set(), rule=Rule.KRUM, f=1)


def test_integer_dtypes_are_refused_not_silently_truncated():
    """adv-02 REGRESSION. Reproduced before fixing.

    `_unflatten` casts the aggregate back to each input's ORIGINAL dtype. For integer
    inputs that truncates the fractional part of a result the binary computed
    correctly, so the adapter DISAGREES with the tool it shells out to and says
    nothing. Measured on unfixed code: MEAN of three 0s and two 1s returned 0 on the
    int64 path where the float64 path returned 0.3999939 -- the whole aggregate
    annihilated, and truncation is toward zero so the error is a systematic BIAS, not
    rounding noise. Krum on the same numbers returned 11 against 11.5.

    Per the standing rule, a value error must not become an order error: REFUSE.
    """
    ints = [[np.array([0, 0, 0], dtype=np.int64)]] * 3 + [
        [np.array([1, 1, 1], dtype=np.int64)]
    ] * 2
    keys = [bytes([i]) for i in range(5)]
    with pytest.raises(AcfaAggregationError, match="integer|dtype"):
        aggregate(ints, rule=Rule.MEAN, f=1, tie_keys=keys)


def test_float_inputs_still_aggregate_after_the_dtype_guard():
    """The refusal must not be vacuous: the accepting side has to still accept."""
    flts = [[np.array([0.0, 0.0, 0.0])]] * 3 + [[np.array([1.0, 1.0, 1.0])]] * 2
    keys = [bytes([i]) for i in range(5)]
    out = aggregate(flts, rule=Rule.MEAN, f=1, tie_keys=keys)
    assert abs(float(out[0][0]) - 0.4) < 1e-4, out


# ---------------------------------------------------------------- flower wiring

# Gate ONLY the wiring tests on flwr. A module-level importorskip aborts the whole
# module import, which silently skipped ALL 26 tests -- including the 16 that never
# touch flwr -- in any environment without it. CI installs flwr so this was never a
# CI-integrity problem (pytest exits 5 on "no tests collected", so a missing flwr
# turns CI RED, verified), but it made every local run vacuous.
# The REASON STRING NAMES THE LOST COVERAGE AND THE REMEDY, because a skip is silent by
# design and this suite exits 0 with 13 of 52 tests not run. Those 13 are the only guards
# for fl-09 (three of them) and fl-11 (one), so a validator who clones, runs pytest without
# installing, and reads the green line concludes the guards pass when they never executed --
# and reverting either fix leaves the suite green, so a fails-without-the-fix check cannot
# fire either. `pip install -e ".[dev]"` pulls flwr and is what the README already says; the
# hazard is running pytest WITHOUT the documented install, not a gap in the project.
requires_flwr = pytest.mark.skipif(
    importlib.util.find_spec("flwr") is None,
    reason=(
        "flwr is not installed, so this test DID NOT RUN -- it is not passing. "
        "13 of 52 tests are gated this way, including the only guards for fl-09 and "
        'fl-11. Run `pip install -e ".[dev]"` (the documented install, which pulls flwr) '
        "before treating this suite as coverage."
    ),
)


@requires_flwr
def test_strategy_aggregate_fit_matches_the_direct_call():
    from flwr.common import Code, FitRes, Status, ndarrays_to_parameters, parameters_to_ndarrays

    from acfa_flower import AcfaStrategy

    class Proxy:
        def __init__(self, cid):
            self.cid = cid

    ups = honest_set()
    results = [
        (
            Proxy(f"client-{i}"),
            FitRes(
                status=Status(code=Code.OK, message=""),
                parameters=ndarrays_to_parameters(u),
                num_examples=10,
                metrics={},
            ),
        )
        for i, u in enumerate(ups)
    ]

    strat = AcfaStrategy(rule=Rule.KRUM, f=1)
    params, metrics = strat.aggregate_fit(1, results, [])
    got = parameters_to_ndarrays(params)

    want = aggregate(
        ups, rule=Rule.KRUM, f=1, tie_keys=[f"client-{i}".encode() for i in range(len(ups))]
    )
    for a, b in zip(got, want):
        assert np.array_equal(a, b)

    assert metrics["acfa_population_bound_met"] is True
    assert metrics["acfa_n"] == 5
    assert metrics["acfa_required_n"] == 5


@requires_flwr
def test_strategy_reports_bound_unmet_without_failing():
    """A round below the bound must still work AND must say the bound is unmet."""
    from flwr.common import Code, FitRes, Status, ndarrays_to_parameters

    from acfa_flower import AcfaStrategy

    class Proxy:
        def __init__(self, cid):
            self.cid = cid

    ups = honest_set()[:3]
    results = [
        (
            Proxy(f"c{i}"),
            FitRes(
                status=Status(code=Code.OK, message=""),
                parameters=ndarrays_to_parameters(u),
                num_examples=1,
                metrics={},
            ),
        )
        for i, u in enumerate(ups)
    ]
    strat = AcfaStrategy(rule=Rule.KRUM, f=1)
    params, metrics = strat.aggregate_fit(1, results, [])
    assert params is not None
    assert metrics["acfa_population_bound_met"] is False
    assert metrics["acfa_n"] == 3 and metrics["acfa_required_n"] == 5


@requires_flwr
def test_num_examples_cannot_amplify_a_client():
    """FedAvg weights by num_examples, which is an unverifiable self-report.

    An attacker claiming a huge num_examples must gain nothing here.
    """
    from flwr.common import Code, FitRes, Status, ndarrays_to_parameters, parameters_to_ndarrays

    from acfa_flower import AcfaStrategy

    class Proxy:
        def __init__(self, cid):
            self.cid = cid

    ups = honest_set()

    def run(counts):
        results = [
            (
                Proxy(f"c{i}"),
                FitRes(
                    status=Status(code=Code.OK, message=""),
                    parameters=ndarrays_to_parameters(u),
                    num_examples=c,
                    metrics={},
                ),
            )
            for i, (u, c) in enumerate(zip(ups, counts))
        ]
        p, _ = AcfaStrategy(rule=Rule.KRUM, f=1).aggregate_fit(1, results, [])
        return parameters_to_ndarrays(p)

    even = run([10] * len(ups))
    skewed = run([10, 10, 10, 10, 10_000_000])
    for a, b in zip(even, skewed):
        assert np.array_equal(a, b), "num_examples must not weight the aggregate"


@requires_flwr
def test_the_default_tie_key_is_content_derived_not_positional():
    """REGRESSION (found by adversarial review, reproduced with an exact-tie construction).

    The default used to be the arrival index, which made the tie key a function of ORDER.
    Under an exact score tie that made the aggregate order-dependent -- the one property
    the stack exists to provide. Mirror-pair construction: two updates equidistant from
    the honest cluster have exactly equal Krum scores, so the tie-break decides, and the
    result must not depend on which arrived first.
    """
    a = [np.array([90.0])]
    b = [np.array([110.0])]
    base = [[np.array([0.0])], [np.array([200.0])], [np.array([100.0])]]

    fwd = aggregate(base + [a, b], rule=Rule.KRUM, f=1)
    rev = aggregate(base + [b, a], rule=Rule.KRUM, f=1)
    assert np.array_equal(fwd[0], rev[0]), (
        f"swapping arrival order changed the aggregate: {fwd[0]} vs {rev[0]}"
    )


@requires_flwr
def test_byte_identical_updates_are_refused_rather_than_ordered_by_arrival():
    """The honest failure mode of a content-derived default, stated explicitly."""
    same = [np.array([1.0, 2.0])]
    with pytest.raises(AcfaAggregationError, match="BYTE-IDENTICAL|distinct"):
        aggregate([same, same, same, same, same], rule=Rule.KRUM, f=1)


@requires_flwr
def test_string_tie_keys_are_accepted_and_match_their_bytes():
    """The docs say "client ids work", and a Flower client id is a str.

    Passing str went into bytes(key) and raised "string argument without an encoding"
    from inside the payload builder -- an error naming neither tie keys nor the mistake.
    str and bytes forms of the same key must also produce the SAME aggregate, or the
    result would depend on how the caller happened to spell the key.
    """
    ups = [[np.array([1.0, 2.0])], [np.array([1.0, 2.0])], [np.array([1.5, 2.5])]]
    as_str = aggregate(ups, rule=Rule.MEAN, f=0, tie_keys=["a", "b", "c"])
    as_bytes = aggregate(ups, rule=Rule.MEAN, f=0, tie_keys=[b"a", b"b", b"c"])
    for x, y in zip(as_str, as_bytes):
        assert np.array_equal(x, y)


@requires_flwr
def test_str_and_bytes_spelling_of_one_key_is_a_duplicate():
    """Normalising after the duplicate check would let "a" and b"a" pass as distinct."""
    ups = [[np.array([1.0, 2.0])], [np.array([3.0, 4.0])]]
    with pytest.raises(AcfaAggregationError, match="distinct"):
        aggregate(ups, rule=Rule.MEAN, f=0, tie_keys=["a", b"a"])


@requires_flwr
def test_non_bytes_tie_key_is_refused_by_name():
    ups = [[np.array([1.0, 2.0])], [np.array([3.0, 4.0])]]
    with pytest.raises(AcfaAggregationError, match="tie_keys\\[1\\] is int"):
        aggregate(ups, rule=Rule.MEAN, f=0, tie_keys=[b"a", 7])


# ---------------------------------------------------------------- fl-02


def test_updates_destroyed_by_quantisation_are_refused_not_aggregated():
    """fl-02. Q16.16 steps by 2^-16, so a coordinate is lost below HALF a step, 7.6e-6 --
    quantised to ZERO, not rounded, gone. Measured at n=10, d=256: at sigma=1e-3 only 0.61%
    of coordinates are lost and Krum agrees with float 99.5% of the time; at sigma=1e-5,
    55.4% are lost and agreement falls to 41.5%.

    The determinism property is intact throughout, and completely beside the point: the
    aggregate is computed perfectly from an update that no longer carries the signal. This
    asserts the refusal, and the next test asserts it is not vacuous.
    """
    tiny = [[np.full(64, 1e-7)] for _ in range(5)]
    keys = [bytes([i]) for i in range(5)]
    with pytest.raises(AcfaAggregationError, match="resolution"):
        aggregate(tiny, rule=Rule.MEAN, f=1, tie_keys=keys)


def test_realistic_gradient_scales_still_aggregate():
    """The guard must not be a blunt instrument. At 1e-3 -- an ordinary post-clipping
    gradient scale -- almost nothing is lost and the aggregate must go through."""
    rng = np.random.default_rng(0)
    ups = [[rng.normal(0.0, 1e-3, size=64)] for _ in range(5)]
    keys = [bytes([i]) for i in range(5)]
    out = aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)
    assert out and out[0].shape == (64,)


def test_the_annihilation_predicate_agrees_with_the_kernel_at_the_boundary():
    """fl-02, second pass. The guard PREDICTS what the kernel will destroy, and the first
    version predicted with np.trunc while `fixed::encode` is `(x * SCALE).round()` --
    half away from zero. So the real floor is HALF a raw unit, 7.63e-6, not a whole one.

    This is differential on purpose. Every other test here asserts the guard against the
    same model the guard uses, which is self-consistent and blind: a wrong model passes its
    own tests. This one asks the SHIPPED BINARY what it actually encodes and requires the
    prediction to match, so the model cannot drift from the kernel again without failing.

    FAILS ON THE UNFIXED CODE at the three band values: trunc calls them destroyed and the
    kernel encodes every one of them to +/-1.
    """
    # Straddle x*SCALE == 0.5 exactly, which is where half-away-from-zero flips.
    for x in (5.0e-6, 7.62e-6, 8.0e-6, 1.0e-5, 1.4e-5, 1.6e-5, -1.0e-5):
        # Built here rather than via the adapter, so the guard cannot filter the input
        # before the kernel sees it -- that is the whole point of the comparison.
        bits = struct.pack(">d", float(x)).hex()
        payload = "rule mean\nf 0\n" + "".join(
            bytes([i + 1] * 32).hex() + " " + bits + "\n" for i in range(3)
        )
        proc = subprocess.run(
            [_find_binary()], input=payload.encode(), capture_output=True, check=False
        )
        assert proc.returncode == 0 and proc.stdout.decode().startswith("ok ")
        kernel_destroyed = int(proc.stdout.decode().strip()[3:].split()[0]) == 0
        # THE MODULE's predicate, not a re-derivation of it. Re-deriving the arithmetic
        # here would compare correct arithmetic against the kernel and pass no matter what
        # `aggregate` does -- a check that cannot fail. The first draft of this test did
        # exactly that and passed against the unfixed code.
        predicted = bool(annihilated_mask(np.array([x]))[0])
        assert predicted == kernel_destroyed, (
            f"guard and kernel disagree at x={x:.3e} (x*SCALE={x * (1 << 16):.4f}): "
            f"guard says destroyed={predicted}, kernel says destroyed={kernel_destroyed}"
        )


def test_an_update_inside_the_rounding_band_is_aggregated_not_refused():
    """The consequence of the trunc/round mismatch, stated as behaviour rather than as a
    predicate. Every coordinate here is inside [7.63e-6, 1.53e-5) -- called destroyed by the
    old guard, encoded to +/-1 by the kernel. The old guard reports 100% annihilation and
    raises; the aggregate is in fact perfectly well defined.

    FAILS ON THE UNFIXED CODE with AcfaAggregationError('... resolution floor ...').
    """
    band = [[np.full(64, 1.0e-5)] for _ in range(5)]
    keys = [bytes([i]) for i in range(5)]
    out = aggregate(band, rule=Rule.MEAN, f=1, tie_keys=keys)
    # 1.0e-5 * 65536 = 0.6554 -> rounds to 1 -> decodes to 1/65536.
    assert abs(float(out[0][0]) - 1.0 / (1 << 16)) < 1e-9


def test_a_genuinely_sparse_update_is_not_mistaken_for_a_destroyed_one():
    """The metric counts coordinates the QUANTISATION destroyed, not zeros. A first version
    counted every zero and refused a legitimate sparse update -- sparsity is not loss."""
    sparse = [[np.array([0.0] * 63 + [1.0])] for _ in range(5)]
    keys = [bytes([i]) for i in range(5)]
    out = aggregate(sparse, rule=Rule.MEAN, f=1, tie_keys=keys)
    assert abs(float(out[0][63]) - 1.0) < 1e-3


# ---------------------------------------------------------------- fl-09

def _fit_results(metrics_per_client):
    """n FitRes carrying the honest updates and the given per-client metrics dicts."""
    from flwr.common import Code, FitRes, Status, ndarrays_to_parameters

    class Proxy:
        def __init__(self, cid):
            self.cid = cid

    ups = honest_set()
    return [
        (
            Proxy(f"client-{i}"),
            FitRes(
                status=Status(code=Code.OK, message=""),
                parameters=ndarrays_to_parameters(u),
                num_examples=10 + i,
                metrics=m,
            ),
        )
        for i, (u, m) in enumerate(zip(ups, metrics_per_client))
    ]


@requires_flwr
def test_fit_metrics_aggregation_fn_is_called_not_silently_dropped():
    """fl-09. `FedAvg.__init__` STORES the callable -- it reaches super() through **kwargs --
    and `AcfaStrategy` overrides the method that consumes it. So the constructor accepted a
    metrics aggregator, raised nothing, and every client-reported training metric vanished.
    Constructor accepts, parent stores, override ignores.

    FAILS ON THE UNFIXED CODE: `called` stays empty and `acc` is absent from the metrics.
    """
    from acfa_flower import AcfaStrategy

    called = []

    def agg(pairs):
        called.append(pairs)
        total = sum(n for n, _ in pairs)
        return {"acc": sum(n * m["acc"] for n, m in pairs) / total}

    results = _fit_results([{"acc": float(i)} for i in range(5)])
    strat = AcfaStrategy(rule=Rule.KRUM, f=1, fit_metrics_aggregation_fn=agg)
    _, metrics = strat.aggregate_fit(1, results, [])

    assert called, "fit_metrics_aggregation_fn was never called"
    # Flower's signature is List[Tuple[num_examples, metrics]]; the counts must reach it
    # even though the AGGREGATE ignores them -- weighting the model by a self-report is the
    # amplifier, a caller's own metrics callback is not.
    assert called[0] == [(10 + i, {"acc": float(i)}) for i in range(5)]
    assert abs(metrics["acc"] - sum((10 + i) * i for i in range(5)) / sum(range(10, 15))) < 1e-9
    # ...and the strategy's own diagnostics still survive alongside the caller's.
    assert metrics["acfa_n"] == 5 and metrics["acfa_population_bound_met"] is True


@requires_flwr
def test_no_metrics_fn_still_returns_the_acfa_diagnostics():
    """The fix must not make the diagnostics conditional on a callback being supplied."""
    from acfa_flower import AcfaStrategy

    strat = AcfaStrategy(rule=Rule.KRUM, f=1)
    _, metrics = strat.aggregate_fit(1, _fit_results([{} for _ in range(5)]), [])
    assert metrics["acfa_rule"] == "krum"
    assert metrics["acfa_n"] == 5 and metrics["acfa_required_n"] == 5
    assert metrics["acfa_population_bound_met"] is True


@requires_flwr
def test_a_caller_metric_colliding_with_the_reserved_prefix_is_refused():
    """Merging has to choose, and BOTH silent choices are bad: overwriting the caller's key
    is the same silent drop fl-09 is about, and overwriting ours would let a client's
    self-reported metric forge `acfa_population_bound_met` -- the field that tells an
    operator the Byzantine guarantee is live. So it refuses, deterministically, on round 1.
    """
    from acfa_flower import AcfaStrategy

    strat = AcfaStrategy(
        rule=Rule.KRUM,
        f=1,
        fit_metrics_aggregation_fn=lambda pairs: {"acfa_population_bound_met": True},
    )
    with pytest.raises(AcfaAggregationError, match="reserved key"):
        strat.aggregate_fit(1, _fit_results([{} for _ in range(5)]), [])


# ---------------------------------------------------------------- fl-05

def test_median_is_named_for_what_it_does_and_the_old_name_still_works():
    """fl-05. `Rule.MEDIAN` selected a median-CENTRED TRIMMED MEAN, not the coordinate-wise
    median of Yin et al. The behaviour is a legitimate rule; the identifier was the defect,
    and an identifier is what a practitioner picks a rule by.

    FAILS ON THE UNFIXED CODE: `Rule.MEDIAN.name` was "MEDIAN".

    The rest pins that renaming broke nothing: same wire value, `Rule("median")` still
    resolves, and the alias is the same object.
    """
    assert Rule.MEDIAN_TRIMMED.value == "median"
    assert Rule.MEDIAN is Rule.MEDIAN_TRIMMED
    assert Rule.MEDIAN.name == "MEDIAN_TRIMMED"
    assert Rule("median") is Rule.MEDIAN_TRIMMED
    assert Rule.MEDIAN == "median"


def test_median_trimmed_differs_from_a_true_coordinate_wise_median_by_half_the_spread():
    """CHARACTERISATION, not a guard -- it pins the divergence rather than claiming a fix.

    The kernel keeps the max(n-2f, 1) values closest to each coordinate's median and
    AVERAGES them: at n=7, f=1 that is 5 of 7, where a median takes 1. The gap is ~50% of
    the honest spread and does NOT shrink as the spread shrinks, so it is structural rather
    than numerical. Federated data is heterogeneous by construction, which is exactly the
    wide-spread case.

    The behaviour lives in the kernel's `coord_median_trim`, outside this adapter. This test
    exists so the adapter's documentation of it cannot drift without something failing.
    """
    rng = np.random.default_rng(3)
    for spread in (0.01, 1.0):
        gaps = []
        for _ in range(20):
            ups = [[rng.normal(0.0, spread, 64)] for _ in range(7)]
            keys = [bytes([i]) for i in range(7)]
            got = aggregate(ups, rule=Rule.MEDIAN_TRIMMED, f=1, tie_keys=keys)[0]
            want = np.median(np.array([u[0] for u in ups]), axis=0)
            gaps.append(float(np.max(np.abs(got - want))))
        relative = float(np.mean(gaps)) / spread
        # Wide band: the claim is "about half the spread, at every scale", not a constant.
        assert 0.3 < relative < 0.8, (spread, relative)


@requires_flwr
def test_inplace_is_inapplicable_rather_than_silently_dropped():
    """The FedAvg constructor-parameter sweep flagged `inplace` alongside
    `fit_metrics_aggregation_fn`: consumed by `aggregate_fit`, never referenced here.

    On measurement it is NOT the same defect. Both of FedAvg's `inplace` branches do
    `num_examples`-weighted averaging, and this class replaces that step entirely, so both
    settings must give the IDENTICAL ACFA result. Nothing the caller supplied is lost --
    which is what separates an inapplicable parameter from a dropped one.

    Refusing it was the other candidate fix and would have been wrong: `inplace` defaults
    to True, so refusing True would break every default construction.
    """
    from acfa_flower import AcfaStrategy

    results = _fit_results([{} for _ in range(5)])
    a, _ = AcfaStrategy(rule=Rule.KRUM, f=1, inplace=True).aggregate_fit(1, results, [])
    b, _ = AcfaStrategy(rule=Rule.KRUM, f=1, inplace=False).aggregate_fit(1, results, [])

    from flwr.common import parameters_to_ndarrays

    for x, y in zip(parameters_to_ndarrays(a), parameters_to_ndarrays(b)):
        assert x.tobytes() == y.tobytes()


def test_trimmed_matches_a_standard_symmetric_trimmed_mean():
    """`Rule.TRIMMED` audited against its own name, after fl-05 showed `MEDIAN` did not
    match its. It DOES: with beta=(1,4), t = floor(n/4), the kernel agrees with a standard
    symmetric trimmed mean to within one Q16.16 step at n = 5, 7, 8 and 12.

    A null needs a positive control, so this also asserts the comparison can tell the two
    apart at all: the same rule differs from a PLAIN MEAN by ~0.2-0.3 on the same data.
    Without that, agreement to 1.5e-5 could just mean the probe measures nothing.
    """
    rng = np.random.default_rng(5)
    step = 1.0 / (1 << 16)
    for n in (5, 7, 8, 12):
        t = (n * 1) // 4
        ups = [[rng.normal(0.0, 1.0, 32)] for _ in range(n)]
        keys = [bytes([i]) for i in range(n)]
        got = aggregate(ups, rule=Rule.TRIMMED, f=1, tie_keys=keys)[0]

        col = np.sort(np.array([u[0] for u in ups]), axis=0)
        want = col[t : n - t].mean(axis=0) if n > 2 * t else col.mean(axis=0)
        assert np.max(np.abs(got - want)) <= step, (n, t)

        # Positive control: the probe must be able to see a difference when there is one.
        plain = np.mean([u[0] for u in ups], axis=0)
        assert np.max(np.abs(got - plain)) > 10 * step, (n, "probe cannot discriminate")


# ---------------------------------------------------------------- fl-10

def _outlier_set():
    """Six honest values near 1.0 and one adversary at 500.0, n=7."""
    ups = [[np.array([v])] for v in (1.0, 1.01, 0.99, 1.02, 0.98, 1.03, 500.0)]
    return ups, [bytes([i]) for i in range(7)]


def test_a_beta_that_cannot_trim_is_refused_not_silently_a_plain_mean():
    """fl-10. The kernel trims `t = min(floor(n*num/den), n)` from each end and trims at all
    only when `n > 2t`. So there are TWO silent-no-trim regions, one at EACH end, and in both
    the rule labelled TRIMMED returns exactly the FedAvg mean it exists to replace -- with no
    error, no warning and no metric. At n=7 with one adversary at 500.0 the plain mean is
    72.29 and a trimming run gives 1.01.

    FAILS ON THE UNFIXED CODE: every case below returns 72.29 instead of raising.
    """
    ups, keys = _outlier_set()
    for beta in ((1, 8), (3, 4), (9, 4)):
        with pytest.raises(AcfaAggregationError, match="plain mean"):
            aggregate(ups, rule=Rule.TRIMMED, f=1, tie_keys=keys, beta=beta)


def test_a_non_integral_beta_is_refused_rather_than_floored_to_zero():
    """`int(0.5)` is 0, so `beta=(0.5, 4)` silently asked for a 0/4 trim -- the small-end
    no-trim region reached by a second route. Flooring a caller's fraction to zero is exactly
    how a 12.5% trim request became a plain mean.

    FAILS ON THE UNFIXED CODE: returns 72.29.
    """
    ups, keys = _outlier_set()
    with pytest.raises(AcfaAggregationError, match="not an integer"):
        aggregate(ups, rule=Rule.TRIMMED, f=1, tie_keys=keys, beta=(0.5, 4))


def test_a_beta_of_the_wrong_length_is_refused_rather_than_partly_ignored():
    """`beta[0]` and `beta[1]` were read and anything further dropped in silence.

    FAILS ON THE UNFIXED CODE: aggregates using (1, 4) and ignores the 7.
    """
    ups, keys = _outlier_set()
    with pytest.raises(AcfaAggregationError, match="pair"):
        aggregate(ups, rule=Rule.TRIMMED, f=1, tie_keys=keys, beta=(1, 4, 7))


def test_betas_that_do_trim_are_untouched_by_the_guard():
    """COUNTER-TEST. A guard that protects the product by breaking it is the other failure
    direction, and the trimming band is n-DEPENDENT: my first guess was that beta >= 1/2
    never trims, and 1/2 trims fine at n=7 (t=3, 7 > 6). These must all still work, and must
    still exclude the adversary.
    """
    ups, keys = _outlier_set()
    for beta in ((1, 4), (2, 7), (1, 3), (2, 5), (1, 2)):
        out = float(aggregate(ups, rule=Rule.TRIMMED, f=1, tie_keys=keys, beta=beta)[0][0])
        assert abs(out - 1.0) < 0.5, (beta, out, "adversary was not excluded")


def test_the_probe_can_see_the_failure_it_is_looking_for():
    """POSITIVE CONTROL for the four tests above. They assert "not the plain mean", which is
    worthless unless the plain mean is actually reachable and actually different. MEAN on the
    same data returns 72.29, two orders of magnitude from the honest 1.01.
    """
    ups, keys = _outlier_set()
    plain = float(aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)[0][0])
    assert plain > 50.0, plain


# ---------------------------------------------------------------- fl-11

@requires_flwr
def test_the_select_all_band_is_reported_distinctly_from_an_unmet_bound():
    """fl-11. There are TWO thresholds on f and only one was reported.

      n >= 2f+3   sound; the population bound in `Rule.required_n`
      n >= f+3    the rule STILL SELECTS with no Byzantine guarantee
      n <  f+3    `multi_krum` returns EVERY index, so the result is the PLAIN MEAN and no
                  robust rule ran at all

    Both lower bands reported `acfa_population_bound_met: False` and nothing else, so an
    operator could not tell a DEGRADED round from an UNDEFENDED one. Measured at n=7 with an
    adversary at 500.0: f=3 excludes it, f=5 returns 72.29, which is FedAvg exactly.

    Not refused: `test_strategy_reports_bound_unmet_without_failing` asserts this case works
    and reports, which is a deliberate decision with a test behind it. The fix is visibility.

    FAILS ON THE UNFIXED CODE: `acfa_rule_selected_all` does not exist.
    """
    from acfa_flower import AcfaStrategy

    results = _fit_results([{} for _ in range(5)])
    _, degraded = AcfaStrategy(rule=Rule.KRUM, f=2).aggregate_fit(1, results, [])
    _, undefended = AcfaStrategy(rule=Rule.KRUM, f=4).aggregate_fit(1, results, [])

    # n=5, f=2: below the bound 2f+3=7, but 5 >= f+3=5, so the rule selects.
    assert degraded["acfa_population_bound_met"] is False
    assert degraded["acfa_rule_selected_all"] is False
    # n=5, f=4: 5 < f+3=7, so multi-Krum selects everything -- no rule ran.
    assert undefended["acfa_population_bound_met"] is False
    assert undefended["acfa_rule_selected_all"] is True


def test_krum_between_the_two_thresholds_still_selects_and_is_not_refused():
    """COUNTER-TEST, and it is the one that stops this guard becoming a different bug.

    At n=7, f=3 and f=4 are BELOW the population bound 2f+3 but AT OR ABOVE f+3, so the rule
    genuinely selects and must keep working. The class docstring's argument -- refuse and
    callers patch the check out -- applies to exactly this band, so refusing here would
    contradict a deliberate design decision rather than fix a defect.
    """
    ups, keys = _outlier_set()
    for f in (1, 2, 3, 4):
        out = float(aggregate(ups, rule=Rule.KRUM, f=f, tie_keys=keys)[0][0])
        assert abs(out - 1.0) < 0.5, (f, out, "adversary was not excluded")


def test_the_other_rules_were_measured_not_assumed_at_large_f():
    """The guard is KRUM-only because only KRUM has the select-all convention. Measured per
    rule rather than reasoned: BULYAN refuses below its own bound, and the two coordinate-wise
    rules still exclude the adversary at every f tested because their `keep` floors at 1.

    MEAN is excluded deliberately -- it is documented as carrying no robustness, so returning
    the plain mean is the correct answer for it and not a defect.
    """
    ups, keys = _outlier_set()
    for f in (5, 99):
        with pytest.raises(AcfaAggregationError):
            aggregate(ups, rule=Rule.BULYAN, f=f, tie_keys=keys)
        for rule in (Rule.MEDIAN_TRIMMED, Rule.TRIMMED):
            out = float(aggregate(ups, rule=rule, f=f, tie_keys=keys)[0][0])
            assert abs(out - 1.0) < 0.5, (rule, f, out)


def test_a_non_integral_f_is_refused_rather_than_floored():
    """`int(1.7)` is 1, so a caller's assumed adversary count silently changed -- and f is
    what every population bound is computed from.

    FAILS ON THE UNFIXED CODE: aggregates as though f=1.
    """
    ups, keys = _outlier_set()
    with pytest.raises(AcfaAggregationError, match="not an integer"):
        aggregate(ups, rule=Rule.KRUM, f=1.7, tie_keys=keys)


# ---------------------------------------------------------------- fl-12

def test_a_structural_disagreement_is_refused_not_resolved_by_arrival_order():
    """fl-12. The shape check compared only the FLATTENED length, and `_unflatten` rebuilds
    the result with `flats[0].shapes` -- whichever client arrived first. Two clients can
    flatten to the same length while disagreeing on structure, so the OUTPUT SHAPE depended
    on arrival order.

    FAILS ON THE UNFIXED CODE: both calls succeed and return different structures.
    """
    odd = [np.array([1.0]), np.array([2.0])]      # two 1-element arrays
    same = [np.array([1.0, 2.0])]                 # one 2-element array
    keys = [bytes([i]) for i in range(5)]
    for ups in ([odd, same, same, same, same], [same, same, same, same, odd]):
        with pytest.raises(AcfaAggregationError, match="arrival order"):
            aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)


def test_a_dtype_disagreement_is_refused_because_it_changes_the_output_bytes():
    """The same defect through `ref.dtypes`, and this half is the sharper one: the result is
    cast back to client 0's dtypes, so a float32 client arriving FIRST downcasts the whole
    aggregate. Measured on the unfixed code -- identical set, permuted:

        float32 first -> dtype float32, bytes 0000c03f00002040
        float32 last  -> dtype float64, bytes 000000000000f83f0000000000000440

    Different BYTES from the same SET, which is precisely the property the adapter claims.

    FAILS ON THE UNFIXED CODE: both calls succeed and disagree byte for byte.
    """
    f32 = [np.array([1.5, 2.5], dtype=np.float32)]
    f64 = [np.array([1.5, 2.5], dtype=np.float64)]
    keys = [bytes([i]) for i in range(5)]
    for ups in ([f32, f64, f64, f64, f64], [f64, f64, f64, f64, f32]):
        with pytest.raises(AcfaAggregationError, match="different BYTES"):
            aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)


def test_agreeing_clients_are_untouched_by_the_structural_check():
    """COUNTER-TEST. Multi-array updates with matching structure must still aggregate -- the
    honest case is every client deriving its parameter list from the same model, which is
    exactly what `honest_set()` builds (two arrays, shapes (2,) and (1, 2))."""
    out = aggregate(honest_set(), rule=Rule.KRUM, f=1)
    assert [o.shape for o in out] == [(2,), (1, 2)]
    assert all(o.dtype == np.float64 for o in out)


# ---------------------------------------------------------------- fl-13

def test_a_mismatch_names_the_minority_not_whoever_arrived_second():
    """fl-13. The checks compared everyone against `flats[0]` and named whoever differed
    from it, so an adversary at index 0 was never named and an honest client was -- with the
    adversary's own value reported as the reference the majority failed to match.

    Six honest 4-element updates, one adversarial 2-element update, adversary at each of the
    seven positions. The adversary must be named in ALL seven.

    FAILS ON THE UNFIXED CODE at position 0: names client 1, an honest node.
    """
    honest = [np.array([1.0, 2.0, 3.0, 4.0])]
    adversary = [np.array([1.0, 2.0])]
    keys = [bytes([i]) for i in range(7)]
    for pos in range(7):
        ups = [honest] * 7
        ups[pos] = adversary
        with pytest.raises(AcfaAggregationError) as ei:
            aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)
        assert f"client(s) [{pos}]" in str(ei.value), (pos, str(ei.value))


def test_with_no_strict_plurality_nobody_is_named():
    """Attribution is an accusation, so where there is no honest majority to attribute
    against -- an even split, or n=2 -- it must refuse WITHOUT naming anyone rather than
    guess. The arrival-order rule guessed confidently in both cases.
    """
    a = [np.array([1.0, 2.0, 3.0, 4.0])]
    b = [np.array([1.0, 2.0])]
    keys = [bytes([i]) for i in range(4)]
    for ups in ([a, a, b, b], [a, b]):
        with pytest.raises(AcfaAggregationError, match="no strict plurality"):
            aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys[: len(ups)])


# ---------------------------------------------------------------- coverage gaps

def test_a_tie_keys_length_mismatch_is_refused():
    """Line coverage of the shipped module found this guard PRESENT, REACHABLE and covered
    by NO test. It is reachable -- a hand probe fires it -- but "reachable" and "guarded"
    are different claims, and only the second one survives a refactor.

    FAILS ON THE UNFIXED CODE: without the length check the short list zips silently and
    the extra clients aggregate with no tie key at all.
    """
    ups = [[np.array([1.0, 2.0])] for _ in range(5)]
    for keys in ([bytes([i]) for i in range(3)], [bytes([i]) for i in range(9)]):
        with pytest.raises(AcfaAggregationError, match="tie_keys length"):
            aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)


def test_a_kernel_failure_is_surfaced_not_swallowed():
    """The other uncovered `raise`: the kernel exits non-zero without the `refused ` prefix.
    Driven by pointing the adapter at a binary that is not the kernel, so the failure is
    real rather than monkeypatched -- `false` exits 1 and prints nothing.
    """
    ups = [[np.array([1.0, 2.0])] for _ in range(5)]
    keys = [bytes([i]) for i in range(5)]
    with pytest.raises(AcfaAggregationError, match="kernel failed"):
        aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys, binary="/usr/bin/false")


def test_required_n_is_right_for_every_rule_not_only_krum():
    """`required_n`'s BULYAN and default branches were never executed by the suite, so the
    `acfa_required_n` metric was only ever checked for KRUM. The bounds are the population
    preconditions the metric exists to report."""
    assert Rule.KRUM.required_n(1) == 5 and Rule.KRUM.required_n(2) == 7
    assert Rule.BULYAN.required_n(1) == 7 and Rule.BULYAN.required_n(2) == 11
    for rule in (Rule.MEDIAN_TRIMMED, Rule.MEAN):
        assert rule.required_n(1) == 2, rule
        assert rule.required_n(3) == 4, rule

    # fl-04. TRIMMED was in the loop above asserting f+1, which is the defect: its tolerance
    # is `t = floor(n*num/den)` and depends on BETA, not on f alone. This is my own test from
    # earlier today, written to cover an unexecuted branch, and it pinned the wrong number --
    # covering a branch is not the same as checking it is right.
    assert Rule.TRIMMED.required_n(1, (1, 4)) == 4
    assert Rule.TRIMMED.required_n(3, (1, 4)) == 12
    assert Rule.TRIMMED.required_n(3, (1, 2)) == 7   # a bigger trim needs fewer clients
    assert Rule.TRIMMED.required_n(1) == 4           # default beta, single-argument callers


@requires_flwr
def test_aggregate_fit_returns_nothing_on_no_results_and_on_refused_failures():
    """Both early returns in `aggregate_fit` were unexecuted. They are the paths a real
    deployment hits first -- a round where every client dropped, and a round with failures
    under the default `accept_failures=False`."""
    from acfa_flower import AcfaStrategy

    strat = AcfaStrategy(rule=Rule.KRUM, f=1)
    assert strat.aggregate_fit(1, [], []) == (None, {})

    results = _fit_results([{} for _ in range(5)])
    strat.accept_failures = False
    assert strat.aggregate_fit(1, results, [RuntimeError("a client died")]) == (None, {})


def test_a_policy_refusal_is_not_reported_as_a_kernel_crash():
    """Found by MUTATION, not by reading: neutering the `refused ` branch left the whole
    suite green, so that guard was carrying no test.

    It survived because `test_bulyan_refuses_below_its_population_bound` matches
    `"refused|Bulyan"`, and the FALLBACK message contains "Bulyan" too -- an alternation
    that made the assertion true down either path. A regex with an OR is one of the ways a
    test stops being able to discriminate while still looking specific.

    The two paths are materially different and a caller has to tell them apart:
        guarded  "kernel refused: BulyanTooFewContributions"   -- a policy answer, fix the input
        mutant   "kernel failed (exit 1): acfa-agg: too few..." -- reads as a broken binary
    Same shape as reporting a valid-but-already-settled certificate as Invalid: the caller
    cannot distinguish "your request was declined" from "the thing you called is broken",
    and those need opposite responses.

    FAILS ON THE UNFIXED CODE: the message says "kernel failed".
    """
    ups = [[np.array([1.0, 2.0, 3.0, 4.0])] for _ in range(6)]  # n=6 < 4f+3 = 7
    keys = [bytes([i]) for i in range(6)]
    with pytest.raises(AcfaAggregationError) as ei:
        aggregate(ups, rule=Rule.BULYAN, f=1, tie_keys=keys)
    msg = str(ei.value)
    assert msg.startswith("kernel refused: "), msg
    assert "kernel failed" not in msg, msg


# ---------------------------------------------------------------- fl-14

def test_the_output_dtype_predicate_matches_measured_spacing():
    """fl-14. `_unflatten` casts the aggregate back to the CLIENT's dtype, and above a
    dtype-dependent magnitude that dtype cannot hold a Q16.16 grid value -- so the
    exactness the whole stack exists to provide is discarded on the way OUT, after every
    part engineered to protect it has already succeeded.

    Thresholds are asserted against numpy's own `spacing`, not against numbers typed here,
    so the predicate is checked against the float format rather than against my arithmetic.
    """
    q = 1.0 / (1 << 16)
    for dtype, boundary in ((np.float16, 0.03125), (np.float32, 256.0)):
        assert float(np.spacing(np.asarray(boundary, dtype=dtype))) > q
        assert float(np.spacing(np.asarray(boundary / 2, dtype=dtype))) <= q
        assert output_dtype_holds_q16_16(dtype, boundary / 2) is True
        assert output_dtype_holds_q16_16(dtype, boundary) is False
    # float64 holds it across the whole Q16.16 range, which saturates at +/-32768.
    assert output_dtype_holds_q16_16(np.float64, 32767.0) is True


@requires_flwr
def test_a_float32_round_that_cannot_hold_the_grid_is_reported():
    """The disclosure, on the path that has a channel for it. Reported and NOT refused:
    float32 is the ordinary dtype of federated learning, and the dtype is the caller's
    choice rather than a defect here -- refusing would break every real deployment, which
    is the mistake I made writing fl-11 as a raise.

    FAILS ON THE UNFIXED CODE: `acfa_output_dtype_holds_q16_16` does not exist.
    """
    from flwr.common import Code, FitRes, Status, ndarrays_to_parameters

    from acfa_flower import AcfaStrategy

    class Proxy:
        def __init__(self, cid):
            self.cid = cid

    def results_at(scale, dtype):
        return [
            (
                Proxy(f"c{i}"),
                FitRes(
                    status=Status(code=Code.OK, message=""),
                    parameters=ndarrays_to_parameters(
                        [np.array([scale + i, scale - i], dtype=dtype)]
                    ),
                    num_examples=1,
                    metrics={},
                ),
            )
            for i in range(5)
        ]

    strat = AcfaStrategy(rule=Rule.MEAN, f=1)
    _, small = strat.aggregate_fit(1, results_at(1.0, np.float32), [])
    _, large = strat.aggregate_fit(1, results_at(1000.0, np.float32), [])

    assert small["acfa_output_dtype_holds_q16_16"] is True
    assert large["acfa_output_dtype_holds_q16_16"] is False


def test_the_documented_downward_bias_is_the_measured_one():
    """fl-03. The aggregate is biased DOWNWARD by `(n-1)/2n` LSB per round because the kernel
    floor-divides, and it never cancels, so it accumulates linearly over training.

    This is a CHARACTERISATION test, not a guard: the behaviour is a deliberate wire contract
    (the vendored reference floors) and the two textbook remedies are barred -- error feedback
    and dithering both make the aggregate a function of delivery HISTORY, which is the exact
    property this stack exists to provide. Nothing here is being fixed.

    What it does is stop the adapter README's numbers drifting from the kernel's behaviour
    without something failing. fl-05 and fl-14 both put measured tables in front of users; a
    table nothing re-derives is a claim, not a measurement.
    """
    scale = 1 << 16
    rng = np.random.default_rng(11)
    for n, predicted in ((3, -1 / 3), (5, -0.4)):
        errors = []
        for _ in range(120):
            vals = [float(rng.uniform(-0.5, 0.5)) for _ in range(n)]
            ups = [[np.array([v])] for v in vals]
            keys = [bytes([i]) for i in range(n)]
            got = float(aggregate(ups, rule=Rule.MEAN, f=1, tie_keys=keys)[0][0])
            # Compare against the mean of the ENCODED values, so this measures the DIVISION
            # and not the encoding -- otherwise it would be re-testing fl-02's rounding.
            exact = float(np.mean([round(v * scale) / scale for v in vals]))
            errors.append((got - exact) * scale)
        measured = float(np.mean(errors))
        assert abs(measured - predicted) < 0.1, (n, measured, predicted)
        # Direction is the part that matters: a downward bias accumulates, a symmetric one
        # cancels. Asserted separately so a sign flip cannot hide inside the tolerance.
        assert measured < 0, (n, measured, "the bias must be DOWNWARD")


@requires_flwr
def test_the_bound_goes_red_where_f_adversaries_actually_beat_trimmed():
    """fl-04. `acfa_population_bound_met` reported GREEN in configurations TRIMMED provably
    loses, because `required_n` returned `f + 1` for it -- a number with no relationship to
    the trim. MEASURED with f adversaries at 500.0 among honest 1.0, beta=(1,4):

        n=8  f=3  aggregate 125.8   bound_met was True
        n=12 f=5  aggregate 167.3   bound_met was True
        n=20 f=8  aggregate 150.7   bound_met was True

    The rule survives `t = floor(n*num/den)` adversaries per side and no more, so the bound
    has to be a function of beta. FAILS ON THE UNFIXED CODE: bound_met is True.
    """
    from flwr.common import Code, FitRes, Status, ndarrays_to_parameters

    from acfa_flower import AcfaStrategy

    class Proxy:
        def __init__(self, cid):
            self.cid = cid

    def round_of(n, f):
        vals = [1.0] * (n - f) + [500.0] * f
        return [
            (
                Proxy(f"c{i}"),
                FitRes(
                    status=Status(code=Code.OK, message=""),
                    parameters=ndarrays_to_parameters([np.array([v])]),
                    num_examples=1,
                    metrics={},
                ),
            )
            for i, v in enumerate(vals)
        ]

    for n, f in ((8, 3), (12, 5), (20, 8)):
        strat = AcfaStrategy(rule=Rule.TRIMMED, f=f, beta=(1, 4))
        params, metrics = strat.aggregate_fit(1, round_of(n, f), [])
        from flwr.common import parameters_to_ndarrays

        moved = abs(float(parameters_to_ndarrays(params)[0][0]) - 1.0) > 0.5
        assert moved, (n, f, "fixture must actually defeat the rule, or this proves nothing")
        assert metrics["acfa_population_bound_met"] is False, (n, f, metrics)

    # COUNTER-TEST: a configuration the rule genuinely survives must still report green.
    strat = AcfaStrategy(rule=Rule.TRIMMED, f=1, beta=(1, 4))
    params, metrics = strat.aggregate_fit(1, round_of(8, 1), [])
    assert metrics["acfa_population_bound_met"] is True, metrics


def test_a_minority_distribution_client_is_excluded_with_zero_adversaries():
    """fl-06. Every rule here selects by DISTANCE, so a client whose data is drawn from a
    different distribution is far from the majority for the same reason an attacker is, and
    the rule cannot tell them apart. CHARACTERISATION, not a guard: this is inherent to
    distance-based robust aggregation and is the cost of the guarantee.

    Its job is to stop the README's table drifting from behaviour, and to hold the CONTROL
    that makes the table mean anything: MEAN excludes nobody, so it must retain ~100% of the
    minority's proportional share. Without that row, "KRUM retains 3%" is unfalsifiable --
    my first version of this measurement asked whether the aggregate was "closer to the
    majority", which EVERY rule satisfies including MEAN, and so measured nothing at all.
    """
    rng = np.random.default_rng(11)
    n = 20
    expected_share = 3.0 / n

    def retained(rule):
        vals = []
        for _ in range(30):
            ups = [[rng.normal(3.0, 1.0, 32)]] + [
                [rng.normal(0.0, 1.0, 32)] for _ in range(n - 1)
            ]
            keys = [bytes([i]) for i in range(n)]
            vals.append(float(np.mean(aggregate(ups, rule=rule, f=1, tie_keys=keys)[0])))
        return float(np.mean(vals)) / expected_share

    mean_keeps = retained(Rule.MEAN)
    krum_keeps = retained(Rule.KRUM)

    # THE CONTROL FIRST: if this fails the comparison below is meaningless.
    assert 0.8 < mean_keeps < 1.2, (mean_keeps, "MEAN must keep the minority's whole share")
    # And the finding: KRUM removes essentially all of it, with no adversary present.
    assert krum_keeps < 0.2, (krum_keeps, "KRUM should exclude the minority client")
    assert krum_keeps < mean_keeps / 3, (krum_keeps, mean_keeps)
