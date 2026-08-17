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
from acfa_flower.strategy import _find_binary, annihilated_mask  # noqa: E402


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
requires_flwr = pytest.mark.skipif(
    importlib.util.find_spec("flwr") is None, reason="flwr is not installed"
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
