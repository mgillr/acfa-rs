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
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from acfa_flower import AcfaAggregationError, Rule, aggregate  # noqa: E402
from acfa_flower.strategy import _find_binary  # noqa: E402


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


# ---------------------------------------------------------------- flower wiring

flwr = pytest.importorskip("flwr")


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


def test_byte_identical_updates_are_refused_rather_than_ordered_by_arrival():
    """The honest failure mode of a content-derived default, stated explicitly."""
    same = [np.array([1.0, 2.0])]
    with pytest.raises(AcfaAggregationError, match="BYTE-IDENTICAL|distinct"):
        aggregate([same, same, same, same, same], rule=Rule.KRUM, f=1)
