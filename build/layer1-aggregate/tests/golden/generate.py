#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Generate cross-implementation golden vectors from the ACFA reference kernel.

The Rust crate's central claim is that an independent implementation computes the
SAME aggregate. That claim is only testable against an actual second implementation,
so these vectors are produced by the published Python reference and committed. If a
Rust change ever diverges, the golden test fails and names the rule.

The reference takes commitment leaf hashes for tie-breaking; we pass the opaque tie
keys in that position, which is exactly the decoupling the Rust layer formalises --
the kernel only ever compares those bytes lexicographically.

WHAT THE `cases` CORPUS CANNOT SEE. Every case is a uniform, in-range, non-empty,
distinctly-keyed rectangle drawn from one LCG, with a beta that always trims. So the
corpus only ever asks the two implementations for an ANSWER, never for a REFUSAL --
and this crate's product is its refusals. Two divergences lived under it (#91, #92):
inputs where the Rust returns a typed `AggError` and the reference computed on them
or crashed. `refusals` below is the section that asks the refusal question.

HOW A REFUSAL IS COMPARED ACROSS THE TWO. The Rust folds its entry gate into every
rule, so `mean(ragged)` is `Err(DimensionMismatch)`. The reference publishes the same
gate as a SEPARATE function, `check(vs, leafs)`, and composes it inside `resolve`.
The vectors therefore compose it the same way -- gate, then rule -- because that is
the reference's own composition, not one invented here. `trimmed_mean` self-gates on
both sides and is compared with no wrapper at all.
"""
import json, os, sys

# The reference kernel lives outside this repo. Its location is an ENV VAR with a
# local default, never a hardcoded path: a generator that only runs on one laptop
# makes the goldens unreproducible, and an unreproducible golden is a number with
# no provenance -- exactly what the cross-impl test exists to rule out.
# The reference kernel is VENDORED at reference/acfa.py, resolved relative to this
# script so the generator works from any working directory. The env var still
# overrides, for checking a rebuilt or patched reference against these vectors.
_VENDORED = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "reference"
)
REF = os.environ.get("ACFA_REFERENCE_DIR", os.path.normpath(_VENDORED))
if not os.path.isfile(os.path.join(REF, "acfa.py")):
    sys.exit(
        f"acfa.py not found under {REF!r}.\n"
        "The vendored copy should be at reference/acfa.py. Set ACFA_REFERENCE_DIR to\n"
        "override it.\n"
        "Failing loudly rather than emitting goldens from an unknown source."
    )
sys.path.insert(0, REF)
import acfa
from acfa import multi_krum_indices, coord_median_trim, trimmed_mean, mean_of

class Lcg:
    """Byte-identical to the Rust Lcg in tests/determinism.rs."""
    def __init__(self, seed): self.s = seed & 0xFFFFFFFFFFFFFFFF
    def next_u64(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.s >> 11
    def next_val(self): return self.next_u64() % 200001 - 100000

def corpus(n, d, seed):
    r = Lcg(seed)
    return [{"tie_key": f"k{i:04}", "v": [r.next_val() for _ in range(d)]} for i in range(n)]

cases = []
for (n, d, f, seed) in [(17,64,3,42),(11,32,2,7),(9,16,1,99),(23,8,5,1234),(7,128,1,5),
                        (12,256,2,777),(31,64,7,2026),(5,32,0,31337),(9,96,1,8080)]:
    cs = corpus(n, d, seed)
    vs = [tuple(c["v"]) for c in cs]
    leafs = [c["tie_key"].encode() for c in cs]
    ci = list(range(d))
    sel = sorted(multi_krum_indices(vs, leafs, f, ci))
    cases.append({
        "n": n, "d": d, "f": f, "seed": seed,
        "contributions": cs,
        "mean": list(mean_of(vs)),
        "trimmed_mean_1_5": list(trimmed_mean(vs, 1, 5)),
        "coord_median_trim": list(coord_median_trim(vs, f)),
        "multi_krum_selected": sel,
        "krum_aggregate": list(mean_of([vs[i] for i in sel])),
    })


# ---------------------------------------------------------------- refusals
# The reference's entry gate is a free function; the Rust folds the same gate into every
# rule. `gated` composes them exactly as the reference's own `resolve` does, so a refusal
# here is the reference's answer, not this script's.
#
# WHAT COUNTS AS A REFUSAL. Only the reference's NAMED refusal class, `AggError`. An
# `IndexError` out of a rule that indexed past a short row is a CRASH, and recording it as
# agreement would be the whole defect: the two implementations do not agree that an input is
# unanswerable just because neither returns a number.
def gated(rule, vs, leafs, **kw):
    """Run the reference's gate and then the rule, reporting refused / value / crash."""
    try:
        acfa.check(vs, leafs)
        return {"refused": False, "error": None, "value": list(rule(vs, **kw))}
    except acfa.AggError as e:
        return {"refused": True, "error": "AggError", "message": str(e), "value": None}
    except Exception as e:                     # noqa: BLE001 -- a crash is a DIFFERENT outcome
        return {"refused": False, "error": type(e).__name__, "value": None}


def ungated(rule, vs, **kw):
    """The rule with no gate in front of it -- for rules that gate themselves."""
    try:
        return {"refused": False, "error": None, "value": list(rule(vs, **kw))}
    except acfa.AggError as e:
        return {"refused": True, "error": "AggError", "message": str(e), "value": None}
    except Exception as e:                     # noqa: BLE001
        return {"refused": False, "error": type(e).__name__, "value": None}


# NOT HERE: Bulyan below `n >= 4f + 3`. The Rust folds that precondition into
# `bulyan_select`, but in the reference it is a guard inside `resolve` and NOT inside
# `bulyan_select`, so comparing the two at this layer would mean writing the precondition
# into this script -- a generator asserting a rule against its own copy of that rule, which
# is the self-corroborating shape these vectors exist to rule out. It is asserted in
# `layer2-receipt/tests/golden/vectors_l2.json` instead, where the reference's own entry
# point applies it and this script only records the answer.


def keys(*names):
    return [n.encode() for n in names]


OUT_OF_RANGE = 1 << 31          # fixed::MAX is 2**31 - 1, so this is the first value over

_ragged = [(1, 2), (1,), (3, 4)]
_oor = [(OUT_OF_RANGE, 0), (1, 1), (2, 2)]
_empty = [(), (), ()]
_trim3 = [(10, 20), (11, 21), (500, -400)]

# `rust_error` is the AggError VARIANT the Rust must return. It is a claim about the Rust,
# written here deliberately: the two implementations name their refusals in different
# vocabularies, and asserting only "something failed" would be satisfied by a rule that
# refused for the wrong reason -- e.g. reporting a dimension mismatch on an out-of-range
# value, which names an innocent contribution.
refusals = [
    {"name": "ragged-dimensions", "issue": 91, "rule": "mean",
     "contributions": [{"tie_key": k.decode(), "v": list(v)}
                       for k, v in zip(keys("k0", "k1", "k2"), _ragged)],
     "rust_error": "DimensionMismatch",
     "reference": gated(mean_of, _ragged, keys("k0", "k1", "k2"))},
    {"name": "value-out-of-q16-16-range", "issue": 91, "rule": "mean",
     "contributions": [{"tie_key": k.decode(), "v": list(v)}
                       for k, v in zip(keys("k0", "k1", "k2"), _oor)],
     "rust_error": "ValueOutOfRange",
     "reference": gated(mean_of, _oor, keys("k0", "k1", "k2"))},
    {"name": "all-empty-vectors", "issue": 91, "rule": "mean",
     "contributions": [{"tie_key": k.decode(), "v": list(v)}
                       for k, v in zip(keys("k0", "k1", "k2"), _empty)],
     "rust_error": "EmptyVectors",
     "reference": gated(mean_of, _empty, keys("k0", "k1", "k2"))},
    {"name": "duplicate-tie-key", "issue": 91, "rule": "mean",
     "contributions": [{"tie_key": k.decode(), "v": list(v)}
                       for k, v in zip(keys("k0", "k0", "k2"), _ragged[:1] * 2 + [(9, 9)])],
     "rust_error": "DuplicateTieKey",
     "reference": gated(mean_of, _ragged[:1] * 2 + [(9, 9)], keys("k0", "k0", "k2"))},
    # adv-05. t = floor(3 * 1 / 5) = 0, so the trim removes NOTHING and the rule labelled
    # "trimmed" would return the plain mean -- including the outlier beta was configured to
    # remove -- at success, with no diagnostic. Both sides must decline.
    {"name": "trimmed-mean-trims-nothing", "issue": 92, "rule": "trimmed_mean",
     "beta_num": 1, "beta_den": 5,
     "contributions": [{"tie_key": f"k{i}", "v": list(v)} for i, v in enumerate(_trim3)],
     "rust_error": "BetaTrimsNothing",
     "reference": ungated(trimmed_mean, _trim3, beta_num=1, beta_den=5)},
    {"name": "trimmed-mean-beta-denominator-zero", "issue": 92, "rule": "trimmed_mean",
     "beta_num": 1, "beta_den": 0,
     "contributions": [{"tie_key": f"k{i}", "v": list(v)} for i, v in enumerate(_trim3)],
     "rust_error": "BetaDenominatorZero",
     "reference": ungated(trimmed_mean, _trim3, beta_num=1, beta_den=0)},
]

# POSITIVE CONTROL. Without it every assertion over `refusals` is satisfied by a kernel that
# refuses everything, and by a reference gate that raises unconditionally. It is the SAME
# rule and the SAME beta as `trimmed-mean-trims-nothing`, at the smallest n where that beta
# trims at all (n = 5 gives t = 1 and 5 > 2), so the two records differ only in the thing
# under test -- and this one must produce a VALUE on both sides.
_trim5 = [(10, 20), (11, 21), (12, 22), (13, 23), (500, -400)]
refusal_control = {
    "name": "trimmed-mean-that-does-trim", "rule": "trimmed_mean",
    "beta_num": 1, "beta_den": 5,
    "contributions": [{"tie_key": f"k{i}", "v": list(v)} for i, v in enumerate(_trim5)],
    "reference": ungated(trimmed_mean, _trim5, beta_num=1, beta_den=5),
}

out = {"source": "reference/acfa.py (kernel released with arXiv:2607.10305, vendored)",
       "cases": cases,
       "refusals": refusals,
       "refusal_control": refusal_control}
print(json.dumps(out, separators=(",", ":")))
