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

out = {"source": "reference/acfa.py (kernel released with arXiv:2607.10305, vendored)", "cases": cases}
print(json.dumps(out, separators=(",", ":")))
