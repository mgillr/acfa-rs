#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""ACFA scale equivalence, on a big-memory box. SELF-CONTAINED -- paste into a Colab A100 cell.

WHAT THIS CLOSES AND WHY IT NEEDS A BIG BOX.

The 1B-parameter scale run is proven on a laptop: multi-Krum over d=1e9 at n=10 in 238s and
81 MB of peak RSS, against 80 GB if the contributions were materialised. But the claim
"streamed == materialised" is only MEASURED where the materialised path fits -- d <= 5e6 on that
machine -- and INFERRED at 1e9 from chunk-invariance.

Chunk-invariance is strong evidence and it is not the same statement. It shows every chunking
agrees with every other chunking; it does not, by itself, show they agree with the single-pass
computation the rest of the codebase performs. On a box with real memory that gap is simply
measurable, and this script measures it.

WHAT IT DOES
  For each d it can afford, it computes the pairwise squared-distance matrix TWICE:
    MATERIALISED -- every contribution resident, one accumulation per pair, as multi_krum does
    STREAMED     -- d walked in chunks, partial sums accumulated, as scale_1b.rs does
  and asserts the two are bit-identical. It also runs the FLOAT control, which must DIFFER --
  a run where the float control also matches proves nothing, because it means the inputs were
  too benign to discriminate.

HONEST LIMIT: this is a Python re-implementation of the same arithmetic, not the Rust binary.
It tests the CLAIM (chunked exact-integer accumulation is bit-identical to single-pass) at a size
the laptop cannot reach. Reproducing the Rust binary's own digests at that size needs the Rust
toolchain on the same box; see the note at the end.
"""
import json
import os
import time

import numpy as np

CHUNKS = [1, 3, 97, 65_536, 999_983]           # primes included: must not divide d evenly
SIZES = [1_000_000, 10_000_000, 100_000_000]   # extend upward while memory allows
N = 10


def coord_block(node, start, end):
    """The same seeded PRF the Rust demos use, vectorised. Deterministic across machines."""
    i = np.arange(start, end, dtype=np.uint64)
    x = (np.uint64(node) * np.uint64(0x9E3779B97F4A7C15)) ^ (i * np.uint64(0xBF58476D1CE4E5B9))
    x ^= x >> np.uint64(30)
    x = x * np.uint64(0xBF58476D1CE4E5B9)
    x ^= x >> np.uint64(27)
    return ((x >> np.uint64(40)).astype(np.int64) % 200_000) - 100_000


def dist_materialised(vecs, i, j):
    """One accumulation over the whole coordinate range, in exact Python ints."""
    delta = vecs[i].astype(object) - vecs[j].astype(object)
    return int((delta * delta).sum())


def dist_streamed(node_i, node_j, d, chunk):
    """Partial sums over chunks, exactly as scale_1b.rs accumulates them."""
    acc = 0
    for s in range(0, d, chunk):
        e = min(s + chunk, d)
        a = coord_block(node_i, s, e).astype(object)
        b = coord_block(node_j, s, e).astype(object)
        delta = a - b
        acc += int((delta * delta).sum())
    return acc


def dist_streamed_float(node_i, node_j, d, chunk):
    """The control. If this also matches, the inputs were too benign to discriminate."""
    acc = 0.0
    for s in range(0, d, chunk):
        e = min(s + chunk, d)
        delta = coord_block(node_i, s, e).astype(np.float64) - coord_block(node_j, s, e).astype(np.float64)
        acc += float((delta * delta).sum())
    return acc


def main():
    results = []
    for d in SIZES:
        gb = N * d * 8 / 1e9
        print(f"\n=== d = {d:,}   materialised corpus {gb:.1f} GB ===", flush=True)
        try:
            t0 = time.time()
            vecs = [coord_block(k, 0, d) for k in range(N)]
            truth = dist_materialised(vecs, 0, 1)
            truth_f = float(((vecs[0].astype(np.float64) - vecs[1].astype(np.float64)) ** 2).sum())
            del vecs
            print(f"  materialised done in {time.time()-t0:.1f}s   value {truth}", flush=True)
        except MemoryError:
            print("  MemoryError -- this box cannot materialise this d. Stopping here.")
            break

        row = {"d": d, "corpus_gb": gb, "materialised": str(truth), "chunks": {}}
        for c in CHUNKS:
            if c > d:
                continue
            t0 = time.time()
            got = dist_streamed(0, 1, d, c)
            got_f = dist_streamed_float(0, 1, d, c)
            exact_ok = got == truth
            float_ok = got_f == truth_f
            row["chunks"][str(c)] = {"exact_identical": exact_ok, "float_identical": float_ok}
            print(f"  chunk {c:>9,}  exact_identical={exact_ok!s:<5} "
                  f"float_identical={float_ok!s:<5}  ({time.time()-t0:.1f}s)", flush=True)
            if not exact_ok:
                print("  *** REFUTED: chunked exact-integer accumulation is NOT bit-identical ***")
        discriminating = any(not v["float_identical"] for v in row["chunks"].values())
        row["float_control_discriminates"] = discriminating
        if not discriminating:
            print("  WARNING: the float control matched everywhere -- this d does NOT discriminate,"
                  " so a pass here is weak evidence.")
        results.append(row)

    out = {"host": os.uname().nodename, "n": N, "results": results}
    with open("acfa_scale_equivalence_result.json", "w") as f:
        json.dump(out, f, indent=1)
    print("\nwrote acfa_scale_equivalence_result.json")
    print("Commit it to colab_results/ in the repo so the number carries a coordinate.")
    print("\nTO GO FURTHER ON THIS BOX: install the Rust toolchain, clone acfa-rs, and run")
    print("  cargo run --release -p acfa-aggregate --example scale_1b -- 10 <d> <chunk>")
    print("at two chunk sizes plus the materialised path, which closes the claim in the SHIPPED")
    print("code rather than in this re-implementation.")


if __name__ == "__main__":
    main()
