#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Generate Layer 2 cross-implementation golden vectors from the published reference.

WHY THIS EXISTS. The Rust Layer 2 claims to be byte-compatible with the reference
kernel of arXiv:2607.10305. A claim about a SECOND implementation is only testable
against an actual second implementation, so these vectors come from the published
Python and are committed alongside the Rust that must reproduce them.

WHAT IS PINNED. Every value a receipt commits to, at every level:
  * Ed25519 public keys and signatures from fixed 32-byte seeds (RFC 8032 makes
    signing deterministic, so a signature is a reproducible constant, not a nonce).
  * contrib_msg bytes, tensor hashes, contribution leaves, proof leaves.
  * Merkle roots, including the empty sentinel and the odd-length duplication path.
  * The full resolve() output: admitted set, aggregate, output root.

The reference lives OUTSIDE this repo, so its location is an env var with a local
default and a loud failure if absent. A golden nobody can rebuild is a number with no
provenance -- which is exactly what these vectors exist to rule out.
"""
import hashlib
import json
import os
import sys

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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import acfa as A  # noqa: E402


def hx(b: bytes) -> str:
    return b.hex()


def node(i: int) -> A.Node:
    """Deterministic identity: seed = the node id repeated 32 times."""
    return A.Node(node_id=i, sk=Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32))


def contrib(n: A.Node, rnd: int, tensor):
    t = tuple(tensor)
    th = A.H(A.enc_tensor(t))
    return A.Contribution(rnd=rnd, node_id=n.node_id, tensor=t,
                          sig=n.sign(A.contrib_msg(rnd, th)))


def main() -> int:
    out = {"note": "generated from the published ACFA reference; do not hand-edit"}

    # ---- primitives -------------------------------------------------------
    out["enc_tensor"] = [
        {"t": [], "hex": hx(A.enc_tensor(()))},
        {"t": [0], "hex": hx(A.enc_tensor((0,)))},
        {"t": [1, -2, 3], "hex": hx(A.enc_tensor((1, -2, 3)))},
        {"t": [-9223372036854775808, 9223372036854775807],
         "hex": hx(A.enc_tensor((-9223372036854775808, 9223372036854775807)))},
    ]
    out["contrib_msg"] = [
        {"rnd": 0, "th": hx(b"\x00" * 32), "hex": hx(A.contrib_msg(0, b"\x00" * 32))},
        {"rnd": 7, "th": hx(A.H(b"x")), "hex": hx(A.contrib_msg(7, A.H(b"x")))},
        {"rnd": 2**63 - 1, "th": hx(A.H(b"y")),
         "hex": hx(A.contrib_msg(2**63 - 1, A.H(b"y")))},
    ]

    # Merkle: empty sentinel, single, even, odd (the duplication path), and an
    # order-permuted set that must land on the same root.
    ml = [A.H(b"a"), A.H(b"b"), A.H(b"c"), A.H(b"d"), A.H(b"e")]
    out["merkle"] = [
        {"leaves": [], "root": hx(A.merkle_root([]))},
        {"leaves": [hx(ml[0])], "root": hx(A.merkle_root(ml[:1]))},
        {"leaves": [hx(x) for x in ml[:2]], "root": hx(A.merkle_root(ml[:2]))},
        {"leaves": [hx(x) for x in ml[:3]], "root": hx(A.merkle_root(ml[:3]))},
        {"leaves": [hx(x) for x in ml], "root": hx(A.merkle_root(ml))},
        {"leaves": [hx(x) for x in reversed(ml)], "root": hx(A.merkle_root(list(reversed(ml))))},
    ]

    out["prf_ints"] = [
        {"seed": hx(A.H(b"seed")), "purpose": hx(b"purpose"), "n": 12, "bound": 7,
         "out": A.prf_ints(A.H(b"seed"), b"purpose", 12, 7)},
        {"seed": hx(A.H(b"seed")), "purpose": hx(b"other"), "n": 12, "bound": 7,
         "out": A.prf_ints(A.H(b"seed"), b"other", 12, 7)},
    ]

    # ---- identities -------------------------------------------------------
    nodes = [node(i) for i in range(1, 8)]
    pki = {n.node_id: n.pk_bytes for n in nodes}
    out["identities"] = [
        {"node_id": n.node_id, "seed": hx(bytes([n.node_id]) * 32), "pk": hx(n.pk_bytes)}
        for n in nodes
    ]

    # ---- entries ----------------------------------------------------------
    tensors = {
        1: [10, 11, 12], 2: [11, 12, 13], 3: [9, 10, 11],
        4: [12, 13, 14], 5: [10, 12, 11], 6: [500, -400, 300], 7: [-7, -8, -9],
    }
    cs = [contrib(n, 1, tensors[n.node_id]) for n in nodes]
    out["contributions"] = [
        {"rnd": c.rnd, "node_id": c.node_id, "tensor": list(c.tensor),
         "sig": hx(c.sig), "tensor_hash": hx(c.tensor_hash()), "leaf": hx(c.leaf())}
        for c in cs
    ]

    # An equivocation by node 1, and the canonical proof both observers derive.
    alt = contrib(nodes[0], 1, [999, 999, 999])
    (h1, s1), (h2, s2) = sorted([(cs[0].tensor_hash(), cs[0].sig),
                                 (alt.tensor_hash(), alt.sig)])
    proof = A.EquivProof(1, 1, h1, h2, s1, s2)
    out["equivocation"] = {
        "alt": {"rnd": alt.rnd, "node_id": alt.node_id, "tensor": list(alt.tensor),
                "sig": hx(alt.sig), "leaf": hx(alt.leaf())},
        "proof": {"rnd": proof.rnd, "node_id": proof.node_id, "h1": hx(proof.h1),
                  "h2": hx(proof.h2), "sig1": hx(proof.sig1), "sig2": hx(proof.sig2),
                  "leaf": hx(proof.leaf()), "valid": proof.valid(pki)},
    }

    # ---- scenarios --------------------------------------------------------
    def scenario(name, entries, proofs, rnd, f, rule):
        st = A.State()
        for c in entries:
            st.add_contribution(c)
        for p in proofs:
            st.add_proof(p)
        agg, root = A.resolve(st, rnd, pki, f, rule=rule)
        adm = A.admit(st, rnd, pki)
        return {
            "name": name, "rnd": rnd, "f": f, "rule": rule,
            "state_root": hx(st.root()),
            "admitted": [hx(c.leaf()) for c in adm],
            "admitted_ids": [c.node_id for c in adm],
            "aggregate": list(agg) if agg is not None else None,
            "output_root": hx(root),
        }

    # KNOWN DIVERGENCE, DELIBERATE, DO NOT "FIX" BY REGENERATING.
    # The reference's bulyan_select loop is
    #     while len(selected) < theta and len(pool) >= f + 3
    # which draws at most n-f-2 candidates while theta = n-2f. Those differ exactly when
    # f < 2, so at f = 1 the reference silently draws theta-1 for EVERY n (measured: n =
    # 5..15 all under-select by one). f = 1 is the common configuration, so this is not an
    # edge case. The Rust refuses below n >= 4f+3 and otherwise draws exactly theta, which
    # is correct and therefore DIVERGENT from the published reference on this path.
    # Recorded here so the divergence is asserted rather than discovered.
    out["known_divergences"] = [
        {
            "scenario": "all-honest-7-bulyan",
            "reason": "reference bulyan_select under-selects by one when f < 2",
            "reference_draws": 4,
            "theta_demands": 5,
        }
    ]

    out["scenarios"] = [
        scenario("empty", [], [], 1, 1, "krum"),
        scenario("all-honest-7-krum", cs, [], 1, 1, "krum"),
        scenario("all-honest-7-bulyan", cs, [], 1, 1, "bulyan"),
        scenario("equivocator-excluded-by-uniqueness", cs + [alt], [], 1, 1, "krum"),
        scenario("equivocator-convicted-by-proof", cs + [alt], [proof], 1, 1, "krum"),
        scenario("wrong-round-is-empty", cs, [], 2, 1, "krum"),
        scenario("five-of-seven-krum", cs[:5], [], 1, 1, "krum"),
        scenario("three-undefended", cs[:3], [], 1, 1, "krum"),
    ]

    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
