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

WHAT THE ORIGINAL SCENARIO SET COULD NOT SEE, and why the sections below exist.
Every `scenarios` entry uses uniform small tensors, genuine keys, distinct leaves,
`add_contribution` rather than `deliver`, and never calls `merge`. So the two
implementations were only ever shown inputs they AGREE on by construction: nine
divergences (#82, #84-#92) lived under a green cross-implementation suite because no
vector instantiated the shape that separates them. Each section added here
instantiates one of those shapes:

  nonce_equivocation   two distinct valid signatures over ONE content   (#84)
  delivery_orders      a three-way equivocator delivered both ways      (#85)
  merge_vs_deliver     the same evidence learned by gossip, not delivery(#86)
  merkle_refusals      a duplicate leaf offered to merkle_root          (#90)
  refusal_scenarios    ragged / out-of-range / empty / Bulyan-too-few   (#91)

A REFUSAL IS A RECORDED OUTCOME, NOT AN OMISSION. Each refusal section records what
the reference ACTUALLY did -- refused, computed, or crashed -- rather than what it
ought to do. When the reference is corrected, regeneration flips that field and the
`golden-is-reproducible` CI job fails until the vectors are committed, so the fix
arrives as a visible diff instead of a silent change of behaviour.
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


# Every golden is generated under a FIXED, NON-ZERO context so the vectors actually exercise
# the ctx bytes. A zero context would let a Rust side that dropped ctx entirely still match.
GOLDEN_CTX = bytes(range(32))
# The round parameters the golden scenarios are signed under. Named, not defaulted: the preimage
# and the leaf both commit to these, so a change here moves every vector.
GOLDEN_PARAMS = A.RoundParams(rule="krum", f=1, frac_bits=A.Q_FRAC_BITS)


def contrib(n: A.Node, rnd: int, tensor):
    t = tuple(tensor)
    th = A.H(A.enc_tensor(t))
    return A.Contribution(ctx=GOLDEN_CTX, params=GOLDEN_PARAMS, rnd=rnd, node_id=n.node_id, tensor=t,
                          sig=n.sign(A.contrib_msg(GOLDEN_CTX, GOLDEN_PARAMS, rnd, n.node_id, th)))


# Two DISTINCT VALID Ed25519 signatures over ONE contrib_msg preimage, produced out-of-tree
# with a chosen-nonce signer. Ed25519 verification checks `S*B == R + H(R,A,M)*A` and NOTHING
# in that equation pins `R`, so the deterministic nonce of RFC 8032 is the signer's discipline
# and never the scheme's guarantee.
#
# THESE ARE THE REPO'S OWN FIXTURES, NOT NEW ONES. They are the exact constants in
# `build/layer2-receipt/tests/crypto04_nonce_equivocation.rs` (`SIG_A` / `SIG_B`), reused so
# that the Rust unit test and this cross-implementation vector are provably about the same
# bytes. Minting a second pair here would let the two drift apart and each stay green.
#
# The preimage they were made over is `NO_CONTEXT`, node 1, round 1, h(enc_tensor([1,2])),
# under the golden round parameters -- so this is the ONE section not generated under
# GOLDEN_CTX, and the vectors carry their own `ctx` for exactly that reason.
NONCE_SIG_A = bytes.fromhex(
    "abcfd403e8bc338fd93d6bc7dbd3326100a6cf2a15a4bae018065b35bc164e6b"
    "c569300033e9c6bbf58080865315ea9a891a32f11a0a533a71fee76e0d44120a")
NONCE_SIG_B = bytes.fromhex(
    "d483c814057859662fbb04dec0cd61c289407a2af2bf887d9f907639dc5eabd6"
    "677999217f02874950a523a7af81597a641c73b33961e97fb0571b5b95f65a03")


def replica(pki, items):
    """A replica that learned `items` by DELIVERY, in the order given.

    `add_contribution` is a raw set insert; `deliver` is the path that derives proofs. No
    golden scenario used to exercise it, which is why an `_auto_proof` that recorded a SAMPLE
    of the conflicts rather than their closure (#85) survived the cross-implementation suite.
    """
    r = A.Replica(0, pki)
    for it in items:
        r.deliver(it)
    return r


def refusal_root(rnd: int) -> bytes:
    """What the Rust commits when Layer 1 declines: `H("refused|" || rnd)`.

    Computed HERE, in Python, from the contract stated in `layer2-receipt/src/resolve.rs`,
    so the Rust's refusal root is checked against an independently derived value rather
    than against itself.
    """
    return A.H(b"refused|" + rnd.to_bytes(8, "big"))


def main() -> int:
    out = {"note": "generated from the published ACFA reference; do not hand-edit"}
    # SELF-DESCRIBING: the vectors state the context they were generated under, so a consumer
    # reconstructs the exact input rather than hardcoding a constant that could silently drift
    # out of step with this generator.
    out["ctx"] = hx(GOLDEN_CTX)

    # ---- primitives -------------------------------------------------------
    out["enc_tensor"] = [
        {"t": [], "hex": hx(A.enc_tensor(()))},
        {"t": [0], "hex": hx(A.enc_tensor((0,)))},
        {"t": [1, -2, 3], "hex": hx(A.enc_tensor((1, -2, 3)))},
        {"t": [-9223372036854775808, 9223372036854775807],
         "hex": hx(A.enc_tensor((-9223372036854775808, 9223372036854775807)))},
    ]
    out["contrib_msg"] = [
        {"ctx": hx(GOLDEN_CTX), "rnd": 0, "node_id": 0, "th": hx(b"\x00" * 32),
         "hex": hx(A.contrib_msg(GOLDEN_CTX, GOLDEN_PARAMS, 0, 0, b"\x00" * 32))},
        {"ctx": hx(GOLDEN_CTX), "rnd": 7, "node_id": 3, "th": hx(A.H(b"x")),
         "hex": hx(A.contrib_msg(GOLDEN_CTX, GOLDEN_PARAMS, 7, 3, A.H(b"x")))},
        {"ctx": hx(GOLDEN_CTX), "rnd": 2**63 - 1, "node_id": 4294967295, "th": hx(A.H(b"y")),
         "hex": hx(A.contrib_msg(GOLDEN_CTX, GOLDEN_PARAMS, 2**63 - 1, 4294967295, A.H(b"y")))},
    ]
    # v1 retained: the preimage old receipts were signed over, pinned so the retained path
    # cannot drift. If this vector ever changes, every receipt in the world stops verifying.
    out["contrib_msg_v1"] = [
        {"rnd": 0, "th": hx(b"\x00" * 32), "hex": hx(A.contrib_msg_v1(0, b"\x00" * 32))},
        {"rnd": 7, "th": hx(A.H(b"x")), "hex": hx(A.contrib_msg_v1(7, A.H(b"x")))},
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

    # DUPLICATE LEAVES ARE REFUSED BY BOTH SIDES, and nothing above reaches that branch:
    # every leaf set in `merkle` is distinct, so the guard both implementations carry was
    # never entered from a vector. (#90)
    #
    # Padding duplicates the sorted MAXIMUM, so a padded tree over S is byte-identical to an
    # honest tree over S + {argmax(S)} and the root does not commit to its own leaf count.
    # The colliding input is CONSTRUCTED here rather than asserted in prose: `argmax` is
    # computed under the leaf domain (0x00 prefix), which is the order the tree actually
    # sorts in, so this is the exact ambiguous input, not a plausible-looking one.
    def leaf_domain_max(leaves):
        return max(leaves, key=lambda x: A.H(b"\x00" + x))

    def merkle_refusal(name, leaves):
        rec = {"name": name, "leaves": [hx(x) for x in leaves]}
        try:
            rec["reference"] = {"refused": False, "error": None,
                                "root": hx(A.merkle_root(list(leaves)))}
        except Exception as e:                                   # noqa: BLE001 -- the outcome IS the datum
            rec["reference"] = {"refused": True, "error": type(e).__name__, "root": None}
        return rec

    out["merkle_refusals"] = [
        merkle_refusal("repeated-leaf", [ml[0], ml[1], ml[0]]),
        merkle_refusal("adjacent-duplicate-pair", [ml[0], ml[1], ml[2], ml[2]]),
        merkle_refusal("cve-2012-2459-padding-collision",
                       ml[:3] + [leaf_domain_max(ml[:3])]),
    ]
    # POSITIVE CONTROL for the section above: the same three leaves WITHOUT the duplicate
    # must still produce a root. Without this a merkle_root that refused everything would
    # satisfy every assertion in `merkle_refusals`, and the golden would be pinning a
    # function that does nothing. The root is the one the padding collision would have
    # collided WITH, so the two records are about the same tree.
    out["merkle_refusal_control"] = {
        "leaves": [hx(x) for x in ml[:3]],
        "root": hx(A.merkle_root(ml[:3])),
    }

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
    proof = A.EquivProof(GOLDEN_CTX, GOLDEN_PARAMS, 1, 1, h1, h2, s1, s2)
    out["equivocation"] = {
        "alt": {"rnd": alt.rnd, "node_id": alt.node_id, "tensor": list(alt.tensor),
                "sig": hx(alt.sig), "leaf": hx(alt.leaf())},
        "proof": {"rnd": proof.rnd, "node_id": proof.node_id, "h1": hx(proof.h1),
                  "h2": hx(proof.h2), "sig1": hx(proof.sig1), "sig2": hx(proof.sig2),
                  "leaf": hx(proof.leaf()), "valid": proof.valid(pki)},
    }

    # ---- crypto-04: two valid signatures over ONE content (#84) ------------
    # `equivocation` above is two DIFFERENT tensors, which every honest implementation
    # separates on the tensor hash. This is the case that separates them on the LEAF: the
    # content is byte-identical and only the signature differs, so an implementation whose
    # `EquivProof.valid` refuses on `h1 == h2` alone finds NO proof while `admit` still
    # excludes the identity on leaf uniqueness -- exclusion with no accountability artefact.
    # The reference's own `EquivProof.valid` docstring records the measurement from when it
    # was wrong. What is measured HERE is the consequence: the whole cross-implementation
    # suite stayed green while the two sides disagreed, because no vector in it had ever
    # shown them one content signed twice.
    nonce_th = A.H(A.enc_tensor((1, 2)))
    nonce_msg = A.contrib_msg(A.NO_CONTEXT, GOLDEN_PARAMS, 1, 1, nonce_th)
    # FAIL LOUDLY ON A MOVED PREIMAGE. A golden built on dead constants would pin whatever
    # the reference happens to do with two signatures that no longer verify -- which is
    # nothing -- and would read exactly like agreement.
    if not (A.verify(pki[1], nonce_msg, NONCE_SIG_A)
            and A.verify(pki[1], nonce_msg, NONCE_SIG_B)):
        sys.exit(
            "chosen-nonce fixtures are STALE, not broken: NONCE_SIG_A/B are signatures over\n"
            "contrib_msg(NO_CONTEXT, krum/f=1/frac=16, rnd 1, node 1, h(enc_tensor([1,2]))).\n"
            "The preimage moved. Regenerate them together with the identical constants in\n"
            "build/layer2-receipt/tests/crypto04_nonce_equivocation.rs -- the two must stay\n"
            "the same bytes or the unit test and this vector stop being about one thing."
        )
    if NONCE_SIG_A == NONCE_SIG_B or nodes[0].sign(nonce_msg) not in (NONCE_SIG_A, NONCE_SIG_B):
        sys.exit("chosen-nonce fixtures no longer bracket the honest RFC 8032 signature")

    nonce_a = A.Contribution(ctx=A.NO_CONTEXT, params=GOLDEN_PARAMS, rnd=1, node_id=1,
                             tensor=(1, 2), sig=NONCE_SIG_A)
    nonce_b = A.Contribution(ctx=A.NO_CONTEXT, params=GOLDEN_PARAMS, rnd=1, node_id=1,
                             tensor=(1, 2), sig=NONCE_SIG_B)
    nonce_rep = replica(pki, [nonce_a, nonce_b])
    nonce_rev = replica(pki, [nonce_b, nonce_a])
    nonce_agg, nonce_root = A.resolve(nonce_rep.state, 1, pki, 1, rule="krum")
    # POSITIVE CONTROL, and it is not optional. Gossip is at-least-once, so ONE entry
    # arriving twice is the normal case, and a detector that convicted here would convict
    # every honest node in any real deployment while satisfying every assertion about the
    # equivocating pair. The control is the same entry delivered twice.
    nonce_ctl = replica(pki, [nonce_a, nonce_a])
    ctl_agg, ctl_root = A.resolve(nonce_ctl.state, 1, pki, 1, rule="krum")
    out["nonce_equivocation"] = {
        "ctx": hx(A.NO_CONTEXT),
        "rnd": 1, "node_id": 1, "f": 1, "rule": "krum",
        "tensor": [1, 2],
        "tensor_hash": hx(nonce_th),
        "sig_a": hx(NONCE_SIG_A), "sig_b": hx(NONCE_SIG_B),
        "leaf_a": hx(nonce_a.leaf()), "leaf_b": hx(nonce_b.leaf()),
        "proof_leaves": sorted(hx(k) for k in nonce_rep.state.E),
        "convicted": sorted(A.convicted(nonce_rep.state, pki)),
        "state_root": hx(nonce_rep.state.root()),
        "reverse_state_root": hx(nonce_rev.state.root()),
        "admitted_ids": [c.node_id for c in A.admit(nonce_rep.state, 1, pki)],
        "aggregate": list(nonce_agg) if nonce_agg is not None else None,
        "output_root": hx(nonce_root),
        "redelivery_control": {
            "proof_leaves": sorted(hx(k) for k in nonce_ctl.state.E),
            "convicted": sorted(A.convicted(nonce_ctl.state, pki)),
            "state_root": hx(nonce_ctl.state.root()),
            "admitted_ids": [c.node_id for c in A.admit(nonce_ctl.state, 1, pki)],
            "aggregate": list(ctl_agg) if ctl_agg is not None else None,
            "output_root": hx(ctl_root),
        },
    }

    # ---- a THREE-way equivocator, delivered in two orders (#85) ------------
    # Two halves expose only ONE conflicting pair, so a `derive_proofs` that returned after
    # the first match looked correct on every two-way vector in this file. Three halves
    # expose three pairs, and recording a SAMPLE of them makes the state root a function of
    # ARRIVAL ORDER -- the reference's own `derive_proofs` docstring records the two roots
    # that came out of forward and reverse delivery before it was fixed. That is strong
    # eventual consistency failing, and the golden set could not see it because no vector
    # used `deliver` at all. Both roots are emitted here so the equality is asserted rather
    # than assumed.
    three = [contrib(nodes[0], 1, t) for t in ([1, 1, 1], [2, 2, 2], [3, 3, 3])]
    honest = cs[1:5]                                   # nodes 2..5, already signed above
    seq = three + honest
    fwd = replica(pki, seq)
    rev = replica(pki, list(reversed(seq)))
    fwd_agg, fwd_root = A.resolve(fwd.state, 1, pki, 1, rule="krum")
    out["delivery_orders"] = {
        "rnd": 1, "f": 1, "rule": "krum",
        "equivocator": [
            {"rnd": c.rnd, "node_id": c.node_id, "tensor": list(c.tensor),
             "sig": hx(c.sig), "leaf": hx(c.leaf())}
            for c in three
        ],
        # By node id, so the Rust rebuilds the honest half from `contributions` rather than
        # from a second copy of the same bytes that could drift out of step with it.
        "honest_node_ids": [c.node_id for c in honest],
        "forward_state_root": hx(fwd.state.root()),
        "reverse_state_root": hx(rev.state.root()),
        "proof_leaves": sorted(hx(k) for k in fwd.state.E),
        "reverse_proof_leaves": sorted(hx(k) for k in rev.state.E),
        "convicted": sorted(A.convicted(fwd.state, pki)),
        "admitted_ids": [c.node_id for c in A.admit(fwd.state, 1, pki)],
        "aggregate": list(fwd_agg) if fwd_agg is not None else None,
        "output_root": hx(fwd_root),
    }

    # ---- the same evidence learned by MERGE, not by delivery (#86) ---------
    # Three replicas each hold ONE of the equivocator's halves, so no replica can derive
    # anything on its own (|E| = 0 on all three, asserted below). Gossip then unions them.
    # A `merge` that is a plain dict update learns the contributions and never forms the
    # evidence their combination implies, so the union holds NO proofs and convicts nobody
    # while the delivery path over the same contribution set holds the full closure.
    # Whether misbehaviour is on the record would then depend on how it arrived, which is
    # crdt-02 live in the spec. Measured against a Rust `merge` mutated back to a plain
    # insert: the merged state root came out 7f9d49de... against 04cf3303... by delivery.
    part_a = replica(pki, [three[0], honest[0], honest[1]])
    part_b = replica(pki, [three[1], honest[2]])
    part_c = replica(pki, [three[2], honest[3]])
    if any(len(p.state.E) for p in (part_a, part_b, part_c)):
        sys.exit("merge fixture is degenerate: a partition already convicts before merging")

    def merged_of(order):
        st = A.State()
        for p in order:
            st.merge(p.state, pki)
        return st

    merged = merged_of([part_a, part_b, part_c])
    merged_rev = merged_of([part_c, part_b, part_a])
    m_agg, m_root = A.resolve(merged, 1, pki, 1, rule="krum")
    out["merge_vs_deliver"] = {
        "rnd": 1, "f": 1, "rule": "krum",
        # Which entries each partition holds, named by the leaves already pinned above.
        "partitions": [
            [hx(c.leaf()) for c in [three[0], honest[0], honest[1]]],
            [hx(c.leaf()) for c in [three[1], honest[2]]],
            [hx(c.leaf()) for c in [three[2], honest[3]]],
        ],
        "partition_proof_counts": [len(p.state.E) for p in (part_a, part_b, part_c)],
        "merged_state_root": hx(merged.root()),
        "reverse_merged_state_root": hx(merged_rev.root()),
        # THE LOAD-BEARING EQUALITY: the same set, learned two different ways.
        "delivered_state_root": hx(fwd.state.root()),
        "proof_leaves": sorted(hx(k) for k in merged.E),
        "convicted": sorted(A.convicted(merged, pki)),
        "admitted_ids": [c.node_id for c in A.admit(merged, 1, pki)],
        "aggregate": list(m_agg) if m_agg is not None else None,
        "output_root": hx(m_root),
    }

    # ---- inputs Layer 1 REFUSES (#91) --------------------------------------
    # Every `scenarios` entry uses uniform, in-range, non-empty tensors and a population
    # that meets its rule's precondition, so the refusal branch of `resolve` -- which
    # commits `H("refused|" || rnd)` -- was never reached from a vector at all. These four
    # reach it. The reference has no refusal path, so each record states what it ACTUALLY
    # did; see `reference.refused`.
    def refusal_scenario(name, issue, entries, rnd, f, rule):
        st = A.State()
        for c in entries:
            st.add_contribution(c)
        adm = A.admit(st, rnd, pki)
        rec = {
            "name": name, "issue": issue, "rnd": rnd, "f": f, "rule": rule,
            "entries": [
                {"rnd": c.rnd, "node_id": c.node_id, "tensor": list(c.tensor),
                 "sig": hx(c.sig), "leaf": hx(c.leaf())}
                for c in entries
            ],
            "state_root": hx(st.root()),
            "admitted_ids": [c.node_id for c in adm],
            # Derived in Python from the contract in layer2-receipt/src/resolve.rs, so the
            # Rust's refusal root is checked against an independent value, not against itself.
            "rust_refusal_root": hx(refusal_root(rnd)),
        }
        try:
            agg, root = A.resolve(st, rnd, pki, f, rule=rule)
        except Exception as e:                                   # noqa: BLE001 -- the outcome IS the datum
            rec["reference"] = {"refused": False, "error": type(e).__name__,
                                "aggregate": None, "output_root": None}
            return rec
        rec["reference"] = {
            "refused": bool(agg is None and root == refusal_root(rnd)),
            "error": None,
            "aggregate": list(agg) if agg is not None else None,
            "output_root": hx(root),
        }
        return rec

    OUT_OF_RANGE = 1 << 31            # fixed::MAX is 2**31 - 1, so this is the first value over
    out["refusal_scenarios"] = [
        refusal_scenario(
            "ragged-dimensions", 91,
            [contrib(nodes[0], 1, [1, 2]), contrib(nodes[1], 1, [1]),
             contrib(nodes[2], 1, [3, 4])], 1, 1, "krum"),
        refusal_scenario(
            "value-out-of-q16-16-range", 91,
            [contrib(nodes[0], 1, [OUT_OF_RANGE, 0]), contrib(nodes[1], 1, [1, 1]),
             contrib(nodes[2], 1, [2, 2])], 1, 1, "krum"),
        refusal_scenario(
            "all-empty-tensors", 91,
            [contrib(n, 1, []) for n in nodes[:3]], 1, 1, "krum"),
        refusal_scenario(
            # n = 5 against Bulyan's 4f+3 = 7. Distinct from the `all-honest-7-bulyan`
            # divergence recorded below, which is n = 7 -- precondition MET, selection wrong.
            "bulyan-below-4f-plus-3", 91,
            [contrib(nodes[i], 1, [i, i + 1, i + 2]) for i in range(5)], 1, 1, "bulyan"),
    ]

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
