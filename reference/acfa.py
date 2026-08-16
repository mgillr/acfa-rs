"""ACFA — Accountable Consensus-Free Aggregation (reference prototype, P1).

Implements the paper-16 construction end-to-end:
  Layer 1a: contribution OR-Set (signed, content-addressed, round-tagged)
  Layer 1b: equivocation-proof G-Set (self-authenticating, monotone)
  Layer 2 : fixed-point multi-Krum + coordinate-wise trimmed mean, computed as a
            deterministic pure function of the converged (C,E) product state:
            hash-canonical order, Merkle-root-seeded stochasticity, integer-only
            arithmetic (Python ints: arbitrary precision, ISA-independent).

The kernel touches NO floats and NO ambient randomness: every bit of the output
is a function of the converged state. That is the whole theorem (Product Lifting).
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------- fixed point
Q_FRAC_BITS = 16                       # Q16.16

def fp_encode(x: float) -> int:
    """Boundary-only float->fixed conversion; the kernel never sees floats."""
    return int(round(x * (1 << Q_FRAC_BITS)))

def fp_decode(v: int) -> float:
    return v / (1 << Q_FRAC_BITS)

# ---------------------------------------------------------------- hashing
def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def enc_tensor(t: Sequence[int]) -> bytes:
    return b"|".join(str(int(v)).encode() for v in t)

def merkle_root(leaves: List[bytes]) -> bytes:
    """Root over the SORTED leaf hashes (canonical: independent of arrival).
    Domain-separated (leaf prefix 0x00, node prefix 0x01) to prevent the
    second-preimage / node-as-leaf confusion of CVE-2012-2459."""
    if not leaves:
        return H(b"\x00empty")
    level = sorted(H(b"\x00" + x) for x in leaves)          # leaf domain
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [H(b"\x01" + level[i] + level[i + 1])       # internal-node domain
                 for i in range(0, len(level), 2)]
    return level[0]

def prf_ints(seed: bytes, purpose: bytes, n: int, bound: int) -> List[int]:
    """Deterministic stream of ints in [0,bound) from a state-derived seed."""
    out, ctr = [], 0
    while len(out) < n:
        block = H(seed + purpose + ctr.to_bytes(8, "big"))
        for i in range(0, 32, 4):
            if len(out) >= n:
                break
            out.append(int.from_bytes(block[i:i + 4], "big") % bound)
        ctr += 1
    return out

# ---------------------------------------------------------------- identities
@dataclass
class Node:
    node_id: int
    sk: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def pk_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization as ser
        return self.sk.public_key().public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw)

    def sign(self, msg: bytes) -> bytes:
        return self.sk.sign(msg)

def verify(pk_raw: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False

def contrib_msg(rnd: int, tensor_hash: bytes) -> bytes:
    return b"ACFA-CONTRIB|" + rnd.to_bytes(8, "big") + b"|" + tensor_hash

# ---------------------------------------------------------------- entries
@dataclass(frozen=True)
class Contribution:
    rnd: int
    node_id: int
    tensor: Tuple[int, ...]            # fixed-point ints
    sig: bytes

    def tensor_hash(self) -> bytes:
        return H(enc_tensor(self.tensor))

    def leaf(self) -> bytes:
        return H(b"C|" + self.rnd.to_bytes(8, "big")
                 + self.node_id.to_bytes(4, "big")
                 + self.tensor_hash() + self.sig)

@dataclass(frozen=True)
class EquivProof:
    """Self-authenticating: two valid signatures by the same key, same round,
    different content. Verifiable offline by anyone holding the PKI."""
    rnd: int
    node_id: int
    h1: bytes
    h2: bytes
    sig1: bytes
    sig2: bytes

    def leaf(self) -> bytes:
        return H(b"P|" + self.rnd.to_bytes(8, "big")
                 + self.node_id.to_bytes(4, "big")
                 + self.h1 + self.h2 + self.sig1 + self.sig2)

    def valid(self, pki: Dict[int, bytes]) -> bool:
        if self.h1 == self.h2 or self.node_id not in pki:
            return False
        pk = pki[self.node_id]
        return (verify(pk, contrib_msg(self.rnd, self.h1), self.sig1)
                and verify(pk, contrib_msg(self.rnd, self.h2), self.sig2))

# ---------------------------------------------------------------- CRDT state
@dataclass
class State:
    """Product CRDT: (contribution OR-Set, proof G-Set). Merge = union x union."""
    C: Dict[bytes, Contribution] = field(default_factory=dict)   # leaf -> entry
    E: Dict[bytes, EquivProof] = field(default_factory=dict)

    def add_contribution(self, c: Contribution) -> None:
        self.C[c.leaf()] = c

    def add_proof(self, p: EquivProof) -> None:
        self.E[p.leaf()] = p

    def merge(self, other: "State") -> None:
        self.C.update(other.C)
        self.E.update(other.E)

    def root(self) -> bytes:
        return merkle_root(list(self.C.keys()) + list(self.E.keys()))

# ---------------------------------------------------------------- admission
def convicted(state: State, pki: Dict[int, bytes]) -> Set[int]:
    return {p.node_id for p in state.E.values() if p.valid(pki)}

def admit(state: State, rnd: int, pki: Dict[int, bytes]) -> List[Contribution]:
    """Visible round-r entries, minus convicted identities, minus any identity
    with >1 distinct same-round tensor (per-round dedup: equivocation never
    yields an admissible entry once both duplicates are visible), minus bad sigs."""
    bad = convicted(state, pki)
    per_id: Dict[int, List[Contribution]] = {}
    for c in state.C.values():
        if c.rnd != rnd or c.node_id in bad or c.node_id not in pki:
            continue
        if not verify(pki[c.node_id], contrib_msg(rnd, c.tensor_hash()), c.sig):
            continue
        per_id.setdefault(c.node_id, []).append(c)
    out = []
    for cs in per_id.values():
        # Def. 7 uniqueness clause: admit only an identity's UNIQUE visible
        # round-r entry. Two visible entries -- even with the same tensor hash
        # (an adversarial signer can emit a second valid signature over the
        # same message; verification does not force the deterministic nonce) --
        # are excluded: keeping cs[0] would be insertion-order-dependent.
        if len(cs) == 1:
            out.append(cs[0])
    return sorted(out, key=lambda c: c.leaf())          # hash-canonical order

# ---------------------------------------------------------------- the kernel
def multi_krum_indices(vs: List[Tuple[int, ...]], leafs: List[bytes],
                       f: int, coord_idx: List[int]) -> List[int]:
    """Integer multi-Krum: score_i = sum of the (n-f-2) smallest squared
    distances to the other vectors over coord_idx (the reference kernel passes
    ALL coordinates); select the n-f-2 lowest-scoring. Ties broken by leaf hash.
    Krum-level robustness (Blanchard'17, n>=2f+3) is Euclidean-distance based and
    is vulnerable to coordinate-concentrated attacks (Mhamdi'18) -- use bulyan
    below for coordinate-wise robustness at n>=4f+3."""
    n = len(vs)
    m = n - f - 2
    if m < 1:
        return list(range(n))
    d2 = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            s = 0
            for k in coord_idx:
                dv = vs[i][k] - vs[j][k]
                s += dv * dv
            d2[i][j] = d2[j][i] = s
    scored = []
    for i in range(n):
        ds = sorted(d2[i][j] for j in range(n) if j != i)
        scored.append((sum(ds[:m]), leafs[i], i))
    scored.sort()
    return [i for _, _, i in scored[:m]]

def bulyan_select(vs: List[Tuple[int, ...]], leafs: List[bytes],
                  f: int, coord_idx: List[int]) -> List[int]:
    """Bulyan step 1 (Mhamdi'18): iteratively single-Krum-select theta = n-2f
    candidates, removing each choice from the pool. Requires n >= 4f+3."""
    n = len(vs)
    theta = n - 2 * f
    pool = list(range(n))
    selected: List[int] = []
    while len(selected) < theta and len(pool) >= f + 3:
        sub_vs = [vs[i] for i in pool]
        sub_lf = [leafs[i] for i in pool]
        best_local = multi_krum_indices(sub_vs, sub_lf, f, coord_idx)[0]  # Krum top-1
        selected.append(pool.pop(best_local))
    return selected

def coord_median_trim(vs: List[Tuple[int, ...]], f: int) -> Tuple[int, ...]:
    """Bulyan step 2: per coordinate, average the theta-2f values CLOSEST to the
    coordinate median (ties by value then index -> canonical). This is what a
    plain mean lacks: it discards coordinate-concentrated outliers Krum admitted."""
    theta, d = len(vs), len(vs[0])
    keep = max(1, theta - 2 * f)
    out = []
    for k in range(d):
        col = sorted(v[k] for v in vs)
        med = col[theta // 2]
        closest = sorted(col, key=lambda x: (abs(x - med), x))[:keep]
        out.append(sum(closest) // len(closest))
    return tuple(out)

def trimmed_mean(vs: List[Tuple[int, ...]], beta_num: int, beta_den: int) -> Tuple[int, ...]:
    """Coordinate-wise trimmed mean; floor division (documented rounding)."""
    n, d = len(vs), len(vs[0])
    t = (n * beta_num) // beta_den
    out = []
    for k in range(d):
        col = sorted(v[k] for v in vs)
        kept = col[t:n - t] if n - 2 * t >= 1 else col
        out.append(sum(kept) // len(kept))
    return tuple(out)

def mean_of(vs: List[Tuple[int, ...]]) -> Tuple[int, ...]:
    """Coordinate-wise integer mean (floor); the multi-Krum averaging step."""
    n, d = len(vs), len(vs[0])
    return tuple(sum(v[k] for v in vs) // n for k in range(d))

def resolve(state: State, rnd: int, pki: Dict[int, bytes], f: int,
            rule: str = "krum") -> Tuple[Optional[Tuple[int, ...]], bytes]:
    """The pure function of the converged (C,E) product state.
    Returns (aggregate, output_root).

    Reference rule = FULL-DIMENSION multi-Krum, average of the m = n-f-2 selected
    (Blanchard et al. 2017); robustness precondition is n >= 2f+3, satisfied by the
    admitted honest quorum. Design decisions forced by the adversarial review:
      * NO coordinate subsampling. An earlier version sub-sampled 64 coordinates
        seeded from the admitted-set root; that (a) is a different estimator than
        full-dim Krum, breaking the imported bound, and (b) is GRINDABLE — a
        last-mover adversary computes its own leaf -> seed -> coords and crafts a
        vector Krum selects on the sample yet far on the un-sampled coords. Dropped.
      * Robustness rests on the SELECTION (n>=2f+3), a canonical hash tie-break
        keeps it deterministic, and the Merkle-seeded PRF remains available for
        stochastic Layer-2 rules (Thm 2 admits them) but is not needed by this
        deterministic reference rule."""
    adm = admit(state, rnd, pki)
    if not adm:
        return None, H(b"none|" + rnd.to_bytes(8, "big"))
    vs = [c.tensor for c in adm]
    leafs = [c.leaf() for c in adm]
    d = len(vs[0])
    if rule == "bulyan":                                     # coordinate-robust, n>=4f+3
        sel = bulyan_select(vs, leafs, f, list(range(d)))
        agg = coord_median_trim([vs[i] for i in sel], f)
    else:                                                    # Krum-level, n>=2f+3
        sel = multi_krum_indices(vs, leafs, f, list(range(d)))
        agg = mean_of([vs[i] for i in sel])
    return agg, H(b"agg|" + enc_tensor(agg))

# ---------------------------------------------------------------- replica
@dataclass
class Replica:
    rid: int
    pki: Dict[int, bytes]
    state: State = field(default_factory=State)

    def deliver(self, item) -> None:
        if isinstance(item, Contribution):
            self.state.add_contribution(item)
            self._auto_proof(item)
        elif isinstance(item, EquivProof):
            self.state.add_proof(item)
        elif isinstance(item, State):
            self.state.merge(item)

    def _auto_proof(self, new: Contribution) -> None:
        """Any honest replica that observes two same-(round,node) different-content
        signed contributions forms the self-authenticating proof itself."""
        for c in self.state.C.values():
            if (c.rnd == new.rnd and c.node_id == new.node_id
                    and c.tensor_hash() != new.tensor_hash()):
                # canonical (h,sig) pairing: both observers derive the SAME proof object
                (h1, s1), (h2, s2) = sorted(
                    [(c.tensor_hash(), c.sig), (new.tensor_hash(), new.sig)])
                p = EquivProof(new.rnd, new.node_id, h1, h2, s1, s2)
                if p.valid(self.pki):
                    self.state.add_proof(p)
                return

    def resolve(self, rnd: int, f: int):
        return resolve(self.state, rnd, self.pki, f)
