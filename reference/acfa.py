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
import math
from fractions import Fraction
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------- fixed point
Q_FRAC_BITS = 16                       # Q16.16
_FP_MAX = (1 << 31) - 1                # the kernel's MAX, mirrored from fixed.rs
_FP_MIN = -(1 << 31)

class FixedError(ValueError):
    """Refusal from the fixed-point boundary. Named, never silent."""


class AggError(ValueError):
    """Refusal from the aggregation kernel. The round produces a committed refusal, not a guess."""


def fp_encode(x: float) -> int:
    """Boundary-only float->fixed conversion; the kernel never sees floats.

    Rounds HALF AWAY FROM ZERO on the EXACT value of the scaled product, matching the Rust
    kernel's `f64::round`.

    IT IS COMPUTED EXACTLY RATHER THAN COMPOSED, and that distinction is the whole point.
    This function twice shipped a rule that was ALMOST the contract:

      1. `int(round(...))` -- Python's round is ties-to-even, which disagreed at every exact
         midpoint whose floor is even (num-01).
      2. `math.floor(s + 0.5)` -- the usual hand-rolled "half away" idiom, which
         `build/layer1-aggregate/src/fixed.rs` names explicitly as WRONG. The addition is
         itself a rounded operation: at the largest double strictly below 0.5 the true sum
         `1 - 2^-54` is a binary64 midpoint, ties-to-even carries it to exactly `1.0`, and the
         floor returns 1 where half-away requires 0.

    Fix (2) was recorded here as RESOLVED while the code still did the wrong thing, and the
    Rust-side guard (`tests/reference_rounding.rs`) re-implemented the SAME idiom, so it agreed
    with this function BY CONSTRUCTION and could not have caught it. `Fraction(s)` is the exact
    rational value of the float, so the comparison below has no intermediate to misround.
    """
    if math.isnan(x) or math.isinf(x):
        raise FixedError(f"not finite: {x!r}")
    s = x * (1 << Q_FRAC_BITS)
    if s > _FP_MAX or s < _FP_MIN:
        raise FixedError(f"out of range: {x!r} scales to {s!r}")
    fs = Fraction(s)
    n, d = fs.numerator, fs.denominator
    # round-half-away = floor(v + 1/2) for v >= 0, mirrored for v < 0.
    return (2 * n + d) // (2 * d) if fs >= 0 else -((-2 * n + d) // (2 * d))

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
    # DUPLICATE LEAVES MAKE THE ROOT AMBIGUOUS, so they are refused rather than hashed.
    # Padding duplicates the sorted MAXIMUM, so a leaf set that already contains its own
    # maximum twice commits to the same root as the set without it: measured,
    # merkle_root([a,b,c,a]) == merkle_root([a,b,c]). That is the CVE-2012-2459 shape this
    # function's own docstring says the domain separation prevents -- domain separation
    # prevents node/leaf confusion, NOT this. The Rust asserts the same condition; a spec
    # that omits it hands an implementer the ambiguity the implementation refuses.
    for i in range(1, len(level)):
        if level[i] == level[i - 1]:
            raise ValueError("merkle_root: duplicate leaves make the root ambiguous")
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

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P


def _decode_point(b: bytes):
    """Decode an ed25519 public key to an affine point, or None if it is not on the curve."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _P:
        return None
    sign = b[31] >> 7
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    xx = u * pow(v, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if (x * x - xx) % _P != 0:
        return None                      # not on the curve at all
    if x % 2 != sign:
        x = (-x) % _P
    return (x, y)


def _add(a, b):
    x1, y1 = a
    x2, y2 = b
    k = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + k, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - k, _P - 2, _P) % _P
    return (x3, y3)


def is_usable_pubkey(pk_raw: bytes) -> bool:
    """Refuse a key no honest participant can hold, at the door.

    The Rust uses `verify_strict`, which rejects small-order public keys. Without an equivalent
    here the reference accepted forgeries the implementation refuses -- measured, `R = identity,
    S = 0` against the eight order-dividing-8 keys was accepted for **622 of 2000** `contrib_msg`
    preimages, where the Rust accepted 0. Two consequences, both in the direction that matters:
    `admit` takes contributions nobody holds a secret key for, and two accepting tensor hashes
    form an `EquivProof` that convicts the key's registered owner PERMANENTLY, on evidence that
    verifies.

    THE SMALL-ORDER SET IS DERIVED, NOT TRANSCRIBED. A point has order dividing 8 exactly when
    `8P` is the identity, so that is what is computed. Eight 64-character literals copied from
    memory into a security check is precisely the kind of constant that is wrong in one nibble
    and passes every test that only ever feeds it honest keys.
    """
    if len(pk_raw) != 32:
        return False
    pt = _decode_point(pk_raw)
    if pt is None:
        return False
    for _ in range(3):                    # 8P == ((P+P)+(P+P)) ...
        pt = _add(pt, pt)
    return pt != (0, 1)                   # identity => order divides 8 => refuse


def verify(pk_raw: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        if not is_usable_pubkey(pk_raw):
            return False
        # AND THE R COMPONENT, which is the half I missed the first time. `verify_strict`
        # rejects a small-order `R` as well as a small-order public key, and closing only the
        # key half left the hole open: a signer choosing nonce r = 0 produces a GENUINE
        # signature -- it satisfies the verification equation -- whose R is the identity point.
        # Measured against the real Rust: `acfa_receipt::identity::verify` returns false and
        # this function returned True, and the divergence reached the aggregate (`admit`
        # returned 1 where the Rust returned 0).
        if len(sig) != 64 or not is_usable_pubkey(sig[:32]):
            return False
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False

def contrib_msg(ctx: bytes, params: "RoundParams", rnd: int, node_id: int,
                tensor_hash: bytes) -> bytes:
    """v2 signed preimage: context and node id are INSIDE the signature.

    The v1 preimage (round and tensor hash only) said neither what a signature was about nor
    who wrote it. Two honest contributions by one node at one round number in two different
    contexts therefore satisfied the equivocation predicate -- a valid proof of cheating
    against a node that had done nothing wrong, and conviction is permanent (#79).

    It also binds the ROUND PARAMETERS -- the rule, the fault bound, and the fixed-point scale.
    Without the scale, two builds compiled at different FRAC_BITS produce different aggregates
    from identical real-valued inputs, both internally consistent and both verifying, with
    nothing on the wire saying they disagree (#77). Without the rule and bound, contributions
    offered for one aggregation can be presented in another the signer never consented to.

    Every field is FIXED-WIDTH, so the concatenation is injective and no choice of ctx or
    parameters can be re-cut to collide with a different (ctx, params, rnd, node, hash).
    Variable-length caller data enters only as a 32-byte hash. That rule is what makes an
    opaque, caller-defined context safe, and any future field must meet it.
    """
    assert len(ctx) == 32, "context commitment must be exactly 32 bytes"
    return (
        b"ACFA-CONTRIB2|"
        + ctx
        + _params_bytes(params)
        + rnd.to_bytes(8, "big")
        + node_id.to_bytes(4, "big")
        + tensor_hash
    )


def _params_bytes(p: "RoundParams") -> bytes:
    """The fixed-width parameter block, identical in the preimage and in a leaf."""
    return bytes([p.rule_wire()]) + p.f.to_bytes(4, "big") + p.frac_bits.to_bytes(4, "big")


NO_CONTEXT = bytes(32)

V1_FRAC_BITS = 16                      # every released v1 build was Q16.16

#: Which signed preimage an entry was made over. `"v1"` is produced ONLY by decoding an
#: `ACFA-R1` receipt; anything constructed here is `"v2"`. It exists so the compatibility
#: promise can be kept without making `NO_CONTEXT` a silent downgrade surface.
PREIMAGE_V1 = "v1"
PREIMAGE_V2 = "v2"


@dataclass(frozen=True)
class RoundParams:
    """The arithmetic and robustness parameters a contribution was made under."""
    rule: str = "krum"
    f: int = 0
    frac_bits: int = Q_FRAC_BITS

    def rule_wire(self) -> int:
        return {"krum": 0, "bulyan": 1}[self.rule]


def contrib_msg_v1(rnd: int, tensor_hash: bytes) -> bytes:
    """Retained so receipts written before v0.4.0 keep verifying. Never used for new ones."""
    return b"ACFA-CONTRIB|" + rnd.to_bytes(8, "big") + b"|" + tensor_hash

# ---------------------------------------------------------------- entries
@dataclass(frozen=True)
class Contribution:
    ctx: bytes                         # opaque, caller-defined, never interpreted here
    params: RoundParams
    rnd: int
    node_id: int
    tensor: Tuple[int, ...]            # fixed-point ints
    sig: bytes
    sig_preimage: str = PREIMAGE_V2

    def tensor_hash(self) -> bytes:
        return H(enc_tensor(self.tensor))

    def msg(self) -> bytes:
        """The preimage THIS contribution's signature was made over."""
        if self.sig_preimage == PREIMAGE_V1:
            return contrib_msg_v1(self.rnd, self.tensor_hash())
        return contrib_msg(self.ctx, self.params, self.rnd, self.node_id, self.tensor_hash())

    def leaf(self) -> bytes:
        """THE LEAF IS VERSIONED FOR THE SAME REASON THE SIGNATURE IS.

        The leaf is what `admit` sorts by and what the state root commits to, so folding ctx
        and the parameter block into a v1 entry's leaf both REORDERS a v0.3.0 receipt and
        CHANGES the state root it already published. Measured while this was wrong: all three
        leaves of the real `three-contribs` v0.3.0 vector differed from the Rust, and the state
        root came out `baa64b18...` against the receipt's own `529a1232...`.
        """
        head = b"C|" if self.sig_preimage == PREIMAGE_V1 else (
            b"C|" + self.ctx + _params_bytes(self.params))
        return H(head
                 + self.rnd.to_bytes(8, "big")
                 + self.node_id.to_bytes(4, "big")
                 + self.tensor_hash() + self.sig)

@dataclass(frozen=True)
class EquivProof:
    """Self-authenticating: two valid signatures by the same key, same round,
    different content. Verifiable offline by anyone holding the PKI.

    THE CONTEXT IS PART OF THE PROOF. Two contributions by one node at one round number in
    DIFFERENT contexts are not equivocation -- that is a node doing its job in two places, and
    convicting it for that was a critical defect (#79)."""
    ctx: bytes
    params: RoundParams
    rnd: int
    node_id: int
    h1: bytes
    h2: bytes
    sig1: bytes
    sig2: bytes
    sig_preimage: str = PREIMAGE_V2

    def leaf(self) -> bytes:
        """Versioned for the same reason as `Contribution.leaf` -- see the note there."""
        head = b"P|" if self.sig_preimage == PREIMAGE_V1 else (
            b"P|" + self.ctx + _params_bytes(self.params))
        return H(head
                 + self.rnd.to_bytes(8, "big")
                 + self.node_id.to_bytes(4, "big")
                 + self.h1 + self.h2 + self.sig1 + self.sig2)

    def valid(self, pki: Dict[int, bytes]) -> bool:
        """Valid iff the two ENTRIES genuinely differ and both signatures verify.

        IT REJECTS THE SAME ENTRY TWICE, NOT MERELY THE SAME CONTENT. Ed25519 does not force a
        deterministic nonce, so one signer can emit two DISTINCT valid signatures over ONE
        message. Those are two entries by one identity in one round -- equivocation by the
        definition `admit` already enforces, since it excludes on leaf uniqueness. Refusing on
        `h1 == h2` alone discarded exactly that case: detection built the proof and `valid`
        threw it away, so the fix that taught detection to key on the leaf produced NOTHING.
        Measured: the repo's own two-signature fixtures gave `|E|=0, convicted=[]` here against
        `|E|=1, convicted={1}` in the Rust.

        The anti-framing guard is unchanged in strength: one entry still cannot convict its own
        author, because `(h1, sig1) == (h2, sig2)` is still refused.
        """
        if (self.h1, self.sig1) == (self.h2, self.sig2) or self.node_id not in pki:
            return False
        pk = pki[self.node_id]

        def msg(th: bytes) -> bytes:
            if self.sig_preimage == PREIMAGE_V1:
                return contrib_msg_v1(self.rnd, th)
            return contrib_msg(self.ctx, self.params, self.rnd, self.node_id, th)

        return verify(pk, msg(self.h1), self.sig1) and verify(pk, msg(self.h2), self.sig2)

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

    def derive_proofs(self, new: Contribution, pki: Dict[int, bytes]) -> None:
        """Form EVERY proof the new entry completes, against everything already held.

        TWO THINGS HERE WERE WRONG AND BOTH BROKE STRONG EVENTUAL CONSISTENCY.

        It used to `return` inside the match, recording a SAMPLE of the conflicts rather than
        their closure. Measured on a three-way equivocator: forward delivery gave root
        `460c45f0...` and reverse gave `dd51de3e...` for the same set. A CRDT whose state root
        depends on arrival order is not a CRDT, and SEC is the property this system is named
        for.

        And it lived only on the delivery path, so a replica that learned of an equivocation by
        GOSSIP never convicted: merged gave `|E|=0, convicted=[]` where delivered gave `|E|=1,
        convicted=[1]`. Whether misbehaviour was recorded depended on how the evidence arrived.
        Both paths now route through here.
        """
        nl = new.leaf()
        for c in list(self.C.values()):
            if (c.ctx == new.ctx and c.params == new.params
                    and c.sig_preimage == new.sig_preimage
                    and c.rnd == new.rnd and c.node_id == new.node_id
                    and c.leaf() != nl):
                (h1, s1), (h2, s2) = sorted(
                    [(c.tensor_hash(), c.sig), (new.tensor_hash(), new.sig)])
                pr = EquivProof(new.ctx, new.params, new.rnd, new.node_id,
                                h1, h2, s1, s2, new.sig_preimage)
                if pr.valid(pki):
                    self.add_proof(pr)
                # NO `return`: keep going, so the whole closure is derived.

    def merge(self, other: "State", pki: Dict[int, bytes]) -> None:
        """Union both sets AND derive the proofs the union completes.

        A plain `dict.update` was crdt-02 live in the spec: it learns the contributions and
        never forms the evidence their combination implies. The PKI is required for the same
        reason `deliver` requires it -- a proof is only recorded if it actually verifies.
        """
        for c in other.C.values():
            # DERIVE FOR EVERY ENTRY, not only for ones we do not already hold. The Rust
            # merge re-DELIVERS each of `other`'s contributions, so derivation runs
            # unconditionally. Guarding on `leaf() not in self.C` looked like a harmless
            # optimisation and was not: two states assembled through `add_contribution` --
            # the path a decoded receipt takes -- each holding one half of an equivocation,
            # merged to convicted=[] here against the Rust's convicted={1}, with roots
            # e4763af7... against 6eef0d83.... Two honest replicas holding an identical
            # contribution set disagreed, which is the exact SEC claim this fix exists to make.
            self.derive_proofs(c, pki)
            self.add_contribution(c)
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
        if not verify(pki[c.node_id],
                      c.msg(), c.sig):
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
    """Coordinate-wise trimmed mean; floor division (documented rounding).

    REFUSES RATHER THAN SILENTLY NOT TRIMMING (adv-05). It used to fall back to `col` when the
    trim would empty the column, which returns the PLAIN MEAN -- including the very outlier the
    caller configured beta to remove -- and says nothing. Measured before the fix:
    `trimmed_mean([(10,),(20,),(30,),(1000,)], 1, 5)` gave `(265,)`, an untrimmed mean, where
    the Rust returns `Err(BetaTrimsNothing { t: 0, n: 4 })`. That is the dangerous direction:
    the caller asked for robustness and got an answer with no signal that it was not applied.
    """
    # GATE FIRST, exactly as the Rust does on its own first line (`let d = check(cs)?`).
    # Without it all four refusal classes were still live INSIDE this function even after
    # `resolve` learned to refuse: empty and ragged raised IndexError, and an out-of-range
    # value or an all-empty set was computed on. A gate that only guards one caller is not
    # a gate.
    check(vs)
    if beta_den == 0:
        raise AggError("beta denominator is zero")
    n, d = len(vs), len(vs[0])
    t = min((n * beta_num) // beta_den, n)
    if t == 0 or n <= 2 * t:
        raise AggError(f"beta trims nothing or everything: t={t}, n={n}")
    out = []
    for k in range(d):
        col = sorted(v[k] for v in vs)
        kept = col[t:n - t]
        out.append(sum(kept) // len(kept))
    return tuple(out)

def check(vs: List[Tuple[int, ...]], leafs: Optional[List[bytes]] = None) -> None:
    """The entry gate every rule funnels through. Refuses, never guesses.

    This had NO counterpart here, so four classes of malformed input that the Rust commits as a
    deterministic REFUSAL were instead computed on -- or crashed. Measured against the Rust's
    refusal root for each: ragged tensors raised `IndexError`; one value at 2^40 gave `(2,2)`;
    an all-empty-dimension set gave `()` and a PRESENT empty aggregate on the wire; and Bulyan
    below `n >= 4f+3` produced an aggregate with no robustness guarantee at all.

    A spec that computes where the implementation refuses is worse than one that merely differs:
    an implementer reading it produces a kernel that answers confidently on exactly the inputs
    the design says are unanswerable.
    """
    if not vs:
        raise AggError("no contributions to aggregate")
    best = len(vs[0])
    if any(len(v) != best for v in vs):
        off = next(i for i, v in enumerate(vs) if len(v) != best)
        raise AggError(f"dimension mismatch: contribution {off} has {len(vs[off])}, expected {best}")
    if best == 0:
        raise AggError("every contribution is empty")
    if leafs is not None and len(set(leafs)) != len(leafs):
        raise AggError("duplicate tie key")
    for i, v in enumerate(vs):
        for k, x in enumerate(v):
            if not (_FP_MIN <= x <= _FP_MAX):
                raise AggError(f"value out of range: contribution {i}, coordinate {k}, value {x}")


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
    # A REFUSAL IS A DETERMINISTIC OUTCOME AND IS COMMITTED TO AS SUCH, so two replicas agree
    # that the round produced nothing rather than one of them inventing an answer.
    try:
        check(vs, leafs)
        d = len(vs[0])
        if rule == "bulyan":                                 # coordinate-robust, n>=4f+3
            if len(vs) < 4 * f + 3:
                raise AggError(f"bulyan needs n >= 4f+3; have n={len(vs)}, f={f}")
            sel = bulyan_select(vs, leafs, f, list(range(d)))
            agg = coord_median_trim([vs[i] for i in sel], f)
        else:                                                # Krum-level, n>=2f+3
            sel = multi_krum_indices(vs, leafs, f, list(range(d)))
            agg = mean_of([vs[i] for i in sel])
    except AggError:
        return None, H(b"refused|" + rnd.to_bytes(8, "big"))
    return agg, H(b"agg|" + enc_tensor(agg))

# ---------------------------------------------------------------- replica
@dataclass
class Replica:
    rid: int
    pki: Dict[int, bytes]
    state: State = field(default_factory=State)

    def deliver(self, item) -> None:
        if isinstance(item, Contribution):
            # DERIVE FIRST, THEN ADD. Adding first puts the new entry in the map the loop then
            # walks, so it would be compared against itself; the leaf-inequality test hides
            # that today, but it is an accident of the test rather than a property of the code.
            self._auto_proof(item)
            self.state.add_contribution(item)
        elif isinstance(item, EquivProof):
            self.state.add_proof(item)
        elif isinstance(item, State):
            self.state.merge(item, self.pki)

    def _auto_proof(self, new: Contribution) -> None:
        """Any honest replica that observes two signed contributions by one node, in one round,
        in the SAME context, under the SAME round parameters and the SAME preimage version,
        whose LEAVES differ, forms the self-authenticating proof itself.

        Delegates to `State.derive_proofs` so the DELIVERY path and the GOSSIP-MERGE path form
        exactly the same proofs -- see the note there for what went wrong when they differed.
        """
        self.state.derive_proofs(new, self.pki)

    def resolve(self, rnd: int, f: int):
        return resolve(self.state, rnd, self.pki, f)
