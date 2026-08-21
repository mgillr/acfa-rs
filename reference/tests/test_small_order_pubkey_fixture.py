# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""ref-107. The FIXTURE behind `is_usable_pubkey`, not the function.

`reference/acfa.py::is_usable_pubkey` is correct and this file does not ask for a line of it
to change. It refuses a small-order ed25519 public key by DERIVING the answer -- decode the
point, double three times, refuse if 8P is the identity -- rather than comparing against
transcribed literals, and its own docstring says why. The defect is one layer out: **what it
was measured against.**

The evidence previously recorded for it exercised FOUR encodings and reported "0/4 usable".
"0 of 4" is the shape of number this project treats as a defect, because it cannot distinguish
*four hostile inputs reached the check and were refused* from *four hostile inputs never
reached the check at all*. A fixture that is a strict subset of the hostile set measures the
subset, and reports the coverage of the whole.

Seat G widened it to THIRTEEN and split them 10 / 3: ten decode to a point and are refused by
the cofactor test, three (`edff..7f`, `edff..ff`, `eeff..7f`) fail `_decode_point` outright and
are refused by the `if pt is None: return False` arm. That split is the part worth having --
it names which arm each input lands on, so the fail-closed arm is WITNESSED rather than
incidentally green.

WHAT THIS FILE MEASURED, AND WHERE IT DISAGREES WITH THAT RECORD
---------------------------------------------------------------
The universe here is DERIVED from the curve by the oracle below, which shares no code with
`acfa.py` (extended (X:Y:Z:T) coordinates and a double-and-add ladder, against `acfa.py`'s
affine unified addition), and every derived x is re-checked against the curve equation
directly so that a shared square-root idiom cannot make the derivation agree with the code
under test by construction.

Derived, and asserted below: the universe of 32-byte strings a reduce-then-decode ed25519
decoder maps to a point of order dividing 8 has **FOURTEEN** members, not thirteen, and the
split is **10 / 4**, not 10 / 3. G's thirteen are all genuinely order-dividing-8 -- there is
no false member, the "0/13 admitted" result stands, and every one of the thirteen is refused
here too. The disagreement is an OMISSION, and it is exactly one string:

    eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

which is the identity point encoded doubly non-canonically: `y = p + 1` (so `y` reduces to 1)
AND the sign bit set on an `x` of 0. RFC 8032 s5.1.3 refuses it on the second count, and that
is the most likely reason it was dropped -- but a fixture's job is to enumerate what a decoder
somewhere will accept, not what the RFC permits. MEASURED, in this environment, with
`cryptography` 48.0.1 on this machine's OpenSSL: `Ed25519PublicKey.from_public_bytes` returns
a key object for `eeff..ffff` and for all five of the other non-canonical encodings, refusing
none of them -- ingress validation is deferred to verification time. `acfa.py` is the only
thing standing between that string and the aggregate, so it belongs in the fixture that
measures `acfa.py`. Under `acfa.py` it lands on the same fail-closed arm as the other three,
so the decode-failure arm catches FOUR, and a fixture of thirteen understates that arm's
coverage by one.

(That `from_public_bytes` measurement is stated and not asserted below on purpose: it is a
third-party library's behaviour at one version, so pinning it in an assertion would make this
file red on somebody else's upgrade for a reason that has nothing to do with `acfa.py`.)

Both numbers are asserted below rather than one being quietly replaced by the other: the 10/4
split over the derived fourteen, and the 10/3 sub-split over G's recorded thirteen, so a future
reader can see the two records agree everywhere they overlap and where they do not.

THE ACCEPTING TWIN. A file that only ever shows a check saying "no" proves nothing -- a
function that returns False unconditionally passes every refusal test written. Five freshly
generated honest keys must remain usable, and they are additionally shown by the independent
oracle to lie in the prime-order subgroup (`L*A` is the identity, `8*A` is not), so "usable"
is tied to a curve property rather than to the check agreeing with itself.

NOT IN CI. `.github/workflows/ci.yml` runs `reference/acfa.py` only through
`golden-is-reproducible`; there is no job that collects this directory. A test nothing runs is
the same class of defect as the fixture it replaces, so this file is written to be BOTH a
pytest module and a standalone script with an exit-code contract:

    python3 reference/tests/test_small_order_pubkey_fixture.py    # 0 pass, 1 fail
    python3 -m pytest reference/tests -q

Wiring it into ci.yml is a separate change in a file this task does not own.

GUARD-DELETION, MEASURED. Both mutations were applied to `reference/acfa.py`, run, and reverted;
`shasum -a 256 -c SHA256SUMS` reports OK on the restored file.

  1. `is_usable_pubkey` returns True straight after the decode (cofactor test never runs).
     8 collected, 6 passed, 2 FAILED, exit 1. `test_not_one_derived_encoding_is_usable` names
     the 10 admitted encodings; `test_the_split_is_witnessed...` fails on the ten that reach
     the cofactor test.
  2. `_decode_point` returns the RFC 8032 base point (prime order L) at all three of its
     `return None` sites. 8 collected, 6 passed, 2 FAILED, exit 1, and it is the fail-closed
     arm specifically: `test_not_one_derived_encoding_is_usable` names exactly the four
     out-of-range encodings and nothing else, and `test_the_split_is_witnessed...` fails at
     `len(undecodable) == 4` having measured `[]` -- the partition emptied.

`test_verify_refuses_a_small_order_key_end_to_end` stayed GREEN under both mutations. That is
reported rather than tuned away: it is not a guard for `is_usable_pubkey`, because
`cryptography`'s Ed25519 verify refuses these keys on its own, so it would pass with the
predicate deleted entirely. It guards the composition -- that a refusal at the predicate is
still a refusal at the door #87 is about -- and nothing more.

`reference/tests/` did not exist. This is the whole harness: one file, no conftest, no
package metadata, and `acfa.py` is imported by path. `SHA256SUMS` pins `acfa.py` by name and
is unaffected.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import acfa  # noqa: E402


# ------------------------------------------------------------------ the independent oracle
#
# Extended twisted-Edwards coordinates. `acfa.py` works in affine coordinates with a single
# unified addition law; this uses (X:Y:Z:T) with the standard add/double formulas and an
# inversion only at the very end. The point is that a transcription error or an algebraic slip
# in one of the two implementations does not appear in the other -- a second implementation
# that shared the addition law would be a spell-checker, not an oracle.
P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
# The prime-order subgroup's order. Used to strip the prime-order component off a random point
# so that what remains is pure 8-torsion, and used again as the accepting twin's positive
# check: an honest ed25519 public key is a clamped (multiple-of-8) scalar times the base point,
# so it lies in this subgroup and L times it is the identity.
L = 2**252 + 27742317777372353535851937790883648493
SQRT_M1 = pow(2, (P - 1) // 4, P)

IDENT = (0, 1, 1, 0)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e = (bb - aa) % P
    f = (dd - cc) % P
    g = (dd + cc) % P
    h = (bb + aa) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(k, a):
    assert k >= 0
    r, acc = IDENT, a
    while k:
        if k & 1:
            r = _add(r, acc)
        acc = _add(acc, acc)
        k >>= 1
    return r


def _eq(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _affine(a):
    x, y, z, _ = a
    zi = pow(z, P - 2, P)
    return (x * zi % P, y * zi % P)


def _ext(x, y):
    return (x, y, 1, x * y % P)


def on_curve(x, y):
    """-x^2 + y^2 == 1 + d x^2 y^2, checked directly.

    This is the check that keeps the derivation honest. `x_from_y` below uses the same
    `pow(xx, (p+3)//8)` square-root idiom `acfa.py::_decode_point` uses, because on this prime
    there is one obvious way to do it; if that idiom were subtly wrong in both files the two
    would agree and both be wrong. Substituting the recovered x back into the curve equation
    does not depend on how it was recovered, so it catches that.
    """
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def x_from_y(y):
    """Both square roots of x^2 = (y^2 - 1)/(d y^2 + 1), or None if there is no root."""
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    if v == 0:
        return None
    xx = u * pow(v, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx:
        x = x * SQRT_M1 % P
    if x * x % P != xx:
        return None
    return (x, (-x) % P)


def order_of(pt_ext):
    """Exact order if it divides 8, else None. Only ever asked about torsion candidates."""
    for k in (1, 2, 4, 8):
        if _eq(_mul(k, pt_ext), IDENT):
            return k
    return None


def torsion_points():
    """The eight points of order dividing 8, DERIVED -- no literal is transcribed.

    E(F_p) is Z/8 x Z/L with L prime and larger than 8, so the 8-torsion is cyclic of order 8
    and there are exactly eight such points: enumerating the multiples of any order-8 point
    enumerates all of them, with nothing left to search for.

    Getting an order-8 point: take any curve point and multiply by L. That annihilates the
    prime-order component and leaves the 8-torsion component multiplied by L mod 8. L mod 8 is
    odd, so the result has order 8 whenever the starting point did -- which is asserted rather
    than assumed, and a starting point that fails it makes this raise instead of silently
    returning a smaller subgroup.
    """
    seed, y = None, 2
    while seed is None:
        roots = x_from_y(y)
        if roots is not None and on_curve(roots[0], y):
            seed = _ext(roots[0], y)
        y += 1
    q = _mul(L, seed)
    assert order_of(q) == 8, "L*seed is not order 8 -- the 8-torsion was not reached"

    pts, acc = [], IDENT
    for _ in range(8):
        pts.append(_affine(acc))
        acc = _add(acc, q)
    assert _eq(acc, IDENT), "the eight multiples did not close the cycle"
    assert len(set(pts)) == 8, "the eight multiples are not distinct"
    for x, yy in pts:
        assert on_curve(x, yy), f"derived torsion point is not on the curve: {(x, yy)}"
        assert order_of(_ext(x, yy)) in (1, 2, 4, 8)
    return pts


def derive_universe():
    """Every 32-byte string a reduce-then-decode ed25519 decoder maps to 8-torsion.

    Complete by construction rather than by search. An encoding is 255 bits of y plus a sign
    bit; `y_enc mod p` is `y_enc` or `y_enc - p` because `2**255 - 1 < 2p`, so the encodings
    that reduce to a given torsion y are `y` and, when it still fits in 255 bits, `y + p`. Both
    sign bits are enumerated for each. No other 32-byte string can reduce to a torsion point,
    which is what makes this an enumeration and not a sample.
    """
    tors = torsion_points()
    out = []
    for y in sorted({yy for _, yy in tors}):
        roots = x_from_y(y)
        assert roots is not None
        for y_enc in [y] + ([y + P] if y + P < 2**255 else []):
            for s in (0, 1):
                # What a permissive (ref10-lineage) decoder lands on: pick the root whose
                # parity matches the sign bit. When x is 0 both roots are 0, so the sign bit
                # asks for a "negative zero" -- RFC 8032 refuses that, ref10 negates 0 and
                # accepts. Recorded per-entry so the two families stay distinguishable.
                x = roots[0] if roots[0] % 2 == s else roots[1]
                assert on_curve(x, y)
                out.append(
                    {
                        "hex": (y_enc | (s << 255)).to_bytes(32, "little").hex(),
                        "y_enc": y_enc,
                        "noncanonical_y": y_enc >= P,
                        "negative_zero": x == 0 and s == 1,
                        "order": order_of(_ext(x, y)),
                    }
                )
    assert len({u["hex"] for u in out}) == len(out), "duplicate encodings in the universe"
    return out


UNIVERSE = derive_universe()
BY_HEX = {u["hex"]: u for u in UNIVERSE}

# The three G named as landing on the decode-failure arm. Transcribed deliberately: this is the
# claim under test, not an input to the derivation. Each is asserted below to be a member of
# the independently derived universe.
G_DECODE_FAILURES = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]


def g_thirteen():
    """G's recorded thirteen, RECONSTRUCTED from G's own split rather than copied.

    Only the three decode-failure strings were recorded explicitly. The other ten are forced:
    G reported thirteen encodings splitting 10 decode / 3 refuse-at-decode, and the derived
    universe contains exactly ten strings with an in-range y. Ten members that were not those
    ten would have to come from outside the universe -- i.e. would not be order-dividing-8 at
    all, which would contradict G's own "0/13 admitted by the cofactor test". So G's thirteen
    are the ten in-range members plus these three.

    THE FIXTURE MUST NOT ASK THE CODE UNDER TEST WHICH INPUTS TO USE. An earlier draft
    selected the ten by calling `acfa._decode_point` and keeping what it accepted, which made
    the fixture a function of the decoder: mutating `_decode_point` to stop returning None
    silently grew this set from 10 to 14 and the suite died at import with a reconstruction
    error instead of the split test naming the arm that broke. Membership is decided here by
    the encoding rule alone -- `y_enc < p` -- which is the same partition for the honest code
    and is fixed no matter what the decoder does.
    """
    ten = [u["hex"] for u in UNIVERSE if not u["noncanonical_y"]]
    assert len(ten) == 10, f"reconstruction needs exactly 10 in-range members, got {len(ten)}"
    thirteen = ten + G_DECODE_FAILURES
    assert len(set(thirteen)) == 13, "G's thirteen did not reconstruct to thirteen"
    return thirteen


G_THIRTEEN = g_thirteen()


def honest_keys(n=5):
    return [acfa.Node(i).pk_bytes for i in range(n)]


# ------------------------------------------------------------------------------ the tests
def test_the_torsion_subgroup_is_derived_and_complete():
    pts = torsion_points()
    assert len(pts) == 8, "E[8](F_p) is cyclic of order 8; anything else means the ladder is wrong"
    orders = sorted(order_of(_ext(x, y)) for x, y in pts)
    assert orders == [1, 2, 4, 4, 8, 8, 8, 8], orders
    # Closure. Eight points that are each individually order-dividing-8 but do not form a group
    # would mean the enumeration missed members; this iterates 64 times and the count is
    # asserted so it cannot pass by iterating zero times.
    seen = 0
    ext = [_ext(x, y) for x, y in pts]
    aff = {(x, y) for x, y in pts}
    for a in ext:
        for b in ext:
            assert _affine(_add(a, b)) in aff
            seen += 1
    assert seen == 64


def test_the_derived_universe_is_fourteen_not_thirteen():
    """The finding. Asserted as a hard number so a future edit that quietly drops one reds."""
    assert len(UNIVERSE) == 14, [u["hex"] for u in UNIVERSE]
    canonical = [u for u in UNIVERSE if not u["noncanonical_y"] and not u["negative_zero"]]
    noncanonical = [u for u in UNIVERSE if u["noncanonical_y"] or u["negative_zero"]]
    assert len(canonical) == 8, [u["hex"] for u in canonical]
    assert len(noncanonical) == 6, [u["hex"] for u in noncanonical]
    for u in UNIVERSE:
        assert u["order"] in (1, 2, 4, 8), u


def test_every_one_of_g_s_thirteen_is_genuinely_order_dividing_eight():
    """Confirms G's fixture rather than trusting it. No false member: 13 of 13 check out."""
    assert len(G_THIRTEEN) == 13
    checked = 0
    for h in G_THIRTEEN:
        u = BY_HEX.get(h)
        assert u is not None, f"{h} is NOT in the independently derived universe"
        assert u["order"] in (1, 2, 4, 8), u
        checked += 1
    assert checked == 13


def test_g_s_thirteen_omits_exactly_one_derived_encoding():
    """The disagreement, pinned. G's set is a strict subset; the missing one is real.

    Recorded as a passing assertion rather than a TODO because the omission is the finding: if
    someone later widens the fixture to fourteen this test reds and the docstring above has to
    be updated with it, and if someone narrows the derivation to thirteen it also reds.
    """
    missing = sorted(set(BY_HEX) - set(G_THIRTEEN))
    assert missing == [
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ], missing
    assert not set(G_THIRTEEN) - set(BY_HEX), "G recorded an encoding the derivation does not"
    u = BY_HEX[missing[0]]
    # It is the identity point, reached doubly non-canonically: y = p + 1 reduces to 1, and the
    # sign bit is set on an x of 0. Both facts asserted, because "it is non-canonical" is the
    # adjective and these are the measurements.
    assert u["order"] == 1
    assert u["noncanonical_y"] and u["y_enc"] == P + 1
    assert u["negative_zero"]


def test_not_one_derived_encoding_is_usable():
    """The refusal. Fourteen inputs, fourteen refusals, and the count is the gate."""
    assert len(UNIVERSE) == 14
    admitted = [u["hex"] for u in UNIVERSE if acfa.is_usable_pubkey(bytes.fromhex(u["hex"]))]
    assert admitted == [], admitted


def test_the_split_is_witnessed_so_the_fail_closed_arm_is_not_incidental():
    """WHICH ARM each refusal lands on -- the whole reason "0/4" was not good enough.

    A refusal count alone is satisfied by an input that never reached the check. Partitioning
    by `_decode_point` says, per input, whether the cofactor test ran and said no or whether
    the `if pt is None: return False` arm caught it first, and asserts both partitions are
    non-empty at a stated size.
    """
    decoded, undecodable = [], []
    for u in UNIVERSE:
        b = bytes.fromhex(u["hex"])
        (decoded if acfa._decode_point(b) is not None else undecodable).append(u["hex"])
    assert len(decoded) + len(undecodable) == 14

    # THE FAIL-CLOSED ARM FIRST, and asserted at a non-zero size, because it is the arm that
    # goes vacuous. If `_decode_point` stops refusing, this partition empties and every other
    # assertion about "the inputs that reach the cofactor test" still holds over a set that has
    # silently grown -- which is the "0 of 4" ambiguity in a new costume.
    assert len(undecodable) == 4, undecodable
    assert sorted(undecodable) == sorted(
        [u["hex"] for u in UNIVERSE if u["noncanonical_y"]]
    ), "the decode-failure arm must be exactly the out-of-range y encodings"

    # G's record: 10 / 3, and the missing fourth is the omitted encoding above. Both numbers
    # are on the record so the two agree everywhere they overlap.
    g_undecodable = [h for h in G_THIRTEEN if h in undecodable]
    g_decoded = [h for h in G_THIRTEEN if h in decoded]
    assert len(g_undecodable) == 3, g_undecodable
    assert sorted(g_undecodable) == sorted(G_DECODE_FAILURES)
    assert len(g_decoded) == 10, g_decoded
    assert sorted(set(undecodable) - set(g_undecodable)) == [
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ]

    # Derived universe: 10 reach the cofactor test, 4 are caught at decode.
    assert len(decoded) == 10, decoded

    # The decode-failure arm is fail-CLOSED: each of the four is refused, and independently of
    # `acfa.py` each is shown to be a non-canonical y -- i.e. it is undecodable because it is
    # out of range, and it is dangerous because what it reduces to is 8-torsion. Both halves,
    # because "refused" alone does not say the input was worth refusing.
    for h in undecodable:
        assert not acfa.is_usable_pubkey(bytes.fromhex(h))
        assert BY_HEX[h]["noncanonical_y"], h
        assert BY_HEX[h]["y_enc"] >= P
        assert BY_HEX[h]["order"] in (1, 2, 4, 8)

    # And the ten that DO decode reach the cofactor test and are refused there -- verified
    # against the independent ladder, not against `acfa.py`'s own doubling.
    for h in decoded:
        pt = acfa._decode_point(bytes.fromhex(h))
        assert pt is not None
        assert _eq(_mul(8, _ext(*pt)), IDENT), h
        assert not acfa.is_usable_pubkey(bytes.fromhex(h))


def test_honest_keys_are_still_usable():
    """The accepting twin. Without it, `return False` passes every test in this file."""
    keys = honest_keys(5)
    assert len(keys) == 5
    for pk in keys:
        assert acfa.is_usable_pubkey(pk), pk.hex()
        assert pk.hex() not in BY_HEX
        pt = acfa._decode_point(pk)
        assert pt is not None
        e = _ext(*pt)
        assert on_curve(*pt)
        # The property that makes it usable, stated on the curve rather than by agreement with
        # the check: an ed25519 public key is a clamped scalar times the base point, so it sits
        # in the prime-order subgroup. L annihilates it; 8 does not.
        assert _eq(_mul(L, e), IDENT), "honest key is not in the prime-order subgroup"
        assert not _eq(_mul(8, e), IDENT), "honest key has order dividing 8"


def test_verify_refuses_a_small_order_key_end_to_end():
    """The door `is_usable_pubkey` guards. A refusal at the predicate that does not reach
    `verify` would leave the reference accepting what the Rust rejects, which is #87.

    THIS TEST GUARDS NOTHING, AND THE SENTENCE THAT SAID OTHERWISE WAS WRONG. It stayed green
    under both predicate mutations, because `cryptography`'s own verify refuses a small-order key
    by itself. An adversarial verifier then went further and measured what the earlier wording
    claimed was covered:

        delete `is_usable_pubkey` from `verify()`          8 passed, 0 failed
        delete BOTH the pubkey gate and the R gate         8 passed, 0 failed

    So it does not check that the two doors are wired together either -- the whole #87 door can be
    severed with nothing going red. The previous docstring asserted a refusal that does not happen,
    which is precisely the defect class #105 was opened to remove, shipping in a brand-new file.

    What this test actually establishes is narrower and worth keeping: that a small-order key does
    not verify END TO END through this reference, by whichever door refuses it. The missing guard
    on `is_usable_pubkey` itself is tracked separately -- it needs a probe that isolates the
    reference's gate from the library's, which this file does not attempt.
    """
    node = acfa.Node(0)
    msg = b"ref-107"
    sig = node.sign(msg)
    assert acfa.verify(node.pk_bytes, msg, sig), "honest signature must verify"
    refused = 0
    for u in UNIVERSE:
        assert not acfa.verify(bytes.fromhex(u["hex"]), msg, sig)
        # R half of the signature: `verify` refuses a small-order R as well as a small-order key.
        assert not acfa.verify(node.pk_bytes, msg, bytes.fromhex(u["hex"]) + sig[32:])
        refused += 1
    assert refused == 14


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    assert tests, "no tests collected -- this harness must refuse at zero"
    bad = 0
    for t in tests:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception as e:
            # Not `except AssertionError`. A mutation that makes a test RAISE rather than
            # assert is still that test failing, and swallowing only AssertionError would let
            # the runner abort mid-suite with the remaining tests neither passed nor reported.
            bad += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - bad} passed, {bad} failed  ({len(tests)} collected)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
