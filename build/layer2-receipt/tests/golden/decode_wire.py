#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Independent DECODER for the acfa-receipt wire format -- second author.

Written from src/wire.rs DOC COMMENTS and public constants only (MAGIC "ACFA-R1\\0",
VERSION u16, "fixed-width big-endian", "identities ascend by id; contributions and
proofs ascend by leaf", "no optional fields -- a presence byte"), plus the PUBLIC struct
declarations of Receipt / Contribution / EquivProof. The encode/decode bodies were not
read while writing this. A second author who reads the first one's code reproduces the
first one's misreadings, and calls the result agreement.

WHAT THIS IS AND IS NOT:

  This is a DECODER, not an independent encoder. It confirms that a second reader of the
  format specification recovers exactly the declared fields from the published bytes. It
  does NOT produce those bytes from scratch, so the encoder is not cross-checked.
  Signatures are carried through as opaque 64-byte blobs, so the signature path is not
  cross-checked here either -- that half exists for the certificate format via
  generate_cert.py, which signs with a different library.

Usage:
    python3 tests/golden/decode_wire.py tests/golden/vectors_wire.json

Exits non-zero if any vector fails to decode or disagrees on any field.
"""
import json
import sys
import hashlib

MAGIC = b"ACFA-R1\0"
VERSION = 1
RULES = {0: "Krum", 1: "Bulyan"}


class R:
    def __init__(s, b):
        s.b, s.i = b, 0

    def take(s, n):
        if s.i + n > len(s.b):
            raise ValueError(f"truncated: want {n} at {s.i}/{len(s.b)}")
        v = s.b[s.i:s.i + n]
        s.i += n
        return v

    def u8(s):
        return s.take(1)[0]

    def u16(s):
        return int.from_bytes(s.take(2), "big")

    def u32(s):
        return int.from_bytes(s.take(4), "big")

    def u64(s):
        return int.from_bytes(s.take(8), "big")

    def i64(s):
        return int.from_bytes(s.take(8), "big", signed=True)

    def done(s):
        return s.i == len(s.b)


def leaf_c(rnd, node_id, tensor, sig):
    """`C|` || rnd || node_id || sha256(enc_tensor) || sig, per the leaf() doc comment.

    enc_tensor is the decimal rendering of each value joined by `|`, per hash.rs.
    """
    enc = "|".join(str(v) for v in tensor).encode()
    th = hashlib.sha256(enc).digest()
    b = b"C|" + rnd.to_bytes(8, "big") + node_id.to_bytes(4, "big") + th + sig
    return hashlib.sha256(b).digest()


def decode(b):
    r = R(b)
    if r.take(8) != MAGIC:
        raise ValueError("bad magic")
    v = r.u16()
    if v != VERSION:
        raise ValueError(f"bad version {v}")
    round_ = r.u64()
    f = r.u32()
    rk = r.u8()
    if rk not in RULES:
        raise ValueError(f"unknown rule {rk}")
    rule = RULES[rk]

    npki = r.u32()
    pki = []
    last = None
    for _ in range(npki):
        i = r.u32()
        r.take(32)
        if last is not None and i <= last:
            raise ValueError("pki not ascending by id")
        last = i
        pki.append(i)

    ncon = r.u32()
    cons = []
    lastleaf = None
    for _ in range(ncon):
        rnd = r.u64()
        nid = r.u32()
        tl = r.u32()
        tensor = [r.i64() for _ in range(tl)]
        sig = r.take(64)
        lf = leaf_c(rnd, nid, tensor, sig)
        if lastleaf is not None and lf <= lastleaf:
            raise ValueError("contributions not ascending by leaf")
        lastleaf = lf
        cons.append(nid)

    nprf = r.u32()
    for _ in range(nprf):
        r.u64()
        r.u32()
        r.take(32)
        r.take(32)
        r.take(64)
        r.take(64)

    sr = r.take(32)
    orr = r.take(32)
    present = r.u8()
    agg = None
    if present == 1:
        al = r.u32()
        agg = [r.i64() for _ in range(al)]
    elif present != 0:
        raise ValueError(f"presence byte must be 0 or 1, got {present}")
    if not r.done():
        raise ValueError(f"trailing bytes: {len(b) - r.i}")
    return dict(round=round_, f=f, rule=rule, pki_n=len(pki), contribs=len(cons),
                proofs=nprf, state_root=sr.hex(), output_root=orr.hex(), agg=agg)


FIELDS = ("round", "f", "rule", "pki_n", "contribs", "proofs", "state_root", "output_root")


def main() -> int:
    vecs = json.load(open(sys.argv[1]))
    if not vecs:
        print("REFUSING: the vector file is empty -- nothing was checked")
        return 1
    ok = bad = 0
    for v in vecs:
        try:
            g = decode(bytes.fromhex(v["wire"]))
            diffs = [k for k in FIELDS if g[k] != v[k]]
            # The aggregate is compared on PRESENCE and contents, since "absent" is a
            # distinct wire state from "present and empty".
            if (g["agg"] is None) != (v["agg"] is None):
                diffs.append("agg-presence")
            elif g["agg"] is not None and g["agg"] != v["agg"]:
                diffs.append("agg")
            if diffs:
                bad += 1
                print(f"  {v['name']:22} MISMATCH {diffs}")
            else:
                ok += 1
                print(f"  {v['name']:22} OK   round={g['round']} f={g['f']} {g['rule']} "
                      f"pki={g['pki_n']} contribs={g['contribs']} "
                      f"agg={'present' if g['agg'] is not None else 'absent'}")
        except Exception as e:
            bad += 1
            print(f"  {v['name']:22} ERROR {e}")
    print(f"\n  decoded {ok} of {len(vecs)} vectors independently, {bad} bad")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
