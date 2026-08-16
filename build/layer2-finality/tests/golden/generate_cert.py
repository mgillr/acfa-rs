#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Independent encoder for the ACFA certificate and fork wire formats.

WHY THIS EXISTS. The Rust wire module had ten tests and every one of them was
SELF-CONSISTENT: it encoded with the Rust encoder and decoded with the Rust decoder.
That proves the implementation agrees with itself, which is exactly the standard this
project rejects everywhere else -- `acfa-receipt` is held to byte-identical agreement
with an independently written reference, and the finality wire format was not.

This is that second implementation. It is written FROM THE SPECIFICATION below, not
transliterated from the Rust. Transliterating would reproduce the Rust's mistakes and
call the result agreement.

It is independent in a second way that matters more than the language: Rust signs with
`ed25519-dalek` and this signs with `cryptography` (OpenSSL). If the two disagree about
Ed25519 for a fixed seed and message, these vectors will not match, so the signature
path is cross-checked too rather than assumed.

THE SPECIFICATION, as documented in src/wire.rs and src/certificate.rs:

  signing message   b"ACFA-CERT|" || round(u64 BE) || a_root(32) || e_cut(32) || rho(32)
  tuple id          sha256(signing message)
  identity          Ed25519 private key from a 32-byte seed; node_id is metadata

  certificate wire  b"ACFA-C1\\0" || version(u16 BE)
                    || round(u64 BE) || a_root(32) || e_cut(32) || rho(32)
                    || sig_count(u32 BE) || repeat[ signer(u32 BE) || sig(64) ]
                    signers STRICTLY ASCENDING by id

  fork wire         b"ACFA-K1\\0" || version(u16 BE) || certbody(a) || certbody(b)
                    canonical orientation: a.id() <= b.id()
                    the two tuples must CONFLICT: same round, and a differing
                    a_root or rho

Regenerate:
  python3 tests/golden/generate_cert.py > tests/golden/vectors_cert.json
"""

import hashlib
import json
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption, PrivateFormat

VERSION = 1
CERT_MAGIC = b"ACFA-C1\0"
FORK_MAGIC = b"ACFA-K1\0"


def sk(node_id: int) -> Ed25519PrivateKey:
    """Seed convention matches the Rust tests: 32 bytes, every byte = node_id."""
    return Ed25519PrivateKey.from_private_bytes(bytes([node_id & 0xFF]) * 32)


def pub(node_id: int) -> bytes:
    return sk(node_id).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def tuple_bytes(round_: int, a_root: bytes, e_cut: bytes, rho: bytes) -> bytes:
    return struct.pack(">Q", round_) + a_root + e_cut + rho


def signing_msg(round_: int, a_root: bytes, e_cut: bytes, rho: bytes) -> bytes:
    return b"ACFA-CERT|" + tuple_bytes(round_, a_root, e_cut, rho)


def tuple_id(round_: int, a_root: bytes, e_cut: bytes, rho: bytes) -> bytes:
    return h(signing_msg(round_, a_root, e_cut, rho))


def cert_body(round_, a_root, e_cut, rho, signers) -> bytes:
    msg = signing_msg(round_, a_root, e_cut, rho)
    out = tuple_bytes(round_, a_root, e_cut, rho)
    out += struct.pack(">I", len(signers))
    # Strictly ascending: the ordering rule is part of the format, not an accident of
    # how the caller happened to collect the signatures.
    for s in sorted(signers):
        out += struct.pack(">I", s) + sk(s).sign(msg)
    return out


def encode_cert(round_, a_root, e_cut, rho, signers) -> bytes:
    return CERT_MAGIC + struct.pack(">H", VERSION) + cert_body(round_, a_root, e_cut, rho, signers)


def conflicts(x, y) -> bool:
    return x["round"] == y["round"] and (x["a_root"] != y["a_root"] or x["rho"] != y["rho"])


def encode_fork(x, y) -> bytes:
    assert conflicts(x, y), "not a fork"
    xi = tuple_id(x["round"], x["a_root"], x["e_cut"], x["rho"])
    yi = tuple_id(y["round"], y["a_root"], y["e_cut"], y["rho"])
    a, b = (x, y) if xi <= yi else (y, x)
    return (
        FORK_MAGIC
        + struct.pack(">H", VERSION)
        + cert_body(a["round"], a["a_root"], a["e_cut"], a["rho"], a["signers"])
        + cert_body(b["round"], b["a_root"], b["e_cut"], b["rho"], b["signers"])
    )


def cert(round_, a_label, signers, rho_label=None, e_label="ecut"):
    return {
        "round": round_,
        "a_root": h(a_label.encode()),
        "e_cut": h(e_label.encode()),
        "rho": h((rho_label or a_label).encode()),
        "signers": signers,
    }


CERT_CASES = [
    ("single-signer", cert(1, "A", [1])),
    ("three-signers-out-of-order-input", cert(7, "A", [3, 1, 2])),
    ("wide-signer-ids", cert(42, "B", [1, 9, 250, 251])),
    ("high-round", cert(4_294_967_296, "C", [2, 5])),
    ("genesis-shape-no-sigs", {
        "round": 0,
        "a_root": h(b"ACFA-GENESIS|A"),
        "e_cut": h(b"ACFA-GENESIS|E"),
        "rho": h(b"ACFA-GENESIS|rho"),
        "signers": [],
    }),
]

FORK_CASES = [
    ("differing-a-root", cert(5, "A", [1, 2]), cert(5, "B", [3, 4])),
    ("differing-rho-only", cert(9, "A", [1, 2], rho_label="rho-x"),
     cert(9, "A", [3, 4], rho_label="rho-y")),
    ("mirrored-input-order", cert(5, "B", [3, 4]), cert(5, "A", [1, 2])),
]

out = {
    "source": "independent Python encoder, written from the spec in src/wire.rs",
    "version": VERSION,
    "pki": {str(i): pub(i).hex() for i in [1, 2, 3, 4, 5, 9, 250, 251]},
    "certs": [
        {
            "name": name,
            "round": c["round"],
            "a_root": c["a_root"].hex(),
            "e_cut": c["e_cut"].hex(),
            "rho": c["rho"].hex(),
            "signers": sorted(c["signers"]),
            "tuple_id": tuple_id(c["round"], c["a_root"], c["e_cut"], c["rho"]).hex(),
            "wire": encode_cert(c["round"], c["a_root"], c["e_cut"], c["rho"], c["signers"]).hex(),
        }
        for name, c in CERT_CASES
    ],
    "forks": [
        {"name": name, "wire": encode_fork(x, y).hex()}
        for name, x, y in FORK_CASES
    ],
}

print(json.dumps(out, separators=(",", ":"), sort_keys=True))
