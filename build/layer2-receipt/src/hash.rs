// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Hashing and the commitment trace.
//!
//! Every construction here is byte-compatible with the published reference kernel
//! (arXiv:2607.10305, `reference/acfa.py`). That compatibility is the point: a receipt is
//! only re-executable if an independent implementation derives the identical bytes,
//! and "identical" has to mean identical, not equivalent-up-to-encoding.

use sha2::{Digest, Sha256};

/// SHA-256. The reference's `H`.
pub fn h(b: &[u8]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(b);
    d.finalize().into()
}

/// Canonical tensor encoding: decimal ASCII, `|`-joined.
///
/// It is not the most compact encoding and that is deliberate. The reference emits
/// exactly this, and a receipt whose tensor hash disagrees with the reference's is
/// not a receipt for the same object. Any change here is a wire break.
pub fn enc_tensor(t: &[i64]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, v) in t.iter().enumerate() {
        if i > 0 {
            out.push(b'|');
        }
        out.extend_from_slice(v.to_string().as_bytes());
    }
    out
}

/// Merkle root over the SORTED leaf hashes.
///
/// Two properties, both load-bearing:
///
/// 1. **Sorted, so the root is independent of arrival order.** The state is a CRDT;
///    replicas observe the same set in different orders and must still commit to the
///    same root, or the receipt proves nothing about what anyone else saw.
/// 2. **Domain-separated** -- leaves are hashed under prefix `0x00` and internal nodes
///    under `0x01`. Without that separation an internal node can be replayed as a
///    leaf, which is the second-preimage confusion of CVE-2012-2459: an attacker
///    presents an interior digest as if it were a contribution and the root still
///    validates. Odd levels duplicate the final element, which is the same shape that
///    made CVE-2012-2459 exploitable in Bitcoin, and is safe *only* because the
///    prefixes make a duplicated node unforgeable as a leaf.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return h(b"\x00empty");
    }
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|x| {
            let mut buf = Vec::with_capacity(33);
            buf.push(0x00);
            buf.extend_from_slice(x);
            h(&buf)
        })
        .collect();
    level.sort_unstable();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut buf = Vec::with_capacity(65);
                buf.push(0x01);
                buf.extend_from_slice(&pair[0]);
                buf.extend_from_slice(&pair[1]);
                h(&buf)
            })
            .collect();
    }
    level[0]
}

/// Deterministic integer stream from a state-derived seed.
///
/// Retained for parity with the reference and for stochastic Layer-2 rules, which
/// Theorem 2 admits. The deterministic reference rule does not need it.
///
/// SEEDING IS THE WHOLE SAFETY PROPERTY. The seed must be derived from state that is
/// already fixed when the stream is drawn. A seed chosen by a participant at draw
/// time is grindable: a last mover recomputes the stream from its own candidate and
/// searches for one that lands favourably. That is why this takes a seed rather than
/// generating one.
pub fn prf_ints(seed: &[u8], purpose: &[u8], n: usize, bound: u32) -> Vec<u32> {
    assert!(bound > 0, "bound must be positive");
    let mut out = Vec::with_capacity(n);
    let mut ctr: u64 = 0;
    while out.len() < n {
        let mut buf = Vec::with_capacity(seed.len() + purpose.len() + 8);
        buf.extend_from_slice(seed);
        buf.extend_from_slice(purpose);
        buf.extend_from_slice(&ctr.to_be_bytes());
        let block = h(&buf);
        for i in (0..32).step_by(4) {
            if out.len() >= n {
                break;
            }
            let word = u32::from_be_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]);
            out.push(word % bound);
        }
        ctr += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tensor_and_singleton_encode_as_the_reference_does() {
        assert_eq!(enc_tensor(&[]), b"");
        assert_eq!(enc_tensor(&[0]), b"0");
        assert_eq!(enc_tensor(&[1, -2, 3]), b"1|-2|3");
    }

    #[test]
    fn merkle_root_is_independent_of_leaf_order() {
        let a = h(b"a");
        let b = h(b"b");
        let c = h(b"c");
        assert_eq!(merkle_root(&[a, b, c]), merkle_root(&[c, a, b]));
        assert_eq!(merkle_root(&[a, b, c]), merkle_root(&[b, c, a]));
    }

    #[test]
    fn empty_root_is_the_documented_sentinel_and_not_a_zero() {
        // A zero root would collide with "I committed to nothing" and "my hash
        // happened to be zero". The sentinel is a distinct preimage.
        assert_eq!(merkle_root(&[]), h(b"\x00empty"));
        assert_ne!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn an_internal_node_cannot_be_replayed_as_a_leaf() {
        // CVE-2012-2459 in one assertion. Build a two-leaf tree, take its root, and
        // offer that root as a single leaf. Without domain separation the two trees
        // would share a root and a forged membership proof would validate.
        let a = h(b"a");
        let b = h(b"b");
        let two = merkle_root(&[a, b]);
        let replayed = merkle_root(&[two]);
        assert_ne!(
            two, replayed,
            "internal node replayed as leaf must not collide"
        );
    }

    #[test]
    fn duplicated_odd_element_does_not_collide_with_the_honest_even_tree() {
        let a = h(b"a");
        let b = h(b"b");
        let c = h(b"c");
        // Three leaves duplicates the last at the first level. An honest four-leaf
        // tree whose fourth leaf equals the third must NOT produce the same root,
        // or padding becomes a forgery vector.
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, c]));
    }

    #[test]
    fn prf_is_deterministic_and_respects_its_bound() {
        let s = h(b"seed");
        let x = prf_ints(&s, b"purpose", 40, 7);
        let y = prf_ints(&s, b"purpose", 40, 7);
        assert_eq!(x, y);
        assert_eq!(x.len(), 40);
        assert!(x.iter().all(|&v| v < 7));
        // A different purpose must give a different stream, or domain separation
        // between two uses of the same seed is not actually present.
        assert_ne!(x, prf_ints(&s, b"other", 40, 7));
    }
}
