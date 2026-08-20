// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The PROOF half of the wire's ordering rule, which nothing witnessed.
//!
//! `wire.rs` states three canonicality rules in its own module doc, and the second is
//! "identities ascend by id; contributions and proofs ascend by leaf". Both halves of the
//! leaf rule are enforced twice -- once by the encoder, which sorts before it writes, and
//! once by the decoder, which refuses a stream that arrives out of order. Four guards, and
//! a by-line mutation sweep found that only the two CONTRIBUTION ones were witnessed. The
//! contribution decode guard is covered by `wire.rs::out_of_order_contributions_are_refused_as_non_canonical`.
//! Its proof twin, and the encoder's defensive `ps.sort_by_key`, could both be deleted and
//! the entire suite stayed green.
//!
//! WHY THAT MATTERS RATHER THAN BEING A COVERAGE STATISTIC. The encoding is load-bearing
//! for the security argument, not packaging: a receipt is checked by re-deriving hashes
//! over its bytes, so two byte sequences that decode to the same logical receipt are two
//! things a verifier and a third party can be shown while each believes they examined the
//! other's copy. `claimed_state_root` commits to the proof set through `State::root`, so
//! the proof set is not decoration -- it is the accountability half of the receipt, the
//! part that says WHICH identities were convicted of equivocation and why. With both
//! proof-ordering guards absent the crate loses that uniqueness for exactly that half:
//! `encode` would emit whatever order it was handed, `decode` would accept whatever order
//! it was given, and a receipt carrying k proofs would have had k! valid encodings.
//!
//! The asymmetry is the sharp part. Contributions kept their guard and proofs did not, so
//! the defect would not have looked like a missing rule -- the format would still have been
//! canonical in its better-tested half, and only the accountability records would have been
//! malleable. That is the shape of bug that survives review: the rule is written down, the
//! code implementing it is present for the case anyone thinks to test, and the twin rots.
//!
//! HOW EACH TEST IS BUILT SO THAT IT CANNOT PASS BY ACCIDENT. Two failure modes were seen
//! elsewhere in this repo on the same day and both are guarded against here explicitly:
//!
//!   * A test that passes for a COINCIDENTAL reason. `is_err()` is not asserted anywhere in
//!     this file. `WireError::NotCanonical` is raised by six distinct guards in `decode`
//!     (pki ordering, unusable key, reused key, contribution ordering, proof ordering, the
//!     aggregate presence byte), so `Err(NotCanonical(_))` would be satisfied by any of the
//!     other five. Each rejection test asserts the guard's own message NAMES PROOFS, which
//!     no other guard's message does.
//!   * A test that never REACHES the branch it is named for. The byte-level mutations here
//!     are placed by walking the stream field by field rather than by a hardcoded offset,
//!     and the walk is checked against two independent facts before any mutation is applied:
//!     the count it lands on must equal `r.proofs.len()`, and the 32 bytes immediately after
//!     the proof block must equal `r.claimed_state_root`. An off-by-anything walk fails
//!     those, loudly, instead of quietly corrupting a different field and being rejected by
//!     a different guard for a different reason.
//!
//! Every rejection test has an ACCEPTING TWIN so that none of the four guards can be
//! satisfied by a decoder or encoder that refuses everything: the canonical form of each
//! mutated stream is asserted to decode, to compare equal to the receipt it came from, and
//! to VERIFY under a policy.
//!
//! WHAT THIS FILE DOES NOT COVER, stated so the coverage is not read as wider than it is:
//!
//!   * `encode_redacted` / `decode_redacted` carry their OWN copy of the proof sort and the
//!     proof ordering guard (`wire.rs`, the redacted section). Those are separate sites and
//!     are not touched here; deleting them leaves this file green.
//!   * Nothing here checks that a proof is CORRECT. `EquivProof::valid`, the anti-framing
//!     self-pairing rejection, and the round binding are `entry.rs`'s business. A stream of
//!     well-ordered garbage proofs is canonical, and canonical is all these guards claim.
//!   * The ordering rule is checked only between ADJACENT records, because that is what the
//!     implementation checks (`windows(2)`). A stream that is globally scrambled is caught
//!     only because scrambling produces at least one descending adjacent pair; that is a
//!     property of sortedness, not an additional guarantee this file establishes.
//!   * Cross-IMPLEMENTATION agreement on the proof bytes is still untested, as `wire.rs`
//!     already says of the format as a whole. One implementation agreeing with itself is a
//!     different property from two implementations agreeing.

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{decode, encode, Contribution, Policy, Receipt, Rule, State, WireError};

/// Krum at `f = 1` on this build's fixed-point scale.
///
/// A NAMED FIXTURE, NOT A DEFAULT. A contribution signed under different round parameters is
/// filtered out of the round by `Receipt::issue`, exactly as a foreign `ctx` is, so a test that
/// needs other parameters has to say so rather than inherit these silently.
const PARAMS_DEFAULT: acfa_receipt::RoundParams = acfa_receipt::RoundParams {
    rule: acfa_receipt::Rule::Krum,
    f: 1,
    frac_bits: acfa_receipt::FRAC_BITS,
};

/// Every proof record is fixed width -- no length prefixes inside it -- which is what makes
/// a record swap a pure reordering rather than a reshaping of the stream.
const PROOF_REC: usize = 8 + 4 + 32 + 32 + 64 + 64; // rnd, node_id, h1, h2, sig1, sig2

/// magic(8) + version(2) + ctx(32) + round(8) + f(4) + rule(1)
///
/// The ctx term arrived in v0.4.0. The walk below is cross-checked against the receipt's own
/// proof count and the trailing state root, which is why a stale HEAD failed loudly here
/// instead of quietly walking into the middle of a signature.
const HEAD: usize = 8 + 2 + 32 + 8 + 4 + 1 + 4; // + frac_bits(4), added in v0.4.0

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &PARAMS_DEFAULT,
            rnd,
            a.node_id,
            &th,
        )),
    }
}

/// A receipt that actually CARRIES several equivocation proofs.
///
/// The guards under test are `windows(2)` predicates, so a receipt with fewer than two
/// proofs cannot exercise them at all -- `windows(2)` on a one-element slice yields nothing
/// and `any` is vacuously false. Every proof-bearing fixture here is asserted to hold three,
/// which is also enough for a swap of the first two records to leave a genuinely mixed
/// stream rather than a simple reversal.
///
/// The proofs are real: each named node delivers a SECOND, conflicting contribution for the
/// same round, `State::deliver` detects the conflict against the one already held, and
/// `EquivProof::canonical` forms a proof both signatures verify under.
fn receipt_with_proofs(n: u32, equivocators: &[u32], f: usize) -> (Receipt, Pki) {
    let ids: Vec<Identity> = (1..=n).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut s = State::new();
    for (i, id) in ids.iter().enumerate() {
        s.deliver(contrib(id, 1, &[i as i64 * 3, i as i64 + 1]), &pki);
    }
    for e in equivocators {
        let id = &ids[(*e - 1) as usize];
        // A different tensor for the same (node, round): this is the equivocation.
        s.deliver(contrib(id, 1, &[-7 - *e as i64, 11 + *e as i64]), &pki);
    }
    let r = Receipt::issue(
        &s,
        acfa_receipt::identity::NO_CONTEXT,
        1,
        &pki,
        f,
        Rule::Krum,
    );
    assert_eq!(
        r.proofs.len(),
        equivocators.len(),
        "fixture is void unless the equivocations really produced proofs; \
         a receipt with < 2 proofs cannot reach a windows(2) guard at all"
    );
    (r, pki)
}

fn be32(b: &[u8], i: usize) -> usize {
    u32::from_be_bytes(b[i..i + 4].try_into().unwrap()) as usize
}

/// Walk an encoded receipt to the offset of the PROOF COUNT, checking as it goes.
///
/// Hardcoding this offset is what the contribution-side test does and it is fine there,
/// because contributions are the first variable-length section. Proofs sit behind the PKI
/// AND behind every contribution's own length-prefixed tensor, so a constant would encode an
/// assumption about the fixture's dimension and node count and would silently drift.
/// Walking the real fields cannot drift; the two assertions in `proof_block` are what prove
/// the walk landed where it claims.
fn walk_to_proof_count(bytes: &[u8]) -> usize {
    let mut i = HEAD;
    let n_pki = be32(bytes, i);
    i += 4 + n_pki * (4 + 32);
    let n_c = be32(bytes, i);
    i += 4;
    for _ in 0..n_c {
        i += 8 + 4; // rnd, node_id
        let d = be32(bytes, i); // tensor dimension, per record
        i += 4 + d * 8 + 64; // dimension, tensor, signature
    }
    i
}

/// `(offset of the first proof record, number of proofs)`, with the walk PROVEN correct.
///
/// TRAP GUARDED HERE. A mutation placed at a misidentified offset would still make `decode`
/// return an error -- some other guard's error -- and a test asserting only `is_err()` would
/// pass while witnessing nothing. So the walk is cross-checked against two facts that come
/// from the receipt rather than from the arithmetic: the count read must equal the number of
/// proofs the receipt holds, and the bytes immediately following the whole proof block must
/// be `claimed_state_root`. A walk off by even one byte fails the second.
fn proof_block(bytes: &[u8], r: &Receipt) -> (usize, usize) {
    let count_off = walk_to_proof_count(bytes);
    let n_p = be32(bytes, count_off);
    assert_eq!(
        n_p,
        r.proofs.len(),
        "walked to a count of {n_p} where the receipt holds {} proofs: \
         the walk is not on the proof section",
        r.proofs.len()
    );
    let first = count_off + 4;
    let after = first + n_p * PROOF_REC;
    assert_eq!(
        &bytes[after..after + 32],
        &r.claimed_state_root[..],
        "the 32 bytes after the proof block are not claimed_state_root: \
         the proof block is not where this walk says it is"
    );
    (first, n_p)
}

/// The proofs of `r` in the order the encoder is required to emit them.
fn leaf_sorted_proofs(r: &Receipt) -> Vec<acfa_receipt::EquivProof> {
    let mut ps = r.proofs.clone();
    ps.sort_by_key(|p| p.leaf());
    ps
}

/// Assert the refusal came from the PROOF ordering guard and not from one of the five other
/// `NotCanonical` sites in `decode`.
fn assert_refused_for_proof_order(bytes: &[u8], what: &str) {
    match decode(bytes) {
        Err(WireError::NotCanonical(why)) => {
            assert!(
                why.contains("proofs") && why.contains("ascending"),
                "{what}: refused as non-canonical, but the reason given was {why:?} -- \
                 that is a DIFFERENT guard, so this test witnesses nothing about proof order"
            );
        }
        other => panic!("{what}: expected NotCanonical naming proofs, got {other:?}"),
    }
}

// ------------------------------------------------------- decoder: wire.rs:406 / wire.rs:407

#[test]
fn out_of_order_proofs_are_refused_as_non_canonical() {
    // The twin of `wire.rs::out_of_order_contributions_are_refused_as_non_canonical`, for
    // the collection that carries the CONVICTIONS. Without this guard two receipts differing
    // only in the order of their proof records both decode, to the same logical receipt, and
    // the bytes therefore stop determining the receipt for the accountability half.
    let (r, pki) = receipt_with_proofs(9, &[2, 5, 8], 1);
    let canonical = encode(&r);

    // The accepting twin, and it is not a formality: it establishes that the fixture is a
    // stream the decoder LIKES, so the only difference between green and red below is the
    // reordering itself.
    let back = decode(&canonical).expect("the canonical form must decode");
    assert_eq!(back, r, "round trip is exact before anything is disturbed");
    assert!(
        back.verify(&Policy::new(pki, 1)).is_ok(),
        "and the fixture is a genuinely valid receipt, not merely a decodable one"
    );

    let (first, n_p) = proof_block(&canonical, &r);
    assert!(
        n_p >= 2,
        "need two adjacent records to have an order at all"
    );

    // Prove the swap really creates a DESCENDING adjacent pair, from the leaves themselves
    // rather than from the assumption that "swapped" implies "out of order".
    let sorted = leaf_sorted_proofs(&r);
    assert!(
        sorted[0].leaf() < sorted[1].leaf(),
        "the encoder's own order must be strictly ascending for the swap to invert it"
    );

    let mut hand = canonical.clone();
    let a = first;
    let b = first + PROOF_REC;
    let (p0, p1) = (hand[a..b].to_vec(), hand[b..b + PROOF_REC].to_vec());
    hand[a..b].copy_from_slice(&p1);
    hand[b..b + PROOF_REC].copy_from_slice(&p0);

    // Exactly the proof records moved: same length, and every byte outside the two swapped
    // records is untouched. This is what rules out the mutation having disturbed a length,
    // a signature or a root and being rejected by some unrelated guard.
    assert_eq!(hand.len(), canonical.len());
    assert_eq!(hand[..a], canonical[..a]);
    assert_eq!(hand[b + PROOF_REC..], canonical[b + PROOF_REC..]);
    assert_ne!(hand, canonical, "the swap must actually change the bytes");

    assert_refused_for_proof_order(&hand, "two adjacent proof records swapped");
}

#[test]
fn a_repeated_proof_record_is_refused_because_the_order_is_strict() {
    // The rule is `>=`, not `>`, and the difference is the whole duplicate case. Relaxing it
    // to `>` still rejects a descending stream, so the swap test above would stay green while
    // a receipt could carry the same conviction record twice -- two encodings of one logical
    // proof set again, by repetition instead of by permutation.
    let (r, pki) = receipt_with_proofs(9, &[2, 5, 8], 1);
    let canonical = encode(&r);
    assert!(
        decode(&canonical).is_ok_and(|d| d == r),
        "accepting twin: the un-duplicated stream is accepted and exact"
    );
    assert!(
        decode(&canonical)
            .unwrap()
            .verify(&Policy::new(pki, 1))
            .is_ok(),
        "accepting twin: and it verifies"
    );

    let (first, n_p) = proof_block(&canonical, &r);
    assert!(n_p >= 2);

    // Overwrite the SECOND record with the first. Count and length are unchanged, so this is
    // a pure content edit: the two adjacent leaves are now equal rather than ascending.
    let mut hand = canonical.clone();
    let p0 = hand[first..first + PROOF_REC].to_vec();
    hand[first + PROOF_REC..first + 2 * PROOF_REC].copy_from_slice(&p0);
    assert_eq!(hand.len(), canonical.len());
    assert_eq!(
        hand[first..first + PROOF_REC],
        hand[first + PROOF_REC..first + 2 * PROOF_REC],
        "the two records must genuinely be identical, i.e. equal leaves"
    );

    assert_refused_for_proof_order(&hand, "the first proof record repeated");
}

// -------------------------------------------------------------- encoder: wire.rs:222

#[test]
fn encode_normalises_an_unsorted_proof_vector() {
    // `Receipt.proofs` is a public `Vec`, and `Receipt::issue` happens to fill it from a
    // leaf-keyed BTreeMap, so on the issue path it arrives sorted already. That is exactly
    // why the encoder's sort is easy to delete without breaking anything: the only caller in
    // the tests never hands it an unsorted vector. Any other route into a `Receipt` -- the
    // public struct literal, a field assignment, a merge written by a consumer -- can, and
    // then a receipt that is canonical in memory would encode to a stream this crate's own
    // decoder refuses. The encoder's job is that order is a function of CONTENT and never of
    // the vector's history.
    let (canonical_receipt, pki) = receipt_with_proofs(9, &[2, 5, 8], 1);
    assert!(canonical_receipt.proofs.len() >= 2);

    let mut scrambled = canonical_receipt.clone();
    scrambled.proofs.reverse();
    assert_ne!(
        scrambled.proofs, canonical_receipt.proofs,
        "the fixture must really be out of order, or this test is about nothing"
    );
    assert!(
        scrambled
            .proofs
            .windows(2)
            .any(|w| w[0].leaf() >= w[1].leaf()),
        "and out of order by the SAME predicate the decoder applies"
    );

    let from_scrambled = encode(&scrambled);

    // 1. The encoder emitted the canonical bytes anyway. This is the direct statement of the
    //    property and it fails the instant the defensive sort is removed.
    assert_eq!(
        from_scrambled,
        encode(&canonical_receipt),
        "encode() must emit leaf order, not vector order"
    );

    // 2. And independently: those bytes are ones this crate's own decoder accepts. Asserted
    //    separately from (1) on purpose -- (1) could in principle be satisfied by both sides
    //    agreeing on a WRONG order, and this pins that the agreed order is the canonical one.
    let back = decode(&from_scrambled).expect(
        "bytes produced from an unsorted proof vector must still be accepted by decode(): \
         an encoder that passes vector order through emits a stream its own decoder refuses",
    );
    assert_eq!(
        back, canonical_receipt,
        "and they decode back to the receipt in canonical proof order"
    );

    // 3. Accepting twin: the normalised bytes are a valid receipt, not merely a decodable
    //    one, so this cannot be satisfied by an encoder that emits something inert.
    assert!(
        back.verify(&Policy::new(pki, 1)).is_ok(),
        "the normalised receipt still verifies"
    );

    // 4. Idempotence: re-encoding what came back is byte-identical. Order is a function of
    //    content, so a second pass cannot move anything.
    assert_eq!(encode(&back), from_scrambled, "re-encoding is stable");
}

#[test]
fn the_proof_order_the_encoder_chooses_is_leaf_order_specifically() {
    // Pins WHICH order, not merely that some order is imposed. A sort by `node_id`, or by
    // `rnd`, would make both tests above pass while disagreeing with the decoder's predicate
    // for any receipt where the two orders differ -- and the leaves are hashes, so they
    // differ routinely. The decoder checks leaves; the encoder must sort by leaves.
    let (r, _) = receipt_with_proofs(9, &[2, 5, 8], 1);
    let bytes = encode(&r);
    let (first, n_p) = proof_block(&bytes, &r);
    assert_eq!(n_p, 3);

    let expected = leaf_sorted_proofs(&r);
    let mut expected_bytes = Vec::new();
    for p in &expected {
        expected_bytes.extend_from_slice(&p.rnd.to_be_bytes());
        expected_bytes.extend_from_slice(&p.node_id.to_be_bytes());
        expected_bytes.extend_from_slice(&p.h1);
        expected_bytes.extend_from_slice(&p.h2);
        expected_bytes.extend_from_slice(&p.sig1);
        expected_bytes.extend_from_slice(&p.sig2);
    }
    assert_eq!(
        &bytes[first..first + n_p * PROOF_REC],
        &expected_bytes[..],
        "the emitted proof block must be exactly the leaf-ascending sequence"
    );

    // And leaf order is not accidentally the same as node_id order for this fixture, so the
    // assertion above genuinely discriminates between the two.
    //
    // THE SET MOVED FROM [2, 5, 7] TO [2, 5, 8] IN v0.4.0. Adding ctx to the leaf preimage
    // reshuffles the leaf hashes, and [2, 5, 7] happened to land back in node_id order -- at
    // which point this test would have passed while proving nothing about WHICH sort the
    // encoder uses. The guard below is what caught that; it is not decoration.
    let by_node: Vec<u32> = expected.iter().map(|p| p.node_id).collect();
    let mut ascending = by_node.clone();
    ascending.sort_unstable();
    assert_ne!(
        by_node, ascending,
        "fixture is degenerate: leaf order coincides with node_id order here, so it cannot \
         tell the two sorts apart -- change the equivocator set"
    );
}
