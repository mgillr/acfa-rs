// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Wire-format tests for certificates and fork evidence.
//!
//! The property under test is not "it round-trips". It is that the encoding is
//! CANONICAL -- exactly one byte string per logical value -- because a verifier that
//! accepts two encodings of one fork can be shown one form while a third party checks
//! another, which is the ambiguity the whole finality argument rests on excluding.

use acfa_finality::wire::{decode_cert, decode_fork, encode_cert, encode_fork, WireError};
use acfa_finality::{CertFork, CertTuple, Certificate};
use acfa_receipt::hash::h;
use acfa_receipt::identity::Identity;

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn tuple(round: u64, a: &str) -> CertTuple {
    CertTuple {
        round,
        a_root: h(a.as_bytes()),
        e_cut_root: h(b"ecut"),
        rho: h(a.as_bytes()),
    }
}

fn signed(t: CertTuple, signers: &[u32]) -> Certificate {
    let mut c = Certificate::new(t);
    for &s in signers {
        c.sign(&ident(s));
    }
    c
}

#[test]
fn a_certificate_round_trips_byte_exactly() {
    let c = signed(tuple(7, "A"), &[3, 1, 2]);
    let bytes = encode_cert(&c);
    let back = decode_cert(&bytes).expect("decodes");
    assert_eq!(back, c);
    // Re-encoding must reproduce the same bytes, or the form is not canonical.
    assert_eq!(encode_cert(&back), bytes);
}

#[test]
fn signature_order_is_content_derived_not_arrival_derived() {
    // Same signers, opposite insertion order. Identical bytes, or "order is a function
    // of content" is false and two nodes would publish different evidence for one fact.
    let ascending = signed(tuple(4, "A"), &[1, 2, 3]);
    let descending = signed(tuple(4, "A"), &[3, 2, 1]);
    assert_eq!(encode_cert(&ascending), encode_cert(&descending));
}

#[test]
fn descending_or_duplicate_signers_are_refused() {
    let c = signed(tuple(2, "A"), &[1, 2]);
    let mut bytes = encode_cert(&c);
    // The two signer ids are the last two 68-byte entries; swap them to descend.
    let n = bytes.len();
    let (first, second) = (n - 2 * 68, n - 68);
    let mut swapped = bytes.clone();
    swapped[first..first + 68].copy_from_slice(&bytes[second..second + 68]);
    swapped[second..second + 68].copy_from_slice(&bytes[first..first + 68]);
    assert_eq!(
        decode_cert(&swapped),
        Err(WireError::NotCanonical("signers must ascend strictly"))
    );

    // A duplicate signer must also be refused: it would double-count toward f+1.
    let first_id: [u8; 4] = bytes[first..first + 4].try_into().unwrap();
    bytes[second..second + 4].copy_from_slice(&first_id);
    assert_eq!(
        decode_cert(&bytes),
        Err(WireError::NotCanonical("signers must ascend strictly"))
    );
}

#[test]
fn a_hostile_length_prefix_is_a_short_read_not_an_allocation() {
    // The defect this test exists to prevent: a few dozen bytes declaring four billion
    // signatures, aborting the verifier on the allocation before a signature is ever
    // checked. That is a denial of service on the tool we ask third parties to point at
    // untrusted input, so it is a security property and not a robustness nit.
    let c = signed(tuple(1, "A"), &[1]);
    let bytes = encode_cert(&c);
    let count_at = 8 + 2 + 8 + 32 + 32 + 32;
    for blow_up in [u32::MAX, u32::MAX / 2, 1 << 20] {
        let mut hostile = bytes.clone();
        hostile[count_at..count_at + 4].copy_from_slice(&blow_up.to_be_bytes());
        assert_eq!(
            decode_cert(&hostile),
            Err(WireError::Truncated),
            "a claimed count of {blow_up} must fail as a short read"
        );
    }
}

#[test]
fn truncation_at_every_offset_is_refused_and_never_panics() {
    let bytes = encode_cert(&signed(tuple(9, "A"), &[1, 2, 3]));
    for cut in 0..bytes.len() {
        assert!(
            decode_cert(&bytes[..cut]).is_err(),
            "prefix of length {cut} must not decode"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(decode_cert(&trailing), Err(WireError::TrailingBytes));
}

#[test]
fn magic_and_version_are_enforced() {
    let bytes = encode_cert(&signed(tuple(1, "A"), &[1]));
    let mut wrong = bytes.clone();
    wrong[0] = b'X';
    assert_eq!(decode_cert(&wrong), Err(WireError::BadMagic));

    let mut ver = bytes.clone();
    ver[8..10].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(decode_cert(&ver), Err(WireError::UnsupportedVersion(9)));

    // A fork must not decode as a certificate, nor a certificate as a fork.
    assert_eq!(decode_fork(&bytes), Err(WireError::BadMagic));
}

#[test]
fn fork_evidence_transfers_and_is_orientation_canonical() {
    let a = signed(tuple(5, "A"), &[1, 2]);
    let b = signed(tuple(5, "B"), &[3, 4]);
    let k = CertFork::canonical(a.clone(), b.clone()).expect("conflicting tuples");

    let bytes = encode_fork(&k);
    let back = decode_fork(&bytes).expect("decodes");
    assert_eq!(back, k);
    assert_eq!(encode_fork(&back), bytes);

    // Observed the other way round, the SAME violation must serialise identically --
    // otherwise two honest observers publish two different proofs of one fact.
    let mirrored = CertFork::canonical(b, a).expect("conflicting tuples");
    assert_eq!(encode_fork(&mirrored), bytes);
}

#[test]
fn a_forged_fork_over_non_conflicting_certificates_is_refused() {
    // Two certificates for DIFFERENT rounds are not a fork. Accepting them would let
    // anyone manufacture "evidence" that halts a healthy run.
    let a = signed(tuple(5, "A"), &[1, 2]);
    let b = signed(tuple(6, "A"), &[1, 2]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ACFA-K1\0");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&encode_cert(&a)[10..]);
    bytes.extend_from_slice(&encode_cert(&b)[10..]);
    assert_eq!(decode_fork(&bytes), Err(WireError::NotAFork));

    // And the same tuple twice is not a fork either.
    let mut same = Vec::new();
    same.extend_from_slice(b"ACFA-K1\0");
    same.extend_from_slice(&1u16.to_be_bytes());
    same.extend_from_slice(&encode_cert(&a)[10..]);
    same.extend_from_slice(&encode_cert(&a)[10..]);
    assert_eq!(decode_fork(&same), Err(WireError::NotAFork));
}

#[test]
fn a_decoded_certificate_still_verifies_against_the_pki() {
    // The point of transferring evidence is that the RECIPIENT can check it. If the
    // signatures did not survive the round trip the evidence would be inert.
    let ids: Vec<Identity> = (1..=4).map(ident).collect();
    let pki: acfa_receipt::identity::Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();

    let c = signed(tuple(3, "A"), &[1, 2, 3]);
    assert!(c.is_valid(&pki, 2), "precondition: valid before encoding");

    let back = decode_cert(&encode_cert(&c)).expect("decodes");
    assert!(back.is_valid(&pki, 2), "must still verify after transfer");

    // A flipped signature byte must fail verification rather than decode-time checks --
    // the wire layer is not the place that decides authenticity.
    let mut bytes = encode_cert(&c);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered = decode_cert(&bytes).expect("still well-formed");
    assert!(
        !tampered.is_valid(&pki, 2),
        "tampered signature must not verify"
    );
}

#[test]
fn genesis_round_trips_with_no_signatures() {
    let g = Certificate::genesis();
    assert!(g.sigs.is_empty());
    let back = decode_cert(&encode_cert(&g)).expect("decodes");
    assert_eq!(back, g);
    assert!(back.is_genesis());
}
