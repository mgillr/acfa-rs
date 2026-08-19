// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The pre-allocation bound on the signature count, witnessed by the ERROR IT PRODUCES
//! rather than by the error it shares with everything else.
//!
//! WHY THIS FILE EXISTS. `wire.rs` carries a three-line guard between the signature
//! count and the loop that reads signature entries: a declared count must fit, times
//! the on-wire entry width, inside the bytes that actually remain, or the record is
//! refused as `Truncated`. A by-line mutation sweep deleted that guard outright and the
//! entire suite stayed green -- including the one test named for it,
//! `a_hostile_length_prefix_is_a_short_read_not_an_allocation`. That test is not wrong.
//! It is UNDER-DETERMINED, and the distinction matters more than the bug.
//!
//! Here is the trap in full. That test feeds a certificate with one signature and
//! rewrites the count to `u32::MAX`, then asserts `Err(Truncated)`. With the bound in
//! place, the guard fires and returns `Truncated`. With the bound deleted, the loop
//! runs, reads the one entry that is there, and the *second* iteration's `r.u32()?`
//! runs off the end of the buffer and returns... `Truncated`. Identical value, four
//! bytes later. The assertion cannot tell rejection-by-bound from rejection-by-read,
//! so it holds either way, so the mutant survives. A test can be a correct statement
//! about the system and still witness nothing, and that is the failure mode this file
//! is built to close.
//!
//! WHAT ACTUALLY DIFFERS, AND SO WHAT WE ASSERT. The bound's whole claim is temporal:
//! it refuses BEFORE any following byte is interpreted as a signature entry. So put a
//! tripwire in those following bytes -- two entries whose signer ids DESCEND. Descending
//! ids are refused by the loop with `NotCanonical("signers must ascend strictly")`, a
//! different error from `Truncated`. Now the two behaviours separate cleanly:
//!
//!   * bound present -> nothing after the count is ever read -> `Truncated`;
//!   * bound absent  -> the loop reads entry one, then entry two -> `NotCanonical`.
//!
//! Every hostile case below first asserts, with an HONEST count, that the swapped pair
//! really is rejected as non-canonical. That is not decoration. It is the proof that the
//! tripwire is armed and that the hostile case is reaching the branch it claims to test
//! -- a guard-test that never reaches its guard is the other way this project has been
//! bitten today, and it looks exactly like a passing test.
//!
//! THE MULTIPLIER IS A SEPARATE CLAIM FROM THE COMPARISON. `need > remaining` where
//! `need` is `count * 68` is not the same guard as `count > remaining`. A count of 100
//! against 136 remaining bytes passes the second and fails the first, and the second is
//! nonsense: 100 entries need 6800 bytes. So the hostile counts here are deliberately
//! chosen to sit BELOW the remaining byte count while sitting far above the remaining
//! ENTRY count, which is the only region where dropping `* SIG_ENTRY` is observable.
//!
//! THE ACCEPTING TWIN IS LOAD-BEARING. Every well-formed certificate arrives at this
//! guard with `need` EXACTLY equal to `remaining` -- the count is followed by precisely
//! its own entries and then the end of the record. The bound therefore lives one
//! character away from rejecting every valid certificate in existence: `>` widened to
//! `>=` turns the decoder into a brick. So the accepting cases are not a courtesy round
//! trip; they are the only thing standing between this guard and a reject-everything
//! stub that would satisfy all the hostile assertions above.
//!
//! WHAT THIS FILE DOES NOT COVER, stated plainly because a coverage claim that overstates
//! itself is worse than none.
//!
//!   * IT DOES NOT WITNESS `checked_mul`'s OVERFLOW ARM. `n` is read as a `u32`, so it
//!     is at most 4,294,967,295; times 68 that is ~2.9e11, which cannot overflow a
//!     64-bit `usize`. On every target this repository's CI runs, `checked_mul` here
//!     ALWAYS returns `Some` and the `is_none_or` None-branch is dead code. Worse, both
//!     branches return the same `Truncated`, so even on a 32-bit target where the
//!     overflow is reachable the public API cannot tell the arms apart. Replacing
//!     `checked_mul` with a plain multiply is an equivalent mutant on 64-bit and an
//!     unobservable one through this interface anywhere. What IS witnessed below is the
//!     multiplication by `SIG_ENTRY` and the comparison against `remaining`.
//!
//!   * IT DOES NOT MEASURE ALLOCATION, despite the guard's name and the module's own
//!     "must fail as a short read, not as an allocation". Signatures land in a
//!     `BTreeMap` built by repeated `insert`, not in a `Vec::with_capacity(n)`. Nothing
//!     is reserved from the declared count, so an allocation counter reads roughly the
//!     same with the guard and without it -- the unbounded version simply allocates a
//!     handful of nodes before the short read stops it. An allocation-counting test here
//!     would pass for a coincidental reason and witness nothing, which is precisely the
//!     defect being repaired. The bound's real, observable effect is that it refuses
//!     before INTERPRETING any following byte, and that is what is asserted.
//!
//!   * IT SAYS NOTHING ABOUT AUTHENTICITY. Everything here is framing. Whether the
//!     signatures verify is `is_valid`'s question and is tested elsewhere.

use acfa_finality::wire::{decode_cert, decode_fork, encode_cert, encode_fork, WireError};
use acfa_finality::{CertFork, CertTuple, Certificate};
use acfa_receipt::hash::h;
use acfa_receipt::identity::Identity;

/// Offset of the u32 signature count inside an encoded certificate:
/// magic(8) + version(2) + round(8) + a_root(32) + e_cut_root(32) + rho(32).
const COUNT_AT: usize = 8 + 2 + 8 + 32 + 32 + 32;
/// On-wire width of one signature entry: signer id(4) + signature(64).
const SIG_ENTRY: usize = 4 + 64;
/// A certificate body after the frame: round(8) + three roots(96) + count(4).
const CERT_BODY: usize = 8 + 32 + 32 + 32 + 4;
/// Frame width: magic(8) + version(2).
const FRAME: usize = 8 + 2;

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

/// Swap the two 68-byte signature entries that begin at `entries_at`, so that the ids
/// on the wire DESCEND. This is the tripwire: the entry loop refuses a descending pair
/// with `NotCanonical`, which is a different error from the `Truncated` the bound emits,
/// so reaching the loop at all becomes observable from outside the crate.
fn swap_entry_pair(bytes: &mut [u8], entries_at: usize) {
    let (first, second) = (entries_at, entries_at + SIG_ENTRY);
    let a = bytes[first..first + SIG_ENTRY].to_vec();
    let b = bytes[second..second + SIG_ENTRY].to_vec();
    bytes[first..first + SIG_ENTRY].copy_from_slice(&b);
    bytes[second..second + SIG_ENTRY].copy_from_slice(&a);
}

/// A single certificate carrying two signature entries written in descending id order,
/// with the declared count overwritten to `declared`.
///
/// The honest-count assertion inside is the reach check: it proves the bytes after the
/// count really would be rejected as non-canonical if the loop ever saw them. Without
/// it, a hostile case asserting `Truncated` could be passing because the tripwire was
/// never armed, which is indistinguishable from passing for the right reason.
fn descending_pair_with_declared_count(declared: u32) -> Vec<u8> {
    let c = signed(tuple(1, "A"), &[1, 5]);
    let mut bytes = encode_cert(&c);
    assert_eq!(
        bytes.len(),
        COUNT_AT + 4 + 2 * SIG_ENTRY,
        "layout assumption: two entries directly follow the count"
    );

    swap_entry_pair(&mut bytes, COUNT_AT + 4);
    assert_eq!(
        decode_cert(&bytes),
        Err(WireError::NotCanonical("signers must ascend strictly")),
        "tripwire must be armed: with an honest count these bytes reach the entry loop \
         and are refused there, so a later Truncated cannot be the loop's doing"
    );

    bytes[COUNT_AT..COUNT_AT + 4].copy_from_slice(&declared.to_be_bytes());
    bytes
}

#[test]
fn a_count_that_cannot_fit_is_refused_before_the_first_entry_is_read() {
    // 136 bytes of entries actually remain after the count. Every declared count below
    // needs more than that, so the bound must fire. The specific error is the whole
    // point: Truncated means the guard refused; NotCanonical would mean the loop ran and
    // tripped over the descending pair, i.e. the bound did not exist.
    for declared in [3u32, 100, 136, 1 << 20, u32::MAX / 2, u32::MAX] {
        let hostile = descending_pair_with_declared_count(declared);
        assert_eq!(
            decode_cert(&hostile),
            Err(WireError::Truncated),
            "a declared count of {declared} must be refused by the bound, before any \
             byte after the count is interpreted as a signature entry"
        );
    }
}

#[test]
fn the_bound_is_bytes_needed_not_entries_declared() {
    // The narrow region where dropping the `* SIG_ENTRY` multiplier is observable: a
    // count that is smaller than the remaining BYTE count but far larger than the
    // remaining ENTRY count. 136 bytes remain; 100 entries need 6800.
    //
    // With `need = count * 68` the guard fires -> Truncated.
    // With `need = count` it does not -> the loop runs -> NotCanonical.
    for declared in [3u32, 50, 100, 136] {
        let hostile = descending_pair_with_declared_count(declared);
        assert!(
            (declared as usize) <= 2 * SIG_ENTRY,
            "precondition: {declared} must sit below the remaining byte count, or this \
             case cannot distinguish the multiplier from its absence"
        );
        assert!(
            (declared as usize) > 2,
            "precondition: {declared} must exceed the entries actually present"
        );
        assert_eq!(
            decode_cert(&hostile),
            Err(WireError::Truncated),
            "the bound must compare BYTES NEEDED ({} = {declared} x {SIG_ENTRY}) against \
             the {} bytes remaining, not the raw count against the byte count",
            declared as usize * SIG_ENTRY,
            2 * SIG_ENTRY
        );
    }
}

#[test]
fn the_second_certificate_of_a_fork_is_bounded_too() {
    // Fork evidence decodes two certificates from one buffer. The second one is where a
    // bound is easiest to lose: by then `remaining` is small and the reader is deep in
    // the record. Same tripwire, applied to the trailing certificate.
    let a = signed(tuple(5, "A"), &[1, 2]);
    let b = signed(tuple(5, "B"), &[3, 7]);
    let k = CertFork::canonical(a, b).expect("conflicting tuples are a fork");
    let mut bytes = encode_fork(&k);

    let b_start = FRAME + CERT_BODY + 2 * SIG_ENTRY;
    let b_count_at = b_start + CERT_BODY - 4;
    let b_entries_at = b_start + CERT_BODY;
    assert_eq!(
        bytes.len(),
        b_entries_at + 2 * SIG_ENTRY,
        "layout assumption for the trailing certificate"
    );

    swap_entry_pair(&mut bytes, b_entries_at);
    assert_eq!(
        decode_fork(&bytes),
        Err(WireError::NotCanonical("signers must ascend strictly")),
        "tripwire must be armed in the SECOND certificate too"
    );

    for declared in [3u32, 100, u32::MAX] {
        let mut hostile = bytes.clone();
        hostile[b_count_at..b_count_at + 4].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(
            decode_fork(&hostile),
            Err(WireError::Truncated),
            "the trailing certificate's count of {declared} must be refused by the bound"
        );
    }
}

#[test]
fn an_inflated_count_cannot_annex_the_bytes_of_the_next_field() {
    // A subtler failure than "claims four billion": claim just a FEW more entries than
    // you brought. Without a bound the loop would happily walk forward into whatever
    // follows -- here, the trailing certificate of a fork -- and reinterpret its header
    // as signature entries. The bound refuses at the count, so the leading certificate
    // can never consume its neighbour.
    let a = signed(tuple(5, "A"), &[1, 2]);
    let b = signed(tuple(5, "B"), &[3, 7]);
    let k = CertFork::canonical(a, b).expect("conflicting tuples are a fork");
    let honest = encode_fork(&k);

    // The leading certificate declares 2 and brings 2, but 244 bytes of the trailing
    // certificate follow it, so an unbounded reader has plenty of material to misread.
    let a_count_at = FRAME + CERT_BODY - 4;
    let mut hostile = honest.clone();
    let overreach = 2 + (CERT_BODY + 2 * SIG_ENTRY).div_ceil(SIG_ENTRY) as u32;
    hostile[a_count_at..a_count_at + 4].copy_from_slice(&overreach.to_be_bytes());
    assert_eq!(
        decode_fork(&hostile),
        Err(WireError::Truncated),
        "a leading certificate declaring {overreach} entries must be refused at the \
         count, not after eating into the record that follows it"
    );
}

#[test]
fn well_formed_records_at_the_exact_bound_still_decode() {
    // THE ACCEPTING TWIN. Every honest certificate hits this guard with `need` exactly
    // equal to `remaining`: the count is followed by its own entries and nothing else.
    // So the guard is one character from rejecting all valid input, and a
    // reject-everything stub would satisfy every hostile assertion above. These cases
    // are what forbid it.
    for signers in [&[][..], &[1][..], &[1, 2][..], &[3, 1, 2, 9, 40][..]] {
        let c = signed(tuple(7, "A"), signers);
        let bytes = encode_cert(&c);
        let back = decode_cert(&bytes).unwrap_or_else(|e| {
            panic!(
                "a certificate with {} signers must decode, got {e:?}",
                signers.len()
            )
        });
        assert_eq!(back, c, "exact-fit decode must be lossless");
        assert_eq!(encode_cert(&back), bytes, "and must stay canonical");
    }

    // And the strict-inequality side of the bound, which the single-certificate cases
    // never exercise: inside fork evidence the LEADING certificate's entries are
    // strictly fewer bytes than what remains, because the trailing certificate is still
    // to come. A bound written as `need != remaining` would pass every test above and
    // die here.
    let a = signed(tuple(5, "A"), &[1, 2]);
    let b = signed(tuple(5, "B"), &[3, 7]);
    let k = CertFork::canonical(a, b).expect("conflicting tuples are a fork");
    let bytes = encode_fork(&k);
    let back = decode_fork(&bytes).expect("well-formed fork evidence must decode");
    assert_eq!(back, k);
    assert_eq!(encode_fork(&back), bytes);
}

#[test]
fn the_honest_count_boundary_moves_by_one_in_each_direction() {
    // Pin the edge from both sides on the same buffer, so the accepting twin is not a
    // different record that happens to work. n is honest; n+1 must be refused by the
    // bound; n-1 leaves a spare entry and must be refused as trailing bytes, which also
    // proves the guard is not simply rejecting everything that is not `n`.
    let c = signed(tuple(2, "A"), &[1, 2, 3]);
    let honest = encode_cert(&c);
    assert!(decode_cert(&honest).is_ok(), "n = 3 is the honest count");

    let mut one_more = honest.clone();
    one_more[COUNT_AT..COUNT_AT + 4].copy_from_slice(&4u32.to_be_bytes());
    assert_eq!(
        decode_cert(&one_more),
        Err(WireError::Truncated),
        "one entry more than the bytes allow must be refused by the bound"
    );

    let mut one_fewer = honest.clone();
    one_fewer[COUNT_AT..COUNT_AT + 4].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(
        decode_cert(&one_fewer),
        Err(WireError::TrailingBytes),
        "under-declaring must fall through the bound and be caught as trailing bytes -- \
         if this reads Truncated the guard is refusing more than it should"
    );
}
