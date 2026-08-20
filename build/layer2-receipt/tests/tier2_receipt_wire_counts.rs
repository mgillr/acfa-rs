// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! The three length prefixes in `decode` that nothing was watching.
//!
//! `wire::decode` bounds every count it reads against the bytes actually present before it
//! hands that count to `Vec::with_capacity`. A by-line mutation sweep found that three of
//! those bounds could be deleted -- replaced by a bare `as usize` cast -- and the entire
//! crate suite stayed green: the CONTRIBUTION count, the PROOF count, and the length of the
//! optional CLAIMED AGGREGATE. Only the PKI count and the per-contribution tensor dimension
//! were witnessed by anything. The guard the crate documents most loudly, in the doc comment
//! on `R::count` -- **never allocate on an untrusted length prefix** -- was three-fifths
//! unguarded.
//!
//! WHY THE EXISTING TESTS COULD NOT SEE IT, WHICH IS THE PART WORTH READING. Two tests
//! already blow these fields up to `u32::MAX` and assert `Err(WireError::Truncated)`. That
//! assertion holds WITH THE BOUND AND WITHOUT IT. Delete the bound and the decoder reserves
//! the gigabytes first and only then runs off the end of the input, a few bytes later, in the
//! per-element read -- which returns the very same `Truncated`. Measured on the fixture below,
//! with the bound deleted: the proof count still returns `Truncated`, and so does the
//! aggregate length. The returned error was never the property under test. The property is
//! WHEN the refusal happens: before or after committing memory that the input never
//! justified. No assertion on the return value can see that, so those tests passed for a
//! reason unrelated to the thing they are named after, and the mutants walked through them.
//!
//! The contribution count is the instructive exception and the reason the error assertions
//! here are kept as well as the allocation ones. With ITS bound deleted, this fixture comes
//! back `ValueOutOfRange` rather than `Truncated` -- the unbounded loop reads the following
//! signature bytes as tensor values and one of them lands outside the Q16.16 range before the
//! input runs out. That is luck, not coverage: it depends on what happens to sit after the
//! count field, it would evaporate under a fixture whose trailing bytes parsed in range, and
//! it did not save the other two sites. An error-variant assertion is a witness for at most
//! one of these three mutants and there is no way to know in advance which.
//!
//! On this host it is invisible a second time over. macOS satisfies a 400 GB
//! `with_capacity` lazily out of address space and never touches a page, so the unguarded
//! decoder does not even slow down; the same mutant on Linux is the 15 GB allocation abort
//! that CI originally caught and that `R::count` exists to prevent. A test that relies on the
//! platform to notice a defect is a test that works on one platform.
//!
//! SO THESE TESTS MEASURE THE ALLOCATION, NOT THE ERROR. The file installs a
//! `#[global_allocator]` that records the largest single request made on the calling thread
//! while armed, and each hostile-count test asserts BOTH that the refusal is the specific
//! `Truncated` variant AND that decoding the 1044-byte fixture never asked the allocator for
//! more than 64 KiB. The second assertion is the witness; the first is there because a
//! decoder that refused with the wrong error, or refused everything, would still satisfy the
//! second.
//!
//! EVERY HOSTILE INPUT HERE IS AN HONEST RECEIPT WITH FOUR BYTES CHANGED. The fixture is
//! encoded by the crate's own encoder, the offset of each count field is computed and then
//! CHECKED against the bytes found there before anything is patched, and each test asserts
//! that the unpatched bytes decode to exactly the receipt they came from. Same bytes, one
//! field, opposite verdicts: that is what makes it the count field, and not some other
//! malformation, that caused the refusal.
//!
//! WHAT THIS FILE DOES NOT COVER, stated plainly because a guard file that oversells itself
//! is worse than none:
//!
//! * **It does not pin an exact length check, because there is not one.** `R::count` is a
//!   coarse allocation bound: it multiplies the claimed count by the SMALLEST an element can
//!   be and compares against the remaining bytes. A count that is only slightly too large --
//!   five contributions claimed where four are carried -- passes the bound and is caught
//!   later by the per-element read. That is by design, and it means an off-by-one test here
//!   would witness nothing at all.
//! * **It does not cover `decode_redacted`.** That function carries its own four `count`
//!   calls on their own lines, which are their own mutants; a bound deleted there is not
//!   caught here.
//! * **It does not cover 32-bit targets, and neither does anything else here.** The
//!   `checked_mul` arm inside `count` cannot overflow at 64-bit width -- the count is a `u32`
//!   and the largest element minimum in the format is 204 bytes, a product under 2^40 -- so on
//!   this host that arm is unreachable and a `wrapping_mul` there is an equivalent mutant,
//!   confirmed against the whole crate suite. At 32-bit `usize` it is not equivalent at all: a
//!   claimed proof count of 21 053 762 wraps to a `need` of 152 bytes, passes the bound, and
//!   reserves 4 GiB. Witnessing that needs a 32-bit target, which this file does not have.
//! * **It measures the largest single request, not total footprint.** A mutant that leaked
//!   the same gigabyte in small pieces would not trip it.
//! * **It says nothing about whether a receipt is true.** Everything here is the decoder;
//!   signatures, roots and the aggregate are `verify`'s business.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki};
use acfa_receipt::{decode, encode, Contribution, EquivProof, Receipt, Rule, WireError};

/// Krum at `f = 1` on this build's fixed-point scale.
///
/// A NAMED FIXTURE, NOT A DEFAULT. A contribution signed under different round parameters is
/// filtered out of the round by `Receipt::issue`, exactly as a foreign `ctx` is, so a test that
/// needs other parameters has to say so rather than inherit these silently.
const BULYAN_F3: acfa_receipt::RoundParams = acfa_receipt::RoundParams {
    rule: acfa_receipt::Rule::Bulyan,
    f: 3,
    frac_bits: acfa_receipt::FRAC_BITS,
};

const PARAMS_DEFAULT: acfa_receipt::RoundParams = acfa_receipt::RoundParams {
    rule: acfa_receipt::Rule::Krum,
    f: 1,
    frac_bits: acfa_receipt::FRAC_BITS,
};

// ------------------------------------------------------------------- the instrument

thread_local! {
    /// Armed only around the call under test, and only on the thread making it -- the
    /// harness runs tests in parallel and every other thread allocates freely.
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

/// A pass-through allocator that records the largest single request while armed.
///
/// `Cell` with a const initialiser and no destructor, reached through `try_with`: thread-local
/// access from inside the allocator must not itself allocate or run a lazy initialiser, or the
/// instrument recurses into the thing it is measuring.
struct Watch;

unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        unsafe { System.realloc(p, l, new_size) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static WATCH: Watch = Watch;

fn note(n: usize) {
    let _ = WATCHING.try_with(|w| {
        if w.get() {
            let _ = LARGEST.try_with(|m| {
                if n > m.get() {
                    m.set(n);
                }
            });
        }
    });
}

fn largest_allocation_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    LARGEST.with(|m| m.set(0));
    WATCHING.with(|w| w.set(true));
    let out = f();
    WATCHING.with(|w| w.set(false));
    (out, LARGEST.with(|m| m.get()))
}

/// The ceiling every decode of the 1044-byte fixture must stay under.
///
/// Two orders of magnitude above what the fixture legitimately needs and five orders below
/// what an unbounded count reserves, so neither a slack allocation in `BTreeMap` nor a change
/// of allocator moves the verdict.
const MAX_HONEST_ALLOC: usize = 64 * 1024;

/// The count each hostile receipt claims.
///
/// Any count above roughly seven already exceeds what the fixture's remaining bytes could
/// carry, so the bound refuses far smaller numbers than this. Four million is chosen so the
/// UNBOUNDED path is unmistakable when it is taken: 416 MB reserved for contributions, 832 MB
/// for proofs, 32 MB for the aggregate, from a receipt of 1044 bytes. `u32::MAX` would be
/// more dramatic and less useful -- on Linux it aborts the process instead of failing an
/// assertion, and an abort is a worse signal than a number.
const HOSTILE_COUNT: u32 = 4_000_000;

// ---------------------------------------------------------------------- the fixture

/// Krum at f = 1, the common case in this file.
fn contrib(a: &Identity, rnd: u64, t: &[i64]) -> Contribution {
    contrib_with(a, PARAMS_DEFAULT, rnd, t)
}

fn ident(n: u32) -> Identity {
    Identity::from_secret(n, &[n as u8; 32])
}

fn contrib_with(
    a: &Identity,
    params: acfa_receipt::RoundParams,
    rnd: u64,
    t: &[i64],
) -> Contribution {
    let th = h(&enc_tensor(t));
    Contribution {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params,
        rnd,
        node_id: a.node_id,
        tensor: t.to_vec(),
        sig: a.sign(&contrib_msg(
            &acfa_receipt::identity::NO_CONTEXT,
            &params,
            rnd,
            a.node_id,
            &th,
        )),
    }
}

fn proof(node_id: u32, tag: u8) -> EquivProof {
    EquivProof {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        sig_preimage: acfa_receipt::identity::PreimageVersion::V2,
        params: PARAMS_DEFAULT,
        rnd: 1,
        node_id,
        h1: [tag; 32],
        h2: [tag.wrapping_add(1); 32],
        sig1: [tag.wrapping_add(2); 64],
        sig2: [tag.wrapping_add(3); 64],
    }
}

/// An honest receipt with every count field populated and NO TWO COUNTS EQUAL.
///
/// Three identities, four contributions, two proofs, an aggregate of five. The distinctness
/// is load-bearing for [`Offsets`]: a wrong offset that happened to land on another count
/// field would otherwise pass the premise check silently, which is the exact way a test stops
/// exercising the branch it is named after.
///
/// BUILT LEAF-SORTED because the decoder refuses any other order. `encode` sorts defensively,
/// so an unsorted fixture would still encode -- but it would then decode to a receipt that is
/// not the one this file built, and the `decode(honest) == fixture` twin assertions would be
/// testing the sort rather than the counts.
fn fixture() -> Receipt {
    let ids: Vec<Identity> = (1..=3u32).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut contributions: Vec<Contribution> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| contrib(id, 1, &[i as i64 * 3, i as i64 + 1]))
        .collect();
    // A fourth contribution from an identity that already contributed: a legitimate shape
    // (it is what an equivocating node produces) and it keeps the count off the pki count.
    contributions.push(contrib(&ids[0], 1, &[41, 42]));
    contributions.sort_by_key(|c| c.leaf());

    let mut proofs = vec![proof(2, 0x10), proof(3, 0x40)];
    proofs.sort_by_key(|p| p.leaf());

    Receipt {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        round: 7,
        f: 1,
        rule: Rule::Krum,
        frac_bits: acfa_receipt::FRAC_BITS,
        pki,
        contributions,
        proofs,
        claimed_state_root: [0xAA; 32],
        claimed_output_root: [0xBB; 32],
        claimed_aggregate: Some(vec![1, 2, 3, 4, 5]),
    }
}

/// Byte offsets of the four length prefixes, derived from the format rather than found by
/// searching -- a search for the count VALUE would find whichever field matched first.
struct Offsets {
    pki_count: usize,
    contribution_count: usize,
    proof_count: usize,
    aggregate_presence: usize,
    aggregate_len: usize,
    total: usize,
}

fn offsets(r: &Receipt) -> Offsets {
    const HEAD: usize = 8 + 2 + 32 + 8 + 4 + 1 + 4; // magic, version, ctx, round, f, rule, frac_bits
    const PKI_ELEM: usize = 4 + 32;
    const PROOF_ELEM: usize = 8 + 4 + 32 + 32 + 64 + 64;

    let pki_count = HEAD;
    let contribution_count = pki_count + 4 + r.pki.len() * PKI_ELEM;
    let mut o = contribution_count + 4;
    for c in &r.contributions {
        o += 8 + 4 + 4 + c.tensor.len() * 8 + 64;
    }
    let proof_count = o;
    let roots = proof_count + 4 + r.proofs.len() * PROOF_ELEM;
    let aggregate_presence = roots + 32 + 32;
    let aggregate_len = aggregate_presence + 1;
    let total = match &r.claimed_aggregate {
        None => aggregate_presence + 1,
        Some(a) => aggregate_len + 4 + a.len() * 8,
    };
    Offsets {
        pki_count,
        contribution_count,
        proof_count,
        aggregate_presence,
        aggregate_len,
        total,
    }
}

fn be32_at(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// The honest bytes with ONE count field overwritten, and a premise check that the field
/// really did hold the honest count first.
fn with_count(bytes: &[u8], off: usize, honest: u32, hostile: u32) -> Vec<u8> {
    assert_eq!(
        be32_at(bytes, off),
        honest,
        "premise: offset {off} must be the count field holding {honest}; if this fires the \
         test is patching some other part of the receipt and witnesses nothing"
    );
    let mut hand = bytes.to_vec();
    hand[off..off + 4].copy_from_slice(&hostile.to_be_bytes());
    hand
}

// ------------------------------------------------------------------ the instrument's own test

/// THE INSTRUMENT MUST BE ABLE TO FAIL. Every assertion below is of the form "the allocator
/// saw nothing large", which a broken instrument that always reports zero satisfies
/// perfectly -- three green tests witnessing nothing, which is the failure mode this whole
/// exercise exists to find. So: it sees a large allocation when one happens, and reports zero
/// when none does.
#[test]
fn the_allocation_instrument_can_actually_see_an_allocation() {
    let (v, peak) = largest_allocation_during(|| Vec::<u8>::with_capacity(8 << 20));
    assert!(
        peak >= 8 << 20,
        "the instrument missed an 8 MiB reservation (saw {peak}); every allocation assertion \
         in this file would then be vacuous"
    );
    drop(v);

    let (sum, quiet) = largest_allocation_during(|| 2 + 2);
    assert_eq!(sum, 4);
    assert_eq!(
        quiet, 0,
        "the instrument reported an allocation where none happened; the ceiling assertions \
         would then be measuring noise"
    );
}

// -------------------------------------------------------------------- the accepting twins

/// ACCEPTING TWIN, and the premise for everything else: the fixture round-trips, its four
/// length prefixes are exactly where [`Offsets`] says they are, and decoding it allocates
/// only what its bytes justify.
///
/// Without this, a decoder that refused every input would satisfy all three hostile-count
/// tests below.
#[test]
fn the_honest_fixture_round_trips_and_its_count_fields_are_where_this_file_says_they_are() {
    let r = fixture();
    let bytes = encode(&r);
    let o = offsets(&r);

    assert_eq!(
        bytes.len(),
        o.total,
        "the offset model disagrees with the encoder about the total length, so every offset \
         below is suspect"
    );
    assert_eq!(be32_at(&bytes, o.pki_count), 3, "pki count");
    assert_eq!(
        be32_at(&bytes, o.contribution_count),
        4,
        "contribution count"
    );
    assert_eq!(be32_at(&bytes, o.proof_count), 2, "proof count");
    assert_eq!(
        bytes[o.aggregate_presence], 1,
        "aggregate presence byte -- the aggregate length only exists when this is 1"
    );
    assert_eq!(be32_at(&bytes, o.aggregate_len), 5, "aggregate length");

    let (back, peak) = largest_allocation_during(|| decode(&bytes));
    assert_eq!(back, Ok(r), "the fixture must decode to itself");
    assert!(
        peak <= MAX_HONEST_ALLOC,
        "decoding {} honest bytes asked for {peak} in a single allocation",
        bytes.len()
    );
}

/// ACCEPTING TWIN for the SHAPE of the bound: it is measured against the bytes present, not
/// against a constant.
///
/// A tempting wrong fix for an unbounded length prefix is a fixed cap -- `if n > 1024 { .. }`
/// -- which stops the attack and also stops every deployment larger than the number someone
/// picked. Forty contributions is a legitimate receipt and must decode, byte-identically, on
/// the same code path.
#[test]
fn a_large_but_honest_receipt_is_still_accepted() {
    let ids: Vec<Identity> = (1..=40u32).map(ident).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let mut contributions: Vec<Contribution> = ids
        .iter()
        .enumerate()
        // SIGNED UNDER THE RECEIPT'S OWN PARAMETERS. The wire carries params ONCE in the
        // header and the decoder stamps every entry from it, so contributions carrying
        // different params hash to different leaves on the way back and land out of order.
        .map(|(i, id)| contrib_with(id, BULYAN_F3, 4, &[i as i64, i as i64 * 7 + 1]))
        .collect();
    contributions.sort_by_key(|c| c.leaf());
    let r = Receipt {
        ctx: acfa_receipt::identity::NO_CONTEXT,
        round: 4,
        f: 3,
        rule: Rule::Bulyan,
        frac_bits: acfa_receipt::FRAC_BITS,
        pki,
        contributions,
        proofs: vec![],
        claimed_state_root: [1; 32],
        claimed_output_root: [2; 32],
        claimed_aggregate: Some((0..64i64).collect()),
    };
    let bytes = encode(&r);
    let back = decode(&bytes).expect("a forty-contribution receipt is not hostile");
    assert_eq!(back, r);
    assert_eq!(encode(&back), bytes, "re-encoding is stable");
}

// ----------------------------------------------------------------- the three hostile counts

/// wire.rs, the CONTRIBUTION count: `let n_c = r.count(n_c_raw, 8 + 4 + 4 + 64)?;`
///
/// GUARD-DELETION: replace that line with `let n_c = n_c_raw as usize;` and this test goes
/// RED on the allocation ceiling -- `Vec::with_capacity(4_000_000)` over a 104-byte
/// `Contribution` reserves exactly 416 000 000 bytes from a 1044-byte receipt, six orders of
/// magnitude of amplification, measured.
///
/// The error assertion below ALSO goes red under that mutant, but for a reason this file
/// does not get to take credit for: the unbounded loop reads the bytes after the count as
/// tensor values and trips `ValueOutOfRange` before the input runs out. Change one signature
/// byte in the fixture and that becomes `Truncated` again, which is exactly what the other
/// two sites do. The ceiling is the witness; the variant assertion is a bonus that happens
/// to hold here.
#[test]
fn a_contribution_count_no_receipt_could_carry_is_refused_before_allocating() {
    let r = fixture();
    let bytes = encode(&r);
    let o = offsets(&r);
    let hand = with_count(&bytes, o.contribution_count, 4, HOSTILE_COUNT);

    let (got, peak) = largest_allocation_during(|| decode(&hand));
    assert!(
        peak <= MAX_HONEST_ALLOC,
        "a {}-byte receipt claiming {HOSTILE_COUNT} contributions made the decoder reserve \
         {peak} bytes in one allocation; the count was not bounded against the bytes present",
        hand.len()
    );
    assert_eq!(
        got,
        Err(WireError::Truncated),
        "the refusal must be Truncated, the variant `count` returns"
    );

    // Same bytes, that field honest: accepted. So it is the count that was refused.
    assert_eq!(
        decode(&bytes),
        Ok(r),
        "the unpatched twin must still decode"
    );
}

/// wire.rs, the PROOF count: `let n_p = r.count(n_p_raw, 8 + 4 + 32 + 32 + 64 + 64)?;`
///
/// GUARD-DELETION: replace that line with `let n_p = n_p_raw as usize;` and this test goes
/// RED on the allocation ceiling -- an `EquivProof` is 208 bytes in memory, so four million
/// of them is exactly 832 000 000 bytes reserved before a single proof byte is read, measured.
///
/// THE ALLOCATION CEILING IS THE ONLY WITNESS HERE. Under that mutant the decoder still
/// returns `Err(WireError::Truncated)`, measured -- identical to the guarded verdict -- so the
/// error assertion below stays green and every pre-existing test of this field with it. This
/// is the site that shows most plainly why the sweep found nothing: there was nothing in the
/// return value to find.
///
/// A SEPARATE MUTANT FROM THE CONTRIBUTION ONE, not a duplicate of it: the two bounds are two
/// lines, the sweep killed them independently, and a decoder can carry one and not the other.
/// The proof field is the more attractive of the two to an attacker for the same reason it is
/// the bigger number -- the per-element minimum is 204 bytes, so each unit of claimed count
/// buys 2.6x the memory a claimed contribution does.
#[test]
fn a_proof_count_no_receipt_could_carry_is_refused_before_allocating() {
    let r = fixture();
    let bytes = encode(&r);
    let o = offsets(&r);
    let hand = with_count(&bytes, o.proof_count, 2, HOSTILE_COUNT);

    let (got, peak) = largest_allocation_during(|| decode(&hand));
    assert!(
        peak <= MAX_HONEST_ALLOC,
        "a {}-byte receipt claiming {HOSTILE_COUNT} equivocation proofs made the decoder \
         reserve {peak} bytes in one allocation",
        hand.len()
    );
    assert_eq!(
        got,
        Err(WireError::Truncated),
        "the refusal must be Truncated, the variant `count` returns"
    );
    assert_eq!(
        decode(&bytes),
        Ok(r),
        "the unpatched twin must still decode"
    );
}

/// wire.rs, the CLAIMED-AGGREGATE length: `let d = r.count(d_raw, 8)?;` in the `Some` arm of
/// the presence byte.
///
/// GUARD-DELETION: replace that line with `let d = d_raw as usize;` and this test goes RED on
/// the allocation ceiling -- exactly 32 000 000 bytes of `i64` reserved for an aggregate the
/// receipt has forty bytes left to carry, measured. As with the proof count, the returned
/// error under that mutant is still `Truncated`, so the ceiling is the only witness.
///
/// THE SMALLEST ELEMENT IN THE FORMAT IS THE POINT, NOT AN AFTERTHOUGHT. Eight bytes per
/// element is the weakest bound of the three, so this field converts a claimed count into
/// memory more efficiently per byte of bound than either of the others, and it is the last
/// count in the stream -- reached only after the decoder has already done the pki, the
/// contributions and the proofs, which is exactly the shape of input a fuzzer explores last
/// and a hand-written test forgets. It also sits behind the presence byte, so a test that
/// built its fixture with `claimed_aggregate: None` would never reach this line at all; the
/// premise assertion on the presence byte in the round-trip test above is there to keep that
/// from happening silently.
#[test]
fn a_claimed_aggregate_length_no_receipt_could_carry_is_refused_before_allocating() {
    let r = fixture();
    let bytes = encode(&r);
    let o = offsets(&r);
    assert_eq!(
        bytes[o.aggregate_presence], 1,
        "premise: the aggregate must be PRESENT or the length field does not exist"
    );
    let hand = with_count(&bytes, o.aggregate_len, 5, HOSTILE_COUNT);

    let (got, peak) = largest_allocation_during(|| decode(&hand));
    assert!(
        peak <= MAX_HONEST_ALLOC,
        "a {}-byte receipt claiming an aggregate of {HOSTILE_COUNT} values made the decoder \
         reserve {peak} bytes in one allocation",
        hand.len()
    );
    assert_eq!(
        got,
        Err(WireError::Truncated),
        "the refusal must be Truncated, the variant `count` returns"
    );
    assert_eq!(
        decode(&bytes),
        Ok(r),
        "the unpatched twin must still decode"
    );
}

// ------------------------------------------------------------- the two arithmetic lines

/// The two arithmetic lines inside `R::count` -- `saturating_sub` and `checked_mul` -- and an
/// honest statement that this test does NOT witness either of them.
///
/// It cannot, and the reason is worth recording rather than leaving for the next sweep to
/// rediscover:
///
/// * `let remaining = self.b.len().saturating_sub(self.i);`. `self.i` only ever advances
///   through `take`, which refuses before advancing whenever `self.i + n > self.b.len()`, so
///   `self.i <= self.b.len()` holds at every call. A plain `-` is therefore an EQUIVALENT
///   MUTANT at every reachable state, and `R` is private, so no test can manufacture an
///   unreachable one. The `saturating_sub` is defence against a FUTURE reader who advances
///   `i` some other way, which is a real reason to keep it and not a property a test can
///   distinguish today.
/// * `match n.checked_mul(min_elem_bytes)`. `n` came from a `u32` and the largest element
///   minimum in this format is 204, so the product cannot exceed `u32::MAX * 204`, under 2^40,
///   and the overflow arm is unreachable at 64-bit width. `wrapping_mul` is an EQUIVALENT
///   MUTANT here -- confirmed, the whole crate suite including this file stays green under it
///   -- and a live one at 32-bit `usize`, where a claimed proof count of 21 053 762 wraps to a
///   `need` of 152 bytes, sails through the comparison and reserves 4 GiB. The arm is not dead
///   code; it is code that only this crate's 32-bit targets can execute, and nothing in this
///   repository executes it.
///
/// What this test does instead is pin the INVARIANT the first argument rests on: across every
/// truncation of an honest receipt -- the inputs most likely to walk `i` to the end of the
/// buffer -- decode terminates and refuses without panicking. Under the `-` mutant a reachable
/// underflow is a debug-build panic here rather than a silent mis-bound elsewhere, so this is
/// the tripwire for the day the invariant stops holding, not a witness for today.
#[test]
fn every_truncation_of_an_honest_receipt_is_refused_without_underflow() {
    let bytes = encode(&fixture());
    for cut in 0..bytes.len() {
        let (got, peak) = largest_allocation_during(|| decode(&bytes[..cut]));
        assert!(
            got.is_err(),
            "a receipt cut at {cut} of {} bytes decoded successfully",
            bytes.len()
        );
        assert!(
            peak <= MAX_HONEST_ALLOC,
            "a receipt cut at {cut} made the decoder reserve {peak} bytes"
        );
    }
    // And the uncut receipt is still accepted, so the loop above is not passing because
    // decode refuses everything.
    assert!(decode(&bytes).is_ok());
}
