// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Canonical wire encoding.
//!
//! THE ENCODING IS PART OF THE SECURITY ARGUMENT, NOT PACKAGING. A receipt is checked
//! by re-deriving hashes over its contents, so if the same logical receipt could be
//! encoded two ways, a verifier could be shown one form while a third party checked
//! another. Three rules make the encoding canonical:
//!
//! 1. **Fixed-width big-endian integers.** No varints, no native endianness. Every
//!    length and every value occupies the same bytes on every target.
//! 2. **Ordered collections.** Identities ascend by id; contributions and proofs ascend
//!    by leaf. Order is a function of content, never of arrival.
//! 3. **No optional or repeated fields.** Absence is encoded as an explicit zero-length
//!    or a presence byte, so there is exactly one encoding of "not there".
//!
//! Decoding is strict: trailing bytes, short reads, unknown rules and out-of-order
//! collections are all errors. A permissive decoder would re-open the ambiguity the
//! encoder just closed.

use crate::entry::{Contribution, EquivProof};
use crate::identity::{Pki, PubKey, Sig};
use crate::receipt::Receipt;
use crate::redact::{RedactedContribution, RedactedReceipt};
use crate::resolve::Rule;

pub const MAGIC: &[u8; 8] = b"ACFA-R1\0";
/// Wire magic for a REDACTED receipt.
///
/// Deliberately a different string, not a flag inside the existing format. A full-receipt
/// decoder must REJECT redacted bytes and this decoder must reject full ones, so no caller can
/// be handed a receipt carrying less evidence than it believes it has. A version bit inside one
/// format would have made that a branch someone could forget to take; a different magic makes
/// it a decode failure.
pub const MAGIC_REDACTED: &[u8; 8] = b"ACFA-X1\0";
pub const VERSION: u16 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    BadMagic,
    UnsupportedVersion(u16),
    Truncated,
    TrailingBytes,
    UnknownRule(u8),
    NotCanonical(&'static str),
    /// A tensor value on the wire lies outside the Q16.16 representable range
    /// (`+/-2^31`).
    ///
    /// This is the UNTRUSTED entry point, so the bound belongs here as well as in the
    /// aggregator's own `check`. Both, not either: this one stops a hostile receipt at the
    /// door, and the aggregator's stops a `Contribution` assembled by any other route. The
    /// aggregator's i128 accumulators are safe by construction only while every value that
    /// reaches them is bounded, and an unbounded value reaching them overflowed the score
    /// accumulator -- a panic reachable from bytes an attacker chooses.
    ValueOutOfRange,
    /// rust-12. A fault bound that does not fit the wire's `u32` field.
    ///
    /// ENCODE-SIDE ONLY. `decode` reads a `u32` and cannot produce this, but the enum is
    /// shared by both directions so every `WireError` match must still cover it.
    FaultBoundTooLarge {
        f: usize,
    },
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::BadMagic => write!(f, "not an ACFA receipt: magic bytes do not match"),
            WireError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported wire version {v}, this build speaks {VERSION}"
                )
            }
            WireError::Truncated => write!(f, "stream ended mid-field"),
            WireError::TrailingBytes => write!(f, "trailing bytes after a complete receipt"),
            WireError::UnknownRule(b) => write!(f, "unknown aggregation rule discriminant {b}"),
            WireError::NotCanonical(why) => write!(f, "not canonically encoded: {why}"),
            WireError::ValueOutOfRange => write!(
                f,
                "a tensor value lies outside the Q16.16 representable range (+/-2^31)"
            ),
            WireError::FaultBoundTooLarge { f: bound } => write!(
                f,
                "fault bound f = {bound} does not fit the wire's u32 field; refusing rather \
                 than truncating, because a truncated bound changes the verdict"
            ),
        }
    }
}

impl core::error::Error for WireError {}

// ------------------------------------------------------------------ encoding

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn raw(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
}

/// KNOWN DEFECT, crypto-09-2, MEASURED AND UNFIXED PENDING AN API RULING. DO NOT "TIDY"
/// THE `as u32` CASTS BELOW WITHOUT READING THIS.
///
/// `Receipt::f` is a `usize`, and this function writes it as a `u32`. On a 64-bit target
/// that cast TRUNCATES MODULO 2^32, silently, with no error path -- `encode` is infallible
/// by signature, so it cannot refuse. That contradicts the crate's own refuse-not-saturate
/// discipline, which `src/fixed.rs` in `acfa-aggregate` holds to for exactly this reason.
///
/// THE CONSEQUENCE IS NOT A LOST NUMBER, IT IS A VERDICT THAT DEPENDS ON WHETHER THE
/// RECEIPT CROSSED A SERIALISATION BOUNDARY. Measured, `f = 2^32 + 1` against a policy of
/// `f = 1`:
///
///   in memory                      -> Err(FaultBoundMismatch { policy: 1, receipt: 4294967297 })
///   after encode + decode          -> Ok(())
///
/// Two honest verifiers holding the SAME receipt reach OPPOSITE verdicts, one having
/// serialised it and one not. For a protocol whose whole proposition is that everyone who
/// re-executes a receipt reaches the same answer, that is the defect, and it is worse than
/// the truncation that causes it. `encode` is also NON-INJECTIVE as a direct result: two
/// receipts differing only in `f` produce byte-identical output, so receipt bytes do not
/// determine the receipt.
///
/// HONEST SEVERITY: THIS IS NOT REMOTELY EXPLOITABLE and should not be filed as though it
/// were. `decode` reads a `u32`, so no attacker-supplied stream can produce an out-of-range
/// `f` in the first place; the state is only reachable by a local caller assigning to the
/// `pub f` field. It is a determinism and injectivity defect, not an attack.
///
/// The other five `as u32` casts here are the same cast on `len()` values, and they are
/// NOT equally reachable: each would require actually materialising four billion elements.
/// `f` is the only one that can be enormous without allocating anything, which is why it
/// is the one called out.
///
/// PARTLY FIXED, AND THE HALF THAT REMAINS IS DELIBERATE. Every candidate breaks something a
/// consumer sees: `encode -> Result` changes a public signature used at 33 call sites across
/// 11 files, `f: usize -> u32` changes a public field, and writing `f` as a `u64` changes the
/// wire format.
///
/// So the fix is ADDITIVE: [`encode_checked`] is the same function with the one refusal it
/// needs, and `encode` is left exactly as it is. A caller who needs bytes that mean what the
/// receipt means now has a total path; a caller who does not is unaffected and no wire byte
/// moved. WHAT IS NOT FIXED is that `encode` remains the obvious name and still truncates --
/// closing that is the signature ruling, and it is still B's rather than taken unilaterally.
///
/// A COMMENT CANNOT FAIL, so this paragraph is not the guard. The guard is
/// `tests/rust12_total_encode.rs`, which pins BOTH halves: that `encode_checked` refuses, and
/// that `encode` still truncates and is still non-injective. The second is a characterisation
/// test and says so -- when it goes red, `encode` became total and it should be inverted, not
/// repaired.
///
/// WHAT DOES AND DOES NOT WITNESS THIS FUNCTION. `examples/digest.rs` encodes each of the
/// five fingerprint scenarios and hashes the RESULTING BYTES, and CI diffs those digests
/// across eight architectures including big-endian s390x. So the wire format IS covered,
/// strongly, ACROSS ARCHITECTURES -- verified by mutation, not by reading: swapping the
/// `round` and `f` field order below moves all five per-scenario digests.
///
/// What is NOT covered is cross-IMPLEMENTATION agreement. `tests/golden/generate_l2.py` is an
/// independent Python reference, but it produces vectors for `resolve` only, so nothing
/// checks that a second implementation emits the same BYTES. One implementation agreeing
/// with itself on eight architectures is a different property from two implementations
/// agreeing, and only the first is tested.
///
/// The fingerprint is also blind to the truncation described above, because all five
/// scenarios use a small `f`, so the case cannot arise in the digest's inputs.
/// rust-12, THE TOTAL ENCODER. `encode` cannot refuse -- it is infallible by signature --
/// so it truncates `f` modulo 2^32 and produces bytes that decode to a DIFFERENT receipt.
/// This is the same function with the one refusal it needs.
///
/// USE THIS WHEREVER THE BYTES WILL BE COMPARED, RE-EXECUTED OR TRUSTED. `encode` is kept
/// unchanged because 33 call sites across 11 files depend on its signature and the wire
/// format is unaffected either way -- but every one of those is a site where a receipt with
/// an out-of-range `f` would serialise to something that is not itself.
///
/// `u32::try_from` rather than `r.f > u32::MAX as usize`: on a 32-bit target that comparison
/// is always false and the guard would be dead code, which is the `num-03` width-dependence
/// class. `try_from` is correct at every width.
pub fn encode_checked(r: &Receipt) -> Result<Vec<u8>, WireError> {
    if u32::try_from(r.f).is_err() {
        return Err(WireError::FaultBoundTooLarge { f: r.f });
    }
    Ok(encode(r))
}

pub fn encode(r: &Receipt) -> Vec<u8> {
    let mut w = W(Vec::new());
    w.raw(MAGIC);
    w.u16(VERSION);
    w.u64(r.round);
    w.u32(r.f as u32);
    w.u8(r.rule.as_wire());

    w.u32(r.pki.len() as u32);
    for (id, pk) in &r.pki {
        w.u32(*id);
        w.raw(pk);
    }

    // BTreeMap iteration in `State` is already leaf-ordered; sort defensively so the
    // encoder cannot emit a non-canonical stream even if handed an unordered vector.
    let mut cs = r.contributions.clone();
    cs.sort_by_key(|c| c.leaf());
    w.u32(cs.len() as u32);
    for c in &cs {
        w.u64(c.rnd);
        w.u32(c.node_id);
        w.u32(c.tensor.len() as u32);
        for v in &c.tensor {
            w.i64(*v);
        }
        w.raw(&c.sig);
    }

    let mut ps = r.proofs.clone();
    ps.sort_by_key(|p| p.leaf());
    w.u32(ps.len() as u32);
    for p in &ps {
        w.u64(p.rnd);
        w.u32(p.node_id);
        w.raw(&p.h1);
        w.raw(&p.h2);
        w.raw(&p.sig1);
        w.raw(&p.sig2);
    }

    w.raw(&r.claimed_state_root);
    w.raw(&r.claimed_output_root);

    match &r.claimed_aggregate {
        None => w.u8(0),
        Some(a) => {
            w.u8(1);
            w.u32(a.len() as u32);
            for v in a {
                w.i64(*v);
            }
        }
    }
    w.0
}

// ------------------------------------------------------------------ decoding

struct R<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.i + n > self.b.len() {
            return Err(WireError::Truncated);
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn arr32(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn arr64(&mut self) -> Result<Sig, WireError> {
        Ok(self.take(64)?.try_into().unwrap())
    }

    /// Read a count and refuse it if the remaining input cannot possibly hold that many
    /// elements of `min_elem_bytes` each.
    ///
    /// **NEVER ALLOCATE ON AN UNTRUSTED LENGTH PREFIX.** A count is 4 bytes the attacker
    /// chooses. `Vec::with_capacity(count)` on it lets a 40-byte hostile receipt ask the
    /// verifier for gigabytes: the process aborts on the allocation before a single
    /// signature is ever checked. That is a denial of service on the exact tool third
    /// parties are supposed to point at untrusted input, and it is not hypothetical --
    /// this crate shipped it, and CI caught it as a 15 GB allocation failure on Linux
    /// while macOS's overcommit hid it entirely.
    ///
    /// Bounding against the bytes actually present makes the count self-limiting: a
    /// receipt can only claim as many elements as it is long enough to carry.
    fn count(&self, n: u32, min_elem_bytes: usize) -> Result<usize, WireError> {
        let n = n as usize;
        let remaining = self.b.len().saturating_sub(self.i);
        match n.checked_mul(min_elem_bytes) {
            Some(need) if need <= remaining => Ok(n),
            _ => Err(WireError::Truncated),
        }
    }
}

pub fn decode(bytes: &[u8]) -> Result<Receipt, WireError> {
    let mut r = R { b: bytes, i: 0 };
    if r.take(8)? != MAGIC {
        return Err(WireError::BadMagic);
    }
    let v = r.u16()?;
    if v != VERSION {
        return Err(WireError::UnsupportedVersion(v));
    }
    let round = r.u64()?;
    let f = r.u32()? as usize;
    let rule_b = r.u8()?;
    let rule = Rule::from_wire(rule_b).ok_or(WireError::UnknownRule(rule_b))?;

    let n_pki_raw = r.u32()?;
    let n_pki = r.count(n_pki_raw, 4 + 32)?;
    let mut pki: Pki = Pki::new();
    let mut last_id: Option<u32> = None;
    // ONE KEY IS ONE IDENTITY, enforced here rather than assumed. Ascending-by-id gives a
    // canonical encoding; it does NOT make the id -> key map injective, and the signed
    // contribution message binds the round and the tensor hash but NOT the signer, so
    // authorship rests entirely on that injectivity. A PKI registering a second id to an
    // honest node's key therefore lets anyone REPLAY that node's signed bytes under the
    // extra identity, with no secret key at all: measured, five honest nodes, aggregate
    // moved from [10, 9] to [750002, 750001] and the receipt VERIFIED, because the clones
    // sit at distance zero from each other and Krum selects the tightest cluster. Refusing
    // a non-injective PKI closes it on the wire and costs no bytes. The README delegates
    // Sybil resistance to the PKI, so a PKI that maps two identities to one key is not a
    // deployment choice to be honoured, it is a broken PKI.
    let mut seen_keys: std::collections::BTreeSet<PubKey> = std::collections::BTreeSet::new();
    for _ in 0..n_pki {
        let id = r.u32()?;
        if let Some(prev) = last_id {
            if id <= prev {
                return Err(WireError::NotCanonical("pki not strictly ascending by id"));
            }
        }
        last_id = Some(id);
        let pk: PubKey = r.arr32()?;
        if !crate::identity::is_usable_pubkey(&pk) {
            return Err(WireError::NotCanonical(
                "pki contains an unusable public key",
            ));
        }
        if !seen_keys.insert(pk) {
            return Err(WireError::NotCanonical("pki reuses a public key"));
        }
        pki.insert(id, pk);
    }

    let n_c_raw = r.u32()?;
    let n_c = r.count(n_c_raw, 8 + 4 + 4 + 64)?;
    let mut contributions = Vec::with_capacity(n_c);
    for _ in 0..n_c {
        let rnd = r.u64()?;
        let node_id = r.u32()?;
        let d_raw = r.u32()?;
        let d = r.count(d_raw, 8)?;
        let mut tensor = Vec::with_capacity(d);
        for _ in 0..d {
            let v = r.i64()?;
            // Refuse at the door rather than saturate. Saturating would admit the receipt
            // and silently change the aggregate, which is the value-error-becoming-an-
            // order-error failure the fixed-point contract exists to exclude.
            if !(-(1i64 << 31)..=(1i64 << 31) - 1).contains(&v) {
                return Err(WireError::ValueOutOfRange);
            }
            tensor.push(v);
        }
        let sig = r.arr64()?;
        contributions.push(Contribution {
            rnd,
            node_id,
            tensor,
            sig,
        });
    }
    if contributions.windows(2).any(|w| w[0].leaf() >= w[1].leaf()) {
        return Err(WireError::NotCanonical(
            "contributions not strictly ascending by leaf",
        ));
    }

    let n_p_raw = r.u32()?;
    let n_p = r.count(n_p_raw, 8 + 4 + 32 + 32 + 64 + 64)?;
    let mut proofs = Vec::with_capacity(n_p);
    for _ in 0..n_p {
        proofs.push(EquivProof {
            rnd: r.u64()?,
            node_id: r.u32()?,
            h1: r.arr32()?,
            h2: r.arr32()?,
            sig1: r.arr64()?,
            sig2: r.arr64()?,
        });
    }
    if proofs.windows(2).any(|w| w[0].leaf() >= w[1].leaf()) {
        return Err(WireError::NotCanonical(
            "proofs not strictly ascending by leaf",
        ));
    }

    let claimed_state_root = r.arr32()?;
    let claimed_output_root = r.arr32()?;

    let claimed_aggregate = match r.u8()? {
        0 => None,
        1 => {
            let d_raw = r.u32()?;
            let d = r.count(d_raw, 8)?;
            let mut a = Vec::with_capacity(d);
            for _ in 0..d {
                a.push(r.i64()?);
            }
            Some(a)
        }
        _ => {
            return Err(WireError::NotCanonical(
                "aggregate presence byte not 0 or 1",
            ))
        }
    };

    if r.i != bytes.len() {
        return Err(WireError::TrailingBytes);
    }

    Ok(Receipt {
        round,
        f,
        rule,
        pki,
        contributions,
        proofs,
        claimed_state_root,
        claimed_output_root,
        claimed_aggregate,
    })
}

// ------------------------------------------------- redacted receipts (see `redact.rs`)

/// Encode a redacted receipt.
///
/// The same layout as `encode` except each contribution carries its 32-byte `tensor_hash` in
/// place of the length-prefixed tensor -- exactly the field the signature and the leaf already
/// committed to. Canonical by the same means: leaf-sorted, so two encoders of one set emit
/// identical bytes.
pub fn encode_redacted(r: &RedactedReceipt) -> Vec<u8> {
    let mut w = W(Vec::new());
    w.raw(MAGIC_REDACTED);
    w.u16(VERSION);
    w.u64(r.round);
    w.u32(r.f as u32);
    w.u8(r.rule.as_wire());

    w.u32(r.pki.len() as u32);
    for (id, pk) in &r.pki {
        w.u32(*id);
        w.raw(pk);
    }

    let mut cs = r.contributions.clone();
    cs.sort_by_key(|c| c.leaf());
    w.u32(cs.len() as u32);
    for c in &cs {
        w.u64(c.rnd);
        w.u32(c.node_id);
        w.raw(&c.tensor_hash);
        w.raw(&c.sig);
    }

    let mut ps = r.proofs.clone();
    ps.sort_by_key(|p| p.leaf());
    w.u32(ps.len() as u32);
    for p in &ps {
        w.u64(p.rnd);
        w.u32(p.node_id);
        w.raw(&p.h1);
        w.raw(&p.h2);
        w.raw(&p.sig1);
        w.raw(&p.sig2);
    }

    w.raw(&r.claimed_state_root);
    w.raw(&r.claimed_output_root);

    match &r.claimed_aggregate {
        None => w.u8(0),
        Some(a) => {
            w.u8(1);
            w.u32(a.len() as u32);
            for v in a {
                w.i64(*v);
            }
        }
    }
    w.0
}

/// Decode a redacted receipt.
///
/// **Carries every guard the full decoder carries.** A redacted receipt is a NARROWER door,
/// never a weaker one, so the checks that make the full door safe are repeated here rather than
/// assumed to have happened elsewhere: strictly-ascending PKI ids (canonical encoding), refusal
/// of an unusable public key (crypto-02 -- a small-order key verifies without any secret),
/// refusal of a reused public key (crypto-03 -- one key wearing several identities defeats the
/// distinctness the robustness argument rests on), counts bounded against the bytes actually
/// present, canonical leaf ordering, and no trailing bytes.
pub fn decode_redacted(bytes: &[u8]) -> Result<RedactedReceipt, WireError> {
    let mut r = R { b: bytes, i: 0 };
    if r.take(8)? != MAGIC_REDACTED {
        return Err(WireError::BadMagic);
    }
    let v = r.u16()?;
    if v != VERSION {
        return Err(WireError::UnsupportedVersion(v));
    }
    let round = r.u64()?;
    let f = r.u32()? as usize;
    let rule_b = r.u8()?;
    let rule = Rule::from_wire(rule_b).ok_or(WireError::UnknownRule(rule_b))?;

    let n_pki_raw = r.u32()?;
    let n_pki = r.count(n_pki_raw, 4 + 32)?;
    let mut pki: Pki = Pki::new();
    let mut last_id: Option<u32> = None;
    let mut seen_keys: std::collections::BTreeSet<PubKey> = std::collections::BTreeSet::new();
    for _ in 0..n_pki {
        let id = r.u32()?;
        if let Some(prev) = last_id {
            if id <= prev {
                return Err(WireError::NotCanonical("pki not strictly ascending by id"));
            }
        }
        last_id = Some(id);
        let pk: PubKey = r.arr32()?;
        if !crate::identity::is_usable_pubkey(&pk) {
            return Err(WireError::NotCanonical(
                "pki contains an unusable public key",
            ));
        }
        if !seen_keys.insert(pk) {
            return Err(WireError::NotCanonical("pki reuses a public key"));
        }
        pki.insert(id, pk);
    }

    // 8 + 4 + 32 + 64 is the smallest a redacted contribution can be on the wire.
    let n_c_raw = r.u32()?;
    let n_c = r.count(n_c_raw, 8 + 4 + 32 + 64)?;
    let mut contributions: Vec<RedactedContribution> = Vec::with_capacity(n_c);
    for _ in 0..n_c {
        let rnd = r.u64()?;
        let node_id = r.u32()?;
        let tensor_hash = r.arr32()?;
        let sig = r.arr64()?;
        contributions.push(RedactedContribution {
            rnd,
            node_id,
            tensor_hash,
            sig,
        });
    }
    if contributions.windows(2).any(|w| w[0].leaf() >= w[1].leaf()) {
        return Err(WireError::NotCanonical(
            "contributions not strictly ascending by leaf",
        ));
    }

    let n_p_raw = r.u32()?;
    let n_p = r.count(n_p_raw, 8 + 4 + 32 + 32 + 64 + 64)?;
    let mut proofs: Vec<EquivProof> = Vec::with_capacity(n_p);
    for _ in 0..n_p {
        proofs.push(EquivProof {
            rnd: r.u64()?,
            node_id: r.u32()?,
            h1: r.arr32()?,
            h2: r.arr32()?,
            sig1: r.arr64()?,
            sig2: r.arr64()?,
        });
    }
    if proofs.windows(2).any(|w| w[0].leaf() >= w[1].leaf()) {
        return Err(WireError::NotCanonical(
            "proofs not strictly ascending by leaf",
        ));
    }

    let claimed_state_root = r.arr32()?;
    let claimed_output_root = r.arr32()?;
    let claimed_aggregate = match r.u8()? {
        0 => None,
        1 => {
            let d_raw = r.u32()?;
            let d = r.count(d_raw, 8)?;
            let mut a = Vec::with_capacity(d);
            for _ in 0..d {
                a.push(r.i64()?);
            }
            Some(a)
        }
        _ => {
            return Err(WireError::NotCanonical(
                "aggregate presence flag not 0 or 1",
            ))
        }
    };

    if r.i != r.b.len() {
        return Err(WireError::TrailingBytes);
    }

    Ok(RedactedReceipt {
        round,
        f,
        rule,
        pki,
        contributions,
        proofs,
        claimed_state_root,
        claimed_output_root,
        claimed_aggregate,
    })
}
