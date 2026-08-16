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
use crate::resolve::Rule;

pub const MAGIC: &[u8; 8] = b"ACFA-R1\0";
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
}

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
    for _ in 0..n_pki {
        let id = r.u32()?;
        if let Some(prev) = last_id {
            if id <= prev {
                return Err(WireError::NotCanonical("pki not strictly ascending by id"));
            }
        }
        last_id = Some(id);
        let pk: PubKey = r.arr32()?;
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
