// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! Canonical wire encoding for certificates and fork evidence.
//!
//! WHY THIS HAS TO EXIST. `Finality::evidence()` describes its return value as the
//! published evidence, "for onward gossip" -- but until now nothing could serialise a
//! `Certificate` or a `CertFork`, so the evidence could not leave the process that
//! observed it. A fork proof that cannot be transferred is not transferable evidence;
//! it is a local log line. The whole claim of the finality layer is that a synchrony
//! violation carries its own proof to *anyone*, and that requires bytes.
//!
//! THE ENCODING IS PART OF THE SECURITY ARGUMENT, NOT PACKAGING -- same three rules as
//! `acfa-receipt`'s wire module, for the same reason:
//!
//! 1. **Fixed-width big-endian integers.** Identical bytes on every target.
//! 2. **Ordered collections.** Signers ascend by id. Order is a function of content,
//!    never of arrival.
//! 3. **Exactly one encoding per logical value.** A fork is written in canonical
//!    orientation only, so two observers of the same violation emit the same bytes and
//!    a verifier cannot be shown one form while a third party checks another.
//!
//! Decoding is strict: short reads, trailing bytes, duplicate or descending signers,
//! and non-conflicting or mis-oriented forks are all errors.
//!
//! ALLOCATION IS BOUNDED BEFORE IT HAPPENS. Every count is checked against the bytes
//! actually remaining before anything is reserved. A hostile 30-byte fork claiming four
//! billion signatures must fail as a short read, not as an allocation -- this is a
//! verifier pointed at untrusted input, and aborting on a length prefix is a denial of
//! service on the exact tool third parties are asked to run.

use crate::certificate::{CertFork, CertTuple, Certificate};
use acfa_receipt::identity::Sig;
use std::collections::BTreeMap;

pub const CERT_MAGIC: &[u8; 8] = b"ACFA-C1\0";
pub const FORK_MAGIC: &[u8; 8] = b"ACFA-K1\0";
pub const VERSION: u16 = 1;

/// Bytes per signature entry on the wire: signer id (4) + signature (64).
const SIG_ENTRY: usize = 4 + 64;
/// Bytes of a certificate body: round (8) + three roots (96) + sig count (4).
const CERT_FIXED: usize = 8 + 32 + 32 + 32 + 4;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    BadMagic,
    UnsupportedVersion(u16),
    Truncated,
    TrailingBytes,
    /// Signers must ascend strictly; a duplicate would also double-count toward f+1.
    NotCanonical(&'static str),
    /// The two certificates do not conflict, so they are not a fork.
    NotAFork,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::BadMagic => write!(
                f,
                "not an ACFA certificate or fork: magic bytes do not match"
            ),
            WireError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported wire version {v}, this build speaks {VERSION}"
                )
            }
            WireError::Truncated => write!(f, "stream ended mid-field"),
            WireError::TrailingBytes => write!(f, "trailing bytes after a complete record"),
            WireError::NotCanonical(why) => write!(f, "not canonically encoded: {why}"),
            WireError::NotAFork => write!(
                f,
                "the two certificates do not conflict, so this is not a fork"
            ),
        }
    }
}

impl core::error::Error for WireError {}

// ------------------------------------------------------------------ encoding

fn put_cert(out: &mut Vec<u8>, c: &Certificate) {
    out.extend_from_slice(&c.tuple.round.to_be_bytes());
    out.extend_from_slice(&c.tuple.a_root);
    out.extend_from_slice(&c.tuple.e_cut_root);
    out.extend_from_slice(&c.tuple.rho);
    out.extend_from_slice(&(c.sigs.len() as u32).to_be_bytes());
    // BTreeMap iterates ascending, which IS the canonical order. Relying on that
    // rather than re-sorting keeps one source of truth for the ordering rule.
    for (id, sig) in &c.sigs {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(sig);
    }
}

pub fn encode_cert(c: &Certificate) -> Vec<u8> {
    let mut out = Vec::with_capacity(CERT_MAGIC.len() + 2 + CERT_FIXED + c.sigs.len() * SIG_ENTRY);
    out.extend_from_slice(CERT_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    put_cert(&mut out, c);
    out
}

/// Encode fork evidence. Always written in canonical orientation, so two independent
/// observers of the same violation produce byte-identical evidence.
pub fn encode_fork(k: &CertFork) -> Vec<u8> {
    let mut out = Vec::with_capacity(FORK_MAGIC.len() + 2 + 2 * (CERT_FIXED + 4 * SIG_ENTRY));
    out.extend_from_slice(FORK_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    put_cert(&mut out, &k.a);
    put_cert(&mut out, &k.b);
    out
}

// ------------------------------------------------------------------ decoding

struct R<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> R<'a> {
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Truncated);
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
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
    fn arr32(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

fn get_cert(r: &mut R) -> Result<Certificate, WireError> {
    let round = r.u64()?;
    let a_root = r.arr32()?;
    let e_cut_root = r.arr32()?;
    let rho = r.arr32()?;
    let n = r.u32()? as usize;

    // Bound BEFORE reserving: a claimed count must fit in the bytes that remain.
    if n.checked_mul(SIG_ENTRY)
        .is_none_or(|need| need > r.remaining())
    {
        return Err(WireError::Truncated);
    }

    let mut sigs: BTreeMap<u32, Sig> = BTreeMap::new();
    let mut prev: Option<u32> = None;
    for _ in 0..n {
        let id = r.u32()?;
        if let Some(p) = prev {
            if id <= p {
                return Err(WireError::NotCanonical("signers must ascend strictly"));
            }
        }
        prev = Some(id);
        let sig: Sig = r.take(64)?.try_into().unwrap();
        sigs.insert(id, sig);
    }

    Ok(Certificate {
        tuple: CertTuple {
            round,
            a_root,
            e_cut_root,
            rho,
        },
        sigs,
    })
}

fn framed<'a>(bytes: &'a [u8], magic: &[u8; 8]) -> Result<R<'a>, WireError> {
    let mut r = R { b: bytes, i: 0 };
    if r.take(8)? != magic {
        return Err(WireError::BadMagic);
    }
    let v = r.u16()?;
    if v != VERSION {
        return Err(WireError::UnsupportedVersion(v));
    }
    Ok(r)
}

pub fn decode_cert(bytes: &[u8]) -> Result<Certificate, WireError> {
    let mut r = framed(bytes, CERT_MAGIC)?;
    let c = get_cert(&mut r)?;
    if r.remaining() != 0 {
        return Err(WireError::TrailingBytes);
    }
    Ok(c)
}

/// Decode fork evidence, re-deriving canonical orientation rather than trusting it.
///
/// A decoder that accepted either orientation would give the same violation two valid
/// encodings, which is exactly the ambiguity the canonical form exists to remove.
pub fn decode_fork(bytes: &[u8]) -> Result<CertFork, WireError> {
    let mut r = framed(bytes, FORK_MAGIC)?;
    let a = get_cert(&mut r)?;
    let b = get_cert(&mut r)?;
    if r.remaining() != 0 {
        return Err(WireError::TrailingBytes);
    }
    let a_id = a.tuple.id();
    let k = CertFork::canonical(a, b).ok_or(WireError::NotAFork)?;
    if k.a.tuple.id() != a_id {
        return Err(WireError::NotCanonical(
            "fork must be written in canonical orientation",
        ));
    }
    Ok(k)
}
