// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! PROVING ACFA VERIFICATION SCALES: full re-execution at bounded memory, independent of d.
//!
//! THE CLAIM THIS ANSWERS, AND THE ONE IT DOES NOT. Seat A measured `layer2-receipt` RSS LINEAR in
//! d -- 0.029, 0.108, 0.444 GB across 4x steps -- and argued it is structural: a third party must
//! RE-EXECUTE, and there is no formulation of "offline re-checkable" that does not put the data in
//! the artefact. That argument is correct about the WIRE. It conflates two things:
//!
//!     WIRE SIZE   O(n*d)      INHERENT. Re-execution needs the data to arrive. A is right.
//!     RESIDENCY   O(n*chunk)  NOT inherent. It is `decode(&[u8]) -> Receipt` materialising
//!                             every `Vec<i64>` before anything is checked.
//!
//! So "ACFA scales" is FALSE for wire and OPEN for memory, and only the second is attackable.
//!
//! WHY THE STRUCTURE ALLOWS IT. Of the three things verification establishes, only one needs a
//! coordinate at all:
//!     state root   `State::root()` reads ONLY leaf keys -- 32 bytes each. No tensors.
//!     signatures   made over `contrib_msg(.., tensor_hash)` -- over the 32-byte hash.
//!     aggregate    needs the pairwise DISTANCES, which #119 proved are chunk-accumulable and
//!                  bit-identical because integer addition is associative.
//!
//! So a verifier can hold `n * chunk` coordinates at a time and never more, seeking into the wire
//! rather than loading it. The wire stays on disk at its full O(n*d); the VERIFIER does not.
//!
//! HONEST LIMIT. This demonstrates the MEMORY claim on a wire this example writes itself, in the
//! canonical layout. It is not `wire::decode`, and it does not make the shipped decoder streaming
//! -- it shows the property is reachable, which is what "structural" was in question about.
//!
//! usage: scale_streaming_verify <n> <d> [chunk]

use acfa_receipt::hash::{h, merkle_root};
use acfa_receipt::identity::{contrib_msg, verify, Identity, Pki, RoundParams};
use acfa_receipt::Rule;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

fn coord(node: u64, i: u64) -> i64 {
    let mut x = node.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ i.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    ((x >> 40) as i64 % 200_000) - 100_000
}

fn main() -> std::process::ExitCode {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: scale_streaming_verify <n> <d> [chunk]");
        return std::process::ExitCode::from(2);
    }
    let p = |s: &String, w: &str| -> Option<usize> {
        s.parse().ok().or_else(|| { eprintln!("scale_streaming_verify: {w} must be a positive integer, got {s:?}"); None })
    };
    let (Some(n), Some(d)) = (p(&a[1], "n"), p(&a[2], "d")) else { return std::process::ExitCode::from(2) };
    let chunk = match a.get(3) { None => 1_000_000, Some(s) => match p(s, "chunk") { Some(c) => c, None => return std::process::ExitCode::from(2) } };

    let ids: Vec<Identity> = (1..=n as u32).map(|i| Identity::from_secret(i, &[i as u8; 32])).collect();
    let pki: Pki = ids.iter().map(|i| (i.node_id, i.public())).collect();
    let params = RoundParams { rule: Rule::Krum, f: (n / 8) as u32, frac_bits: acfa_receipt::FRAC_BITS };
    let ctx = acfa_receipt::identity::NO_CONTEXT;
    let path = std::env::temp_dir().join(format!("acfa_wire_{}_{}.bin", std::process::id(), d));

    // ---- WRITE THE WIRE. Coordinates are streamed straight out; never all resident. ----
    let t0 = std::time::Instant::now();
    let mut f = std::fs::File::create(&path).expect("create wire");
    let mut offsets = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    let mut sigs = Vec::with_capacity(n);
    let mut pos: u64 = 0;
    for (k, id) in ids.iter().enumerate() {
        let mut hasher = Sha256::new();
        let mut buf: Vec<u8> = Vec::with_capacity(chunk * 12);
        let mut raw: Vec<u8> = Vec::with_capacity(chunk * 8);
        offsets.push(pos);
        let mut s = 0usize;
        while s < d {
            let e = (s + chunk).min(d);
            buf.clear(); raw.clear();
            for i in s..e {
                let v = coord(k as u64, i as u64);
                if i > 0 { buf.push(b'|'); }
                buf.extend_from_slice(v.to_string().as_bytes());
                raw.extend_from_slice(&v.to_be_bytes());
            }
            hasher.update(&buf);
            f.write_all(&raw).expect("write");
            pos += raw.len() as u64;
            s = e;
        }
        let th: [u8; 32] = hasher.finalize().into();
        sigs.push(id.sign(&contrib_msg(&ctx, &params, 1, id.node_id, &th)));
        hashes.push(th);
    }
    f.flush().expect("flush");
    // NEGATIVE CONTROL. `--corrupt` flips one bit in the tensor region, which is exactly C's
    // probe. Before the re-derivation above, this changed NOTHING a verifier checks: signatures
    // 4/4 and state root both unchanged, with only the distance digest noticing. A guard that
    // cannot fail on a corrupted wire is not a verifier, so the corruption path ships with the
    // demo rather than being run once and described.
    if std::env::args().any(|x| x == "--corrupt") {
        use std::io::{Read as _, Seek as _, Write as _};
        let mut g = std::fs::OpenOptions::new().read(true).write(true).open(&path).expect("reopen");
        let mid = pos / 2;
        g.seek(SeekFrom::Start(mid)).expect("seek");
        let mut one = [0u8; 1];
        g.read_exact(&mut one).expect("read");
        one[0] ^= 0x01;
        g.seek(SeekFrom::Start(mid)).expect("seek");
        g.write_all(&one).expect("write");
        g.flush().expect("flush");
        eprintln!("  [--corrupt] flipped one bit at byte {mid} of {pos}");
    }
    let wire_bytes = pos;
    let write_t = t0.elapsed();

    // ---- VERIFY, holding only n*chunk coordinates. ----
    let t1 = std::time::Instant::now();
    let mut f = std::fs::File::open(&path).expect("open wire");

    // (1) signatures -- over the 32-byte hash, RE-DERIVED FROM THE BYTES ON DISK.
    //
    // THIS RE-DERIVATION IS THE WHOLE POINT AND THE FIRST VERSION SKIPPED IT. Seat C flipped one
    // bit in the tensor region of a 6.4 MB wire and measured: signatures 4/4 UNCHANGED -- which I
    // had predicted -- and STATE ROOT UNCHANGED, which I had not. The state root is the commitment
    // a third party actually checks, and it is built from leaves derived from these hashes, so it
    // inherited the defect: a verifier would confirm the root of a receipt whose tensor bytes had
    // been altered. Only the distance digest noticed.
    //
    // C's structural reading is sharper than "not re-derived": the hash covers `enc_tensor`, the
    // DECIMAL TEXT joined by '|', while the wire holds BIG-ENDIAN BINARY. The hash covered an
    // encoding that never reached the disk, so re-deriving it was not merely skipped -- it was
    // impossible without re-encoding. That is what this loop does: read the binary back in chunks,
    // re-encode to the canonical decimal form, and hash THAT. Bounded memory, and the hash now
    // commits to bytes a verifier can actually see.
    let mut sigs_ok = 0usize;
    let mut rederived: Vec<[u8; 32]> = Vec::with_capacity(n);
    {
        let mut rb = vec![0u8; chunk * 8];
        let mut tb: Vec<u8> = Vec::with_capacity(chunk * 12);
        for k in 0..n {
            let mut hasher = Sha256::new();
            let mut s0 = 0usize;
            while s0 < d {
                let e0 = (s0 + chunk).min(d);
                let want = (e0 - s0) * 8;
                f.seek(SeekFrom::Start(offsets[k] + (s0 as u64) * 8)).expect("seek");
                f.read_exact(&mut rb[..want]).expect("read");
                tb.clear();
                for (t, c) in rb[..want].chunks_exact(8).enumerate() {
                    let v = i64::from_be_bytes(c.try_into().unwrap());
                    if s0 + t > 0 { tb.push(b'|'); }
                    tb.extend_from_slice(v.to_string().as_bytes());
                }
                hasher.update(&tb);
                s0 = e0;
            }
            rederived.push(hasher.finalize().into());
        }
    }
    let hash_matches = rederived == hashes;
    for (k, id) in ids.iter().enumerate() {
        if verify(pki.get(&id.node_id).expect("key"), &contrib_msg(&ctx, &params, 1, id.node_id, &rederived[k]), &sigs[k]) {
            sigs_ok += 1;
        }
    }

    // (2) state root -- leaves only, 32 bytes each, no coordinates.
    let leaves: Vec<[u8; 32]> = (0..n).map(|k| {
        let mut b = Vec::with_capacity(2 + 32 + 9 + 8 + 4 + 32 + 64);
        b.extend_from_slice(b"C|"); b.extend_from_slice(&ctx);
        b.push(params.rule.as_wire());
        b.extend_from_slice(&params.f.to_be_bytes());
        b.extend_from_slice(&params.frac_bits.to_be_bytes());
        b.extend_from_slice(&1u64.to_be_bytes());
        b.extend_from_slice(&ids[k].node_id.to_be_bytes());
        b.extend_from_slice(&rederived[k]); b.extend_from_slice(&sigs[k]);
        h(&b)
    }).collect();
    let root = merkle_root(&leaves);

    // (3) THE AGGREGATE -- re-executed from the wire, chunk-parallel across all n by SEEKING.
    //     This is the step A's argument said forces residency. It forces TRANSMISSION.
    let mut acc = vec![0i128; n * n];
    let mut bufs: Vec<Vec<i64>> = vec![Vec::with_capacity(chunk); n];
    let mut rawbuf = vec![0u8; chunk * 8];
    let mut s = 0usize;
    while s < d {
        let e = (s + chunk).min(d);
        let want = (e - s) * 8;
        for k in 0..n {
            f.seek(SeekFrom::Start(offsets[k] + (s as u64) * 8)).expect("seek");
            f.read_exact(&mut rawbuf[..want]).expect("read");
            bufs[k].clear();
            bufs[k].extend(rawbuf[..want].chunks_exact(8).map(|c| i64::from_be_bytes(c.try_into().unwrap())));
        }
        for i in 0..n {
            for j in (i + 1)..n {
                let mut part: i128 = 0;
                for t in 0..(e - s) {
                    let delta = (bufs[i][t] as i128) - (bufs[j][t] as i128);
                    part += delta * delta;
                }
                acc[i * n + j] += part;
            }
        }
        s = e;
    }
    for i in 0..n { for j in 0..i { acc[i * n + j] = acc[j * n + i]; } }
    let verify_t = t1.elapsed();

    let mut dh: u64 = 1469598103934665603;
    for v in &acc { for b in v.to_be_bytes() { dh ^= b as u64; dh = dh.wrapping_mul(1099511628211); } }

    println!("# ACFA STREAMING VERIFICATION -- full re-execution, bounded memory");
    println!("  n {n}   d {d}   chunk {chunk}");
    println!("  WIRE ON DISK          {:.2} GB   <- O(n*d), inherent: re-execution needs the data", wire_bytes as f64 / 1e9);
    println!("  verifier working set  {:.3} GB   <- O(n*chunk), independent of d", (n * chunk * 8) as f64 / 1e9);
    println!("  tensor hashes RE-DERIVED from disk, match write-time: {hash_matches}");
    println!("  signatures verified   {sigs_ok}/{n}");
    println!("  state root            {}", root.iter().map(|x| format!("{x:02x}")).collect::<String>());
    println!("  distance-digest       {dh:016x}");
    println!("  write {:.2}s   verify {:.2}s", write_t.as_secs_f64(), verify_t.as_secs_f64());
    let _ = std::fs::remove_file(&path);
    if sigs_ok != n { return std::process::ExitCode::from(1); }
    std::process::ExitCode::SUCCESS
}
