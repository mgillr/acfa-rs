// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ryan Gillespie
//! num-01. Cross-check `fixed::encode` against the VENDORED PYTHON reference's `fp_encode`,
//! by running the Python.
//!
//! WHY THIS FILE WAS REWRITTEN, because the shape of its previous failure is the point.
//! It used to define its own `reference_encode` in Rust as `(s + 0.5).floor()` and compare
//! `encode` against that. Two things were wrong with it, and either alone makes the test
//! worthless:
//!
//!   1. It RE-IMPLEMENTED the rule instead of calling the reference, and it re-implemented it
//!      as the exact idiom `src/fixed.rs` names as WRONG. So it agreed with whatever the
//!      Python actually did only by coincidence, and it agreed with the idiom under test by
//!      construction. When `reference/acfa.py::fp_encode` was itself shipping
//!      `math.floor(s + 0.5)` -- a live defect, recorded as RESOLVED while the code still did
//!      the wrong thing -- this file was green throughout and could not have been anything
//!      else.
//!   2. Its only probe set was the exact midpoints `k + 0.5` for `k` in -1000..=1000. Those
//!      discriminate ties-to-even from half-away, which is the num-01 divergence, but every
//!      composed "half away" form -- `floor(s + 0.5)`, `ceil(s - 0.5)` -- returns the CONTRACT'S
//!      answer on every one of them. A test whose whole probe set is where the candidate
//!      rules agree cannot separate them.
//!
//! So the comparison is now made against the actual `reference/acfa.py`, in a `python3`
//! subprocess, and the probe set includes the double where the composed idiom and the contract
//! DISAGREE: `f64::from_bits(0x3EDF_FFFF_FFFF_FFFF)`, whose scaled product is the largest
//! double strictly below 0.5. `floor(s + 0.5)` returns 1 there; the contract requires 0.
//!
//! DECISION (num-01): half-away-from-zero is canonical. It is the wire contract documented in
//! `fixed.rs`, the cross-architecture fingerprint is built on it, and the annihilation
//! threshold argument (`|s| < 0.5` encodes to 0) rests on it. Correcting the reference has no
//! wire or fingerprint impact -- golden generation feeds the kernel integers and never calls
//! `fp_encode` -- whereas changing the implementation would break the fingerprint.
//!
//! THE GAP THIS COVERS. The cross-implementation golden corpus (`tests/cross_impl.rs`,
//! `golden/vectors.json`) is INTEGER-ONLY by design, so it never calls `fp_encode` at all.
//! The float boundary is therefore not reachable from there, and that is why the encoder's
//! cross-implementation coverage lives in this file rather than in the golden corpus.
//!
//! GUARD-DELETION, MEASURED rather than asserted. Two mutations of `fixed::encode`, each run
//! against BOTH the old probe set and this one, `cargo test --test reference_rounding`:
//!
//!   | mutation of `encode`                                    | old file | this file |
//!   |---------------------------------------------------------|----------|-----------|
//!   | `(scaled + 0.5).floor()`                                 | 3/3 fail | 4/5 fail  |
//!   | `if s >= 0 { (s + 0.5).floor() } else { (s - 0.5).ceil() }` | 3/3 PASS | 2/5 fail  |
//!   | `ACFA_REFERENCE_DIR=/nonexistent`, `encode` unmutated     | 3/3 PASS | 5/5 fail  |
//!
//! Row two is the finding. That symmetric composed form is the exact idiom the vendored
//! reference shipped as its "fix", and the old file was GREEN on it -- because it compared
//! `f64::round` against a Rust copy of that same idiom, at inputs where the two cannot differ.
//! Row three is the same defect stated more bluntly: with the reference removed entirely, the
//! old file still passed, which is the whole of the argument that it never read it.
//!
//! WHAT THIS FILE DOES NOT COVER. It compares only IN-RANGE finite inputs. The refusal
//! boundary (`FixedError::OutOfRange`, `FixedError::NotFinite` against the reference's
//! `FixedError`) is not cross-checked here; it is exercised Rust-side in `src/fixed.rs`.
//! Stated rather than left for someone to discover.

use acfa_aggregate::encode;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------------------
// Reaching the vendored reference.
// ---------------------------------------------------------------------------------------

/// Where `acfa.py` lives. Resolved relative to the manifest so the test works from any
/// working directory, with an env override -- the same rule `tests/golden/generate.py` uses,
/// for the same reason: a check that only runs on one laptop is not a check.
fn reference_dir() -> PathBuf {
    if let Ok(d) = std::env::var("ACFA_REFERENCE_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference")
}

/// The Python side. Reads one big-endian IEEE-754 bit pattern per whitespace-separated hex
/// token on stdin, prints `fp_encode` of each, one integer per line.
///
/// Bit patterns rather than decimal literals: the inputs that matter here are single-ULP
/// distinctions, and a decimal round-trip through two languages' float parsers is exactly the
/// kind of intermediate that this whole contract exists to eliminate. The bits are what is
/// compared, so the bits are what is sent.
const PY: &str = r#"
import sys, struct, types
sys.path.insert(0, sys.argv[1])
try:
    from acfa import fp_encode
except ModuleNotFoundError as e:
    # acfa.py imports Ed25519 at module scope for the signing layer. `fp_encode` touches no
    # crypto, so a missing `cryptography` is satisfied with a stub rather than making
    # `cargo test` depend on a pip install on all thirteen CI legs. ANY OTHER missing module
    # is a real error and is re-raised -- in particular a missing `acfa` means the vendored
    # reference is not where this test thinks it is, and that must fail loudly.
    if e.name != "cryptography" and not (e.name or "").startswith("cryptography."):
        raise
    stubs = {}
    for name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives",
                 "cryptography.hazmat.primitives.asymmetric",
                 "cryptography.hazmat.primitives.asymmetric.ed25519",
                 "cryptography.exceptions"):
        stubs[name] = types.ModuleType(name)
    ed = stubs["cryptography.hazmat.primitives.asymmetric.ed25519"]
    ed.Ed25519PrivateKey = ed.Ed25519PublicKey = object
    stubs["cryptography.exceptions"].InvalidSignature = type(
        "InvalidSignature", (Exception,), {})
    sys.modules.update(stubs)
    from acfa import fp_encode
out = []
for tok in sys.stdin.read().split():
    x = struct.unpack(">d", bytes.fromhex(tok))[0]
    out.append(str(fp_encode(x)))
sys.stdout.write("\n".join(out) + "\n")
"#;

/// Run every `x` through the reference in ONE subprocess and return its answers in order.
///
/// FAILS rather than skips when `python3` is absent, following `cli_reject.rs`'s treatment of
/// `mkfifo`: the test cannot run, so it fails. A cross-implementation check that quietly
/// degrades to "no comparison performed" is indistinguishable from passing, which is the
/// defect class this file was rewritten to stop being an example of. `python` is tried after
/// `python3` only because Windows runners are not consistent about which name is on PATH.
fn reference_encode_all(xs: &[f64]) -> Vec<i64> {
    let refdir = reference_dir();
    let kernel = refdir.join("acfa.py");
    assert!(
        kernel.is_file(),
        "vendored reference not found at {}. Set ACFA_REFERENCE_DIR to override. \
         Refusing to report agreement with a reference that was never read.",
        kernel.display()
    );

    let mut stdin_text = String::with_capacity(xs.len() * 17);
    for x in xs {
        stdin_text.push_str(&format!("{:016X}\n", x.to_bits()));
    }

    let mut last_err = String::new();
    for exe in ["python3", "python"] {
        let spawned = Command::new(exe)
            .arg("-c")
            .arg(PY)
            .arg(&refdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("{exe}: {e}");
                continue;
            }
        };
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(stdin_text.as_bytes())
            .expect("write probe list to the reference");
        let out = child.wait_with_output().expect("wait for the reference");
        assert!(
            out.status.success(),
            "{exe} running the vendored reference exited {:?}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        let vals: Vec<i64> = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(|t| t.parse::<i64>().expect("reference printed a non-integer"))
            .collect();
        assert_eq!(
            vals.len(),
            xs.len(),
            "the reference answered {} of {} probes",
            vals.len(),
            xs.len()
        );
        return vals;
    }
    panic!(
        "no python3 on PATH, so the reference cannot be run and this test cannot perform its \
         comparison -- it fails rather than reporting agreement it did not measure. \
         last error: {last_err}"
    );
}

/// Compare `encode` against the reference's answers, naming the exact bit pattern on failure
/// so a disagreement is reproducible without re-deriving which probe it was.
fn assert_agrees(xs: &[f64], what: &str) {
    let theirs = reference_encode_all(xs);
    for (x, t) in xs.iter().zip(theirs) {
        let ours = encode(*x).unwrap_or_else(|e| panic!("{what}: encode({x:?}) refused: {e}"));
        assert_eq!(
            ours,
            t,
            "{what}: disagreement at x = f64::from_bits(0x{:016X}) = {x:?} \
             (scaled {:?}); rust {ours}, reference/acfa.py {t}",
            x.to_bits(),
            x * 65536.0
        );
    }
}

// ---------------------------------------------------------------------------------------
// The probe sets.
// ---------------------------------------------------------------------------------------

/// The double that separates the CONTRACT from the composed idiom, and the reason this file
/// exists in its present form.
///
/// `x = f64::from_bits(0x3EDF_FFFF_FFFF_FFFF)` scales to `0x1.fffffffffffffp-2`, the largest
/// double strictly below 0.5. Half-away-from-zero requires 0. `floor(s + 0.5)` computes
/// `s + 0.5` first; the true sum `1 - 2^-54` is a binary64 midpoint, ties-to-even carries it
/// to exactly 1.0, and the floor then returns 1. Measured on the vendored reference at the
/// time of writing: `fp_encode(x) = 0`, `fp_encode(-x) = 0`; the composed form gives 1 and -1.
///
/// Exactly one double per sign in the whole Q16.16 range behaves this way, which is why a
/// probe set built from exact midpoints never saw it.
const DISCRIMINATING_BITS: u64 = 0x3EDF_FFFF_FFFF_FFFF;

/// Step one ULP in magnitude. `from_bits`/`to_bits` arithmetic rather than `f64::next_up`,
/// so the probe set does not depend on a stabilisation later than the declared MSRV.
fn ulp_step(x: f64, away_from_zero: bool) -> f64 {
    let b = x.abs().to_bits();
    let n = if away_from_zero { b + 1 } else { b - 1 };
    f64::from_bits(n).copysign(x)
}

/// The case the old probe set could not see: the composed idiom returns 1 here, the contract
/// requires 0, and the reference must agree with the contract.
///
/// This test also asserts that the discriminating input STILL DISCRIMINATES -- that
/// `(scaled + 0.5).floor()` really does give 1 -- so that if the input is ever "simplified"
/// into something both rules agree on, this goes red instead of quietly becoming decorative.
#[test]
fn the_reference_and_the_encoder_agree_at_the_largest_double_below_a_half() {
    let x = f64::from_bits(DISCRIMINATING_BITS);
    let scaled = x * 65536.0;
    assert!(
        scaled < 0.5 && (scaled + 0.5).floor() == 1.0,
        "this probe is supposed to be the one where the composed idiom is WRONG; \
         scaled = {scaled:?}, floor(scaled + 0.5) = {}",
        (scaled + 0.5).floor()
    );
    assert_eq!(encode(x), Ok(0), "half-away requires 0 below the half unit");
    assert_eq!(encode(-x), Ok(0), "and the same on the negative side");
    assert_agrees(&[x, -x], "largest double below a half");
}

/// num-01 proper: exact midpoints, where ties-to-even and half-away part company. Kept
/// because that divergence was the original defect -- but it is no longer the ONLY probe set,
/// which is what made it useless on its own.
#[test]
fn the_reference_and_the_encoder_agree_at_every_midpoint() {
    let xs: Vec<f64> = (-1000i64..=1000)
        .map(|k| (k as f64 + 0.5) / 65536.0)
        .collect();
    assert_agrees(&xs, "exact midpoints");
}

/// The midpoints reachable from ORDINARY float32, which is what made the num-01 divergence a
/// live defect rather than a curiosity: every float32 that is an odd multiple of 2^-17 scales
/// to exactly `k + 0.5`.
#[test]
fn the_reference_and_the_encoder_agree_at_float32_midpoints() {
    let xs: Vec<f64> = (1i64..=4001)
        .step_by(2)
        .map(|odd| ((odd as f32) / 131_072.0) as f64)
        .collect();
    assert!(
        xs.len() > 500,
        "must exercise the midpoints, got {}",
        xs.len()
    );
    let neg: Vec<f64> = xs.iter().map(|x| -x).collect();
    assert_agrees(&xs, "float32 midpoints");
    assert_agrees(&neg, "float32 midpoints, negative");
}

/// One ULP either side of each midpoint. These are NOT midpoints, so a composed rule that
/// rounds them by adding 0.5 first has an intermediate that can carry -- this is the
/// neighbourhood the single discriminating double lives in, swept rather than spot-checked.
#[test]
fn the_reference_and_the_encoder_agree_one_ulp_either_side_of_a_midpoint() {
    let mut xs = Vec::new();
    for k in -200i64..=200 {
        let m = (k as f64 + 0.5) / 65536.0;
        if m == 0.0 {
            continue;
        }
        xs.push(ulp_step(m, false));
        xs.push(ulp_step(m, true));
    }
    assert_agrees(&xs, "midpoint neighbourhoods");
}

/// A deterministic sweep of ordinary doubles across the representable range. The targeted
/// probes above test the boundaries someone already thought of; this one is here to catch a
/// rule that is wrong in a way nobody has thought of yet.
///
/// The LCG is byte-identical to the one in `tests/determinism.rs` and
/// `tests/golden/generate.py`, so the probe set is the same on every machine and a failure
/// names a reproducible input.
#[test]
fn the_reference_and_the_encoder_agree_on_a_deterministic_sweep() {
    let mut s: u64 = 20260821;
    let mut xs = Vec::with_capacity(4096);
    for _ in 0..4096 {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let u = (s >> 11) as f64; // 53 bits, exactly representable
                                  // Into [-32767, 32767), so the scaled product stays inside Q16.16 and every probe is
                                  // a comparison rather than a refusal on both sides.
        xs.push(u / 9007199254740992.0 * 65534.0 - 32767.0);
    }
    assert_agrees(&xs, "deterministic sweep");
}
