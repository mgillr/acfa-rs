#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
# ACFA demos -- one command each, from the repository root.
#
#   ./demos/run.sh          list them
#   ./demos/run.sh 1        run one
#   ./demos/run.sh all      run all
#
# Every demo prints what it does not establish.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
L1="$ROOT/build/layer1-aggregate"
L2="$ROOT/build/layer2-receipt"
WORK="${TMPDIR:-/tmp}/acfa-demo.$$"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

rule() { printf '\n\033[1m%s\033[0m\n%s\n' "$1" "$(printf '%.0s-' {1..72})"; }

uc1() {
  rule "UC1 -- Byzantine-robust FL where pooling is barred"
  ( cd "$L1" && cargo run -q --release --example uc1_poisoned_fl )
}

uc2() {
  rule "UC2 -- Reproducible multi-party merging, one byte-identical result"
  ( cd "$L2" && cargo run -q --release --example uc2_merge_order )
}

uc3() {
  rule "UC3 -- Multi-party benchmark aggregation with no trusted scorer"
  cat <<'TXT'
Five labs submit scores. Nobody administers the benchmark. One lab equivocates --
it signs two different scores for the same round. No administrator adjudicates:
the two conflicting signatures ARE the proof, and any verifier reaches the same
verdict independently.
TXT
  ( cd "$L2"
    cargo run -q --release --example issue -- --pki        > "$WORK/trusted.pki"
    cargo run -q --release --example issue -- --equivocate > "$WORK/equiv.bin"
    set +e
    cargo run -q --release --bin acfa-verify -- "$WORK/equiv.bin" --pki "$WORK/trusted.pki" --f 1
    echo "  exit $?"
    set -e )
  cat <<'TXT'

  Read `convicted [1]` and `bound n>=req NOT MET` together. Lab 1 is convicted by its own
  two signatures -- that is attribution with a self-authenticating proof, and it
  needs no trusted centre. But removing it leaves 4 admitted where this rule needs
  5, so the tool refuses to claim a Byzantine guarantee it no longer has.

  LIMITS

  1. Conviction covers EQUIVOCATION only. A participant that submits one
     plausible-but-wrong score leaves no proof and is not convicted here.
     Detecting that is a different problem and this tool does not claim it.

  2. Conviction requires the PROOF to be PRESENT in the receipt. This demo forms
     it automatically because the contributions arrive through the detection
     path. A receipt carrying both conflicting contributions but NOT the proof
     leaves that node in NEITHER the admitted list NOR the convicted list, and
     the verifier reports nothing about it. Absence from both lists is a signal.

  3. The proof is DERIVABLE FROM THE RECEIPT
     ITSELF. The verifier rebuilds state through a raw insert path that does not
     run detection, so it HOLDS both signed contributions and does not compute
     the conviction they imply. Absence of the proof is an ISSUER CHOICE, not an
     information gap. Today the tool cannot distinguish an issuer who withheld a
     proof from one who never noticed. (Measured: same bytes, raw path convicts
     nobody, detection path convicts node 1.)
TXT
}

uc5() {
  rule "UC5 -- Offline audit and re-execution"
  cat <<'TXT'
An auditor with no access to any party, no network and no clock re-derives the
result months later from the receipt alone.
TXT
  ( cd "$L2"
    cargo run -q --release --example issue -- --pki > "$WORK/t.pki"
    cargo run -q --release --example issue          > "$WORK/r.bin" )
  echo "  receipt: $(wc -c < "$WORK/r.bin" | tr -d ' ') bytes, pki: $(wc -c < "$WORK/t.pki" | tr -d ' ') bytes"
  echo "  running the verifier with the network unavailable to it:"
  ( cd "$L2"
    set +e
    cargo run -q --release --bin acfa-verify -- "$WORK/r.bin" --pki "$WORK/t.pki" --f 1
    echo "  exit $?"
    set -e )
  cat <<'TXT'

  Nothing was contacted. The receipt carries the contributions, the commitment
  trace and the signatures; the verifier recomputes the aggregate and compares.

  LIMITS: the auditor still needs the PKI from a trusted channel. The receipt
  cannot supply it -- a receipt that carries its own identity set verifies itself,
  which is exactly the forgery the `--pki` flag exists to defeat. Run demo 6 to
  see that fail.
TXT
}

uc6() {
  rule "The forgery -- why a receipt cannot certify itself"
  ( cd "$L2"
    cargo run -q --release --example issue -- --pki         > "$WORK/t.pki"
    cargo run -q --release --example issue -- --forged-pki  > "$WORK/f.bin"
    echo "  A forged receipt. Every signature in it is GENUINE -- for keys the forger owns."
    echo
    echo "  checked against the trusted identity set:"
    set +e
    cargo run -q --release --bin acfa-verify -- "$WORK/f.bin" --pki "$WORK/t.pki" --f 1 >/dev/null 2>&1
    echo "    exit $?  (rejected)"
    echo "  checked against itself, with no --pki:"
    cargo run -q --release --bin acfa-verify -- "$WORK/f.bin" >/dev/null 2>&1
    echo "    exit $?  (refuses to give a security verdict at all)"
    set -e )
  cat <<'TXT'

  Any artefact that carries its own trust anchor verifies itself. Without --pki
  the tool returns SELF-CONSISTENT ONLY, not a verdict.
TXT
}

case "${1:-}" in
  1) uc1 ;;
  2) uc2 ;;
  3) uc3 ;;
  5) uc5 ;;
  6) uc6 ;;
  all) uc1; uc2; uc3; uc5; uc6 ;;
  *)
    cat <<'TXT'
ACFA demos -- run from the repository root.

  ./demos/run.sh 1     Byzantine-robust FL where pooling is barred
  ./demos/run.sh 2     Reproducible multi-party merging -- 120 orders, one result
  ./demos/run.sh 3     Multi-party benchmark, no trusted scorer, equivocation convicted
  ./demos/run.sh 5     Offline audit -- re-derive the result from the receipt alone
  ./demos/run.sh 6     The forgery -- why a receipt cannot certify itself
  ./demos/run.sh all   all of them

NOT BUILT, and named rather than quietly omitted:
  UC4  Cross-org sensor fusion under a pooling bar. HONEST NOTE: mechanically this
       is UC1 with different labels -- same aggregation, same attribution, different
       domain story. Shipping it as a separate demo would be padding, so it is
       listed here until it demonstrates something UC1 does not.
TXT
    ;;
esac
