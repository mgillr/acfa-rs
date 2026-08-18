#!/usr/bin/env bash
# regression-guard.sh -- REVERT GUARD. Fails if a landed fix, its guard test, or the
# cross-architecture fingerprint is reverted. Runs in CI on every push. "We do not revert."
#
# Every audit fix carries a guard-deletion test that goes RED if the FIX is reverted, and the
# full suite runs in CI -- so reverting a fix is caught. The gap this closes: a revert that
# also DELETES the guard test removes both the fix and its alarm together. This asserts the
# guard tests still exist, the fingerprint is unchanged, and the suite has not collapsed.
# Every check REFUSES AT ZERO with a named reason; none can pass silently.
set -euo pipefail
cd "$(dirname "$0")/.."

FP="bd13ba3209a940b2025368a63c546ffd59e2580a1b8aa7128cc9b423d1957e40"
fail=0

echo "== fingerprint unchanged (byte-identity is load-bearing; a change needs a wire-version bump) =="
if grep -rq "$FP" build/ README.md 2>/dev/null; then
  echo "  OK  fingerprint present"
else
  echo "  FAIL fingerprint $FP GONE -- byte-identity changed without an intended wire-version bump"; fail=1
fi

echo "== every finding's guard test file exists (a revert cannot delete its own alarm) =="
GUARDS=(
  "build/layer1-aggregate/tests/value_range.rs"
  "build/layer1-aggregate/tests/reference_rounding.rs"
  "build/layer1-aggregate/tests/one_client_denial.rs"
  "build/layer1-aggregate/tests/work_bound.rs"
  "build/layer1-aggregate/tests/quantisation_power.rs"
  "build/layer1-aggregate/tests/cli.rs"
  "build/layer1-aggregate/tests/rust04_argv.rs"
  "build/layer2-receipt/tests/crdt01_range_at_the_untrusted_door.rs"
  "build/layer2-receipt/tests/require_bound_spellings.rs"
  "build/layer2-receipt/tests/cli_reject.rs"
  "build/layer2-receipt/tests/equivocation_closure.rs"
  "build/layer2-receipt/tests/crdt11_leaf_disjointness.rs"
  "build/layer2-receipt/tests/crypto02_key_strength.rs"
  "build/layer2-receipt/tests/crypto04_nonce_equivocation.rs"
  "build/layer2-receipt/tests/crypto08_rule_pinning.rs"
  "build/layer2-receipt/tests/rust04_argv.rs"
  "build/layer2-receipt/tests/rust08_expected_state_root.rs"
  "build/layer2-receipt/tests/rust12_total_encode.rs"
  "build/layer2-receipt/tests/receipt_verify_dos.rs"
  "build/layer2-finality/tests/crdt05_orientation_and_attribution.rs"
  "build/layer2-finality/tests/crdt05_third_door_gossip_reader.rs"
  "build/layer2-finality/tests/crdt09_predecessor_binding.rs"
  "build/layer2-finality/tests/crypto03_finality_quorum_by_key.rs"
  "build/layer2-finality/tests/rust04_argv.rs"
)
miss=0
for g in "${GUARDS[@]}"; do
  [ -f "$g" ] || { echo "  FAIL guard deleted: $g"; miss=$((miss+1)); fail=1; }
done
[ "$miss" -eq 0 ] && echo "  OK  all ${#GUARDS[@]} finding guard tests present"

echo "== named guard functions present (a revert cannot gut a file and keep its name) =="
check_fn () { local fn="$1" f="$2"; if [ -f "$f" ] && grep -q "fn $fn" "$f"; then :; else echo "  FAIL guard fn missing: $fn in $f"; fail=1; fi; }
check_fn "a_defended_rule_below_its_robustness_threshold_is_refused_at_the_cli" build/layer1-aggregate/tests/cli.rs
check_fn "the_encoder_agrees_with_the_reference_at_every_midpoint"              build/layer1-aggregate/tests/reference_rounding.rs
check_fn "the_merge_path_and_the_deliver_path_convict_and_root_identically"     build/layer2-receipt/tests/equivocation_closure.rs
check_fn "every_accepted_spelling_of_require_bound_enforces_the_bound"          build/layer2-receipt/tests/require_bound_spellings.rs
check_fn "verify_refuses_a_receipt_that_would_derive_too_much"                  build/layer2-receipt/tests/receipt_verify_dos.rs
check_fn "the_total_encoder_refuses_a_fault_bound_that_does_not_fit"            build/layer2-receipt/tests/rust12_total_encode.rs
check_fn "two_honest_nodes_do_not_finalise_conflicting_states_after_resume"     build/layer2-finality/tests/crdt05_orientation_and_attribution.rs
check_fn "a_double_signer_conviction_and_its_evidence_survive_a_resume"         build/layer2-finality/tests/crdt05_orientation_and_attribution.rs
check_fn "a_chain_anchored_to_the_wrong_predecessor_is_not_admitted"            build/layer2-finality/tests/crdt09_predecessor_binding.rs
[ "$fail" -eq 0 ] && echo "  OK  named guard functions present"

echo "== test suite has not collapsed =="
N=$(grep -rhoE '#\[test\]' build/*/tests/*.rs build/*/src/*.rs 2>/dev/null | wc -l | tr -d ' ')
FLOOR=250
if [ "$N" -ge "$FLOOR" ]; then echo "  OK  $N tests (floor $FLOOR)"; else echo "  FAIL only $N tests, below floor $FLOOR"; fail=1; fi

if [ "$fail" -ne 0 ]; then echo; echo "REGRESSION GUARD FAILED: a fix, guard, or the fingerprint was reverted."; exit 1; fi
echo; echo "REGRESSION GUARD PASSED."
