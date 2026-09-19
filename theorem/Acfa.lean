/-
acfa-rs machine-checked proofs (Lean 4, self-contained — no mathlib).

Run: scripts/check_theorems.sh  (exit 0 = all verified, zero holes)

Correspondence to the Rust kernel:
  src/*/fixed.rs (Q16.16 integer aggregation)  -> perm_isum, sum_append
  receipts re-execution (byte-identical audit) -> the same two theorems
    as the foundation: integer summation is an EXACT function of the
    input MULTISET — grouping and order cannot change the aggregate, so
    any two replicas (or any auditor re-executing a receipt) that hold
    the same set derive the identical result. This is the arithmetic
    half of the accountability guarantee; the signature half is
    cryptographic, not mathematical.

First formalized for converge (mgillr/converge theorem/Converge.lean,
P-112). Pure mathematics; unpatentable subject matter by nature.
-/

def lsum : List Nat → Nat
  | [] => 0
  | x :: xs => x + lsum xs

theorem sum_append (l1 l2 : List Nat) :
    lsum l1 + lsum l2 = lsum (l1 ++ l2) := by
  induction l1 with
  | nil => simp [lsum]
  | cons x xs ih =>
      simp only [lsum, List.cons_append]
      rw [Nat.add_assoc x (lsum xs) (lsum l2), ih]

theorem perm_isum : ∀ {l1 l2 : List Int}, l1.Perm l2 → l1.sum = l2.sum := by
  intro l1 l2 hp
  induction hp with
  | nil => rfl
  | cons x p ih => simp only [List.sum_cons]; omega
  | swap x y l => simp only [List.sum_cons]; omega
  | trans h1 h2 ih1 ih2 => exact ih1.trans ih2
