#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Every place a load-bearing claim is MADE must carry its caveat.

WHY THIS EXISTS. Three audit findings -- fl-03, fl-06 and fl-08 -- were each closed by a
careful, measured disclosure, and each disclosure was filed somewhere the person it was
written for would never be standing:

    fl-06  "Drop-in for FedAvg" appeared in THREE places; the non-IID correction reached ONE.
    fl-08  the model-size measurement existed in ONE place; the two surfaces where a reader
           actually CHOOSES the adapter -- the root README and the class docstring -- had
           nothing at all.
    fl-03  the floor-bias measurement lived in the FLOWER adapter's README, but the bias is
           a property of the KERNEL, so a Rust caller using the primary API never met it.

None of the three was a missing measurement. All three measurements existed and were good.
THE DEFECT WAS PLACEMENT, and placement is invisible to any check that asks "is this
documented?" -- it is only visible to one that asks "where is this CLAIMED, and what does
it say THERE?"

A caveat that has to be remembered is one edit from being lost again: the next person to
write a quickstart, a docstring or a landing paragraph re-states the claim and has no reason
to know a correction exists three files away. So the pairing is enforced here rather than
remembered. Re-state a guarded claim without its caveat and this fails, naming the file and
line; the fix is to carry the caveat or to stop making the claim.

This is the same shape as `coverage-claim-check.py`, which holds the architecture table to
what CI actually runs so that sentence cannot outlive its job. Same idea, applied to claims
whose contradicting evidence is a measurement rather than a workflow.

Usage:
    python3 tools/claim-caveat-check.py            check the tree
    python3 tools/claim-caveat-check.py --self-test  prove the check can FAIL
"""
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]

# (finding, file, claim pattern, caveat pattern, window)
#
# WINDOW is in LINES, and it is deliberately tight. A caveat 150 lines below a claim is
# what fl-06 already had and it is what this exists to reject -- the reader has decided
# long before they get there. `None` means "anywhere in the file", used only where the
# claim and its caveat are structurally forced into different sections.
RULES = [
    (
        "fl-06",
        "README.md",
        r"Drop-in for `FedAvg`",
        r"not a drop-in for FedAvg's BEHAVIOUR|non-IID",
        12,
    ),
    (
        "fl-06",
        "adapters/flower/README.md",
        r"Drop-in for `FedAvg`",
        r"read \"Non-IID data\" below|non-IID",
        12,
    ),
    (
        "fl-06",
        "adapters/flower/acfa_flower/strategy.py",
        r"drop-in swap",
        r"THE WIRING IS DROP-IN; THE BEHAVIOUR IS NOT|non-IID",
        20,
    ),
    (
        "fl-08",
        "README.md",
        r"AcfaStrategy\(rule=",
        r"hundred thousand parameters",
        30,
    ),
    (
        "fl-08",
        "adapters/flower/acfa_flower/strategy.py",
        r"class AcfaStrategy",
        r"IT IS FOR SMALL MODELS|hundred thousand parameters",
        60,
    ),
    (
        "fl-03",
        "README.md",
        r"use acfa_aggregate::\{krum_aggregate, bulyan_aggregate",
        r"biased DOWNWARD",
        30,
    ),
]


def violations(text_overrides=None):
    """Return a list of human-readable failures. `text_overrides` is for --self-test."""
    out = []
    for finding, relpath, claim, caveat, window in RULES:
        path = REPO / relpath
        if text_overrides and relpath in text_overrides:
            text = text_overrides[relpath]
        elif path.is_file():
            text = path.read_text()
        else:
            out.append(f"{relpath}: MISSING -- {finding} rule cannot be checked")
            continue

        lines = text.split("\n")
        claim_re, caveat_re = re.compile(claim), re.compile(caveat)
        hits = [i for i, l in enumerate(lines) if claim_re.search(l)]
        if not hits:
            # A claim that vanished is not a failure -- deleting it is a valid way to
            # satisfy the pairing. But say so, because a silently-dropped rule is a rule
            # that stops protecting anything.
            print(f"  note: {finding} {relpath}: claim /{claim}/ no longer present")
            continue
        for i in hits:
            lo = 0 if window is None else max(0, i - window)
            hi = len(lines) if window is None else min(len(lines), i + window + 1)
            if not any(caveat_re.search(l) for l in lines[lo:hi]):
                out.append(
                    f"{relpath}:{i + 1}: {finding} -- claim /{claim}/ is stated here with "
                    f"no /{caveat}/ within {window} lines. The measurement exists; this is "
                    f"a reader who will not meet it."
                )
    return out


def self_test():
    """PROVE THE CHECK CAN FAIL. A guard nobody has seen fail is not known to be a guard.

    Strips the caveat out of a real file in memory and requires the checker to notice.
    Measured on the day this was written: without this, a typo in a caveat pattern would
    make every rule vacuously pass and the check would report success forever.
    """
    ok = True
    for finding, relpath, claim, caveat, _w in RULES:
        path = REPO / relpath
        if not path.is_file():
            print(f"  SELF-TEST SKIP {finding} {relpath}: file missing")
            ok = False
            continue
        text = path.read_text()
        if not re.search(claim, text):
            print(f"  SELF-TEST SKIP {finding} {relpath}: claim absent, nothing to break")
            continue
        broken = re.sub(caveat, "XXCAVEAT-REMOVEDXX", text)
        if broken == text:
            print(f"  SELF-TEST FAIL {finding} {relpath}: caveat pattern matched NOTHING, "
                  f"so the rule was already vacuous")
            ok = False
            continue
        if not violations({relpath: broken}):
            print(f"  SELF-TEST FAIL {finding} {relpath}: caveat removed and the check "
                  f"still passed")
            ok = False
        else:
            print(f"  SELF-TEST PASS {finding} {relpath}: caveat removed -> detected")
    return ok


def main():
    if "--self-test" in sys.argv:
        print("claim-caveat-check --self-test: each rule must DETECT a removed caveat")
        if not self_test():
            sys.exit("SELF-TEST FAILED -- the check cannot be trusted")
        print("self-test passed: every rule fails on a removed caveat")
        return
    bad = violations()
    if bad:
        print("claim-caveat-check: a guarded claim is stated without its caveat\n")
        for b in bad:
            print(f"  {b}")
        print(
            "\nEach of these was an audit finding closed by documentation. Re-stating the "
            "claim without the caveat re-opens it for whoever reads THIS copy."
        )
        sys.exit(1)
    print(f"claim-caveat-check: {len(RULES)} claim/caveat pairings hold")


if __name__ == "__main__":
    main()
