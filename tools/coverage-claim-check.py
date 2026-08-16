#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Hold ARCHITECTURE-COVERAGE.md to what CI actually runs.

WHY THIS EXISTS. That document ships to readers and opens with "Enforced on every push:
CI blocks any push where these fail." It then lists eight targets. For a while that was
false in the published repository: the internal workflow ran all eight, the published one
ran the four hosted rows, and the four emulated rows -- the 32-bit and big-endian cases,
the only rows that make byte-identity a non-trivial claim -- were enforced nowhere a reader
could see. The table was true of a file strangers never receive.

A claim about what CI enforces is checkable against CI. This parses the table out of the
prose and requires every row to appear in a workflow, so the sentence cannot outlive the
job that justifies it. Delete a matrix entry and this fails; the fix is to restore the job
or to stop claiming the row.

Usage: python3 tools/coverage-claim-check.py
"""
import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # loud, never silent: a skipped check reads as a passed one
    sys.exit("coverage-claim-check needs PyYAML (pip install pyyaml)")

REPO = pathlib.Path(__file__).resolve().parents[1]
DOC = REPO / "build/ARCHITECTURE-COVERAGE.md"

# How a table row names a target -> the strings that prove a workflow runs it.
EVIDENCE = {
    "x86_64 linux": ["ubuntu-latest"],
    "aarch64 linux": ["ubuntu-24.04-arm"],
    "aarch64 macos": ["macos-latest"],
    "x86_64 windows": ["windows-latest"],
    "i386": ["linux/386"],
    "armv7": ["linux/arm/v7"],
    "ppc64le": ["linux/ppc64le"],
    "s390x": ["linux/s390x"],
}


def rows(text: str):
    """Target names from the enforced-on-every-push table, ignoring header and rule."""
    section = text.split("## Enforced on every push", 1)[-1].split("\n## ", 1)[0]
    for line in section.splitlines():
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        cell = line.split("|")[1].strip()
        if cell.lower() in ("target", ""):
            continue
        yield re.sub(r"[*`]|\(.*?\)", "", cell).strip()


def main() -> int:
    if not DOC.is_file():
        print(f"{DOC} not found")
        return 2

    workflows = list((REPO / ".github/workflows").glob("*.yml"))
    pub = REPO / "publish/public/ci.yml"
    if pub.is_file():
        workflows.append(pub)
    if not workflows:
        print("no workflows found to check against")
        return 2

    corpus = {p: p.read_text(encoding="utf-8") for p in workflows}
    claimed = list(rows(DOC.read_text(encoding="utf-8")))
    if not claimed:
        print("no target rows parsed from the coverage table")
        return 2

    bad = []
    for target in claimed:
        key = next((k for k in EVIDENCE if k in target.lower()), None)
        if key is None:
            bad.append(f"{target}: claimed, but this checker knows no evidence for it")
            continue
        needles = EVIDENCE[key]
        covering = [p.name for p, t in corpus.items()
                    if any(n in t for n in needles)]
        # A row must be enforced by the workflow that ships with this tree. A row enforced
        # only by some other workflow is not enforced as far as this document is concerned.
        if pub.is_file() and pub.name not in covering:
            bad.append(f"{target}: not in the PUBLISHED workflow "
                       f"({'internal only: ' + ', '.join(covering) if covering else 'nowhere'})")
        elif not covering:
            bad.append(f"{target}: claimed, run by no workflow")
        else:
            print(f"OK   {target:<34} {needles[0]:<16} {', '.join(sorted(covering))}")

    # Every SHIPPED document that states how many architectures CI gates must state the
    # same number. Checking only the coverage table left CONTRIBUTING.md claiming four and
    # DETERMINISM-RESULTS.md describing the emulated rows as a local run, both shipped, both
    # contradicting the README's eight. A number in prose is a claim like any other.
    # A target that runs is not a target that is enforced. This check exists because the
    # version above it reported "all 8 enforced" while the gate enforced 4: the four
    # emulated rows ran, uploaded their fingerprints, and the job that compares
    # fingerprints did not list them in `needs`, so it started without them and diffed
    # only the hosted four. Every string this file looked for was present. Presence was
    # never the property that mattered.
    #
    # So: find the jobs that PRODUCE a fingerprint, find the job that COMPARES them, and
    # require the comparer to wait on every producer. Then require it to assert how many
    # it expects, because a diff loop over one file passes having compared nothing.
    for wf in workflows:
        spec = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        jobs = spec.get("jobs", {})
        producers, comparers = set(), {}
        for name, job in jobs.items():
            steps = job.get("steps", []) or []
            for st in steps:
                uses = str(st.get("uses", ""))
                if "upload-artifact" in uses and "fingerprint" in str(st.get("with", {})):
                    producers.add(name)
                if "download-artifact" in uses:
                    comparers[name] = job
        for cname, cjob in comparers.items():
            needs = cjob.get("needs") or []
            needs = [needs] if isinstance(needs, str) else list(needs)
            missing = sorted(producers - set(needs))
            if missing:
                bad.append(f"{wf.name}: job '{cname}' compares fingerprints but does not "
                           f"wait on {', '.join(missing)} -- those targets run and are "
                           f"never compared")
            run = " ".join(st.get("run", "") for st in cjob.get("steps", []) or [])
            if "-ne" not in run and "!=" not in run:
                bad.append(f"{wf.name}: job '{cname}' does not assert how many "
                           f"fingerprints it received; it is green on one file")
            elif not missing:
                print(f"OK   {wf.name}: '{cname}' waits on "
                      f"{', '.join(sorted(producers))} and asserts a count")

    # SCOPE, deliberately narrow. Only sentences asserting the SIZE OF THE WHOLE GATE are
    # checked: "N architectures [fail to] produce a byte-identical receipt". Counting every
    # "N architectures" in the tree flagged three true sentences -- a paper quote about a
    # prototype, an experiment run on two machines, and a correctly scoped claim about the
    # four real-silicon rows. A checker that cries wolf on true prose gets ignored, and an
    # ignored checker is worse than none.
    #
    # The narrowness is the limitation: a doc that miscounts the gate in different words
    # will pass here. The table above is the guard that cannot be worded around.
    n = len(claimed)
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
             "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}
    pat = re.compile(
        r"\*{0,2}(\w+)\*{0,2}\s+architectures?\b[^.]{0,80}?byte-identical receipt", re.I)
    for doc in sorted(REPO.rglob("*.md")):
        rel = doc.relative_to(REPO).as_posix()
        if any(rel.startswith(p) for p in ("publish/", "screening/", "docs/")) \
                or "/target/" in rel:
            continue
        text = doc.read_text(encoding="utf-8")
        for m in pat.finditer(text):
            tok = m.group(1).lower()
            val = words.get(tok, int(tok) if tok.isdigit() else None)
            if val is not None and val != n:
                line = text[:m.start()].count("\n") + 1
                bad.append(f"{rel}:{line}: claims the gate spans {val} architectures, "
                           f"the table and CI say {n}")

    print()
    if bad:
        print(f"{len(bad)} claimed target(s) not enforced where the document says:")
        for b in bad:
            print(f"  - {b}")
        return 1
    print(f"all {len(claimed)} claimed targets are enforced by the published workflow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
