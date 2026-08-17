#!/usr/bin/env python3
"""adv-08. Every CLI must REFUSE an interactive stdin instead of blocking on it.

WHY THIS IS NOT A RUST TEST. The guard is `path.is_none() && stdin().is_terminal()`, and
`is_terminal()` is false under every ordinary test runner -- cargo gives a child a pipe or
/dev/null, so the branch is unreachable from `cargo test` and the whole suite stays green
with the guard deleted. Reaching it needs a real pty, which needs a crate these crates do
not depend on. Python's stdlib has `pty`, and `tools/*.py` invoked from CI is an existing
pattern here, so the check lives where it can actually run rather than where it would look
tidiest.

That is the finding, not an aside: adv-08 was recorded with `covering_test = NONE`, and the
reason nobody wrote one is that the only test that could fail is one no Rust test harness
can express.

WHAT IT ASSERTS, per binary: with NO arguments and stdin attached to a pty, the process must
exit 2 within the ceiling. A HANG is the defect adv-08 names -- measured at 10.1s against
5ms elsewhere -- so the timeout is a failure, never a skip.

NO SILENT SKIPS. A missing binary is a FAILURE, not a pass: a check that quietly succeeds
when it cannot run is the defect this repository has spent a day removing.
"""

from __future__ import annotations

import os
import pty
import subprocess
import sys
import time

CEILING_S = 5.0

BINARIES = [
    ("acfa-agg", "build/layer1-aggregate/target/release/acfa-agg"),
    ("acfa-verify", "build/layer2-receipt/target/release/acfa-verify"),
    ("acfa-finality", "build/layer2-finality/target/release/acfa-finality"),
]


def run_on_a_pty(path: str) -> tuple[int | None, float, str]:
    """Run `path` with no arguments and stdin on a real terminal."""
    master, slave = pty.openpty()
    started = time.time()
    proc = subprocess.Popen(
        [path], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        _, err = proc.communicate(timeout=CEILING_S)
        code: int | None = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
        code = None  # hung
    finally:
        os.close(master)
        os.close(slave)
    first_line = (err.decode(errors="replace").strip().split("\n") or [""])[0]
    return code, time.time() - started, first_line


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)

    failures: list[str] = []
    print("adv-08: interactive stdin must be refused, not blocked on")
    print(f"  ceiling {CEILING_S:.0f}s, stdin on a real pty, no arguments\n")

    for name, rel in BINARIES:
        if not os.path.exists(rel):
            failures.append(f"{name}: NOT BUILT at {rel} -- cannot verify, so this FAILS")
            print(f"  {name:<15} NOT BUILT -- {rel}")
            continue

        code, elapsed, message = run_on_a_pty(rel)
        if code is None:
            failures.append(f"{name}: HUNG on an interactive stdin ({elapsed:.1f}s)")
            verdict = "*** HUNG ***"
        elif code != 2:
            failures.append(f"{name}: exit {code}, expected 2")
            verdict = f"exit={code} WRONG"
        elif not message:
            failures.append(f"{name}: exited 2 but printed nothing to stderr")
            verdict = "exit=2 but SILENT"
        else:
            verdict = "exit=2 ok"
        print(f"  {name:<15} {verdict:<16} {elapsed:5.2f}s  {message[:56]}")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nAll {len(BINARIES)} CLIs refuse an interactive stdin.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
