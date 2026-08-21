#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Refuse a tree that CLAIMS a release it does not have.

WHY THIS EXISTS. The manifests declared 0.4.0, the CHANGELOG carried a dated v0.4.0 section, and
the README's release table listed it -- while `git ls-remote --tags` returned only v0.1.0, v0.2.0
and v0.3.0. The README states that releases ARE signed annotated tags, so the tree asserted a
release that could not be obtained or verified by the process the tree itself documents. Nothing
noticed, because no check compares the version a tree claims against the tags that exist.

THE RULE, and it is deliberately narrow: if the manifest version has no tag, the CHANGELOG section
for that version must say UNRELEASED. Declaring an untagged version is fine -- that is what `main`
between releases IS. Declaring it as though it shipped is not.

REFUSES AT ZERO. If it finds no manifests, no CHANGELOG section, or no tags at all, it FAILS rather
than reporting success over an empty set -- a check that passes because it looked at nothing is the
failure mode this repository treats as worse than no check.

Exit 0 = consistent. Exit 1 = the tree claims a release it does not have. Exit 2 = cannot check.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fail(msg, code=1):
    print(f"FAIL {msg}")
    sys.exit(code)


def main() -> int:
    manifests = sorted(ROOT.glob("build/*/Cargo.toml"))
    if not manifests:
        fail("no build/*/Cargo.toml found -- refusing to pass over an empty set", 2)

    versions = {}
    for m in manifests:
        hit = re.search(r'^version = "([^"]+)"', m.read_text(), re.M)
        if not hit:
            fail(f"{m.relative_to(ROOT)} has no version line", 2)
        versions[str(m.relative_to(ROOT))] = hit.group(1)

    distinct = set(versions.values())
    if len(distinct) != 1:
        fail(f"crate manifests disagree about the version: {versions}")
    version = distinct.pop()
    print(f"  manifests agree: {version}  ({len(versions)} crates)")

    try:
        out = subprocess.run(
            ["git", "tag", "--list"], cwd=ROOT, capture_output=True, text=True, timeout=30
        )
    except Exception as e:  # noqa: BLE001
        fail(f"cannot list tags: {e}", 2)
    tags = {t.strip() for t in out.stdout.splitlines() if t.strip()}
    if not tags:
        fail("no tags found at all -- cannot distinguish 'unreleased' from 'tags unavailable'", 2)
    print(f"  tags present: {len(tags)}")

    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        fail("no CHANGELOG.md", 2)
    text = changelog.read_text()

    heading = re.search(rf"^## v{re.escape(version)}\s*(?:—|--|-)\s*(.+)$", text, re.M)
    if not heading:
        fail(f"CHANGELOG.md has no section for the declared version v{version}")
    marker = heading.group(1).strip()

    tagged = f"v{version}" in tags
    unreleased = "UNRELEASED" in marker.upper()

    if tagged and unreleased:
        fail(f"v{version} IS tagged but the CHANGELOG still says UNRELEASED: {marker!r}")
    if not tagged and not unreleased:
        fail(
            f"the tree declares v{version} and the CHANGELOG dates it {marker!r}, but NO v{version} "
            f"TAG EXISTS. A reader following the documented release process cannot obtain or verify "
            f"this artefact. Either create the signed annotated tag, or mark the section UNRELEASED."
        )

    print(f"  v{version}: tagged={tagged} changelog={marker!r} -- consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
