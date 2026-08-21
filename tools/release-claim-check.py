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


def _git(*args):
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=30
    )


def is_release_tag(name: str, tags: set) -> tuple:
    """Is `name` a release tag AS THIS REPOSITORY DEFINES ONE, or merely a tag with that name?

    README.md:121 promises three properties, and this function exists because the first version of
    this check tested none of them. It asked `name in tags` -- whether a NAME EXISTS -- which is a
    strictly weaker property than the process it was written to defend.

    Seat C broke it in the way the gap invites: `git tag v0.4.0 <ROOT COMMIT>` creates a
    LIGHTWEIGHT, UNSIGNED tag pointing at the repository's first commit, and the check printed
    "consistent" over a tree that declared v0.4.0 in three manifests, dated its CHANGELOG as
    shipped, and had no release anywhere. No amount of careful coding fixes "has a tag" when the
    promise is "has THIS tag, annotated, signed, and on main".

    So all three are checked:
      ANNOTATED -- `git cat-file -t` must return `tag`, not `commit`. A lightweight tag is a
                   bare ref with no object, so it carries no author, no date and no message.
      SIGNED    -- the tag object must contain a signature block. The KEY is not verified here;
                   that needs the signer's public key and belongs in a release workflow, not in a
                   check every contributor runs. Absence of any signature is what this catches.
      NAMES THIS VERSION -- the COMMIT THE TAG POINTS AT must itself declare this version in its
                   manifests. This replaced a reachability test, which was wrong and which my own
                   mutation sweep caught: EVERY commit in history is reachable from main,
                   including the root commit, so `merge-base --is-ancestor` passed on exactly the
                   construction it was added to block. Asking whether the tagged tree declares the
                   version is the property that actually matters -- it is what makes the tag NAME
                   this release rather than merely coexist with it.
    """
    if name not in tags:
        return False, "no tag with that name"

    kind = _git("cat-file", "-t", name).stdout.strip()
    if kind != "tag":
        return False, f"tag is {kind or 'unreadable'}, not annotated (lightweight tags carry no message or date)"

    # SIGNED -- AND THIS PROPERTY CANNOT BE CHECKED WITHOUT A KEY, SO IT REFUSES RATHER THAN
    # PRETENDS.
    #
    # Two attempts failed here and the second failure is the instructive one. First a substring
    # test for the signature marker: C defeated it by typing the marker into `git tag -a -m`,
    # because `git cat-file tag` emits headers, a blank line, then the MESSAGE, and a real
    # signature lands in that same region. In C's words, the forger does not need a key, they
    # need a keyboard.
    #
    # Then `git verify-tag`, on the assumption that git parses structurally where a substring
    # cannot. MEASURED, and it does not: on the same forged tag,
    #     git for-each-ref --format='%(contents:signature)'
    # returns the fake block, and with no gpg on the box `git verify-tag --raw` reports
    # "cannot run gpg" and EXITS 0. Git's own parser splits message from signature by looking for
    # the marker, so it is fooled by exactly the same input.
    #
    # The honest conclusion: "is this tag signed" is decidable only by verifying the signature,
    # which needs gpg and the signer's public key. A check that cannot decide a property must not
    # report it as satisfied -- that is the gate-that-cannot-fail shape this repository treats as
    # worse than having no gate. So when a tag exists and the signature cannot be verified, this
    # REFUSES with exit 2 and says why, rather than passing on an unverifiable claim.
    ver = _git("verify-tag", "--raw", name)
    blob = ((ver.stderr or "") + (ver.stdout or "")).lower()
    if "no signature found" in blob:
        return False, "tag is annotated but UNSIGNED (git verify-tag: no signature found)"
    if "cannot run gpg" in blob or "not found" in blob:
        fail(
            f"{name} exists but its signature CANNOT BE VERIFIED here -- gpg is unavailable, and "
            f"git's own message/signature split is defeated by putting the marker in the tag "
            f"message (measured). Refusing rather than reporting an unverifiable property as "
            f"satisfied. Run this where gpg and the signer's public key are present.",
            2,
        )
    if "goodsig" not in blob and "validsig" not in blob and ver.returncode != 0:
        return False, f"tag signature did not verify: {blob.strip().splitlines()[:1]}"

    # README:121 -- "the same version appears in all three Rust crate manifests AND IN THE PYTHON
    # ADAPTER". The adapter was not read, so a tree could ship it at a version that never existed
    # and the guard called that consistent. C set it to 9.9.9 against three crates at 0.4.0 and the
    # check passed. Everything the README names as carrying the version is now checked.
    want = name.lstrip("v")
    seen = []
    for m in sorted(ROOT.glob("build/*/Cargo.toml")):
        rel = m.relative_to(ROOT)
        blob = _git("show", f"{name}:{rel}")
        if blob.returncode != 0:
            return False, f"tag does not contain {rel} -- it does not name a tree of this project"
        hit = re.search(r'^version = "([^"]+)"', blob.stdout, re.M)
        if not hit:
            return False, f"{rel} at {name} has no version line"
        seen.append(hit.group(1))
    if any(v != want for v in seen):
        return False, (
            f"the tagged commit declares {sorted(set(seen))}, not {want} -- the tag does not name "
            f"this release, it merely shares its name"
        )
    return True, f"annotated, signed, and the tagged tree declares {want}"


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

    adapter = ROOT / "adapters/flower/pyproject.toml"
    if not adapter.exists():
        fail("adapters/flower/pyproject.toml is missing -- the README names it as carrying the "
             "version, so its absence is a refusal, not a pass", 2)
    hit = re.search(r'^version = "([^"]+)"', adapter.read_text(), re.M)
    if not hit:
        fail("adapters/flower/pyproject.toml has no version line", 2)
    versions["adapters/flower/pyproject.toml"] = hit.group(1)

    distinct = set(versions.values())
    if len(distinct) != 1:
        fail(f"crate manifests disagree about the version: {versions}")
    version = distinct.pop()
    print(f"  manifests agree: {version}  ({len(versions)} files incl. the adapter)")

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

    tagged, why = is_release_tag(f"v{version}", tags)
    unreleased = "UNRELEASED" in marker.upper()
    if not tagged:
        print(f"  v{version} is not a release tag: {why}")

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
