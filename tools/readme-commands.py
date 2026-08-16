#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ryan Gillespie
"""Execute the commands the README tells a reader to run.

WHY THIS EXISTS. Four documented install paths were broken at once: a clone URL that
resolved to a different repository, a Cargo block with both `git` and `path` (a manifest
error, so a reader could not even reach a compile error), a Python block that installed
flwr and numpy but never the adapter, and an MSRV that disagreed with every manifest.

None of it was caught, because nothing ran it. The tests test the code; the README was
prose that happened to contain commands. A reader executes those commands before they
execute anything else, so they are the first thing that should be tested, not the last.

This builds the publishable tree, serves it as a local git remote, rewrites the documented
repository URL to point at it, and runs the documented paths for real: cargo install, the
dependency block as an actual manifest, the pip install, and the quickstart.

Usage:
    python3 tools/readme-commands.py            hermetic; substitutes a local remote
    python3 tools/readme-commands.py --live     uses the documented URL as written

The default is hermetic so it runs offline on every push. It therefore CANNOT verify
the URL itself -- it reads the documented URL only to replace it. --live closes that
gap and needs the network and a published repository, so it belongs on release.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"


def sh(cmd, cwd=None, env=None, check=True):
    r = subprocess.run(cmd, cwd=cwd, env=env, shell=isinstance(cmd, str),
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"$ {cmd}\nexit {r.returncode}\n{r.stdout}\n{r.stderr}")
    return r


def documented_url() -> str:
    m = re.search(r"https://github\.com/[\w.-]+/[\w.-]+", README.read_text())
    if not m:
        sys.exit("no repository URL found in README.md")
    return m.group(0)


def check_url_resolves(url: str, work: Path, failures: list) -> None:
    """Clone the URL the README actually documents, and confirm it is THIS software.

    WHY THIS IS A SEPARATE MODE. Everything else here is hermetic: it builds a local
    remote and substitutes it for the documented URL, so the checks run offline and
    deterministically. That substitution is correct for a per-push gate -- and it means
    the default mode reads the documented URL only in order to replace it. So the one
    defect it CANNOT catch is the first one in the list above: a URL pointing at the
    wrong repository. Proven, not assumed: with the README pointing at the paper repo,
    the hermetic mode exits 0 and reports that every documented command runs.

    A wrong URL is not a dead link. `github.com/mgillr/acfa` resolves -- to a different
    repository, with no build/ in it -- so the failure a reader sees is not 404 but
    software that does not contain what the page describes. Existence is not the property
    to test; identity is.

    This needs the network and a published repository, so it runs on release rather than
    on every push. Both halves are needed: hermetic on push, real URL on release.
    """
    dest = work / "live"
    r = subprocess.run(f"git clone --quiet --depth 1 {url} {dest}",
                       shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        failures.append(f"the documented URL does not clone: {url}\n    {r.stderr.strip()}")
        return

    # Identity, not existence. These are the paths the README tells a reader to use.
    expected = ["build/layer1-aggregate/Cargo.toml",
                "build/layer2-receipt/Cargo.toml",
                "adapters/flower/pyproject.toml"]
    missing = [e for e in expected if not (dest / e).is_file()]
    if missing:
        failures.append(
            f"{url} clones, but it is not this software: missing {', '.join(missing)}. "
            "A URL that resolves to the wrong repository fails a reader more confusingly "
            "than a dead one.")
        return
    print(f"OK   {url} clones and contains the crates the README names")


def main() -> int:
    keep = "--keep" in sys.argv
    live = "--live" in sys.argv
    work = Path(tempfile.mkdtemp(prefix="acfa-readme-"))
    failures = []

    try:
        url = documented_url()
        print(f"README documents: {url}")
        if live:
            print("live mode: the documented URL is NOT substituted\n")
            check_url_resolves(url, work, failures)

        # Install the README's commands from a real git remote rather than the working
        # copy, so a missing or uncommitted file fails here exactly as it would for a
        # stranger. When the extractor script is present it builds that remote;
        # otherwise this repository is already the tree under test and is cloned directly.
        # The checks below are identical either way.
        extractor = REPO / "publish/extract.py"
        if extractor.is_file():
            pub = work / "pub"
            sh([sys.executable, str(extractor), "--dest", str(pub),
                "--git-init", "--force"])
            print(f"source repo: testing the extracted tree at {pub}\n")
        else:
            pub = work / "pub"
            sh(f"git clone --quiet --depth 1 file://{REPO} {pub}")
            print(f"published repo: testing this repository at {pub}\n")
        # In live mode the documented URL stands unmodified, so every install below
        # exercises the string a reader would actually paste.
        local = url if live else f"file://{pub}"

        # 1. The dependency block, used as a real manifest.
        block = re.search(r"```toml\n(\[dependencies\][^`]+)```", README.read_text())
        if not block:
            failures.append("no [dependencies] block found in README")
        else:
            deps = block.group(1).replace(url, local)
            proj = work / "dep"
            (proj / "src").mkdir(parents=True)
            (proj / "Cargo.toml").write_text(
                '[package]\nname = "readme-dep-check"\nversion = "0.1.0"\n'
                'edition = "2021"\n\n' + deps)
            (proj / "src/main.rs").write_text(
                "fn main() { println!(\"{}\", acfa_aggregate::FRAC_BITS); }\n")
            try:
                sh("cargo build", cwd=proj)
                print("OK   dependency block parses and builds")
            except RuntimeError as e:
                failures.append(f"dependency block: {e}")

        # 2. cargo install, PARSED FROM THE README, not from a list kept here.
        #
        # The first version of this check hardcoded the crate names. It passed while the
        # README named a crate that does not exist, because it was testing this file's
        # beliefs rather than the document. A harness that cannot fail on bad input is not
        # evidence. Every command below is read out of the README.
        root = work / "cargo"
        installs = re.findall(r"^cargo install --git \S+ (\S+)\s*(?:#\s*(\S+))?",
                              README.read_text(), re.M)
        if not installs:
            failures.append("no `cargo install --git` line found in README")
        for crate, binary in installs:
            try:
                sh(f"cargo install --quiet --git {local} {crate} --root {root}")
                if binary and not (root / "bin" / binary).is_file():
                    raise AssertionError(
                        f"installed, but the binary the README names ({binary}) is absent; "
                        f"got {sorted(p.name for p in (root / 'bin').glob('*'))}")
                print(f"OK   cargo install --git ... {crate}"
                      + (f" -> {binary}" if binary else ""))
            except (RuntimeError, AssertionError) as e:
                failures.append(f"cargo install {crate}: {e}")

        # 3. pip, exactly as documented.
        venv = work / "venv"
        sh([sys.executable, "-m", "venv", str(venv)])
        pip, py = venv / "bin/pip", venv / "bin/python"
        pipcmd = None
        for line in README.read_text().splitlines():
            if line.strip().startswith("pip install") and "subdirectory=" in line:
                pipcmd = line.strip().replace(url, local)
                break
        if not pipcmd:
            failures.append("no pip install line with a subdirectory found in README")
        else:
            try:
                sh(f"{pip} install --quiet " + pipcmd.split("pip install", 1)[1].strip())
                sh(f"{py} -c 'import acfa_flower'")
                print("OK   pip install installs the adapter and it imports")
            except RuntimeError as e:
                failures.append(f"pip install: {e}")

        # 4. The quickstart, end to end, with the documented exit codes.
        rc = pub / "build/layer2-receipt"
        try:
            sh("cargo build --release --example issue --bin acfa-verify", cwd=rc)
            sh(f"cargo run -q --release --example issue -- --pki > {work}/t.pki", cwd=rc)
            sh(f"cargo run -q --release --example issue > {work}/r.acfa", cwd=rc)
            sh(f"cargo run -q --release --example issue -- --forged-pki > {work}/f.acfa", cwd=rc)
            v = rc / "target/release/acfa-verify"
            for path, want, what in [(f"{work}/r.acfa", 0, "honest receipt"),
                                     (f"{work}/f.acfa", 1, "forged PKI")]:
                got = subprocess.run(f"{v} {path} --pki {work}/t.pki --f 1",
                                     shell=True, capture_output=True).returncode
                if got != want:
                    failures.append(f"{what}: exit {got}, documented {want}")
            got = subprocess.run(f"{v} {work}/f.acfa", shell=True,
                                 capture_output=True).returncode
            if got != 3:
                failures.append(f"no --pki: exit {got}, documented 3")
            print("OK   quickstart runs and exit codes match the README")
        except RuntimeError as e:
            failures.append(f"quickstart: {e}")

        # 5. Every path any documented command touches must exist in the shipped tree.
        #
        # The install and quickstart checks above only cover the commands they know about.
        # A documented command once named a file this tree does not contain. It failed
        # with "No such file or directory" and no check noticed, because no check looked at
        # that block. This one looks at all of them, so a command can be wrong about the
        # tree it ships in only once.
        for block in re.findall(r"```sh\n(.*?)```", README.read_text(), re.S):
            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for tok in re.findall(r"[\w./-]+\.(?:py|rs|json|toml|pdf|md)", line):
                    # Paths under a `cd`-ed crate resolve there; only reject what resolves
                    # nowhere in the tree.
                    rel = tok.lstrip("./")
                    if (pub / rel).exists() or list(pub.rglob(pathlib.Path(rel).name)):
                        continue
                    failures.append(
                        f"documented command references a path not in the tree: {rel}\n"
                        f"    in: {line}")

        # 6. MSRV must agree with the manifests.
        claimed = re.search(r"Rust (\d+\.\d+)\+", README.read_text())
        declared = {p.name: re.search(r'rust-version = "(\d+\.\d+)"', p.read_text())
                    for p in pub.glob("build/*/Cargo.toml")}
        vals = {m.group(1) for m in declared.values() if m}
        if claimed and vals and claimed.group(1) not in vals:
            failures.append(
                f"README says Rust {claimed.group(1)}+, manifests declare {sorted(vals)}")
        else:
            print(f"OK   MSRV agrees: README {claimed.group(1) if claimed else '?'}, "
                  f"manifests {sorted(vals)}")

    finally:
        if keep:
            print(f"\nkept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} DOCUMENTED PATH(S) BROKEN:")
        for f in failures:
            print(f"  - {f.splitlines()[0]}")
        return 1
    print("every documented command runs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
