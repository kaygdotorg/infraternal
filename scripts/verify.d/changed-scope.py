#!/usr/bin/env python3
"""Map the files changed against a base ref to what `scripts/verify quick` must check (#329).

Prints one token per line:
  workspace       a root manifest, lockfile, toolchain, cargo config or vendored source changed,
                  so every crate can be affected: check the whole workspace
  package <name>  a workspace package that owns a changed file
  tracer          TypeScript under apps/tracer or packages/ changed: run the tracer typecheck

"Changed" is the merge base with BASE up to the working tree: commits, staged and unstaged
edits, and untracked files. A file outside every package and outside the lists above (docs,
scripts, contracts) selects nothing: quick then runs only fmt, and `verify fast` stays the gate.
"""

import json
import os
import subprocess
import sys

WORKSPACE_WIDE = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/", "vendor/")
TRACER_ROOTS = ("apps/tracer/", "packages/")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main():
    base = sys.argv[1]
    merge_base = run("git", "merge-base", "HEAD", base).strip()
    changed = set(run("git", "diff", "--name-only", merge_base).splitlines())
    changed |= set(run("git", "ls-files", "--others", "--exclude-standard").splitlines())

    root = os.path.realpath(run("git", "rev-parse", "--show-toplevel").strip())
    metadata = json.loads(run("cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"))
    members = {
        os.path.relpath(os.path.dirname(p["manifest_path"]), root): p["name"]
        for p in metadata["packages"]
    }

    packages = set()
    for path in changed:
        # Longest owning directory wins: crates/plugins/ssh is not crates/.
        for directory in sorted(members, key=len, reverse=True):
            if path == directory or path.startswith(directory + "/"):
                packages.add(members[directory])
                break

    if any(path.startswith(WORKSPACE_WIDE) or path in WORKSPACE_WIDE for path in changed):
        print("workspace")
    for name in sorted(packages):
        print("package", name)
    if any(path.startswith(TRACER_ROOTS) for path in changed):
        print("tracer")


main()
