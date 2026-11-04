#!/usr/bin/env python3
"""Map the files changed against a base ref to what `scripts/verify quick` must check (#329).

Prints one token per line:
  workspace       a root manifest, lockfile, toolchain, cargo config or vendored source changed,
                  so every crate can be affected: check the whole workspace
  package <name>  a workspace package that owns a changed file
  tracer          TypeScript under apps/tracer or packages/ changed: run the tracer typecheck
  exclude <name>  a cargo-fuzz package (`[package.metadata] cargo-fuzz = true`), always printed.
                  Its bins link libFuzzer's main, which never returns: `cargo test --bins` runs
                  them even with `test = false` (an explicit --bins overrides it) and `quick`
                  hung for 23-25 minutes on it (#329). A fuzz package is never printed as
                  `package`; when only it changed, `fuzz` is printed instead so clippy still runs.

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


def scope(changed, members, fuzz_dirs):
    """Return the output lines for the changed paths. Pure: no git, no cargo (tested without both)."""
    packages = set()
    fuzz_changed = False
    for path in changed:
        # Longest owning directory wins: crates/plugins/ssh is not crates/.
        for directory in sorted(members, key=len, reverse=True):
            if path == directory or path.startswith(directory + "/"):
                if directory in fuzz_dirs:
                    fuzz_changed = True
                else:
                    packages.add(members[directory])
                break

    lines = []
    if any(path.startswith(WORKSPACE_WIDE) or path in WORKSPACE_WIDE for path in changed):
        lines.append("workspace")
    lines += [f"package {name}" for name in sorted(packages)]
    if fuzz_changed:
        lines.append("fuzz")
    if any(path.startswith(TRACER_ROOTS) for path in changed):
        lines.append("tracer")
    lines += [f"exclude {members[d]}" for d in sorted(fuzz_dirs)]
    return lines


def main():
    base = sys.argv[1]
    merge_base = run("git", "merge-base", "HEAD", base).strip()
    changed = set(run("git", "diff", "--name-only", merge_base).splitlines())
    changed |= set(run("git", "ls-files", "--others", "--exclude-standard").splitlines())

    root = os.path.realpath(run("git", "rev-parse", "--show-toplevel").strip())
    metadata = json.loads(run("cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"))
    members, fuzz_dirs = {}, set()
    for p in metadata["packages"]:
        directory = os.path.relpath(os.path.dirname(p["manifest_path"]), root)
        members[directory] = p["name"]
        if (p.get("metadata") or {}).get("cargo-fuzz"):
            fuzz_dirs.add(directory)

    print("\n".join(scope(changed, members, fuzz_dirs)))


if __name__ == "__main__":
    main()
