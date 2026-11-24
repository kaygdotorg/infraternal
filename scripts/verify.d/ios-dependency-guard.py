#!/usr/bin/env python3
"""Refuse crates in an iOS dependency tree that must never ship to an iPhone (#580, T3).

The packet tunnel extension has a small memory budget and Apple's review rules
behind it, and the shared client core is built there with rustls and ring only.
This script reads the output of

    cargo tree --target aarch64-apple-ios -e normal,features --prefix none -p <crate>

on standard input and exits 1, naming every offender, when the tree contains:

- `openssl*` (including `openssl-sys`, `openssl-src`, `tokio-openssl`),
- `sqlx*`, `libsqlite3-sys`,
- `aws-lc*`,
- the `rt-multi-thread` feature of `tokio` (the extension runs one current-thread
  runtime).

With `--prefix none` every line is `name vX.Y.Z ...` for a package, or
`name feature "x"` for a feature node that `-e features` adds.
"""

import re
import sys

# Package-name patterns. `openssl` anywhere in a name (`openssl-sys`, `tokio-openssl`)
# and a prefix for the others: a new wrapper around the same library is as wrong.
FORBIDDEN_PACKAGES = (
    re.compile(r"openssl"),
    re.compile(r"^sqlx"),
    re.compile(r"^libsqlite3-sys$"),
    re.compile(r"^aws-lc"),
)

# (package, feature) pairs that must not be switched on.
FORBIDDEN_FEATURES = (("tokio", "rt-multi-thread"),)

_PACKAGE = re.compile(r"^(\S+) v\S+")
_FEATURE = re.compile(r'^(\S+) feature "([^"]+)"')


def offenders(tree_text):
    """Return the sorted, de-duplicated offending entries found in `cargo tree` text."""
    found = set()
    for line in tree_text.splitlines():
        line = line.strip()
        feature = _FEATURE.match(line)
        if feature:
            if (feature.group(1), feature.group(2)) in FORBIDDEN_FEATURES:
                found.add(f"{feature.group(1)}/{feature.group(2)}")
            continue
        package = _PACKAGE.match(line)
        if package and any(p.search(package.group(1)) for p in FORBIDDEN_PACKAGES):
            found.add(package.group(1))
    return sorted(found)


def main():
    """Check the tree on stdin; print offenders to stderr and return the exit code."""
    bad = offenders(sys.stdin.read())
    if bad:
        print("iOS dependency guard: forbidden in an iOS build: " + ", ".join(bad), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
