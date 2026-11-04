#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Reject new sequential SQL migrations and duplicate numeric versions (D347).

The fixed legacy list includes the eight already allocated 0041–0048 files.
It is independent of Git history, so this also works after a merge and in an
archive. Do not extend it: create new files with scripts/new-migration.
"""
from datetime import datetime
from pathlib import Path
import re
import sys

# Resolve the repository from the script so the caller's directory never changes the scope.
ROOT = Path(__file__).resolve().parents[2]


def legacy_names() -> set[str]:
    """Read the immutable names allocated before the timestamp transition."""
    return set(Path(__file__).with_name("legacy-migrations.txt").read_text().splitlines())


def check_names(names) -> list[str]:
    """Check every SQL filename, including untracked files and integer aliases."""
    legacy = legacy_names()
    versions = {}
    errors = []
    for name in sorted(names):
        prefix, _, _ = name.partition("_")
        if prefix.isascii() and prefix.isdigit():
            version = int(prefix)
            if version in versions:
                errors.append(f"duplicate migration version: {versions[version]} and {name}")
            versions[version] = name
        if name in legacy:
            continue
        if not re.fullmatch(r"[0-9]{14}_[a-z][a-z0-9]*(?:_[a-z0-9]+)*\.sql", name):
            errors.append(f"{name}: new migrations need YYYYMMDDHHMMSS_name.sql; use scripts/new-migration")
            continue
        try:
            datetime.strptime(prefix, "%Y%m%d%H%M%S")
        except ValueError:
            errors.append(f"{name}: invalid UTC timestamp")
    return errors


def main() -> int:
    """Check the working tree, without fetching or depending on a base ref."""
    directory = ROOT / "crates/infraternal-server/migrations"
    errors = check_names(path.name for path in directory.glob("*.sql"))
    for error in errors:
        print(error, file=sys.stderr)
    print(f"migration names: {'FAIL' if errors else 'PASS'}")
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
