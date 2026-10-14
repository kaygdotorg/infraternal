#!/usr/bin/env python3
"""Verify ordinary versus callback-free compiled VT APIs without running terminal input (#189)."""
import argparse
import json
from pathlib import Path
import subprocess


def exports(archive: Path) -> set[str]:
    result = subprocess.run(
        ["nm", "-g", "--defined-only", str(archive)],
        check=True, capture_output=True, text=True,
    )
    return {line.split()[-1] for line in result.stdout.splitlines() if line.split()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ordinary", type=Path)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    rows = []
    for mode, archive in [("ordinary", args.ordinary), ("image", args.image)]:
        symbols = exports(archive)
        expected = dict.fromkeys([
            "ghostty_terminal_new", "ghostty_terminal_resize", "infraternal_vt_snapshot",
        ], True)
        expected.update(dict.fromkeys([
            "ghostty_sys_set", "ghostty_sys_log_stderr",
        ], mode == "ordinary"))
        actual = {name: name in symbols for name in expected}
        if actual != expected:
            raise RuntimeError(f"Unexpected {mode} native API: {json.dumps(actual, sort_keys=True)}")
        rows.append({"mode": mode, "exports": actual})
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
