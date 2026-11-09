#!/usr/bin/env python3
"""Check that binary release bundles carry the linked VT engine's MIT notice (#419).

Pass a real static ELF with --binary. Its architecture does not matter here:
the same ELF fills each payload slot because this checks packaging, not linking.
The temporary target and bundle are removed even when the assertion fails.
"""
# SPDX-License-Identifier: AGPL-3.0-only

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    """Package known static fixture bytes and require the upstream notice text."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="vt-release-notices-") as temporary:
        scratch = Path(temporary)
        target = scratch / "target"
        for variant, name in (("", "infraternal"), ("bootstrap", "infraternal"),
                              ("session", "infraternal-session")):
            for architecture in ("x86_64", "aarch64"):
                directory = target / variant / f"{architecture}-unknown-linux-musl" / "release"
                directory.mkdir(parents=True)
                (directory / name).symlink_to(binary)
        bundle = scratch / "bundle"
        subprocess.run(
            [str(root / "scripts/package-release"), str(bundle), "x86_64", "--built"],
            cwd=root,
            env={**os.environ, "CARGO_TARGET_DIR": str(target)},
            check=True,
        )
        notices = bytearray()
        required = {
            "licenses/libghostty-vt/libghostty-vt-MIT.txt": (
                b"Mitchell Hashimoto",
                b"Permission is hereby granted",
            ),
            "licenses/libghostty-vt/highway-Apache-2.0.txt": (
                b"Apache License",
                b"Version 2.0",
            ),
            "licenses/libghostty-vt/highway-BSD-3-Clause.txt": (
                b"Highway Project Authors",
                b"Redistribution and use",
            ),
            "licenses/libghostty-vt/simdutf-Apache-2.0.txt": (
                b"Apache License",
                b"Version 2.0",
            ),
            "licenses/libghostty-vt/simdutf-MIT.txt": (b"simdutf authors",),
            "licenses/libghostty-vt/translate_c-MIT.txt": (b"Zig contributors",),
            "licenses/libghostty-vt/uucode-MIT.txt": (b"Jacob Sandlund",),
            "licenses/libghostty-vt/Unicode-3.0.txt": (b"Unicode, Inc.",),
            "licenses/libghostty-vt/aro-MIT.txt": (b"Veikka Tuominen",),
            "licenses/libghostty-vt/wuffs-Apache-2.0.txt": (
                b"Apache License",
                b"Version 2.0",
            ),
            "licenses/libghostty-vt/wuffs-MIT.txt": (b"Wuffs Authors",),
        }
        for relative, markers in required.items():
            path = bundle / relative
            assert path.is_file(), f"release omits required licence notice: {relative}"
            notice = path.read_bytes()
            assert all(marker in notice for marker in markers), (
                f"licence notice does not match the signed dependency asset: {relative}"
            )
        for path in sorted(bundle.rglob("*")):
            if not path.is_file():
                continue
            print(path.relative_to(bundle), flush=True)
            # Executable strings do not provide a readable distributed notice.
            # A consolidated text notice or individual licence files both work.
            if path.stat().st_size <= 2 * 1024 * 1024:
                notices.extend(path.read_bytes())
        assert b"Mitchell Hashimoto" in notices and b"Permission is hereby granted" in notices, (
            "release omits the linked libghostty-vt MIT copyright and permission notice"
        )


if __name__ == "__main__":
    main()
