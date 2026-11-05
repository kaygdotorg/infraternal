#!/usr/bin/env python3
"""Check ordered remapping and literal paths with the host's Bash, including macOS 3.2 (#366)."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="remap-flags-") as directory:
    scratch = Path(directory)
    # Shell metacharacters must remain data when appending to a caller's array.
    checkout = scratch / "checkout ' $(false)"
    cargo = scratch / "cargo home"
    registry = cargo / "registry/src/pinned-registry"
    registry.mkdir(parents=True)
    target = checkout / "target"
    rustup = scratch / "rustup"
    mappings = [(str(registry), "/cargo"), (str(checkout), "/infraternal"),
                (str(cargo), "/cargo"), (str(target), "/build"), (str(rustup), "/rustup")]
    expected = ["existing"] + [
        f"--remap-path-prefix={source}={destination}"
        for source, destination in sorted(mappings, key=lambda pair: -len(pair[0]))
    ]
    result = subprocess.run([
        os.environ.get("REMAP_TEST_BASH", "/bin/bash"), "-c",
        '''set -euo pipefail
source "$1"
flags=(existing)
infraternal_append_path_remap_flags flags --remap-path-prefix= "$2" "$3" "$4" "$5"
printf '%s\\0' "${flags[@]}"
''', "remap-test", str(ROOT / ".cargo/rust-remap-flags.sh"),
        str(checkout), str(cargo), str(target), str(rustup),
    ], capture_output=True, check=True)
    actual = result.stdout.decode().split("\0")[:-1]
    assert actual == expected, (actual, expected)
    # Invalid indirect destinations must fail before the shell evaluates them.
    rejected = subprocess.run([
        os.environ.get("REMAP_TEST_BASH", "/bin/bash"), "-c",
        '''set -euo pipefail
source "$1"
infraternal_append_path_remap_flags 'flags; false' prefix /checkout /cargo /target ""
''', "remap-test", str(ROOT / ".cargo/rust-remap-flags.sh"),
    ], capture_output=True, text=True)
    assert rejected.returncode == 2, rejected
    assert "invalid remap destination array name" in rejected.stderr, rejected.stderr
print("PASS: host Bash preserves literal remap paths, ordering and existing flags")
