#!/usr/bin/env python3
"""Keep the pinned crypto provider's compiler description independent of checkout paths (D243, #229)."""

import fcntl
import os
from pathlib import Path
import sys

SOURCE = Path('util/mkbuildinf.pl')
ORIGINAL = '$cflags = "compiler: $cflags";'
# Keep the wrapper name and every compiler option; only its checkout prefix is
# private to the builder. Configure may quote paths containing spaces; consume
# the closing quote with that prefix, preserving later path-valued options.
# The wrapper runs during Configure, before generation.
PATCHED = r'''$cflags =~ s{^.*?/\.cargo/(musl-cc(?:-avx512)?\.sh)["']?(?=\s|$)}{.cargo/$1};
$cflags = "compiler: $cflags";'''


def patch_source(root: Path) -> None:
    """Serialize compiler probes and replace the copied generator atomically."""
    with (root / '.infraternal-build-metadata.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        source = root / SOURCE
        text = source.read_text()
        marker = root / '.infraternal-build-metadata'
        if text.count(PATCHED) == 1 and text.count(ORIGINAL) == 1:
            marker.touch()
            return
        if text.count(ORIGINAL) != 1:
            raise ValueError('pinned crypto metadata generator changed')
        temporary = source.with_suffix('.infraternal-tmp')
        try:
            temporary.write_text(text.replace(ORIGINAL, PATCHED))
            temporary.chmod(source.stat().st_mode & 0o777)
            os.replace(temporary, source)
            marker.touch()
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: patch-openssl-build-metadata.py SOURCE_ROOT')
    patch_source(Path(sys.argv[1]))
