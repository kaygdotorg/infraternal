#!/usr/bin/env python3
"""Remove build-directory/compiler command metadata from the generated native version header [D243]."""

from pathlib import Path
import re
import sys


def normalize(header: str) -> str:
    """Keep platform and version metadata; compiler argv is not part of the runtime contract."""
    declaration = 'static const char compiler_flags[] = "compiler: pinned musl toolchain";'
    if header.count(declaration) == 1:
        return header
    normalized, count = re.subn(
        r"static const char compiler_flags\[\] = \{.*?\n\};",
        declaration,
        header,
        flags=re.S,
    )
    if count != 1:
        raise ValueError("unexpected native build metadata format")
    return normalized


if __name__ == "__main__":
    path = Path(sys.argv[1])
    content = path.read_text()
    normalized = normalize(content)
    if content != normalized:
        path.write_text(normalized)
