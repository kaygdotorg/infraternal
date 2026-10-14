#!/usr/bin/env python3
"""Omit only OpenSSL's AVX-512 AES-GCM dispatch from the pinned x86_64 build [D264]."""

from pathlib import Path
import fcntl
import os
import sys


SOURCE = Path("providers/implementations/ciphers/cipher_aes_gcm_hw_aesni.inc")
ASSEMBLY = Path("crypto/modes/asm/aes-gcm-avx512.pl")
INCLUDE = '#include "cipher_aes_gcm_hw_vaes_avx512.inc"'
PATCH_NOTE = "/* D264: retain AES-NI and generic AES-GCM; omit only VAES/AVX-512. */"
MARKER = ".infraternal-d264-avx512-gcm"
LOCK = ".infraternal-d264-avx512-gcm.lock"


def patch_source(source_root: Path) -> bool:
    """Patch the build's copied source once, failing closed on source drift."""
    include_path = source_root / SOURCE
    if not (source_root / ASSEMBLY).is_file() or not include_path.is_file():
        raise ValueError("expected pinned OpenSSL AES-GCM source files are missing")

    lock_path = source_root / LOCK
    marker_path = source_root / MARKER
    with lock_path.open("a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        source = include_path.read_text(encoding="utf-8")
        patched = source.count(PATCH_NOTE) == 1 and INCLUDE not in source
        if marker_path.exists():
            if marker_path.read_text(encoding="utf-8") != "D264\n" or not patched:
                raise ValueError("AES-GCM patch marker does not match the copied source")
            return False
        if patched:
            marker_path.write_text("D264\n", encoding="utf-8")
            return False
        if source.count(INCLUDE) != 1 or PATCH_NOTE in source:
            raise ValueError("pinned OpenSSL AES-GCM dispatch source changed")

        temporary = include_path.with_name(include_path.name + ".infraternal-tmp")
        try:
            temporary.write_text(source.replace(INCLUDE, PATCH_NOTE, 1), encoding="utf-8")
            os.replace(temporary, include_path)
            marker_path.write_text("D264\n", encoding="utf-8")
        finally:
            temporary.unlink(missing_ok=True)
        print("D264: disabled only VAES/AVX-512 AES-GCM dispatch", file=sys.stderr)
        return True


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch-openssl-avx512-gcm.py OPENSSL_SOURCE_ROOT")
    patch_source(Path(sys.argv[1]))
