#!/usr/bin/env python3
"""Seeds release parser boundaries using embedded public trust, without any signing secret [224]."""
import base64
from pathlib import Path
import struct

root = Path(__file__).resolve().parents[1]
corpus = root / "fuzz/corpus/release_verify"
corpus.mkdir(parents=True, exist_ok=True)
manifest = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  payload\n"
public = next(line for line in (root / "release/allowed_signers").read_text().splitlines() if line.startswith("release@"))
key = base64.b64decode(public.split()[3])
def field(value):
    return struct.pack(">I", len(value)) + value
blob = b"SSHSIG" + struct.pack(">I", 1) + field(key) + field(b"infraternal-release") + field(b"") + field(b"sha512") + field(field(b"ssh-ed25519") + field(bytes(64)))
encoded = base64.b64encode(blob)
armor = b"-----BEGIN SSH SIGNATURE-----\n" + b"\n".join(encoded[i:i + 70] for i in range(0, len(encoded), 70)) + b"\n-----END SSH SIGNATURE-----\n"
seed = struct.pack(">H", len(manifest)) + manifest + armor
(corpus / "known-key-envelope").write_bytes(seed)
for length in (0, 1, 2, 3, len(seed) - 1):
    (corpus / f"truncated-{length}").write_bytes(seed[:length])
