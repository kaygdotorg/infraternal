#!/usr/bin/env python3
"""Serve a disposable real SSH target with a memory-only generated host key (#169)."""
import base64
import os
from pathlib import Path
import struct
import subprocess
import sys

root = Path("/run/addhost-breakit2")
root.mkdir(mode=0o755, exist_ok=True)
authorized = root / "authorized_keys"
authorized.write_text(sys.stdin.readline())  # Public fixture identity only.
authorized.chmod(0o644)
private = subprocess.check_output(["openssl", "genpkey", "-algorithm", "ED25519"], stderr=subprocess.DEVNULL)
public = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private, stderr=subprocess.DEVNULL)
fd = os.memfd_create("breakit2-host-key", 0)
os.fchmod(fd, 0o600)
os.write(fd, private)
raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + public[12:]
print("ssh-ed25519 " + base64.b64encode(raw).decode(), flush=True)
config = root / "sshd_config"
config.write_text(f"""# Isolated #169 SSH target; no real-host trust or credentials.
Port 22
HostKey /proc/{os.getpid()}/fd/{fd}
AuthorizedKeysFile {authorized}
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin yes
UsePAM yes
StrictModes yes
PerSourcePenalties no
LogLevel ERROR
PidFile {root}/sshd.pid
""")
Path("/run/sshd").mkdir(exist_ok=True)
subprocess.run(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], check=True)
