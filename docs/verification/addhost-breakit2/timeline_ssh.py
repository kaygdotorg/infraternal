#!/usr/bin/env python3
"""Reduce owned OpenSSH diagnostics to fixed protocol boundaries; never store arbitrary stderr, command text or private values (#189)."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

arguments = sys.argv[1:]
if "-M" in arguments and os.environ.get("ADDHOST_SSH_COMPRESSION") == "1":
    # Public fixture-only candidate; the shipping transport is unchanged.
    arguments = ["-C", *arguments]
if "-M" not in arguments:
    # A trusted experiment changes only the retained prompt command's shared
    # pipe, before exec; it neither reads input nor changes full-install pipes.
    if os.environ.get("ADDHOST_PROMPT_PIPE_BYTES") and any("CHECK ready" in arg for arg in arguments):
        import fcntl
        capacity = int(os.environ["ADDHOST_PROMPT_PIPE_BYTES"])
        if capacity not in (8192, 16384, 32768):
            raise ValueError("invalid public prompt pipe capacity")
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETPIPE_SZ, capacity)
    os.execv("/usr/bin/ssh", ["ssh", *arguments])
steps = {
    "Connection established.": "tcp_connected",
    "Local version string ": "version_sent",
    "Remote protocol version ": "version_received",
    "SSH2_MSG_KEXINIT sent": "kexinit_sent",
    "SSH2_MSG_KEXINIT received": "kexinit_received",
    "SSH2_MSG_NEWKEYS sent": "newkeys_sent",
    "SSH2_MSG_NEWKEYS received": "newkeys_received",
    "SSH2_MSG_SERVICE_ACCEPT received": "auth_service_accepted",
    "Host ": "host_key_checked",
    "muxserver_listen: temporary control path": "master_ready",
}
evidence = Path(os.environ["ADDHOST_TIMELINE_EVIDENCE"]) / "ssh-boundaries.jsonl"
child = subprocess.Popen(["/usr/bin/ssh", "-vvv", *arguments], stderr=subprocess.PIPE)
with evidence.open("a") as output:
    for line in child.stderr:
        # The generated command and identities can appear in verbose lines.
        # Only exact protocol tokens and numeric message types survive.
        text = line.decode(errors="replace")
        step = next((value for key, value in steps.items() if key in text), None)
        message = re.search(r"(?:debug3: )?(send|receive) packet: type (\d+)\r?\n$", text)
        if message:
            step = f"packet_{message.group(1)}_{int(message.group(2))}"
        if "Authenticated to " in text and ' using "' in text:
            step = "authenticated"
            # This exact local method receipt is the production recognizer's
            # input. It never contains a credential or command body.
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()
        if step:
            output.write(json.dumps({"source": "ssh", "step": step, "epoch_ms": time.time()*1000}) + "\n")
            output.flush()
sys.exit(child.wait())
