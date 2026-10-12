#!/usr/bin/env python3
"""Probe an IPv6-only SSH listener entirely inside the owned target namespace (#169)."""
import os
from pathlib import Path
import re
import subprocess
import time
from measure import DOCKER, ROOT, TARGET, generated_key


def main():
    private, public = generated_key()
    source = (ROOT / "docs/verification/addhost-breakit2/sshd.py").read_text()
    source = source.replace("Port 22\n", "Port 22\nListenAddress ::1\n")
    server = subprocess.Popen(DOCKER + ["exec", "-i", TARGET, "python3", "-u", "-c", source], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        server.stdin.write((public + "\n").encode())
        server.stdin.close()
        host_public = server.stdout.readline().decode().strip()
        assert host_public.startswith("ssh-ed25519 ")
        check = re.search(r'pub const CHECK_SCRIPT: &str = r#"(.*?)"#;', (ROOT / "crates/plugins/ssh/src/probe.rs").read_text(), re.S).group(1)
        # The client also lives in the target netns. This proves the IPv6 SSH
        # boundary, not a routed IPv6-only full enrollment/controller path.
        client = """import os, pathlib, subprocess, sys, time
root=pathlib.Path('/run/addhost-breakit2')
known=root/'client_known_hosts'; known.write_text('::1 '+sys.argv[1]+'\\n')
sock=root/'client_agent.sock'
agent=subprocess.Popen(['ssh-agent','-D','-a',str(sock)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
env=dict(os.environ,SSH_AUTH_SOCK=str(sock),SSH_ASKPASS_REQUIRE='never')
try:
 for _ in range(100):
  if sock.exists(): break
  time.sleep(.05)
 subprocess.run(['ssh-add','-'],input=sys.stdin.buffer.read(),env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 started=time.monotonic()
 result=subprocess.run(['ssh','-F','/dev/null','-T','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null','-o','BatchMode=yes','target@::1',sys.argv[2]],env=env,capture_output=True,timeout=5)
 lines=result.stdout.decode(errors='replace').splitlines()
 canonical=len(lines)==9 and lines[0]=='INFRATERNAL_CHECK_V1'
 print(f'IPV6_ONLY status={result.returncode} canonical={canonical} elapsed_ms={(time.monotonic()-started)*1000:.3f} output_bytes={len(result.stdout)}')
 assert result.returncode==0 and canonical
finally:
 agent.terminate(); agent.wait(timeout=5)
"""
        time.sleep(.5)
        print(f"ENVIRONMENT machine={os.uname().nodename} cores={os.cpu_count()} load={Path('/proc/loadavg').read_text().strip()}", flush=True)
        command = "sh -c '" + check.replace("'", "'\\''") + "'"
        subprocess.run(DOCKER + ["exec", "-i", TARGET, "python3", "-c", client, host_public, command], input=private, check=True)
    finally:
        subprocess.run(DOCKER + ["exec", TARGET, "sh", "-c", "if [ -f /run/addhost-breakit2/sshd.pid ]; then kill $(cat /run/addhost-breakit2/sshd.pid); fi"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    main()
