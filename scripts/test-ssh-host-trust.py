#!/usr/bin/env python3
"""Run the trust regression on a real sshd with three memory-held host keys (#87)."""
import base64
import getpass
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


def ed25519():
    private = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'ED25519'], stderr=subprocess.DEVNULL)
    public = subprocess.check_output(['openssl', 'pkey', '-pubout', '-outform', 'DER'], input=private, stderr=subprocess.DEVNULL)[12:]
    wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + public
    return private, 'ssh-ed25519 ' + base64.b64encode(wire).decode()


scratch = Path.home() / '.cache/codex-scratch/release-addhost'
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='s', dir=scratch) as temporary:
    fixture = Path(temporary)
    fixture.chmod(0o700)
    client, public = ed25519()
    host, host_public = ed25519()
    host_keys = [host,
        subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'], stderr=subprocess.DEVNULL),
        subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1'], stderr=subprocess.DEVNULL)]
    host_keys[1] = subprocess.check_output(['openssl', 'rsa', '-traditional'], input=host_keys[1], stderr=subprocess.DEVNULL)
    host_keys[2] = subprocess.check_output(['openssl', 'ec'], input=host_keys[2], stderr=subprocess.DEVNULL)
    descriptors = []
    for private in host_keys:
        fd = os.memfd_create('infraternal-trust-fixture', os.MFD_CLOEXEC)
        os.fchmod(fd, 0o600)
        os.write(fd, private)
        descriptors.append(fd)
    (fixture / 'authorized_keys').write_text(public + '\n')
    (fixture / 'authorized_keys').chmod(0o600)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    host_paths = ''.join(f'HostKey /proc/{os.getpid()}/fd/{fd}\n' for fd in descriptors)
    (fixture / 'sshd_config').write_text(f'# Memory-only synthetic fixture; all stock key families.\nPort {port}\nListenAddress 127.0.0.1\n{host_paths}AuthorizedKeysFile {fixture}/authorized_keys\nPidFile {fixture}/sshd.pid\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes yes\nAllowUsers {getpass.getuser()}\nPerSourcePenalties no\nLogLevel ERROR\n')
    (fixture / 'config').write_text('# Isolated public SSH policy; no preseeded trust.\nHost *\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n IdentityFile none\n')
    (fixture / 'ssh').write_text(f'#!/bin/sh\n# Public fixture configuration only.\nexec /usr/bin/ssh -F "{fixture}/config" "$@"\n')
    (fixture / 'ssh').chmod(0o700)
    _, old_public = ed25519()
    (fixture / 'old.pub').write_text(f'[127.0.0.1]:{port} {old_public}\n')
    expected = subprocess.check_output(['ssh-keygen', '-l', '-E', 'sha256', '-f', '/dev/stdin'], input=(host_public + '\n').encode()).decode().split()[1]
    child = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(fixture / 'sshd_config')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if child.poll() is not None:
                raise RuntimeError('synthetic sshd failed to start (diagnostics withheld)')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        scanned = subprocess.check_output(['ssh-keyscan', '-T', '3', '-t', 'rsa,ecdsa,ed25519', '-p', str(port), '127.0.0.1'], stderr=subprocess.DEVNULL).decode()
        families = {line.split()[1] for line in scanned.splitlines() if not line.startswith('#')}
        assert families == {'ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'}, families
        env = {**os.environ, 'INFRATERNAL_SSH_FIXTURE': str(fixture), 'INFRATERNAL_SSH_FIXTURE_PORT': str(port), 'INFRATERNAL_SSH_EXPECTED_ED25519': expected}
        result = subprocess.run([sys.argv[1], '--ignored', '--nocapture', *sys.argv[2:]], input=client, env=env)
        sys.exit(result.returncode)
    finally:
        child.terminate()
        child.wait(timeout=5)
        for fd in descriptors:
            os.close(fd)
