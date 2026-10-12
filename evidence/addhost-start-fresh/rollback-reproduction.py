"""Reproduce the previous-attempt rendezvous refusal with the real rollback shell."""
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile

source = Path('crates/plugins/ssh/src/install.rs').read_text()
constants = dict(re.findall(r'const (\w+): &str = r#"(.*?)"#;', source, re.S))
scratch = Path.home() / '.cache/codex-scratch/asf'
with tempfile.TemporaryDirectory(dir=scratch) as root:
    base = Path(root) / 'infraternal'
    base.mkdir(mode=0o700)
    host, transaction = '1' * 32, '2' * 32
    owner = base / '.bootstrap-owner'
    owner.write_text(host + '\n')
    owner.chmod(0o600)
    sessions = base / 'sessions/sessions'
    sessions.mkdir(parents=True)
    sessions.chmod(0o700)
    sessions.parent.chmod(0o700)
    previous = Path.cwd()
    os.chdir(sessions)
    s = socket.socket(socket.AF_UNIX)
    s.bind('3' * 32 + '.sock')
    s.close()
    Path('3' * 32 + '.sock').chmod(0o600)
    os.chdir(previous)
    receipt = Path(str(base) + '.bootstrap-rollback-' + transaction)
    receipt.write_text(f'{host} {transaction} fresh {base.stat().st_dev}:{base.stat().st_ino}\n')
    receipt.chmod(0o600)
    script = f'set -euC\numask 077\nbase="{base}"\nhost={host}\ntransaction={transaction}\n' + constants['FRESH_CLEANUP'] + constants['ROLLBACK_TRANSACTION']
    result = subprocess.run(['/bin/sh', '-c', script], capture_output=True)
    print('previous-attempt rollback status:', result.returncode)
    assert result.returncode == 0, 'owned stale socket still requires manual cleanup'
