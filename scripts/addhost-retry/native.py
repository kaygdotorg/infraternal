#!/usr/bin/env python3
"""Exercise SSH bootstrap on a disposable rootless VM account, keeping fixture keys in memory (#230)."""
import argparse
import base64
import os
from pathlib import Path
import pwd
import shutil
import struct
import subprocess
import sys
import time


def run(*args, **kwargs):
    kwargs.setdefault('check', True)
    return subprocess.run(args, **kwargs)


def key():
    private = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'ED25519'], stderr=subprocess.DEVNULL)
    public = subprocess.check_output(['openssl', 'pkey', '-pubout', '-outform', 'DER'], input=private, stderr=subprocess.DEVNULL)
    wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + public[12:]
    return private, 'ssh-ed25519 ' + base64.b64encode(wire).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--timeout-retry', action='store_true')
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert os.uname().nodename == 'infraternal-perf-test', 'fixture runs only on the named VM'
    assert args.label.isalnum()
    root = Path('/root/infraternal-bench/addhost-retry') / args.label
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    account = 'ahr230' + args.label
    home = Path('/home') / account
    # A unique account owns every target-side artifact. Never reuse a preexisting home.
    assert not home.exists()
    sshd = None
    created = False
    public_created = False
    blocked = False
    fd = None
    try:
        # Account deletion can precede logind's retirement of the old uid.
        # Keep execution uids distinct across adjacent fixture runs.
        counter = root.parent / 'next_uid'
        uid = int(counter.read_text()) if counter.exists() else 30000
        while True:
            try:
                pwd.getpwuid(uid)
                uid += 1
            except KeyError:
                break
        assert uid < 60000
        counter.write_text(str(uid + 1))
        run('useradd', '--create-home', '--uid', str(uid), '--shell', '/bin/bash', account)
        created = True
        run('loginctl', 'enable-linger', account)
        run('systemctl', 'start', f'user@{uid}.service')
        for _ in range(100):
            if Path(f'/run/user/{uid}/bus').exists():
                break
            time.sleep(.1)
        else:
            raise AssertionError('disposable user manager did not start')
        private, public = key()
        host_private, host_public = key()
        fd = os.memfd_create('addhost-retry-host', 0)
        os.fchmod(fd, 0o600)
        os.write(fd, host_private)
        # The daemon reads its generated public allow-list from a root-owned public directory.
        public_root = Path('/run') / account
        public_root.mkdir(mode=0o755)
        public_created = True
        authorized = public_root / 'authorized_keys'
        authorized.write_text(public + '\n')
        authorized.chmod(0o644)
        config = root / 'sshd_config'
        config.write_text(f'''# Isolated rootless retry fixture, with a memory-only host key.
ListenAddress 127.0.0.1
Port 4928
HostKey /proc/{os.getpid()}/fd/{fd}
AuthorizedKeysFile {authorized}
AllowUsers {account}
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
SetEnv XDG_RUNTIME_DIR=/run/user/{uid}
StrictModes yes
PerSourcePenalties no
LogLevel ERROR
PidFile {root}/sshd.pid
''')
        sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)], stderr=subprocess.DEVNULL)
        known = root / 'known_hosts'
        known.write_text('[127.0.0.1]:4928 ' + host_public + '\n')
        client = root / 'config'
        client.write_text(f'# Isolated fixture trust.\nHost *\n UserKnownHostsFile {known}\n GlobalKnownHostsFile /dev/null\n StrictHostKeyChecking yes\n UpdateHostKeys no\n')
        wrapper = root / 'ssh'
        wrapper.write_text(f'#!/bin/sh\nexec /usr/bin/ssh -F {client} "$@"\n')
        wrapper.chmod(0o700)
        environment = dict(os.environ, INFRATERNAL_TEST_RTT='0',
            INFRATERNAL_TEST_STATE_ROOT=str(root),
            INFRATERNAL_REMOTE_TEST_BINARY=str(args.binary.resolve()),
            BREAKIT2_TARGET=f'{account}@127.0.0.1:4928',
            BREAKIT2_CONTROLLER_IP='127.0.0.1', BREAKIT2_SERVER_NAME='localhost')
        if args.timeout_retry:
            assert run('nft', 'list', 'table', 'inet', 'addhost_retry_230',
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False).returncode != 0, 'test table already exists'
            rule = f"""table inet addhost_retry_230 {{
    chain output {{
        type filter hook output priority 0; policy accept;
        meta skuid {uid} ip daddr 127.0.0.1 tcp dport 4930 drop;
        meta skuid {uid} ip daddr 127.0.0.1 udp dport 4930 drop;
    }}
}}
"""
            run('nft', '-f', '-', input=rule.encode())
            blocked = True
            environment['BREAKIT2_TIMEOUT_RETRY'] = '1'
        print(f'ENVIRONMENT machine={os.uname().nodename} cpus={os.cpu_count()} load={Path("/proc/loadavg").read_text().strip()} label={args.label} uid={uid}', flush=True)
        time.sleep(.2)
        result = subprocess.run([str(args.test_binary.resolve()), 'breakit2_live_ssh_install_join_and_terminal', '--ignored', '--nocapture'], input=private, env=environment)
        base = home / '.local/share/infraternal'
        print('RECEIPTS', [p.name for p in base.parent.glob('infraternal.bootstrap-rollback-*')], flush=True)
        if base.exists():
            print('REMAINING', sorted(str(p.relative_to(base)) for p in base.rglob('*')), flush=True)
        return result.returncode
    finally:
        if blocked:
            subprocess.run(['nft', 'delete', 'table', 'inet', 'addhost_retry_230'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if sshd:
            sshd.terminate()
            sshd.wait(timeout=10)
            print(f'CLEANUP sshd_pid={sshd.pid} exited={sshd.returncode}', flush=True)
        if fd is not None:
            os.close(fd)
        if created:
            run('runuser', '-u', account, '--', 'env', f'XDG_RUNTIME_DIR=/run/user/{uid}', 'systemctl', '--user', 'disable', '--now', 'infraternal-agent.service', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            run('loginctl', 'disable-linger', account)
            run('loginctl', 'terminate-user', account, check=False, stderr=subprocess.DEVNULL)
            # Account retirement must wait for the manager and its PAM child.
            run('systemctl', 'stop', f'user@{uid}.service')
            run('userdel', '--remove', account, stderr=subprocess.DEVNULL)
            if public_created:
                shutil.rmtree(public_root)
        assert subprocess.run(['nft', 'list', 'table', 'inet', 'addhost_retry_230'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
        if created:
            try:
                pwd.getpwnam(account)
            except KeyError:
                pass
            else:
                raise AssertionError('disposable account survived cleanup')
            assert not home.exists()
        print('CLEANUP nft_table_absent=true disposable_account_removed=true', flush=True)


if __name__ == '__main__':
    sys.exit(main())
