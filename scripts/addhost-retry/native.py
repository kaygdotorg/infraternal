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
import threading
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
    parser.add_argument('--retry', action='store_true', help='inject an immediate published setup failure, then measure Retry (#230)')
    parser.add_argument('--route-wait-max-ms', type=int, help='optional route-wait assertion, separate from Retry duration')
    parser.add_argument('--mode', choices=['rootless', 'root'], default='rootless')
    parser.add_argument('--session-binary', type=Path, help='early session image; selects the published (instant) path')
    parser.add_argument('--stale-helper', type=Path, help='older binary swapped into the executable cache once the agent runs')
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if args.retry and args.timeout_retry:
        parser.error('--retry cannot be combined with --timeout-retry')
    if args.retry and args.session_binary is None:
        parser.error('--retry requires --session-binary')
    assert os.geteuid() == 0
    assert os.uname().nodename == 'infraternal-perf-test', 'fixture runs only on the named VM'
    assert args.label.isalnum()
    root = Path('/root/infraternal-bench/addhost-retry') / args.label
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    account = 'ahr230' + args.label
    home = Path('/home') / account
    # A unique account owns every target-side artifact. Never reuse a preexisting home.
    assert not home.exists()
    root_mode = args.mode == 'root'
    root_paths = [Path('/var/lib/infraternal'), Path('/var/lib/infraternal.bootstrap-cache'),
                  Path('/usr/local/bin/infraternal'), Path('/etc/systemd/system/infraternal-agent.service')]
    if root_mode:
        # Root installs touch fixed system paths: admit only a host that has none.
        assert not any(p.exists() or p.is_symlink() for p in root_paths), 'root install paths already exist'
        assert not list(Path('/var/lib').glob('infraternal.bootstrap-rollback-*'))
    root_installed = False
    swapper = None
    sshd = None
    created = False
    public_created = False
    blocked = False
    fd = None
    lock_trace_path = None
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
        login = 'root' if root_mode else account
        authorized.chmod(0o644)
        config = root / 'sshd_config'
        config.write_text(f'''# Isolated rootless retry fixture, with a memory-only host key.
ListenAddress 127.0.0.1
Port 4928
HostKey /proc/{os.getpid()}/fd/{fd}
AuthorizedKeysFile {authorized}
AllowUsers {login}
PermitRootLogin {'prohibit-password' if root_mode else 'no'}
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
            BREAKIT2_TARGET=f'{login}@127.0.0.1:4928', BREAKIT2_MODE=args.mode,
            BREAKIT2_CONTROLLER_IP='127.0.0.1', BREAKIT2_SERVER_NAME='localhost')
        if args.timeout_retry:
            assert run('nft', 'list', 'table', 'inet', 'addhost_retry_230',
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False).returncode != 0, 'test table already exists'
            rule = f"""table inet addhost_retry_230 {{
    chain output {{
        type filter hook output priority 0; policy accept;
        meta skuid {0 if root_mode else uid} ip daddr 127.0.0.1 tcp dport 4930 drop;
        meta skuid {0 if root_mode else uid} ip daddr 127.0.0.1 udp dport 4930 drop;
    }}
}}
"""
            run('nft', '-f', '-', input=rule.encode())
            blocked = True
            environment['BREAKIT2_TIMEOUT_RETRY'] = '1'
            if args.session_binary:
                environment['ADDHOST_RETRY_PHASE_TIMING'] = '1'
                environment['ADDHOST_RETRY_LOCK_TIMING'] = '1'
                environment['BREAKIT2_RETRY_MAX_MS'] = '2000'
        if args.session_binary:
            environment['ADDHOST_INSTANT'] = '1'
            environment['INFRATERNAL_REMOTE_TEST_SESSION_BINARY'] = str(args.session_binary.resolve())
        if args.retry:
            environment['BREAKIT2_RETRY'] = '1'
            environment['BREAKIT2_RETRY_MAX_MS'] = '2000'
            environment['ADDHOST_RETRY_PHASE_TIMING'] = '1'
            environment['ADDHOST_RETRY_LOCK_TIMING'] = '1'
        # A silent first attempt retains its link-scaled startup allowance.
        # Retry's LAN budget remains separate from that deliberately blocked wait.
        if args.route_wait_max_ms is not None:
            assert args.route_wait_max_ms > 0
            environment['BREAKIT2_ROUTE_WAIT_MAX_MS'] = str(args.route_wait_max_ms)
        if args.session_binary and (args.retry or args.timeout_retry):
            lock_trace_path = root / 'retry-lock-trace' if root_mode else Path(f'/run/user/{uid}/retry-lock-trace')
            lock_trace_path.touch(mode=0o600, exist_ok=False)
            if not root_mode:
                os.chown(lock_trace_path, uid, uid)
            environment['ADDHOST_RETRY_LOCK_TRACE_PATH'] = str(lock_trace_path)
        base = Path('/var/lib/infraternal') if root_mode else home / '.local/share/infraternal'
        root_installed = root_mode
        if args.stale_helper:
            stale = args.stale_helper.read_bytes()
            def swap():
                # Once the agent runs from bin/live, replace only the cached copy
                # with an older release, as an earlier version would have left it.
                cache = base.with_name('infraternal.bootstrap-cache') / 'payload'
                for _ in range(1200):
                    if (base / 'sessions/.lifetime-lock').exists() and (base / 'bin/live').exists() and cache.exists():
                        break
                    time.sleep(.05)
                else:
                    print('STALE helper swap skipped: agent never started', flush=True)
                    return
                time.sleep(2)
                owner = cache.stat()
                temporary = cache.with_name('payload.stale')
                temporary.write_bytes(stale)
                os.chown(temporary, owner.st_uid, owner.st_gid)
                temporary.chmod(0o700)
                temporary.replace(cache)
                print(f'STALE helper swapped bytes={len(stale)}', flush=True)
            swapper = threading.Thread(target=swap, daemon=True)
            swapper.start()
        print(f'ENVIRONMENT machine={os.uname().nodename} cpus={os.cpu_count()} load={Path("/proc/loadavg").read_text().strip()} label={args.label} uid={uid} mode={args.mode} instant={bool(args.session_binary)} retry={args.retry} timeout_retry={args.timeout_retry} stale_helper={bool(args.stale_helper)}', flush=True)
        time.sleep(.2)
        result = subprocess.run([str(args.test_binary.resolve()), 'breakit2_live_ssh_install_join_and_terminal', '--ignored', '--nocapture'], input=private, env=environment)
        print('RECEIPTS', [p.name for p in base.parent.glob('infraternal.bootstrap-rollback-*')], flush=True)
        if base.exists():
            print('REMAINING', sorted(str(p.relative_to(base)) for p in base.rglob('*')), flush=True)
        return result.returncode
    finally:
        if blocked:
            subprocess.run(['nft', 'delete', 'table', 'inet', 'addhost_retry_230'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if root_installed:
            # Remove only the fixed system paths this run was admitted to create.
            run('systemctl', 'disable', '--now', 'infraternal-agent.service', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            for path in root_paths:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                elif path.exists() or path.is_symlink():
                    path.unlink()
            for receipt in Path('/var/lib').glob('infraternal.bootstrap-rollback-*'):
                receipt.unlink()
            run('systemctl', 'daemon-reload')
            print('CLEANUP root_paths_removed=true', flush=True)
        if sshd:
            sshd.terminate()
            sshd.wait(timeout=10)
            print(f'CLEANUP sshd_pid={sshd.pid} exited={sshd.returncode}', flush=True)
        if fd is not None:
            os.close(fd)
        if lock_trace_path is not None:
            lock_trace_path.unlink(missing_ok=True)
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
        if root.exists():
            shutil.rmtree(root)
            print('CLEANUP fixture_directory_removed=true', flush=True)


if __name__ == '__main__':
    sys.exit(main())
