#!/usr/bin/env python3
"""Prove D362 against a disposable host account as real root on a systemd host.

Run with a freshly built binary: python3 scripts/test-revoke-account.py BINARY.
The local SSH socket (.host) must support public-key logins. This creates only
its own account, keys and login identities, and removes them even on failure.
Never run against a production host.
"""
import json
import filecmp
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from agent_fixture import Binary, cleanup, control


def command(*args, check=True):
    """Run an administrative test command without logging credentials or shell argv."""
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=90)


def processes(uid):
    """Read real/effective/saved/filesystem UIDs, including processes outside user.slice."""
    found = []
    for path in Path('/proc').glob('[0-9]*/status'):
        try:
            lines = path.read_text().splitlines()
            ids = next(line.split()[1:] for line in lines if line.startswith('Uid:'))
            if str(uid) in ids:
                found.append(int(path.parent.name))
        except FileNotFoundError:
            pass
    return found


def wait_until(predicate):
    """Poll for a state transition; the deadline detects a hang, not a speed budget."""
    deadline = time.monotonic() + 30
    while not predicate():
        assert time.monotonic() < deadline, 'state transition did not complete'
        # sleep: poll only until the owned process or logind account disappears.
        time.sleep(0.05)


def prepare(client, number, person, account):
    """Record an actual grant and start the host login through its public action."""
    return control(client, number, 'terminal.login.prepare', dict(
        person=str(person), account=account, uid=pwd.getpwnam(account).pw_uid, cols=80, rows=24))


def prove(binary):
    """Plant a detached local-SSH process, revoke shared then sole access, and clean up."""
    assert os.geteuid() == 0, 'requires real host root, not a user namespace'
    assert Path('/run/systemd/system').is_dir(), 'D354 root logins require systemd'
    account = 'ifrv' + uuid.uuid4().hex[:8]
    people = [uuid.uuid4(), uuid.uuid4()]
    cache = Path("/var/cache/infraternal-login-bin")
    images_before = set(cache.glob("infraternal-*"))
    directories = [cache, cache.parent / '.infraternal-login-bin-locks',
                   Path('/run/infraternal-access-records/reports'),
                   Path('/run/infraternal-access-records'), Path('/run/infraternal-login-records'),
                   Path('/run/infraternal-login-locks')]
    existed = {path: path.exists() for path in directories}
    client = None
    uid = None
    with tempfile.TemporaryDirectory(prefix='rv-', dir='/root') as scratch:
        root = Path(scratch)
        state = root / 's'
        state.mkdir(mode=0o700)
        try:
            command('useradd', '-m', '-s', '/bin/bash', account)
            user = pwd.getpwnam(account)
            uid = user.pw_uid
            print(json.dumps(dict(account=account, uid=uid)), flush=True)
            client = Binary(binary, state)
            prepare(client, 100, people[0], account)
            prepare(client, 101, people[1], account)
            home = Path(user.pw_dir)
            keys = home / '.ssh'
            keys.mkdir(mode=0o700)
            key = root / 'key'
            command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
            authorized = keys / 'authorized_keys'
            authorized.write_bytes(key.with_suffix('.pub').read_bytes())
            authorized.chmod(0o600)
            os.chown(keys, uid, user.pw_gid)
            os.chown(authorized, uid, user.pw_gid)
            planted = command('ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                              '-o', 'UserKnownHostsFile=/dev/null', '-i', str(key),
                              account + '@.host',
                              'nohup setsid sleep 600 >/dev/null 2>&1 </dev/null & echo $!')
            pid = int(planted.stdout.strip())
            wait_until(lambda: pid in processes(uid))
            cgroup = Path(f'/proc/{pid}/cgroup').read_text().strip()
            assert 'session-' in cgroup, cgroup
            shutil.rmtree(keys)
            print(json.dumps(dict(plant_pid=pid, cgroup=cgroup)), flush=True)
            shared = control(client, 102, 'terminal.login.revoke', dict(person=str(people[0])))
            assert pid in processes(uid), 'shared revoke stopped another holder\'s process'
            report = shared['access']['accounts'][0]
            assert report['state'] == 'not_checked', report
            assert report['reason'] == 'programs_may_remain', report
            assert any(row.startswith(f'{pid} ') for row in report['processes']), report
            print(json.dumps(dict(shared=shared)), flush=True)
            sole = control(client, 103, 'terminal.login.revoke', dict(person=str(people[1])))
            left = processes(uid)
            print(json.dumps(dict(sole=sole, remaining_pids=left)), flush=True)
            for report in sole['access']['accounts']:
                assert not report.get('processes'), report
                if left:
                    assert report['state'] != 'unchanged', report
            assert not left, left
            print('D362_REAL_ROOT_PASS', flush=True)
        finally:
            if client is not None:
                client.kill()
            if uid is not None:
                command('loginctl', 'terminate-user', str(uid), check=False)
                command('systemctl', 'stop', f'user-{uid}.slice', check=False)
                command('loginctl', 'disable-linger', str(uid), check=False)
                wait_until(lambda: not processes(uid))
                command('userdel', '-r', account)
                assert not processes(uid)
                for person in people:
                    unit = f'infraternal-login-{person.hex}-{uid}'
                    command('systemctl', 'stop', unit + '.service', check=False)
                    for registry in ('infraternal-login-locks', 'infraternal-login-records'):
                        directory = Path('/run') / registry
                        for path in directory.glob(f'*{person.hex}*'):
                            if path.is_file():
                                if path.suffix == '.record':
                                    reserved = path.parent / (path.read_text() + '.reserved')
                                    reserved.unlink(missing_ok=True)
                                path.unlink()
                    shutil.rmtree(Path('/run') / unit, ignore_errors=True)
                    store = Path('/run/infraternal-access-records')
                    (store / 'reports' / f'{person.hex}.json').unlink(missing_ok=True)
                    (store / 'reports' / f'{person.hex}.staging').unlink(missing_ok=True)
                    (store / f'{uid}-{person.hex}.failed').unlink(missing_ok=True)
                shutil.rmtree(Path('/run/infraternal-access-records') / str(uid), ignore_errors=True)
            cleanup(state)
            # Only this root-built binary's newly published image belongs to this proof.
            for image in set(cache.glob("infraternal-*")) - images_before:
                if image.is_file() and filecmp.cmp(image, binary, shallow=False):
                    image.unlink()
                    (cache.parent / ".infraternal-login-bin-locks" / image.name).unlink(missing_ok=True)
            for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
                if not existed[directory]:
                    try:
                        directory.rmdir()
                    except OSError:
                        pass  # Another job may now have its own files here.
            print('CLEANUP_PASS', flush=True)


if __name__ == '__main__':
    prove(sys.argv[1])
