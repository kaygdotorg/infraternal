#!/usr/bin/env python3
"""Prove D362 against a disposable host account as real root on a systemd host.

Run with a freshly built binary: python3 scripts/test-revoke-account.py BINARY.
The local SSH socket (.host) must support public-key logins. This creates only
its own account, keys and login identities, and removes them even on failure.
Never run against a production host.
"""
import json
import filecmp
import grp
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


def job_plant(account, user, scenario, created):
    """Install one never-started system job; return its report label and root route."""
    privileged = scenario.startswith('root-job')
    target = Path(user.pw_dir) / 'scheduled-script'
    if privileged and scenario != 'root-job-parent':
        directory = Path('/run') / (account + '-job-input')
        directory.mkdir(mode=0o755)
        created.append(directory)
        target = directory / 'scheduled-script'
        created.append(target)
    target.write_text('#!/bin/sh\nexit 0\n')
    target.chmod(0o755)
    os.chown(target, user.pw_uid, user.pw_gid)
    runner = 'root' if privileged else (str(user.pw_uid) if scenario == 'system-uid' else account)
    if scenario in ('system-cron', 'root-job-cron'):
        path = Path('/etc/cron.d') / account
        with path.open('x') as cron:
            cron.write(f'0 0 1 1 * {runner} {target}\n')
        created.append(path)
        path.chmod(0o644)
        return str(path), privileged
    unit = Path('/etc/systemd/system') / (account + '-scheduled.service')
    with unit.open('x') as service:
        service.write(f'[Unit]\nDescription=Disposable revoke job\n[Service]\nType=oneshot\nUser={runner}\nExecStart=/bin/sh {target}\n')
    created.append(unit)
    unit.chmod(0o644)
    if scenario == 'root-job-unit':
        os.chown(unit, user.pw_uid, user.pw_gid)
        os.chown(target, 0, 0)
    if scenario == 'root-job-group':
        os.chown(target, 0, user.pw_gid)
        target.chmod(0o775)
    if scenario == 'root-job-parent':
        os.chown(target, 0, 0)
        target.chmod(0o755)
    if scenario == 'root-job-acl':
        os.chown(target, 0, 0)
        import struct
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in
               [(1, 7, 0xffffffff), (2, 6, user.pw_uid), (4, 5, 0xffffffff),
                (16, 7, 0xffffffff), (32, 5, 0xffffffff)])
        os.setxattr(target, 'system.posix_acl_access', acl)
    if privileged:
        checked = target.parent if scenario == 'root-job-parent' else (unit if scenario == 'root-job-unit' else target)
        assert command('runuser', '-u', account, '--', '/usr/bin/test', '-w', str(checked), check=False).returncode == 0
    if scenario == 'system-timer':
        timer = unit.with_suffix('.timer')
        with timer.open('x') as trigger:
            trigger.write(f'[Timer]\nOnCalendar=2099-01-01\nUnit={unit.name}\n')
        created.append(timer)
    command('systemctl', 'daemon-reload')
    assert command('systemctl', 'show', '--value', '-p', 'User', unit.name).stdout.strip() == runner
    return unit.name, privileged


def prove(binary, scenario="sessions"):
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
    sudoers = Path("/etc/sudoers.d") / account
    sudoers_created = False
    polkit_dir = Path({'polkit-run': '/run/polkit-1/rules.d',
                       'polkit-local': '/usr/local/share/polkit-1/rules.d',
                       'polkit-policy': '/run/polkit-1/actions'}.get(scenario, '/etc/polkit-1/rules.d'))
    polkit_existed = polkit_dir.exists()
    polkit_parent_existed = polkit_dir.parent.exists()
    polkit_rule = polkit_dir / (f'{account}.policy' if scenario == 'polkit-policy' else f'50-{account}.rules')
    polkit_created = False
    polkit_triggers = []
    root_unit = f'{account}-polkit'
    system_unit = f'{account}-system-process'
    system_started = False
    created_jobs = []
    with tempfile.TemporaryDirectory(prefix='rv-', dir='/root') as scratch:
        root = Path(scratch)
        # Root units write only under this private directory: a local user must
        # never be able to plant a symlink at the output path.
        root_plant = root / 'root-plant'
        state = root / 's'
        state.mkdir(mode=0o700)
        try:
            command('useradd', '-m', '-s', '/bin/bash', account)
            user = pwd.getpwnam(account)
            uid = user.pw_uid
            print(json.dumps(dict(account=account, uid=uid)), flush=True)
            client = Binary(binary, state)
            prepare(client, 100, people[0], account)
            if scenario in ('system-cron', 'system-unit', 'system-uid', 'system-timer',
                            'root-job-owner', 'root-job-group', 'root-job-parent',
                            'root-job-unit', 'root-job-cron', 'root-job-acl'):
                label, privileged = job_plant(account, user, scenario, created_jobs)
                reply = control(client, 102, 'terminal.login.revoke', dict(person=str(people[0])))
                report = reply['access']['accounts'][0]
                print(json.dumps(dict(scenario=scenario, label=label, reply=reply)), flush=True)
                assert report['state'] == 'not_checked', report
                if privileged:
                    assert report['reason'] == 'privileged', report
                else:
                    assert report['programs_may_remain'], report
                assert any(label in job for job in report.get('jobs', [])), report
                if scenario == 'system-timer':
                    assert any(account + '-scheduled.timer' in job for job in report['jobs']), report
                for path in created_jobs:
                    assert path.exists(), 'revoke deleted a system job'
                print('SYSTEM_JOB_REAL_ROOT_PASS ' + scenario, flush=True)
                return
            if scenario == 'system-process':
                system_started = True
                command('systemd-run', '--system', '--unit=' + system_unit,
                        '--uid=' + account, '/bin/sleep', '600')
                pid = int(command('systemctl', 'show', '--value', '-p', 'MainPID',
                                  system_unit + '.service').stdout.strip())
                wait_until(lambda: pid in processes(uid))
                cgroup = Path(f'/proc/{pid}/cgroup').read_text().strip()
                assert '/system.slice/' in cgroup, cgroup
                reply = control(client, 102, 'terminal.login.revoke', dict(person=str(people[0])))
                report = reply['access']['accounts'][0]
                print(json.dumps(dict(scenario=scenario, pid=pid, cgroup=cgroup, reply=reply)), flush=True)
                assert pid in processes(uid), 'revocation killed a system-owned process'
                if not report['privileged']:
                    assert {'sudo', 'doas', 'polkit', 'admin groups', 'root-run jobs',
                            'container sockets'} <= set(report['root_checks']), report
                assert report['state'] == 'not_checked', report
                assert report['programs_may_remain'], report
                assert any(row.startswith(f'{pid} ') for row in report['processes']), report
                print('SYSTEM_PROCESS_REPORTED_NOT_KILLED_PASS', flush=True)
                return
            if scenario.startswith('polkit'):
                def root_route():
                    """Exercise J357's actual polkit-to-systemd root route without prompting."""
                    if scenario == 'polkit-policy':
                        return command('runuser', '-u', account, '--', '/bin/sh', '-c',
                                       f'pkcheck --action-id org.infraternal.{account} --process $$', check=False)
                    return command('runuser', '-u', account, '--', 'systemd-run',
                                   '--system', '--no-ask-password', '--wait', '--collect',
                                   '--unit=' + root_unit, '/bin/sh', '-c',
                                   f'id -u > {root_plant}', check=False)

                assert root_route().returncode != 0, 'control unexpectedly has root access'
                polkit_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
                with polkit_rule.open('x') as rule:
                    polkit_created = True
                    if scenario == 'polkit-policy':
                        rule.write(f'<?xml version="1.0"?><policyconfig><action id="org.infraternal.{account}">'
                                   '<description>Disposable administrator action</description>'
                                   '<message>Disposable administrator action</message><defaults>'
                                   '<allow_any>yes</allow_any><allow_inactive>yes</allow_inactive>'
                                   '<allow_active>yes</allow_active></defaults></action></policyconfig>')
                    else:
                        rule.write('polkit.addRule(function(action, subject) {\n'
                               f'    if (subject.user == "{account}") return polkit.Result.YES;\n'
                               '});\n')
                polkit_rule.chmod(0o644)
                if scenario != 'polkit':
                    # A newly created load directory may have no daemon watch
                    # yet. An owned harmless file in an existing watched tree
                    # invalidates the cache without restarting the host daemon.
                    trigger = Path('/etc/polkit-1/rules.d') / f'99-{account}-reload.rules'
                    with trigger.open('x') as file:
                        file.write('\n')
                    polkit_triggers.append(trigger)
                    if scenario == 'polkit-policy':
                        trigger = Path('/usr/share/polkit-1/actions') / f'{account}-reload.policy'
                        with trigger.open('x') as file:
                            file.write('<?xml version="1.0"?><policyconfig/>')
                        polkit_triggers.append(trigger)
                wait_until(lambda: root_route().returncode == 0)
                if scenario != 'polkit-policy':
                    assert root_plant.read_text().strip() == '0'
                    assert root_plant.stat().st_uid == 0
                print('POLKIT_ACTION_DEFAULT_YES_CONFIRMED' if scenario == 'polkit-policy'
                      else 'POLKIT_ROOT_ROUTE_CONFIRMED uid=0', flush=True)
                reply = control(client, 102, 'terminal.login.revoke', dict(person=str(people[0])))
                print(json.dumps(dict(scenario=scenario, reply=reply)), flush=True)
                if scenario != 'polkit-policy':
                    assert root_plant.exists(), 'the root plant must survive until fixture cleanup'
                report = reply['access']['accounts'][0]
                assert report['privileged'] is True, report
                assert report['state'] == 'not_checked', report
                assert report['reason'] == 'privileged', report
                print('POLKIT_REAL_ROOT_PASS', flush=True)
                return
            if scenario in ("sudoers", "docker"):
                if scenario == "sudoers":
                    with sudoers.open("x") as rule:
                        sudoers_created = True
                        rule.write(f"{account} ALL=(ALL) NOPASSWD: ALL\n")
                    sudoers.chmod(0o440)
                    command("visudo", "-cf", str(sudoers))
                    command("sudo", "-n", "-l", "-U", account)
                else:
                    grp.getgrnam("docker")  # The compute01 fixture already has this group.
                    command("usermod", "-aG", "docker", account)
                    assert grp.getgrnam("docker").gr_gid in os.getgrouplist(account, user.pw_gid)
                reply = control(client, 102, "terminal.login.revoke", dict(person=str(people[0])))
                print(json.dumps(dict(scenario=scenario, reply=reply)), flush=True)
                report = reply["access"]["accounts"][0]
                assert report["privileged"] is True, report
                assert report["state"] == "not_checked", report
                assert report["reason"] == "privileged", report
                print("PRIVILEGE_REAL_ROOT_PASS " + scenario, flush=True)
                return
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
            assert report['programs_may_remain'], report
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
            for path in reversed(created_jobs):
                if path.is_dir() and not path.is_symlink():
                    path.rmdir()
                else:
                    path.unlink(missing_ok=True)
            if created_jobs:
                command('systemctl', 'daemon-reload')
            if system_started:
                command('systemctl', 'stop', system_unit + '.service', check=False)
                command('systemctl', 'reset-failed', system_unit + '.service', check=False)
            if sudoers_created:
                sudoers.unlink(missing_ok=True)
            for trigger in polkit_triggers:
                trigger.unlink(missing_ok=True)
            if polkit_created:
                polkit_rule.unlink(missing_ok=True)
            if scenario.startswith('polkit'):
                command('systemctl', 'stop', root_unit + '.service', check=False)
                command('systemctl', 'reset-failed', root_unit + '.service', check=False)
                root_plant.unlink(missing_ok=True)
                if not polkit_existed:
                    try:
                        polkit_dir.rmdir()
                    except OSError:
                        pass  # Concurrent policy belongs to the host, not this fixture.
                if not polkit_parent_existed:
                    try:
                        polkit_dir.parent.rmdir()
                    except OSError:
                        pass  # Another policy user may have populated it meanwhile.
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
    prove(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "sessions")
