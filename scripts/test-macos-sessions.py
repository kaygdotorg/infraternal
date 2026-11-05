#!/usr/bin/env python3
"""Prove macOS terminal sessions end to end with the real binary (#328, D13, D335).

Run as root on the Mac build machine, from the repository root:

    sudo python3 scripts/test-macos-sessions.py \\
        --binary /var/lib/infraternal-test/bin/infraternal \\
        --upgrade /path/to/second/build \\
        --gui-uid 501 --plain-uid 1500 [--asid-probe /path/to/probe]

It starts the infraternal agent the way production does: as a launchd system
job (`launchctl bootstrap system`), so it has a LaunchDaemon's audit session and
bootstrap rather than an SSH login's (#328 P2, P3-3). The job's tiny launcher
connects leg B (the link the server uses) back to this script as descriptor 3,
and deliberately plants what must never reach a shell: descriptor 9 open on a
root-only file without close-on-exec, plus DYLD_LIBRARY_PATH, BASH_ENV, ENV,
ZDOTDIR and a marker variable in the environment (#328 P1, P3-1). It then:
1. opens a shell for an account with a GUI login and one without, types into
   each and reads the output back;
2. checks D335 placement inside each shell: the GUI account's shell is in its
   login session (launchd manager `Aqua`, the session's ssh-agent socket, the
   GUI audit session), the other is a plain shell in a session of its own
   (`Background`, audit user = the person, no agent socket, neither the
   daemon's nor the GUI audit session);
3. checks that neither shell nor shim holds the planted descriptor, that no
   planted variable reached the shells, and that the root shims run with the
   allow-listed environment only (no planted variable and no PATH);
4. stops the infraternal agent abruptly (SIGKILL), starts the job again and
   reattaches: the same shell process answers;
5. replaces the installed binary with `--upgrade` (atomic rename), starts the
   job again, checks that its census adopts both sessions and reattaches;
6. ends both shells and waits until the infraternal agent's census drops them.

`--asid-probe` names a small program that prints its own audit record
(`uid= euid= asid= auid= flags=`); it must be readable and executable by both
accounts. The test profile and launcher live in root-owned directories.

It reads only the keychain *search list* (`security list-keychains`); it never
reads keychain items and never touches the privacy database.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_fixture import Binary, cleanup, detach, select_terminal, varint  # noqa: E402

LABEL = 'org.infraternal.test.macos-sessions'
MARKER = 'ROOT-ONLY-J146-PLANTED-DESCRIPTOR'
PLANTED_ENV = {
    'DYLD_LIBRARY_PATH': '/private/tmp/j146-planted-dyld',
    'BASH_ENV': '/private/tmp/j146-planted-bash-env',
    'ENV': '/private/tmp/j146-planted-env',
    'ZDOTDIR': '/private/tmp/j146-planted-zdotdir',
    'J146_PLANTED': 'leaked',
}
# Runs inside the launchd job as root: records the daemon's own context, puts
# leg B on descriptor 3 and the root-only file on descriptor 9 (no CLOEXEC),
# then execs the infraternal agent in place, keeping that context.
LAUNCHER = r'''
import json, os, socket, subprocess, sys
leg_b, secret, agent, state, probe, context, planted = sys.argv[1:8]
if probe:
    with open(context, 'w') as out:
        subprocess.run([probe], stdout=out, check=False)
        subprocess.run(['/bin/launchctl', 'managername'], stdout=out, check=False)
peer = socket.socket(socket.AF_UNIX)
peer.connect(leg_b)
if peer.fileno() != 3:
    os.dup2(peer.fileno(), 3)
# launchd starts jobs with only 0-2, so the socket may already be 3; dup2 onto
# itself keeps CLOEXEC, so mark leg B inheritable explicitly.
os.set_inheritable(3, True)
os.dup2(os.open(secret, os.O_RDONLY), 9)
os.set_inheritable(9, True)
env = dict(os.environ, **json.loads(planted))
os.execve(agent, [agent, 'agent', '--fd', '3', '--state', state], env)
'''


class LaunchdJob:
    """Stands in for the fixture's subprocess handle: the agent is a launchd job."""

    def __init__(self, pid, log):
        self.pid = pid
        self.returncode = None
        self.log = log
        self.stderr = self

    def read(self):
        return Path(self.log).read_bytes() if Path(self.log).exists() else b''

    def close(self):
        pass

    def poll(self):
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            self.returncode = -9
            return self.returncode
        return None

    def kill(self):
        subprocess.run(['/bin/launchctl', 'kill', 'SIGKILL', f'system/{LABEL}'],
                       capture_output=True, check=False)

    def wait(self, timeout=10):
        deadline = time.monotonic() + (timeout or 10)
        while self.poll() is None:
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(LABEL, timeout)
            time.sleep(0.05)
        subprocess.run(['/bin/launchctl', 'bootout', f'system/{LABEL}'],
                       capture_output=True, check=False)
        return self.returncode


class Agent(Binary):
    """The fixture client, with the infraternal agent run as a launchd system job.

    Each session keeps its own output and input cursors across detach and
    infraternal agent restarts: input is sequenced exactly once, so a writer
    that restarted its cursor at zero would have its bytes discarded as
    duplicates (correctly) by the shim.
    """
    cursors = {}
    config = None  # set by main(): paths for the job, probe and planted file

    def start(self):
        """Bootstrap the launchd job and accept its leg-B connection."""
        config = Agent.config
        listener_path = config['work'] / 'leg-b.sock'
        listener_path.unlink(missing_ok=True)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(listener_path))
        os.chmod(listener_path, 0o600)
        listener.listen(1)
        listener.settimeout(20)
        log = config['work'] / 'agent.log'
        plist = config['work'] / f'{LABEL}.plist'
        arguments = ['/usr/bin/python3', str(config['launcher']), str(listener_path),
                     str(config['secret']), str(self.binary), str(self.state),
                     config['probe'] or '', str(config['context']), json.dumps(PLANTED_ENV)]
        plist.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f'<key>Label</key><string>{LABEL}</string>\n'
            '<key>ProgramArguments</key><array>'
            + ''.join(f'<string>{a}</string>' for a in arguments)
            + '</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><false/>\n'
            '<key>ProcessType</key><string>Background</string>\n'
            '<key>StandardOutPath</key><string>/dev/null</string>\n'
            f'<key>StandardErrorPath</key><string>{log}</string>\n'
            '</dict></plist>\n')
        os.chmod(plist, 0o644)
        subprocess.run(['/bin/launchctl', 'bootout', f'system/{LABEL}'],
                       capture_output=True, check=False)
        subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(plist)], check=True)
        self.sock, _ = listener.accept()
        listener.close()
        listener_path.unlink(missing_ok=True)
        self.sock.settimeout(20)
        self.link = None
        listing = subprocess.run(['/bin/launchctl', 'print', f'system/{LABEL}'],
                                 capture_output=True, text=True, check=True).stdout
        self.child = LaunchdJob(int(re.search(r'\bpid = (\d+)', listing).group(1)), log)
        stream, kind, _ = self.read()
        assert (stream, kind) == (0, 0)
        self.send(0, 0, struct.pack('<HQ', 1, 0) + varint(6) + b'tracer')
        self.ping(0, 0)

    def kill(self):
        """An abrupt stop of the job (SIGKILL); detached shims keep their shells."""
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait()
        self.sock.close()

    def remember(self):
        Agent.cursors[str(self.id)] = (self.out, self.entered, self.acked)

    def switch(self, session):
        out, entered, acked = Agent.cursors[str(session)]
        self.id = uuid.UUID(str(session))
        self.out, self.entered, self.acked = out, entered, acked
        self.credit_pending = self.credit_available = 0
        self.data.clear()
        self.attach()

    def open_as(self, uid, cols=100, rows=30):
        action = b'terminal.open'
        self.send(0, 0x30, struct.pack('<I', 1) + varint(len(action)) + action
                  + json.dumps(dict(uid=uid, cols=cols, rows=rows)).encode())
        while True:
            stream, kind, body = self.read()
            if (stream, kind) == (0, 0x31):
                break
            if stream == 0:
                self.process(frame=(stream, kind, body))
        assert body[4] == 1, ('terminal.open refused', body[5:])
        session = json.loads(body[5:])['session_id']
        select_terminal(self, session)
        self.remember()
        return session

    def run(self, command, tag):
        """Type one command line and return the output between two tags."""
        self.data.clear()
        line = f"printf '{tag}-%s\\n' begin; {command}; printf '{tag}-%s\\n' end\n"
        self.input(line.encode())
        self.until(f'{tag}-end\r\n'.encode())
        self.wait_ack()
        self.remember()
        text = self.data.decode(errors='replace')
        start = text.index(f'{tag}-begin\r\n') + len(f'{tag}-begin\r\n')
        return text[start:text.index(f'{tag}-end\r\n')]


PROBE = ('id -un; launchctl managername; printf "SOCK=%s\\n" "$SSH_AUTH_SOCK"; '
         'printf "SHELLPID=%s\\n" "$$"; printf "LOGIN=%s\\n" "$(logname)"; '
         'if : <&9 2>/dev/null; then echo FD9=open; else echo FD9=closed; fi; '
         'printf "PLANTED=%s\\n" "$J146_PLANTED$DYLD_LIBRARY_PATH$BASH_ENV$ENV$ZDOTDIR"; '
         'security list-keychains')


def probe(agent, asid, tag):
    command = PROBE + (f'; {asid}' if asid else '')
    return agent.run(command, tag)


def field(text, name):
    match = re.search(rf'^{name}=(.*?)\r?$', text, re.M)
    return match.group(1) if match else None


def exit_and_wait(agent, session):
    """End one shell and wait until the infraternal agent's census drops it."""
    agent.switch(session)
    agent.input(b'exit\n')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        stream, kind, body = agent.read()
        if (stream, kind) == (0, 0x33):
            event = json.loads(body[4:])
            if (event.get('type') == 'terminal.sessions.snapshot'
                    and session not in event.get('session_ids', [])):
                return
    raise AssertionError(f'the census still lists exited session {session}')


def gui_asid(uid):
    listing = subprocess.run(['/bin/launchctl', 'print', f'gui/{uid}'], capture_output=True,
                             text=True, check=True).stdout
    return re.search(r'asid = (\d+)', listing).group(1)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit(text):
    """(asid, auid, flags) from the probe's `asid= auid= flags=` line."""
    match = re.search(r'asid=(\d+) auid=(\d+) flags=(0x[0-9a-f]+)', text)
    assert match, ('no audit record in the probe output', text)
    return match.group(1), int(match.group(2)), int(match.group(3), 16)


def check_common(text, user, uid):
    """What every shell shares: the right account, nothing planted inherited."""
    assert text.splitlines()[0].strip() == user, text
    assert field(text, 'LOGIN') == user, text
    assert field(text, 'FD9') == 'closed', ('the planted root descriptor reached the shell', text)
    assert field(text, 'PLANTED') == '', ('a planted variable reached the shell', text)
    assert MARKER not in text, text


def check_gui(text, user, uid, gui_asid_value):
    check_common(text, user, uid)
    assert text.splitlines()[1].strip() == 'Aqua', ('not in the login session', text)
    sock = field(text, 'SOCK')
    assert sock and 'com.apple.launchd.' in sock, ('no ssh-agent socket', text)
    assert f'/Users/{user}/Library/Keychains/login.keychain-db' in text, text
    asid, auid, flags = audit(text)
    assert asid == gui_asid_value and auid == uid and flags & 0x10, ('not the GUI audit session', text)


def check_plain(text, user, uid, gui_asid_value, daemon_asid):
    check_common(text, user, uid)
    assert text.splitlines()[1].strip() == 'Background', ('not a background session', text)
    assert field(text, 'SOCK') == '', text
    asid, auid, flags = audit(text)
    assert auid == uid, ('the plain shell has no audit user of its own', text)
    assert asid not in (gui_asid_value, daemon_asid), ('the plain shell shares a session', text)
    assert not flags & 0x10, text


def holders(pid):
    """Paths the process holds open (lsof), to look for the planted file."""
    out = subprocess.run(['/usr/sbin/lsof', '-p', str(pid), '-Fn'], capture_output=True,
                         text=True, check=False).stdout
    return [line[1:] for line in out.splitlines() if line.startswith('n')]


def shim_pid(state, session):
    """The shim's pid from its Hello on the rendezvous socket."""
    from agent_fixture import exact
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(5)
        peer.connect(str(state / 'sessions' / f'{uuid.UUID(session).hex}.sock'))
        hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
    return struct.unpack('<I', hello[27:31])[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, help='installed, root-owned binary path')
    parser.add_argument('--upgrade', required=True, help='a different build to install')
    parser.add_argument('--gui-uid', type=int, required=True)
    parser.add_argument('--plain-uid', type=int, required=True)
    parser.add_argument('--asid-probe', help='optional program printing its audit session')
    parser.add_argument('--state', default='/var/run/infraternal-macos-test')
    args = parser.parse_args()
    assert os.geteuid() == 0, 'run as root: the root infraternal agent starts shells for other accounts'
    assert args.asid_probe, '--asid-probe is required: placement is checked from audit records'
    work = Path(args.state + '.work')
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700)
    secret = work / 'root-only'
    secret.write_text(MARKER)
    os.chmod(secret, 0o600)
    launcher = work / 'launcher.py'
    launcher.write_text(LAUNCHER)
    Agent.config = dict(work=work, secret=secret, launcher=launcher,
                        probe=args.asid_probe, context=work / 'daemon-context')
    import pwd
    gui_user = pwd.getpwuid(args.gui_uid).pw_name
    plain_user = pwd.getpwuid(args.plain_uid).pw_name
    asid = gui_asid(args.gui_uid)
    state = Path(args.state)
    shutil.rmtree(state, ignore_errors=True)
    state.mkdir(mode=0o700)
    print(f'binary {args.binary} sha256 {digest(args.binary)}')
    print(f'upgrade {args.upgrade} sha256 {digest(args.upgrade)}')
    assert digest(args.binary) != digest(args.upgrade), 'the upgrade must be a different build'
    print(f'gui/{args.gui_uid} audit session {asid}')
    agent = None
    try:
        agent = Agent(args.binary, state)
        context = Agent.config['context'].read_text()
        daemon_asid = audit(context)[0]
        print(f'--- infraternal agent (launchd system job) ---\n{context}')
        gui = agent.open_as(args.gui_uid)
        text = probe(agent, args.asid_probe, 'GUI')
        print(f'--- {gui_user} shell {gui} (GUI login) ---\n{text}')
        check_gui(text, gui_user, args.gui_uid, asid)
        gui_pid = field(text, 'SHELLPID')
        typed = agent.run('echo typed-$((6*7))', 'TYPE')
        assert 'typed-42' in typed, typed
        detach(agent)

        plain = agent.open_as(args.plain_uid)
        text = probe(agent, args.asid_probe, 'PLAIN')
        print(f'--- {plain_user} shell {plain} (no GUI login) ---\n{text}')
        check_plain(text, plain_user, args.plain_uid, asid, daemon_asid)
        plain_pid = field(text, 'SHELLPID')
        detach(agent)
        print('PASS: shells open, take input and return output; D335 placement holds')
        for session, pid in ((gui, gui_pid), (plain, plain_pid)):
            for holder in (int(pid), shim_pid(state, session)):
                leaked = [path for path in holders(holder) if path.endswith('/root-only')]
                assert not leaked, ('the planted root descriptor is held', holder, leaked)
        print('PASS: no shell or shim holds the planted root descriptor; no planted variable reached a shell')
        for session in (gui, plain):
            shim = shim_pid(state, session)
            environment = subprocess.run(['/bin/ps', '-E', '-ww', '-o', 'command=', '-p', str(shim)],
                                         capture_output=True, text=True, check=True).stdout
            leaked = [name for name in [*PLANTED_ENV, 'PATH'] if f' {name}=' in environment]
            assert not leaked, ('planted variables reached a root shim', shim, leaked)
        print('PASS: the root shims run with the allow-listed environment only (no planted variable, no PATH)')

        # An abrupt stop of the infraternal agent; the shims keep their shells.
        agent.kill()
        agent = Agent(args.binary, state)
        for session, pid, tag in ((gui, gui_pid, 'R1'), (plain, plain_pid, 'R2')):
            agent.switch(session)
            after = agent.run('printf "SHELLPID=%s\\n" "$$"', tag)
            assert field(after, 'SHELLPID') == pid, (session, pid, after)
            detach(agent)
        print(f'PASS: both shells survive an infraternal agent restart (pids {gui_pid}, {plain_pid})')

        # Upgrade: install a different build over the running binary's path.
        agent.kill()
        staged = Path(args.binary).with_name('.infraternal-upgrade')
        shutil.copyfile(args.upgrade, staged)
        os.chmod(staged, 0o755)
        os.replace(staged, args.binary)
        print(f'installed upgrade: {args.binary} sha256 {digest(args.binary)}')
        agent = Agent(args.binary, state)
        census = set((agent.inventory or {}).get('session_ids', []))
        assert {gui, plain} <= census, ('the upgraded infraternal agent did not adopt both', census)
        for session, pid, tag in ((gui, gui_pid, 'U1'), (plain, plain_pid, 'U2')):
            agent.switch(session)
            after = agent.run('printf "SHELLPID=%s\\n" "$$"; echo upgraded-$((7*6))', tag)
            assert field(after, 'SHELLPID') == pid and 'upgraded-42' in after, (session, after)
            detach(agent)
        agent.switch(gui)
        text = probe(agent, args.asid_probe, 'UG')
        check_gui(text, gui_user, args.gui_uid, asid)
        detach(agent)
        print('PASS: both shells survive an upgrade of the infraternal agent; placement unchanged')

        for session in (plain, gui):
            exit_and_wait(agent, session)
        print('PASS: shell exits reach the infraternal agent (kqueue exit watches); the census drops both')
    finally:
        if agent is not None:
            agent.kill()
        subprocess.run(['/bin/launchctl', 'bootout', f'system/{LABEL}'],
                       capture_output=True, check=False)
        cleanup(state)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
