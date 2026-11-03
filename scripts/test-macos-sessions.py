#!/usr/bin/env python3
"""Prove macOS terminal sessions end to end with the real binary (#328, D13, D335).

Run as root on the Mac build machine, from the repository root:

    sudo python3 scripts/test-macos-sessions.py \\
        --binary /var/lib/infraternal-test/bin/infraternal \\
        --upgrade /path/to/second/build \\
        --gui-uid 501 --plain-uid 1500 [--asid-probe /path/to/probe]

It speaks leg B to `infraternal agent --fd 3` (the link the server uses) and:
1. opens a shell for an account with a GUI login and one without, types into
   each and reads the output back;
2. checks D335 placement inside each shell: the GUI account's shell is in its
   login session (launchd manager `Aqua`, the session's ssh-agent socket, the
   GUI audit session when a probe is given), the other is a plain shell
   (`Background`, no agent socket);
3. stops the infraternal agent abruptly, starts it again and reattaches: the
   same shell process answers;
4. replaces the installed binary with `--upgrade` (atomic rename), starts the
   new infraternal agent, checks that its census adopts both sessions and
   reattaches both shells again;
5. ends both shells and waits until the infraternal agent's census drops them.

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
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_fixture import Binary, cleanup, detach, select_terminal, varint  # noqa: E402


class Agent(Binary):
    """The fixture client, opening terminals for an explicit account.

    Each session keeps its own output and input cursors across detach and
    infraternal agent restarts: input is sequenced exactly once, so a writer
    that restarted its cursor at zero would have its bytes discarded as
    duplicates (correctly) by the shim.
    """
    cursors = {}

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


def check_gui(text, user, asid_probe, asid):
    lines = text.splitlines()
    assert lines[0].strip() == user, text
    assert lines[1].strip() == 'Aqua', ('not in the login session', text)
    sock = field(text, 'SOCK')
    assert sock and 'com.apple.launchd.' in sock, ('no ssh-agent socket', text)
    assert field(text, 'LOGIN') == user, text
    assert f'/Users/{user}/Library/Keychains/login.keychain-db' in text, text
    if asid_probe:
        assert f'asid={asid} ' in text, ('not in the GUI audit session', asid, text)


def check_plain(text, user, asid_probe, asid):
    lines = text.splitlines()
    assert lines[0].strip() == user, text
    assert lines[1].strip() == 'Background', ('unexpected login-session placement', text)
    assert field(text, 'SOCK') == '', text
    assert field(text, 'LOGIN') == user, text
    if asid_probe:
        assert f'asid={asid} ' not in text, text


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
        gui = agent.open_as(args.gui_uid)
        text = probe(agent, args.asid_probe, 'GUI')
        print(f'--- {gui_user} shell {gui} (GUI login) ---\n{text}')
        check_gui(text, gui_user, args.asid_probe, asid)
        gui_pid = field(text, 'SHELLPID')
        typed = agent.run('echo typed-$((6*7))', 'TYPE')
        assert 'typed-42' in typed, typed
        detach(agent)

        plain = agent.open_as(args.plain_uid)
        text = probe(agent, args.asid_probe, 'PLAIN')
        print(f'--- {plain_user} shell {plain} (no GUI login) ---\n{text}')
        check_plain(text, plain_user, args.asid_probe, asid)
        plain_pid = field(text, 'SHELLPID')
        detach(agent)
        print('PASS: shells open, take input and return output; D335 placement holds')

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
        check_gui(text, gui_user, args.asid_probe, asid)
        detach(agent)
        print('PASS: both shells survive an upgrade of the infraternal agent; placement unchanged')

        for session in (plain, gui):
            exit_and_wait(agent, session)
        print('PASS: shell exits reach the infraternal agent (kqueue exit watches); the census drops both')
    finally:
        if agent is not None:
            agent.kill()
        cleanup(state)


if __name__ == '__main__':
    main()
