"""D368 real-root proof with real shim PTYs and systemd scopes on a disposable build VM.

Run only while holding the mesh claim, under /root, with the root-built recovery-helper.
The old service is a parked executable; terminal ownership and closing use the shipping shim.
Never runs automatically: the ordinary gate has no access to the system service manager.
"""
import os
from pathlib import Path
import socket
import select
import struct
import subprocess
import sys
import time
import unittest
import uuid

from previous_attempt_shell import EarlierSetup, HOST, TAKEOVER


class RootTerminals(EarlierSetup):
    """Own a temporary system unit and unique scopes; refuse before touching a preexisting unit."""

    def setUp(self):
        """Require our live claim and an unused system unit before allocating the fixture."""
        self.assertEqual(os.geteuid(), 0)
        self.assertTrue(Path('/home/claude/mesh-vm.claim').read_text().startswith('J379 '), 'claim the live VM pair before running')
        self.assertTrue(str(Path.cwd()).startswith('/root/'))
        loaded = subprocess.check_output(['systemctl', 'show', '-p', 'LoadState', '--value', 'infraternal-agent.service'], text=True).strip()
        self.assertEqual(loaded, 'not-found', 'never replace an existing unit')
        self.scope_units = []
        self.scope_launchers = []
        super().setUp()
        self.unit = Path('/run/systemd/system/infraternal-agent.service')
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.unit.is_symlink())
        self.wants_directory = self.unit.parent / 'default.target.wants'
        self.wants_directory_existed = self.wants_directory.exists()
        wants = self.wants_directory / 'infraternal-agent.service'
        self.assertFalse(wants.exists() or wants.is_symlink(), 'never replace an existing enable link')
        self.addCleanup(self.cleanup_units)

    def cleanup_units(self):
        """Stop only names created by this fixture, then remove its own temporary unit and wants link."""
        for unit in self.scope_units:
            subprocess.run(['systemctl', 'stop', unit], check=False)
        subprocess.run(['systemctl', 'stop', 'infraternal-agent.service'], check=False)
        self.unit.unlink(missing_ok=True)
        (self.unit.parent / 'default.target.wants/infraternal-agent.service').unlink(missing_ok=True)
        if not self.wants_directory_existed:
            try:
                self.wants_directory.rmdir()
            except OSError:
                pass  # A missing directory or another job's entries must be left alone.
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        for child in self.scope_launchers:
            child.wait(timeout=10)

    def tearDown(self):
        """Remove owned units before deleting the temporary files their processes used."""
        self.cleanup_units()
        # Cleanup runs before removing files backing the fixture's executable.
        self._cleanups.clear()
        super().tearDown()

    def run_shell(self, body):
        """Use the real system manager, with enables constrained to the temporary /run hierarchy."""
        return super().run_shell('\nmanager="systemctl --runtime"\n' + body)

    def make_takeover_fixture(self):
        """A root-owned finished install from an unknown server, with a live service executable."""
        super().make_takeover_fixture()
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'start', 'infraternal-agent.service'], check=True)
        self.assertEqual(subprocess.check_output(['systemctl', 'is-active', 'infraternal-agent.service'], text=True).strip(), 'active')
        return self.check_record()

    def check_record(self):
        """Read the exact production inspection record; Check has no terminal-close side effects."""
        checked = self.run_shell('\nsetup_check=yes\ninspect_previous')
        self.assertEqual(checked.returncode, 0, checked.stderr)
        return checked.stdout.decode().strip()

    def open_terminal(self, checked=True):
        """Launch the shipping shim and an idle root shell in a fresh, uniquely owned system scope."""
        session = uuid.uuid4().hex
        scope = f'infraternal-session-{session}.scope'
        self.assertEqual(subprocess.check_output(['systemctl', 'show', '-p', 'LoadState', '--value', scope], text=True).strip(), 'not-found')
        self.scope_units.append(scope)
        command = ['systemd-run', '--scope', '--quiet', '--unit', scope, str(self.base / 'bin/live'), '__shim',
                   '--session', session, '--uid', '0', '--cols', '80', '--rows', '24', '--state', str(self.base / 'sessions')]
        child = subprocess.Popen(command, stdout=subprocess.DEVNULL)
        self.scope_launchers.append(child)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if checked:
                record = self.check_record()
            else:
                probe = subprocess.run([os.environ['INFRATERNAL_TEST_RUNTIME_HELPER'], '--bootstrap-runtime', str(self.base), self.identity, 'takeover-terminals'], capture_output=True, text=True)
                record = probe.stdout
            if f'{session},726f6f74,62617368,' in record:
                print(f'OPEN {scope} {record}', flush=True)
                return session, record
            if child.poll() is not None:
                self.fail('shim exited before publishing a terminal')
            # sleep: await the real PTY and endpoint publication, with a hang watchdog only.
            time.sleep(0.02)
        self.fail(f'terminal was not offered: {record}')

    def scope_active(self, session):
        """Whether our unique scope still runs, independent of socket cleanup timing."""
        return subprocess.run(['systemctl', 'is-active', '--quiet', f'infraternal-session-{session}.scope']).returncode == 0

    def test_offer_then_confirm_closes_only_the_reviewed_terminal(self):
        """A read-only offer leaves the real PTY live; confirmation closes it and sets the install aside."""
        self.make_takeover_fixture()
        session, record = self.open_terminal()
        self.assertIn(' live ready ', record)
        self.assertTrue(self.scope_active(session))
        result = self.take_over(record)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.scope_active(session))
        self.assertFalse(self.base.exists())
        self.assertEqual((self.takeover_aside() / 'install/.bootstrap-owner').read_text(), HOST + '\n')
        # The existing commit path retires the old install only after a fresh one commits.
        # The real manager removes an empty wants directory when disabling the old unit.
        self.wants_directory.mkdir(exist_ok=True)
        self.committed_install_in_place(self.takeover_aside() / 'install')
        committed = self.commit_new_install('')
        self.assertEqual(committed.returncode, 0, committed.stdout + committed.stderr)
        self.assertFalse(self.takeover_aside().exists())
        self.assertEqual((self.base / '.bootstrap-owner').read_text(), '5' * 32 + '\n')

    def test_new_terminal_between_offer_and_confirm_refuses_without_closing_either(self):
        """An added scope invalidates consent; no terminal the person saw or did not see is closed."""
        self.make_takeover_fixture()
        first, record = self.open_terminal()
        second, _ = self.open_terminal()
        result = self.take_over(record)
        self.assertEqual(result.returncode, 75, result.stdout + result.stderr)
        self.assertTrue(self.scope_active(first))
        self.assertTrue(self.scope_active(second))
        self.assertFalse(self.takeover_aside().exists())

    def test_changed_terminal_record_refuses_without_closing_it(self):
        """Changing the record displayed in the confirmation cannot authorize closing its scope."""
        self.make_takeover_fixture()
        session, record = self.open_terminal()
        result = self.take_over(record.replace(',62617368,', ',7368,'))
        self.assertEqual(result.returncode, 75, result.stdout + result.stderr)
        self.assertTrue(self.scope_active(session))

    def test_foreground_program_changed_since_the_offer_refuses(self):
        """A real foreground command invalidates the reviewed account/program and process identity."""
        self.make_takeover_fixture()
        session, record = self.open_terminal()
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(5)
            peer.connect(str(self.sessions / f'{session}.sock'))
            hello = peer.recv(4096)
            self.assertTrue(hello)
            attach = bytes([2]) + struct.pack('<Q', 0)
            command = bytes([0x10]) + b'sleep 120\n'
            peer.sendall(struct.pack('<I', len(attach)) + attach + struct.pack('<I', len(command)) + command)
        deadline = time.monotonic() + 5
        changed = record
        while time.monotonic() < deadline:
            changed = self.check_record()
            if ',736c656570,' in changed:
                break
            # sleep: await the shell assigning its PTY foreground group to the command.
            time.sleep(0.02)
        self.assertIn(',736c656570,', changed)
        result = self.take_over(record)
        self.assertEqual(result.returncode, 75, result.stdout + result.stderr)
        self.assertTrue(self.scope_active(session))

    def test_a_terminal_opened_during_the_stop_is_not_closed(self):
        """The last recheck after stopping the old unit must still bind the entire terminal set."""
        self.make_takeover_fixture()
        first, record = self.open_terminal()
        ready = Path(self.temp).resolve() / 'ready'
        proceed = Path(self.temp).resolve() / 'proceed'
        os.mkfifo(ready, 0o600)
        os.mkfifo(proceed, 0o600)
        prefix = f'''
last_check_manager() {{
 systemctl --runtime "$@" || return $?
 if [ "$1 ${{2:-}}" = "stop infraternal-agent.service" ]; then
  printf x > "{ready}"
  read -r answer < "{proceed}"
 fi
}}
manager=last_check_manager
'''
        script = self.shell_script('\nmanager="systemctl --runtime"\n' + prefix + f'\ntake_over_finished_install "{record}" {TAKEOVER}\n')
        action = subprocess.Popen(['/bin/sh', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(action)
        with ready.open() as handle:
            self.assertEqual(handle.read(1), 'x')
        second, _ = self.open_terminal(checked=False)
        with proceed.open('w') as handle:
            handle.write('continue\n')
        output, errors = action.communicate(timeout=20)
        self.assertIn(action.returncode, (73, 75), output + errors)
        self.assertTrue(self.scope_active(first))
        self.assertTrue(self.scope_active(second))

    def test_nonterminal_holder_still_refuses(self):
        """A process outside the old unit and its terminal scopes keeps the install busy."""
        self.make_takeover_fixture()
        session, record = self.open_terminal()
        # A root-opened descriptor can survive dropping to another account. It is still a holder.
        holder = subprocess.Popen(['python3', '-c',
            'import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY); os.set_inheritable(fd,True); '
            'os.setgid(65534); os.setuid(65534); os.execv("/bin/sleep",["sleep","30"])', str(self.identity_path)])
        self.children.append(holder)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if Path(f'/proc/{holder.pid}').stat().st_uid == 65534:
                break
            # sleep: await the descriptor holder dropping privileges, without asserting elapsed time.
            time.sleep(0.01)
        self.assertTrue(self.check_record().endswith(' busy'))
        result = self.take_over(record)
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertTrue(self.scope_active(session))

    def test_other_account_holder_appearing_after_close_still_refuses(self):
        """The final holder scan covers every account too, before moving the old install."""
        self.make_takeover_fixture()
        session, record = self.open_terminal()
        before = self.base.stat().st_ino
        ready = Path(self.temp).resolve() / 'ready'
        proceed = Path(self.temp).resolve() / 'proceed'
        os.mkfifo(ready, 0o600)
        os.mkfifo(proceed, 0o600)
        prefix = f'''
after_close_manager() {{
 systemctl --runtime "$@" || return $?
 if [ "$1" = disable ]; then
  printf x > "{ready}"
  read -r answer < "{proceed}"
 fi
}}
manager=after_close_manager
'''
        descriptor = os.open(ready, os.O_RDWR | os.O_NONBLOCK)
        try:
            script = self.shell_script(prefix + f'\ntake_over_finished_install "{record}" {TAKEOVER}\n')
            action = subprocess.Popen(['/bin/sh', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.children.append(action)
            self.assertTrue(select.select([descriptor], [], [], 30)[0], 'watchdog waiting for terminal close')
            self.assertEqual(os.read(descriptor, 1), b'x')
            self.assertFalse(self.scope_active(session))
            holder = subprocess.Popen(['python3', '-c',
                'import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY); os.set_inheritable(fd,True); '
                'os.setgid(65534); os.setuid(65534); os.execv("/bin/sleep",["sleep","30"])', str(self.identity_path)])
            self.children.append(holder)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if Path(f'/proc/{holder.pid}').stat().st_uid == 65534:
                    break
                # sleep: await the holder dropping privileges before the final scan.
                time.sleep(0.01)
            with proceed.open('w') as handle:
                handle.write('continue\n')
            output, errors = action.communicate(timeout=30)
            # Every confirmed terminal closed, then a holder refused: 74, which says they were closed.
            self.assertEqual(action.returncode, 74, output + errors)
            self.assertEqual(self.base.stat().st_ino, before)
            self.assertFalse(self.takeover_aside().exists())
            self.assertEqual(subprocess.check_output(['systemctl', 'is-active', 'infraternal-agent.service'], text=True).strip(), 'active')
        finally:
            os.close(descriptor)

    def test_failure_after_close_restores_the_old_install_and_service(self):
        """D359 rollback restores files and service state, while the explicitly closed terminal stays closed."""
        self.make_takeover_fixture()
        session, record = self.open_terminal()
        before = (self.base.stat().st_ino, self.identity_path.read_bytes(), self.unit.read_bytes())
        result = self.take_over(record, prefix='''
fail_after_close() {
 case "$1" in disable) return 1;; *) systemctl --runtime "$@";; esac
}
manager=fail_after_close
''')
        # A service step failing after a terminal closed: 79 (closing could not finish), never "busy".
        self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
        self.assertFalse(self.scope_active(session))
        self.assertEqual((self.base.stat().st_ino, self.identity_path.read_bytes(), self.unit.read_bytes()), before)
        self.assertEqual(subprocess.check_output(['systemctl', 'is-active', 'infraternal-agent.service'], text=True).strip(), 'active')
        self.assertFalse(self.takeover_aside().exists())


if __name__ == '__main__':
    names = sys.argv[1:] or [name for name in RootTerminals.__dict__ if name.startswith('test_')]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(RootTerminals(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
