"""Exercise the shipped ownership shell on isolated real files and live Unix listeners (#169)."""
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSPECT = (ROOT / 'src/setup_lock.sh').read_text() + (ROOT / 'src/runtime_cleanup.sh').read_text() + (ROOT / 'src/previous_attempt.sh').read_text()
SOURCE = (ROOT / 'src/install.rs').read_text()
CONSTANTS = dict(re.findall(r'(?:pub\(crate\) )?const (\w+): &str = r#"(.*?)"#;', SOURCE, re.S))
HOST, TRANSACTION = '1' * 32, '2' * 32

class EarlierSetup(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get('INFRATERNAL_TEST_STATE_ROOT', Path.home() / '.cache/codex-scratch/asf'))
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.base = Path(self.temp.name) / 'infraternal'
        self.base.mkdir(mode=0o700)
        self.owner = self.base / '.bootstrap-owner'
        self.owner.write_text(HOST + '\n')
        self.owner.chmod(0o600)
        self.identity = f'{self.base.stat().st_dev}:{self.base.stat().st_ino}'
        self.receipt = Path(str(self.base) + '.bootstrap-rollback-' + TRANSACTION)
        self.receipt.write_text(f'{HOST} {TRANSACTION} fresh {self.identity}\n')
        self.receipt.chmod(0o600)
        self.sessions = self.base / 'sessions/sessions'
        self.sessions.mkdir(parents=True)
        self.sessions.chmod(0o700)
        self.sessions.parent.chmod(0o700)
        self.socket = self.sessions / ('3' * 32 + '.sock')
        previous = Path.cwd()
        os.chdir(self.sessions)
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(self.socket.name)
        self.socket.chmod(0o600)
        os.chdir(previous)

    def tearDown(self):
        self.listener.close()
        self.temp.cleanup()

    def run_shell(self, body):
        script = f'set -euC\numask 077\nbase="{self.base}"\nhost={HOST}\ntransaction={TRANSACTION}\n' + INSPECT + body
        return subprocess.run(['/bin/sh', '-c', script], capture_output=True)

    def recover(self, expected=None):
        if expected is None:
            expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        body = f'\nsetup_guard\nobserved=$(inspect_previous)\n[ "$observed" = "{expected}" ] || exit 75\nnot_live\n'
        body += 'for entry in "$base/sessions"/*.sock "$base/sessions/sessions"/*.sock; do [ ! -S "$entry" ] || rm -- "$entry"; done\n'
        body += CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION']
        return self.run_shell(body)

    def test_stale_socket_is_removed(self):
        self.listener.close()
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.decode(), f'INFRATERNAL_SETUP_STALE {HOST} {TRANSACTION} {self.identity} 1\n')
        self.assertEqual(self.recover().returncode, 0)
        self.assertFalse(self.base.exists())
        self.assertFalse(self.receipt.exists())

    def test_live_listener_is_refused(self):
        self.listener.listen()
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 73)
        self.assertTrue(self.socket.exists())
        self.assertTrue(self.receipt.exists())

    def test_foreign_file_alongside_is_untouched(self):
        self.listener.close()
        foreign = self.base / 'personal.txt'
        foreign.write_text('foreign data')
        self.assertEqual(self.recover().returncode, 71)
        self.assertEqual(foreign.read_text(), 'foreign data')
        self.assertTrue(self.socket.exists(), 'foreign contents must refuse before removing any leftovers')
        self.assertTrue(self.owner.exists())
        self.assertTrue(self.receipt.exists())

    def test_old_unbound_format_is_refused(self):
        self.listener.close()
        self.receipt.write_text(f'{HOST} {TRANSACTION} fresh\n')
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 75)
        self.assertTrue(self.socket.exists())

    def test_foreign_socket_name_is_refused(self):
        self.listener.close()
        self.socket.rename(self.socket.with_name('foreign.sock'))
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 75)
        self.assertTrue(self.socket.with_name('foreign.sock').exists())

    def test_live_executable_is_refused(self):
        self.listener.close()
        binary = self.base / 'bin/live'
        binary.parent.mkdir()
        binary.write_bytes(Path('/usr/bin/sleep').read_bytes())
        binary.chmod(0o700)
        with subprocess.Popen([str(binary), '60']) as child:
            try:
                self.assertEqual(self.run_shell('\ninspect_previous').returncode, 73)
                self.assertTrue(self.receipt.exists())
            finally:
                child.terminate()
                child.wait()

    def test_live_lock_holder_is_refused(self):
        self.listener.close()
        with subprocess.Popen(['/bin/sh', '-c', 'exec 9< "$1"; flock 9; echo ready; read answer', 'sh', str(self.base.parent)], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
            self.assertEqual(child.stdout.readline(), b'ready\n')
            self.assertEqual(self.run_shell('\ninspect_previous').returncode, 73)
            child.communicate(b'done\n')

    def test_recovery_keeps_lock_through_removal(self):
        self.listener.close()
        # A second shell must be refused while confirmation holds its guard,
        # including after inspect_previous runs in command substitution.
        body = '\nsetup_guard\nobserved=$(inspect_previous)\n'
        body += f'flock -n "{self.base.parent}" true && exit 99\nexit 0\n'
        self.assertEqual(self.run_shell(body).returncode, 0)

    def test_bound_socket_before_listen_is_live(self):
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 73)
        self.assertTrue(self.socket.exists())
        self.assertTrue(self.receipt.exists())

    def test_listener_started_after_observation_is_refused(self):
        self.listener.close()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        self.socket.unlink()
        self.listener = socket.socket(socket.AF_UNIX)
        previous = Path.cwd()
        os.chdir(self.sessions)
        try:
            self.listener.bind(self.socket.name)
        finally:
            os.chdir(previous)
        self.socket.chmod(0o600)
        self.listener.listen()
        self.assertEqual(self.recover(expected).returncode, 73)
        self.assertTrue(self.socket.exists())
        self.assertTrue(self.receipt.exists())

    def test_changed_journal_after_observation_is_refused(self):
        self.listener.close()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        self.receipt.write_text(f'{HOST} {TRANSACTION} fresh 0:1\n')
        self.assertEqual(self.recover(expected).returncode, 75)
        self.assertTrue(self.socket.exists())
        self.assertTrue(self.receipt.exists())

    def test_changed_acquisition_beside_receipt_refuses_before_removal(self):
        self.listener.close()
        acquiring = self.base / '.bootstrap-acquiring'
        acquiring.write_text('9' * 32 + ' fresh\n')
        acquiring.chmod(0o600)
        self.assertEqual(self.recover().returncode, 75)
        self.assertTrue(self.socket.exists())
        self.assertTrue(acquiring.exists())

    def test_foreign_private_root_without_setup_marker_is_refused(self):
        self.listener.close()
        self.owner.unlink()
        self.receipt.unlink()
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 71)
        self.assertTrue(self.socket.exists())

    def test_foreign_file_inside_old_lock_is_refused_before_removal(self):
        self.listener.close()
        stage = self.base / '.bootstrap-lock'
        stage.mkdir(mode=0o700)
        for name, value in [('transaction', TRANSACTION), ('kind', 'fresh')]:
            item = stage / name
            item.write_text(value + '\n')
            item.chmod(0o600)
        foreign = stage / 'personal.txt'
        foreign.write_text('foreign data')
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 75)
        self.assertEqual(foreign.read_text(), 'foreign data')
        self.assertTrue(self.socket.exists())

    def test_replaced_directory_binding_is_refused(self):
        self.listener.close()
        self.receipt.write_text(f'{HOST} {TRANSACTION} fresh 0:1\n')
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 75)
        self.assertTrue(self.socket.exists())

    def test_review_symlink_ancestor_refuses_before_removing_leftovers(self):
        self.listener.close()
        # The final base and its immediate parent are real directories, but an
        # earlier home-path component redirects host provisioning outside them.
        container = self.base.parent / 'external-local'
        container.mkdir(mode=0o700)
        share = container / 'share'
        share.mkdir(mode=0o700)
        alias = self.base.parent / 'local-alias'
        alias.symlink_to(container, target_is_directory=True)
        outside = share / 'infraternal'
        self.base.rename(outside)
        receipt = Path(str(outside) + '.bootstrap-rollback-' + TRANSACTION)
        self.receipt.rename(receipt)
        self.base = alias / 'share/infraternal'
        self.receipt = receipt
        result = self.recover()
        self.assertEqual(result.returncode, 71, 'a symlink ancestor must be refused')
        self.assertTrue(outside.exists(), 'host provisioning removed the redirected directory')
        self.assertTrue(receipt.exists(), 'the refused journal must survive')

if __name__ == '__main__':
    unittest.main()
