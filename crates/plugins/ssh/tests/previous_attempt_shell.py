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

    def test_retired_owner_with_nonempty_root_is_refused(self):
        self.listener.close()
        self.owner.unlink()
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 71)
        self.assertTrue(self.socket.exists())
        self.assertTrue(self.receipt.exists())

    def test_retired_base_receipt_never_owns_replacement_directory(self):
        self.listener.close()
        retained = self.base.with_name('retained')
        self.base.rename(retained)
        self.base.mkdir(mode=0o700)
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 75)
        self.assertTrue(self.receipt.exists())
        self.assertTrue(retained.exists())

    def test_stale_socket_is_removed(self):
        self.listener.close()
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.decode(), f'INFRATERNAL_SETUP_STALE {HOST} {TRANSACTION} {self.identity} 1\n')
        self.assertEqual(self.recover().returncode, 0)
        self.assertFalse(self.base.exists())
        self.assertFalse(self.receipt.exists())

    def test_stale_control_socket_is_recoverable(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        self.socket.rename(control)
        control.chmod(0o755)
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.recover().returncode, 0)
        self.assertFalse(control.exists())
        self.assertFalse(self.receipt.exists())

    def test_original_rollback_finishes_after_service_stop(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        self.socket.rename(control)
        result = self.run_shell(CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION'])
        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.base.exists())
        self.assertFalse(self.receipt.exists())

    def test_control_socket_in_another_root_does_not_block_cleanup(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        self.socket.rename(control)
        other = Path(self.temp.name) / 'other'
        other.mkdir(mode=0o700)
        unrelated = other / 'plugins.sock'
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(unrelated))
            unrelated.chmod(0o600)
            listener.listen()
            self.assertEqual(self.run_shell('\ninspect_previous').returncode, 0)
            self.assertEqual(self.recover().returncode, 0)
            self.assertTrue(unrelated.exists())
        self.assertFalse(self.base.exists())

    def test_live_control_socket_preserves_original_receipt(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(control))
        control.chmod(0o600)
        self.listener.listen()
        result = self.run_shell(CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION'])
        self.assertEqual(result.returncode, 73)
        self.assertTrue(control.exists())
        self.assertTrue(self.receipt.exists())

    def test_control_socket_symlink_is_never_followed(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        control.symlink_to(self.socket)
        result = self.run_shell(CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION'])
        self.assertEqual(result.returncode, 71)
        self.assertTrue(self.socket.exists())
        self.assertTrue(control.is_symlink())

    def test_live_relative_control_socket_after_cwd_change_is_retained(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        previous = Path.cwd()
        try:
            os.chdir(self.base)
            self.listener = socket.socket(socket.AF_UNIX)
            self.listener.bind('sessions/plugins.sock')
            self.listener.listen()
        finally:
            os.chdir(previous)
        for body in ['\ninspect_previous', CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION']]:
            self.assertEqual(self.run_shell(body).returncode, 73)
            self.assertTrue(control.exists())
            self.assertTrue(self.receipt.exists())

    def test_live_renamed_control_socket_is_retained(self):
        # The filesystem inode remains live even when the kernel's saved name
        # no longer resolves. A pathname-only guard cannot prove this stale.
        control = self.sessions.parent / 'plugins.sock'
        self.socket.rename(control)
        self.listener.listen()
        for body in ['\ninspect_previous', CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION']]:
            self.assertEqual(self.run_shell(body).returncode, 73)
            self.assertTrue(control.exists())
            self.assertTrue(self.receipt.exists())

    def test_live_control_socket_with_high_inode_bits_is_retained(self):
        # Unix diagnostics expose the low 32 bits of the filesystem inode.
        # Model wide inode values without requiring a separate mounted fixture.
        control = self.sessions.parent / 'plugins.sock'
        self.socket.rename(control)
        self.listener.listen()
        metadata = control.stat()
        for upper in [1 << 32, 1 << 63, ((1 << 64) - 1) ^ ((1 << 32) - 1)]:
            inode = upper | (metadata.st_ino & ((1 << 32) - 1))
            prefix = f"""stat() {{
    if [ \"$#\" = 3 ] && [ \"$1\" = -c ] && [ \"$2\" = '%d:%i' ] && [ \"$3\" = \"$base/sessions/plugins.sock\" ]; then
        printf '%s\\n' '{metadata.st_dev}:{inode}'
    else
        command stat \"$@\"
    fi
}}
"""
            for body in ['\ninspect_previous', CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION']]:
                self.assertEqual(self.run_shell(prefix + body).returncode, 73, inode)
                self.assertTrue(control.exists())
                self.assertTrue(self.receipt.exists())
        self.listener.close()
        self.assertEqual(self.run_shell(prefix + CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION']).returncode, 0)
        self.assertFalse(control.exists())
        self.assertFalse(self.receipt.exists())

    def test_missing_socket_diagnostics_does_not_replace_direct_probe(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        self.socket.rename(control)
        result = self.run_shell('ss() { return 1; }\n' + CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION'])
        self.assertEqual(result.returncode, 0)
        self.assertFalse(control.exists())
        self.assertFalse(self.receipt.exists())

    def test_full_control_socket_backlog_preserves_receipt_as_uncertain(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        with socket.socket(socket.AF_UNIX) as listener, socket.socket(socket.AF_UNIX) as queued:
            listener.bind(str(control))
            listener.listen(0)
            queued.connect(str(control))
            result = self.run_shell(CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION'])
        self.assertEqual(result.returncode, 77)
        self.assertTrue(control.exists())
        self.assertTrue(self.receipt.exists())

    def test_unavailable_control_probe_preserves_receipt(self):
        self.listener.close()
        control = self.sessions.parent / 'plugins.sock'
        self.socket.rename(control)
        result = self.run_shell('python3() { return 76; }\n' + CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION'])
        self.assertEqual(result.returncode, 76)
        self.assertTrue(control.exists())
        self.assertTrue(self.receipt.exists())

    def test_partial_stage_retirement_never_adopts_another_transaction(self):
        self.listener.close()
        stage = self.base / '.bootstrap-lock'
        stage.mkdir(mode=0o700)
        marker = stage / 'transaction'
        marker.write_text('4' * 32 + '\n')
        marker.chmod(0o600)
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 75)
        self.assertTrue(marker.exists())
        self.assertTrue(self.receipt.exists())

    def test_partial_stage_retirement_keeps_unknown_files(self):
        self.listener.close()
        stage = self.base / '.bootstrap-lock'
        stage.mkdir(mode=0o700)
        unknown = stage / 'retained'
        unknown.write_text('retained data')
        unknown.chmod(0o600)
        self.assertEqual(self.recover().returncode, 75)
        self.assertTrue(unknown.exists())
        self.assertTrue(self.socket.exists())
        self.assertTrue(self.receipt.exists())

    def test_partial_stage_retirement_never_follows_a_nested_link(self):
        self.listener.close()
        stage = self.base / '.bootstrap-lock'
        state = stage / 'state'
        stage.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        retained = self.base.parent / 'retained'
        retained.write_text('retained data')
        retained.chmod(0o600)
        (state / 'link').symlink_to(retained)
        self.assertEqual(self.recover().returncode, 71)
        self.assertTrue((state / 'link').is_symlink())
        self.assertTrue(retained.exists())
        self.assertTrue(self.receipt.exists())

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
