"""Exercise the shipped ownership shell on isolated real files and live Unix listeners (#169)."""
import datetime
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
# Confirmation programs: the shared guard, the lease (rollback retires it),
# runtime cleanup and the inspector, in the order install.rs sends them.
INSPECT = ''.join((ROOT / f'src/{name}').read_text() for name in ('setup_guard.sh', 'setup_lock.sh', 'runtime_cleanup.sh', 'previous_attempt.sh'))
RUNTIME_CLEANUP = (ROOT / 'src/runtime_cleanup.sh').read_text()
SOURCE = (ROOT / 'src/install.rs').read_text()
CONSTANTS = dict(re.findall(r'(?:pub\(crate\) )?const (\w+): &str = r#"(.*?)"#;', SOURCE, re.S))
HOST, TRANSACTION = '1' * 32, '2' * 32

class EarlierSetup(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get('INFRATERNAL_TEST_STATE_ROOT', Path.home() / '.cache/codex-scratch/asf'))
        scratch.mkdir(parents=True, exist_ok=True)
        os.chdir(scratch)
        # Keep the fixture directory name short for AF_UNIX; the shell receives
        # a canonical absolute root so its path ownership checks stay realistic.
        self.temp = Path(f'asf-{uuid.uuid4().hex[:12]}')
        self.temp.mkdir(mode=0o700)
        self.base = Path.cwd() / self.temp / 'infraternal'
        self.base.mkdir(mode=0o700)
        self.home = Path.cwd() / self.temp / 'home'
        self.home.mkdir(mode=0o700)
        self.unit = self.home / '.config/systemd/user/infraternal-agent.service'
        self.launcher = self.home / '.local/bin/infraternal'
        self.manager_log = Path.cwd() / self.temp / 'manager.log'
        self.children = []
        helper = Path(os.environ['INFRATERNAL_TEST_RUNTIME_HELPER'])
        cache = Path(str(self.base) + '.bootstrap-cache')
        cache.mkdir(mode=0o700)
        import shutil
        shutil.copyfile(helper, cache / 'payload')
        (cache / 'payload').chmod(0o700)
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
        Path(self.socket.name).chmod(0o600)
        os.chdir(previous)

    def tearDown(self):
        if self.listener:
            self.listener.close()
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
        shutil.rmtree(self.temp)

    def shell_script(self, body):
        return f'''set -euC
umask 077
base="{self.base}"
home="{self.home}"
unit="{self.unit}"
launcher="{self.launcher}"
manager=mock_manager
manager_log="{self.manager_log}"
mock_manager() {{ printf '%s\\n' "$*" >> "$manager_log"; }}
host={HOST}
transaction={TRANSACTION}
''' + INSPECT + body

    def run_shell(self, body):
        script = self.shell_script(body)
        environment = dict(os.environ, HOME=str(self.home))
        return subprocess.run(['/bin/sh', '-c', script], capture_output=True, env=environment)

    def make_upgrade_fixture(self, lease='99999999 1\n'):
        if self.listener:
            self.listener.close()
            self.listener = None
        self.receipt.unlink(missing_ok=True)
        shutil.rmtree(self.base)
        self.base.mkdir(mode=0o700)
        self.identity = f'{self.base.stat().st_dev}:{self.base.stat().st_ino}'
        self.owner.write_text(HOST + '\n')
        self.owner.chmod(0o600)

        stage = self.base / '.bootstrap-lock'
        stage.mkdir(mode=0o700)
        for name, value in [
            ('transaction', TRANSACTION + '\n'),
            ('kind', 'upgrade\n'),
            ('lease', lease),
        ]:
            marker = stage / name
            marker.write_text(value)
            marker.chmod(0o600)
        for name in ('activating', 'replacing-binary', 'replacing-launcher'):
            marker = stage / name
            marker.touch(mode=0o600)
            marker.chmod(0o600)

        payload = stage / 'payload'
        shutil.copyfile(os.environ['INFRATERNAL_TEST_RUNTIME_HELPER'], payload)
        payload.chmod(0o700)
        cache = stage / 'cache'
        cache.mkdir(mode=0o700)
        os.link(payload, cache / 'payload')
        owner = cache / 'owner'
        owner.write_text('INFRATERNAL_PAYLOAD_CACHE_V1\n')
        owner.chmod(0o600)

        binary_dir = self.base / 'bin'
        binary_dir.mkdir(mode=0o700)
        live = binary_dir / 'live'
        shutil.copyfile(os.environ['INFRATERNAL_TEST_RUNTIME_HELPER'], live)
        live.chmod(0o700)
        (binary_dir / 'current').symlink_to(live)
        self.launcher.parent.mkdir(parents=True, mode=0o700)
        self.launcher.symlink_to(binary_dir / 'current')

        self.unit.parent.mkdir(parents=True, mode=0o700)
        self.unit.write_text(
            f'# infraternal bootstrap {HOST}\n[Unit]\n[Service]\n'
            f'ExecStart="{binary_dir / "current"}" agent --data "{self.base / "state"}" '
            f'--state "{self.base / "sessions"}" run\n[Install]\nWantedBy=default.target\n'
        )
        self.unit.chmod(0o600)
        enabled = self.unit.parent / 'default.target.wants/infraternal-agent.service'
        enabled.parent.mkdir(mode=0o700)
        enabled.symlink_to(self.unit)

        state = self.base / 'state'
        state.mkdir(mode=0o700)
        self.identity_path = state / 'identity.json'
        self.identity_path.write_text('{"endpoint":"127.0.0.1:7443"}\n')
        self.identity_path.chmod(0o600)
        runtime = self.base / 'sessions'
        (runtime / 'sessions').mkdir(parents=True, mode=0o700)
        runtime.chmod(0o700)
        (runtime / 'sessions').chmod(0o700)
        lifetime = runtime / '.lifetime-lock'
        lifetime.touch(mode=0o600)
        lifetime.chmod(0o600)
        self.socket = runtime / 'sessions' / ('3' * 32 + '.sock')
        self.manager_log.unlink(missing_ok=True)
        return stage, payload

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
        other = self.base.parent / 'other'
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
        Path(str(self.base) + '.bootstrap-cache/payload').unlink()
        result = self.run_shell(CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION'])
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

    def test_live_parent_lock_reports_the_actual_holder_not_the_inspector(self):
        self.listener.close()
        inspect_now = self.temp / 'inspect-now'
        observer = subprocess.Popen(
            ['/bin/sh', '-c', self.shell_script(
                f'\nwhile [ ! -e "{inspect_now}" ]; do sleep 0.01; done\ninspect_previous'
            )],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(os.environ, HOME=str(self.home)),
        )
        self.children.append(observer)
        with subprocess.Popen(['/bin/sh', '-c', 'exec 9< "$1"; flock 9; echo ready; read answer', 'sh', str(self.base.parent)], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
            self.assertEqual(child.stdout.readline(), b'ready\n')
            stat = Path(f'/proc/{child.pid}/stat').read_text()
            suffix = stat[stat.rfind(') ') + 2:].split()
            start_time = suffix[19]
            boot_time = next(int(line.split()[1]) for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))
            since = datetime.datetime.fromtimestamp(boot_time + int(start_time) / os.sysconf('SC_CLK_TCK'), datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            inspect_now.touch(mode=0o600)
            stdout, stderr = observer.communicate(timeout=5)
            fields = stdout.decode().strip().split(' ')
            self.assertEqual(observer.returncode, 0, stderr.decode())
            self.assertEqual(fields[:2], ['INFRATERNAL_SETUP_LOCKED', socket.gethostname()])
            self.assertEqual(fields[2:4], [str(child.pid), start_time])
            self.assertEqual(fields[4], since)
            child.communicate(b'done\n')

    def test_upgrade_journal_rejects_extra_lease_fields(self):
        stage, _ = self.make_upgrade_fixture('99999999 1 extra\n')
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 75, result.stderr.decode())
        self.assertTrue(stage.exists(), 'a malformed lease cannot authorize takeover')

    def test_upgrade_journal_rejects_an_oversized_lease(self):
        stage, _ = self.make_upgrade_fixture('9' * 70 + '\n')
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 75, result.stderr.decode())
        self.assertTrue(stage.exists(), 'an oversized lease cannot authorize takeover')

    def test_archived_failed_upgrade_with_dead_lease_owner_is_classified_for_replacement(self):
        # Sanitized from the archived #305 field fixture. It keeps the exact
        # journal shape and an old 7443 endpoint without the private key or binary.
        stage, _ = self.make_upgrade_fixture()
        stale_socket = self.socket
        listener = socket.socket(socket.AF_UNIX)
        previous = Path.cwd()
        try:
            os.chdir(self.sessions)
            listener.bind(stale_socket.name)
        finally:
            os.chdir(previous)
        listener.close()
        stale_socket.chmod(0o600)
        # A crash can leave the private Exited record between its write and rename.
        ending = self.sessions / ('4' * 32 + '.ending')
        ending.write_bytes(bytes(17))
        ending.chmod(0o600)

        result = self.run_shell('\ninspect_previous')
        fields = result.stdout.decode().strip().split(' ')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(fields[:2], ['INFRATERNAL_SETUP_UPGRADE', HOST])
        self.assertEqual(fields[2], TRANSACTION)
        self.assertEqual(fields[3], self.identity)
        self.assertEqual(fields[4], socket.gethostname())
        self.assertEqual(fields[5:7], ['99999999', '1'])
        since = datetime.datetime.fromtimestamp(
            (stage / 'lease').stat().st_mtime, datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.assertEqual(fields[7], since)
        self.assertEqual(fields[8], '1')
        self.assertEqual(self.identity_path.read_text(), '{"endpoint":"127.0.0.1:7443"}\n')

    def test_upgrade_with_lifetime_lock_requests_helper_refresh_before_confirmation(self):
        stage, _ = self.make_upgrade_fixture()
        shutil.rmtree(Path(str(self.base) + '.bootstrap-cache'))
        previous = Path.cwd()
        try:
            os.chdir(self.sessions)
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(self.socket.name)
            self.socket.chmod(0o600)
        finally:
            os.chdir(previous)

        result = self.run_shell('\ninspect_previous')
        self.assertEqual(
            result.returncode,
            76,
            'preflight must request a compatible runtime helper before offering replacement',
        )
        self.assertTrue(stage.exists(), 'preflight must preserve the failed-upgrade journal')
        self.assertTrue(self.identity_path.exists(), 'preflight must preserve enrolled state')

    def test_failed_upgrade_rollback_marks_failed_before_stopping_the_service(self):
        stage, _ = self.make_upgrade_fixture()
        script = self.shell_script(f'''
receipt="$base.bootstrap-rollback-$transaction"
manager=observe_manager
observe_manager() {{
 printf '%s\\n' "$*" >> "$manager_log"
 if [ "$1" = stop ]; then
  [ -f "$stage/failed" ] && [ ! -e "$stage/activating" ] || exit 80
 fi
}}
{CONSTANTS['ROLLBACK_TRANSACTION']}
''')
        result = subprocess.run(['/bin/sh', '-c', script], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn('stop infraternal-agent.service', self.manager_log.read_text())
        self.assertFalse(stage.exists(), 'a rolled back upgrade must retire its journal')

    def test_live_setup_lock_diagnostic_names_the_machine_process_and_start_time(self):
        self.listener.close()
        stage = self.base / '.bootstrap-lock'
        stage.mkdir(mode=0o700)
        holder = subprocess.Popen(
            ['/bin/sh', '-c', 'exec 7< "$1"; flock 7; echo ready; read answer', 'sh', str(stage)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.children.append(holder)
        self.assertEqual(holder.stdout.readline(), b'ready\n')
        stat = Path(f'/proc/{holder.pid}/stat').read_text()
        suffix = stat[stat.rfind(') ') + 2:].split()
        start_time = suffix[19]
        lease = stage / 'lease'
        lease.write_text(f'{holder.pid} {start_time}\n')
        lease.chmod(0o600)

        result = self.run_shell('\ninspect_previous')
        fields = result.stdout.decode().strip().split(' ')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(fields[:2], ['INFRATERNAL_SETUP_LOCKED', socket.gethostname()])
        self.assertEqual(fields[2:4], [str(holder.pid), start_time])
        since = datetime.datetime.fromtimestamp(
            lease.stat().st_mtime, datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.assertEqual(fields[4], since)
        holder.communicate(b'done\n', timeout=5)

    def test_replacement_stops_only_the_journaled_payload_process_and_keeps_host_state(self):
        stage, payload = self.make_upgrade_fixture()
        # A process launched through the journaled payload path has that exact
        # executable inode in /proc; sleep gives the shell a real process to stop.
        shutil.copyfile('/bin/sleep', payload)
        payload.chmod(0o700)
        child = subprocess.Popen(
            [str(payload), '30'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.children.append(child)
        import time
        time.sleep(.02)
        self.assertIsNone(
            child.poll(),
            'the journaled payload process must be live before replacement',
        )

        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        body = f'''\nsetup_guard
observed=$(inspect_previous)
[ "$observed" = "{expected}" ] || exit 75
replace_stuck_install "$observed"
'''
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        child.wait(timeout=5)
        self.assertFalse(stage.exists())
        self.assertTrue((self.base / 'bin/live').exists(), 'the old binary remains available for transactional replacement')
        self.assertTrue(self.identity_path.exists(), 'identity and state stay available for HTTPS re-enrollment')
        self.assertEqual(self.manager_log.read_text().splitlines(), [
            'stop infraternal-agent.service',
            'disable infraternal-agent.service',
            'daemon-reload',
        ])

    def test_replacement_does_not_signal_an_unrelated_process_with_a_host_file_open(self):
        stage, payload = self.make_upgrade_fixture()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        opened = open(self.base / 'bin/live', 'rb')
        unrelated = subprocess.Popen(['sleep', '30'], pass_fds=[opened.fileno()])
        self.children.append(unrelated)
        opened.close()
        body = f'''\nsetup_guard
observed=$(inspect_previous)
[ "$observed" = "{expected}" ] || exit 75
replace_stuck_install "$observed"
'''
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 73, result.stderr.decode())
        self.assertIsNone(unrelated.poll(), 'a process that only has a host file open is not an infraternal agent')
        self.assertTrue(stage.exists(), 'uncertain host activity keeps the journal for retry')

    def test_reused_lease_pid_with_a_different_start_time_is_never_signalled(self):
        stage, _ = self.make_upgrade_fixture(f'{os.getpid()} 1\n')
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        result = self.run_shell(
            f'\nsetup_guard\nobserved=$(inspect_previous)\n'
            f'[ "$observed" = "{expected}" ] || exit 75\n'
            'replace_stuck_install "$observed"\n'
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(Path(f'/proc/{os.getpid()}').exists(), 'the reused PID belongs to this test process')
        self.assertFalse(stage.exists())

    def test_failed_upgrade_rollback_replaces_activating_with_failed_before_stop(self):
        stage, _ = self.make_upgrade_fixture()
        body = f'''\nstage="$base/.bootstrap-lock"
mock_manager() {{
    [ -f "$stage/failed" ] && [ ! -e "$stage/activating" ] || exit 90
    return 1
}}
{RUNTIME_CLEANUP}
{CONSTANTS['FRESH_CLEANUP']}
{CONSTANTS['ROLLBACK_TRANSACTION']}
'''
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertTrue((stage / 'failed').exists(), 'the rollback journal must record failed activation')
        self.assertFalse((stage / 'activating').exists(), 'a failed activation cannot remain labeled activating')

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

class LeaseBirthFields(unittest.TestCase):
    def decode(self, records):
        script = 'set -eu\n' + INSPECT + '''
while IFS= read -r record; do
  if lease_birth_field "$record"; then printf '%s\\n' "$lease_actual_birth"
  else printf 'refused\\n'; fi
done
'''
        result = subprocess.run(['/bin/sh', '-c', script], input=('\n'.join(records) + '\n').encode(), capture_output=True, check=True)
        return result.stdout.decode().splitlines()

    def test_kernel_start_time_corpus_preserves_comm_boundaries(self):
        records, expected = [], []
        for name in ['sh', 'sleep', 'two words', 'inner) name', '(name)', ') )', '* [name]', 'tést\tname']:
            for value in range(64):
                fields = ['S'] + ['0'] * 49
                fields[19] = str(100000 + value)
                records.append(f'123 ({name}) ' + ' '.join(fields))
                expected.append(fields[19])
        self.assertEqual(self.decode(records), expected)

    def test_uncertain_start_time_records_are_refused(self):
        records = ['', 'no delimiter', '123 (sleep) S 1']
        for value in ['invalid', '-1', '*', '[0]', '0;1']:
            fields = ['S'] + ['0'] * 49
            fields[19] = value
            records.append('123 (sleep) ' + ' '.join(fields))
        self.assertEqual(self.decode(records), ['refused'] * len(records))

if __name__ == '__main__':
    unittest.main()
