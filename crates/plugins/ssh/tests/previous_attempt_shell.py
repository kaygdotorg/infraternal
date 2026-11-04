"""Exercise the shipped ownership shell on isolated real files and live Unix listeners (#169)."""
import datetime
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
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
        # The mock service manager keeps state: enabled is the wants link it
        # creates and removes, active is this file. So "put back as it was
        # found" is checked against the state, not only against the calls.
        self.manager_active = Path.cwd() / self.temp / 'manager.active'
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
manager_active="{self.manager_active}"
mock_manager() {{
 printf '%s\\n' "$*" >> "$manager_log"
 mock_wants="${{unit%/*}}/default.target.wants/infraternal-agent.service"
 case "$1" in
  is-enabled) [ -L "$mock_wants" ];;
  is-active) [ -e "$manager_active" ];;
  enable)
   [ -f "$unit" ] || return 1
   mkdir -p "${{mock_wants%/*}}"
   [ -L "$mock_wants" ] || ln -s "$unit" "$mock_wants"
   [ "$2" != --now ] || : >| "$manager_active";;
  disable) rm -f "$mock_wants";;
  stop) rm -f "$manager_active";;
  start) [ -f "$unit" ] || return 1; : >| "$manager_active";;
 esac
}}
host={HOST}
transaction={TRANSACTION}
''' + INSPECT + body

    def run_shell(self, body):
        script = self.shell_script(body)
        environment = dict(os.environ, HOME=str(self.home))
        return subprocess.run(['/bin/sh', '-c', script], capture_output=True, env=environment)

    def make_upgrade_fixture(self, lease='99999999 1\n', transaction=TRANSACTION):
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
            ('transaction', transaction + '\n'),
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
        self.launcher.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.launcher.unlink(missing_ok=True)
        self.launcher.symlink_to(binary_dir / 'current')

        self.unit.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.unit.write_text(
            f'# infraternal bootstrap {HOST}\n[Unit]\n[Service]\n'
            f'ExecStart="{binary_dir / "current"}" agent --data "{self.base / "state"}" '
            f'--state "{self.base / "sessions"}" run\n[Install]\nWantedBy=default.target\n'
        )
        self.unit.chmod(0o600)
        enabled = self.unit.parent / 'default.target.wants/infraternal-agent.service'
        enabled.parent.mkdir(mode=0o700, exist_ok=True)
        enabled.unlink(missing_ok=True)
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
        # As on the field host: the stuck install's service is enabled and running.
        self.manager_active.touch()
        return stage, payload

    def mutating_calls(self):
        """Manager calls that change the service; inspection only reads it."""
        if not self.manager_log.exists():
            return []
        return [call for call in self.manager_log.read_text().splitlines()
                if call.split(' ')[0] not in ('is-active', 'is-enabled', 'show')]

    def service_state(self):
        """(enabled, active) as the mock service manager holds it."""
        wants = self.unit.parent / 'default.target.wants/infraternal-agent.service'
        return wants.is_symlink(), self.manager_active.exists()

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
            self.assertEqual(fields[5], 'unknown', 'the parent guard names no setup attempt')
            child.communicate(b'done\n')

    def test_parent_guard_holder_is_dated_by_its_own_start_not_another_lease(self):
        # A stage whose old lease names a dead process must not date the live
        # holder of the parent guard (#305).
        self.listener.close()
        stage = self.base / '.bootstrap-lock'
        stage.mkdir(mode=0o700)
        lease = stage / 'lease'
        lease.write_text('99999999 1\n')
        lease.chmod(0o600)
        os.utime(lease, (1_000_000_000, 1_000_000_000))
        transaction = stage / 'transaction'
        transaction.write_text(TRANSACTION + '\n')
        transaction.chmod(0o600)
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
            start_time = stat[stat.rfind(') ') + 2:].split()[19]
            boot_time = next(int(line.split()[1]) for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))
            since = datetime.datetime.fromtimestamp(boot_time + int(start_time) / os.sysconf('SC_CLK_TCK'), datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            inspect_now.touch(mode=0o600)
            stdout, stderr = observer.communicate(timeout=5)
            fields = stdout.decode().strip().split(' ')
            self.assertEqual(observer.returncode, 0, stderr.decode())
            self.assertEqual(fields[2], str(child.pid))
            self.assertEqual(fields[4], since)
            self.assertEqual(fields[5], TRANSACTION, 'the stage names its own attempt')
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
        # The stale socket file has no listener: it is not an open session (#305).
        self.assertEqual(fields[8], '0')
        self.assertEqual(self.identity_path.read_text(), '{"endpoint":"127.0.0.1:7443"}\n')

    def test_upgrade_counts_only_sessions_a_live_shim_serves(self):
        self.make_upgrade_fixture()
        previous = Path.cwd()
        try:
            os.chdir(self.sessions)
            with socket.socket(socket.AF_UNIX) as stale:
                stale.bind('4' * 32 + '.sock')
            os.chmod('4' * 32 + '.sock', 0o600)
            live = socket.socket(socket.AF_UNIX)
            live.bind(self.socket.name)
            os.chmod(self.socket.name, 0o600)
            live.listen()
        finally:
            os.chdir(previous)
        try:
            result = self.run_shell('\ninspect_previous')
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout.decode().strip().split(' ')[8], '1')
        finally:
            live.close()

    def test_upgrade_beside_the_proxy_credential_store_is_classified(self):
        # A current agent keeps the proxy plugin's owner-only store in its
        # runtime directory (#281). A stuck upgrade beside it is still this
        # install's journal, not "ownership not proven" (71).
        self.make_upgrade_fixture()
        store = self.base / 'sessions/proxy-secrets/provider'
        store.mkdir(parents=True, mode=0o700)
        store.parent.chmod(0o700)
        secret = store / 'token'
        secret.write_text('x')
        secret.chmod(0o600)
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(result.stdout.decode().startswith(f'INFRATERNAL_SETUP_UPGRADE {HOST} {TRANSACTION} '), result.stdout)
        # Still owner-only: a readable credential is not ours to vouch for.
        secret.chmod(0o644)
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 71)

    def test_upgrade_with_a_running_old_agents_control_socket_is_classified(self):
        # The real b-0.1.0 binary, running against the restored #305 fixture,
        # bound sessions/plugins.sock as 0775 inside the 0700 sessions directory.
        self.make_upgrade_fixture()
        control = self.base / 'sessions/plugins.sock'
        listener = socket.socket(socket.AF_UNIX)
        previous = Path.cwd()
        try:
            os.chdir(control.parent)
            listener.bind(control.name)
        finally:
            os.chdir(previous)
        listener.close()
        control.chmod(0o775)
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        self.assertTrue(result.stdout.decode().startswith(f'INFRATERNAL_SETUP_UPGRADE {HOST} {TRANSACTION} '))
        # A control socket that is not the user's own socket stays refused.
        control.unlink()
        control.symlink_to(self.base / 'state')
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 71)

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
        self.assertEqual(fields[5], 'unknown', 'this stage has no transaction record')
        holder.communicate(b'done\n', timeout=5)

    def test_replacement_keeps_an_unauthenticated_payload_process_and_stays_retryable(self):
        stage, payload = self.make_upgrade_fixture()
        # A process running the journaled payload without a session endpoint
        # cannot be stopped safely, so replacement refuses (73) and keeps the
        # journal. Session shims are stopped through their socket; the Rust
        # legacy-shim regressions cover that path.
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
        self.assertEqual(result.returncode, 73, result.stderr.decode())
        self.assertIsNone(child.poll(), 'an unauthenticated payload process is never signalled')
        self.assertTrue(stage.exists())
        self.assertTrue((self.base / 'bin/live').exists())
        self.assertTrue(self.identity_path.exists())
        # The read-only check refuses before the stop: the service and its
        # sessions are never touched (#305 P2-3).
        self.assertEqual(self.mutating_calls(), [], 'the service is never stopped for a refusal a read-only check can see')
        self.assertEqual(self.service_state(), (True, True))
        # A later add-host must still see the same stuck install instead of an
        # ownership refusal (#305).
        child.terminate()
        child.wait(timeout=5)
        retry = self.run_shell('\ninspect_previous')
        self.assertEqual(retry.returncode, 0, retry.stdout.decode())
        self.assertTrue(retry.stdout.decode().startswith(f'INFRATERNAL_SETUP_UPGRADE {HOST} {TRANSACTION} '))

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
        # Found by the read-only scan, before the service was touched (#305 P1-2).
        self.assertEqual(self.mutating_calls(), [], 'the service is never stopped for a refusal the scan can see')

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

    def confirm(self, action):
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        self.assertTrue(expected.startswith('INFRATERNAL_SETUP_UPGRADE '), expected)
        return self.run_shell(f'\n{action} "{expected}"\n')

    def test_replacement_keeps_rollback_copies_until_the_next_commit(self):
        stage, _ = self.make_upgrade_fixture()
        previous = stage / 'previous-binary'
        previous.write_bytes(b'old agent')
        previous.chmod(0o700)
        result = self.confirm('replace_stuck_install')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        replaced = Path(f'{self.base}.bootstrap-replaced-{TRANSACTION}')
        self.assertFalse(stage.exists())
        self.assertEqual((replaced / 'previous-binary').read_bytes(), b'old agent', 'rollback copies survive replacement (#305 P2-3)')
        commit = self.run_shell('\nretire_set_aside\n')
        self.assertEqual(commit.returncode, 0, commit.stderr.decode())
        self.assertFalse(replaced.exists(), 'the next commit retires them')

    def test_a_replace_keeps_the_open_terminals_for_the_new_agent(self):
        # D337: a Replace (same server) stops only the agent; the shims keep
        # their terminals and the new agent adopts them. A session listener
        # stands in for a shim: the old code drove sessions-stop at it.
        stage, _ = self.make_upgrade_fixture()
        previous = Path.cwd()
        try:
            os.chdir(self.socket.parent)
            live = socket.socket(socket.AF_UNIX)
            live.bind(self.socket.name)
            os.chmod(self.socket.name, 0o600)
            live.listen()
        finally:
            os.chdir(previous)
        try:
            expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
            self.assertEqual(expected.split(' ')[8], '1', expected)
            result = self.run_shell(f'\nreplace_stuck_install "{expected}"\n')
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertFalse(stage.exists())
            self.assertTrue(self.socket.is_socket(), 'the session endpoint is left in place')
            # Relative to its directory: the absolute path can pass the
            # 108-byte AF_UNIX limit under the gate's scratch root.
            previous = Path.cwd()
            try:
                os.chdir(self.socket.parent)
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(self.socket.name)
            finally:
                os.chdir(previous)
            live.settimeout(5)
            accepted, _ = live.accept()
            accepted.close()
            self.assertEqual(self.mutating_calls()[:2], ['stop infraternal-agent.service', 'disable infraternal-agent.service'])
        finally:
            live.close()

    def test_a_replacement_records_the_service_found_with_its_journal(self):
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        replaced = Path(f'{self.base}.bootstrap-replaced-{TRANSACTION}')
        self.assertEqual((replaced / 'found-service').read_text(), 'yes yes\n')
        self.assertEqual(self.service_state(), (False, False))

    def test_a_failed_replacement_is_put_back_as_found(self):
        stage, _ = self.make_upgrade_fixture()
        before = self.run_shell('\ninspect_previous').stdout
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        # The new upgrade failed and its rollback removed its own journal (#305 P1-1).
        restore = self.run_shell(f'\nrestore_replaced_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 0, restore.stderr.decode())
        self.assertEqual(restore.stdout, b'restored\n')
        self.assertEqual(self.service_state(), (True, True), 'enabled and running, as found')
        self.assertFalse((stage / 'found-service').exists())
        self.assertFalse(Path(f'{self.base}.bootstrap-replaced-{TRANSACTION}').exists())
        self.assertEqual(self.run_shell('\ninspect_previous').stdout, before, 'the same stuck install, as found')

    def test_a_replaced_journal_waits_for_the_new_attempts_rollback(self):
        stage, _ = self.make_upgrade_fixture()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        stage.mkdir(mode=0o700)
        restore = self.run_shell(f'\nrestore_replaced_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 72, restore.stderr.decode())
        self.assertTrue(Path(f'{self.base}.bootstrap-replaced-{TRANSACTION}').exists())
        self.assertEqual(self.service_state(), (False, False))

    def test_restoring_what_was_never_set_aside_changes_nothing(self):
        self.make_upgrade_fixture()
        for action in ('restore_replaced_install', 'restore_superseded_install'):
            restore = self.run_shell(f'\n{action} {TRANSACTION}\n')
            self.assertEqual(restore.returncode, 0, restore.stderr.decode())
            self.assertEqual(restore.stdout, b'untouched\n')
        self.assertFalse(self.manager_log.exists())

    def test_an_interrupted_replacement_record_keeps_the_journal_recognized(self):
        stage, _ = self.make_upgrade_fixture()
        found = stage / 'found-service'
        found.write_text('yes yes\n')
        found.chmod(0o600)
        result = self.run_shell('\ninspect_previous')
        self.assertTrue(result.stdout.decode().startswith(f'INFRATERNAL_SETUP_UPGRADE {HOST} {TRANSACTION} '), result.stdout)

    def test_another_servers_install_is_set_aside_whole_and_can_be_put_back(self):
        stage, _ = self.make_upgrade_fixture()
        result = self.confirm('supersede_stuck_install')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        aside = Path(f'{self.base}.bootstrap-superseded-{TRANSACTION}')
        self.assertFalse(self.base.exists(), 'the setup directory is free for a new host (D335)')
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.launcher.is_symlink())
        self.assertTrue((aside / 'state/identity.json').exists(), 'nothing is deleted')
        self.assertTrue((aside / '.bootstrap-lock/transaction').exists())
        self.assertEqual((aside / '.superseded-service').read_text(), 'yes yes\n')
        self.assertIn('# infraternal bootstrap', (aside / '.superseded-unit').read_text())
        log = self.mutating_calls()
        self.assertEqual(log[:3], [
            'stop infraternal-agent.service',
            'disable infraternal-agent.service',
            'daemon-reload',
        ])
        self.assertNotIn('start infraternal-agent.service', log)
        self.assertEqual(self.service_state(), (False, False))
        self.manager_log.unlink()
        restore = self.run_shell(f'\nrestore_superseded_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 0, restore.stderr.decode())
        self.assertFalse(aside.exists())
        self.assertTrue(self.identity_path.exists())
        self.assertTrue(stage.exists(), 'the stuck journal is back exactly as found')
        self.assertTrue(self.unit.exists())
        self.assertEqual(os.readlink(self.launcher), str(self.base / 'bin/current'))
        self.assertFalse((self.base / '.superseded-service').exists())
        self.assertEqual(self.manager_log.read_text().splitlines(), [
            'daemon-reload',
            'enable infraternal-agent.service',
            'start infraternal-agent.service',
        ])
        self.assertEqual(self.service_state(), (True, True), 'enabled and running, as found')

    def test_an_upgrade_names_its_agent_live_whenever_the_unit_is_active(self):
        # #305 P2-2: the upgrade's own START ran (the agent started after the
        # lease) and the commit was lost.
        stage, _ = self.make_upgrade_fixture()
        os.utime(stage / 'lease', (1, 1))
        self.assertTrue(self.run_shell('\ninspect_previous').stdout.decode().endswith(' live\n'))
        # The commonest stuck shape: the session dropped before ACTIVATE (no
        # stopping marker), so the old agent was never stopped. It started long
        # before the lease and is still serving and connected.
        self.assertFalse((stage / 'stopping').exists())
        now = datetime.datetime.now().timestamp() + 3600
        os.utime(stage / 'lease', (now, now))
        self.assertTrue(self.run_shell('\ninspect_previous').stdout.decode().endswith(' live\n'))
        # Not running at all.
        self.manager_active.unlink()
        self.assertTrue(self.run_shell('\ninspect_previous').stdout.decode().endswith(' idle\n'))

    def test_an_agent_that_starts_after_an_idle_confirmation_is_asked_about_again(self):
        # #305 P2-2: the person confirmed an idle install; its agent started
        # while they decided. Nothing is stopped and Check shows the warning.
        self.make_upgrade_fixture()
        self.manager_active.unlink()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        self.assertTrue(expected.endswith(' idle'), expected)
        self.manager_active.touch()
        self.manager_log.unlink(missing_ok=True)
        for action in ('replace_stuck_install', 'supersede_stuck_install'):
            with self.subTest(action=action):
                result = self.run_shell(f'\n{action} "{expected}"\n')
                self.assertEqual(result.returncode, 75, result.stderr.decode())
                self.assertEqual(self.mutating_calls(), [])
                self.assertEqual(self.service_state(), (True, True))

    def test_another_servers_install_running_with_open_terminals_is_never_set_aside(self):
        # D337: a running agent with a live terminal may be in use by its
        # server; the set-aside refuses even a record the server confirmed.
        stage, _ = self.make_upgrade_fixture()
        previous = Path.cwd()
        try:
            os.chdir(self.socket.parent)
            live = socket.socket(socket.AF_UNIX)
            live.bind(self.socket.name)
            os.chmod(self.socket.name, 0o600)
            live.listen()
        finally:
            os.chdir(previous)
        try:
            expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
            fields = expected.split(' ')
            self.assertEqual((fields[8], fields[-1]), ('1', 'live'), expected)
            result = self.run_shell(f'\nsupersede_stuck_install "{expected}"\n')
            self.assertEqual(result.returncode, 75, result.stderr.decode())
            self.assertEqual(self.mutating_calls(), [])
            self.assertTrue(stage.exists())
            self.assertEqual(self.service_state(), (True, True))
        finally:
            live.close()

    def test_an_agent_that_stopped_after_a_live_confirmation_is_still_replaced(self):
        # Confirmed with the live warning; stopping less than that is no surprise.
        self.make_upgrade_fixture()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        self.assertTrue(expected.endswith(' live'), expected)
        self.manager_active.unlink()
        result = self.run_shell(f'\nreplace_stuck_install "{expected}"\n')
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_a_disabled_stopped_install_is_put_back_disabled_and_stopped(self):
        self.make_upgrade_fixture()
        (self.unit.parent / 'default.target.wants/infraternal-agent.service').unlink()
        self.manager_active.unlink()
        self.assertEqual(self.confirm('supersede_stuck_install').returncode, 0)
        aside = Path(f'{self.base}.bootstrap-superseded-{TRANSACTION}')
        self.assertEqual((aside / '.superseded-service').read_text(), 'no no\n')
        restore = self.run_shell(f'\nrestore_superseded_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 0, restore.stderr.decode())
        self.assertEqual(self.service_state(), (False, False), 'as found, not "fixed"')

    def signal_after_the_stop(self, signal, status):
        # /bin/sh is dash on Debian and Ubuntu, and dash runs no EXIT trap when
        # a signal ends it; a dropped SSH session sends HUP or PIPE (#305 P2-1).
        stage, _ = self.make_upgrade_fixture()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        result = self.run_shell(f'''
signal_manager() {{
 mock_manager "$@"
 [ "$1" != disable ] || kill -{signal} $$
}}
manager=signal_manager
supersede_stuck_install "{expected}"
''')
        self.assertEqual(result.returncode, status, result.stderr.decode())
        self.assertEqual(self.service_state(), (True, True), 'enabled and running, as found')
        self.assertTrue(stage.exists())
        self.assertFalse((stage / 'found-service').exists())
        self.assertFalse(Path(f'{self.base}.bootstrap-superseded-{TRANSACTION}').exists())

    def test_a_hangup_after_the_stop_still_puts_the_service_back(self):
        self.signal_after_the_stop('HUP', 129)

    def test_a_termination_after_the_stop_still_puts_the_service_back(self):
        self.signal_after_the_stop('TERM', 143)

    def test_a_broken_pipe_after_the_stop_still_puts_the_service_back(self):
        self.signal_after_the_stop('PIPE', 141)

    def cancel_during_the_stop(self, action, restore):
        # #305 P2-1: a cancel kills only the local ssh client. sshd signals no
        # non-pty command when its channel closes, so the set-aside runs on to
        # the end while the restore starts; the restore must wait for it, not
        # give up on the guard it holds.
        stage, _ = self.make_upgrade_fixture()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        stopping = Path(self.temp) / 'stopping'
        script = self.shell_script(f'''
slow_manager() {{
 if [ "$1" = stop ]; then : > "{stopping.resolve()}"; sleep 2; fi
 mock_manager "$@"
}}
manager=slow_manager
{action} "{expected}"
''')
        set_aside = subprocess.Popen(['/bin/sh', '-c', script], env=dict(os.environ, HOME=str(self.home)),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.children.append(set_aside)
        for _ in range(500):
            if stopping.exists() or set_aside.poll() is not None:
                break
            time.sleep(0.01)
        self.assertTrue(stopping.exists(), set_aside.stderr.read().decode() if set_aside.poll() is not None else '')
        result = self.run_shell(f'\n{restore} {TRANSACTION}\n')
        self.assertEqual(set_aside.wait(timeout=30), 0)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'restored\n')
        self.assertEqual(self.service_state(), (True, True), 'enabled and running, as found')
        self.assertEqual((stage / 'transaction').read_text(), TRANSACTION + '\n', 'the journal is back')
        self.assertFalse((stage / 'found-service').exists())
        self.assertTrue(self.unit.exists())

    def test_a_reenroll_cancelled_during_the_stop_is_put_back(self):
        self.cancel_during_the_stop('supersede_stuck_install', 'restore_superseded_install')

    def test_a_replace_cancelled_during_the_stop_is_put_back(self):
        self.cancel_during_the_stop('replace_stuck_install', 'restore_replaced_install')

    def test_a_set_aside_killed_between_the_stop_and_the_move_is_put_back(self):
        # SIGKILL or power loss after the stop: no trap ran, the journal is in
        # place and found-service says what to bring back (#305 P2-1).
        stage, _ = self.make_upgrade_fixture()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        result = self.run_shell(f'''
kill_manager() {{
 mock_manager "$@"
 [ "$1" != disable ] || kill -KILL $$
}}
manager=kill_manager
supersede_stuck_install "{expected}"
''')
        self.assertEqual(result.returncode, -9, result.stderr.decode())
        self.assertEqual(self.service_state(), (False, False))
        for restore in ('restore_superseded_install', 'restore_replaced_install'):
            with self.subTest(restore=restore):
                result = self.run_shell(f'\n{restore} {TRANSACTION}\n')
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(self.service_state(), (True, True), 'enabled and running, as found')
                self.assertFalse((stage / 'found-service').exists())
                self.manager_log.unlink(missing_ok=True)
                (self.unit.parent / 'default.target.wants/infraternal-agent.service').unlink()
                self.manager_active.unlink()
                found = stage / 'found-service'
                found.write_text('yes yes\n')
                found.chmod(0o600)

    def test_check_reports_an_install_set_aside_and_never_put_back(self):
        # #305 P2-1: the restore never ran, so Check must not answer CLEAR.
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('supersede_stuck_install').returncode, 0)
        result = self.run_shell('\nsetup_check=yes\ninspect_previous')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            result.stdout.decode(),
            f'INFRATERNAL_SETUP_SET_ASIDE superseded {HOST} {TRANSACTION} {socket.gethostname()} yes yes\n',
        )

    def test_check_reports_a_replaced_journal_never_put_back(self):
        self.make_upgrade_fixture()
        self.manager_active.unlink()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        result = self.run_shell('\nsetup_check=yes\ninspect_previous')
        self.assertEqual(
            result.stdout.decode(),
            f'INFRATERNAL_SETUP_SET_ASIDE replaced {HOST} {TRANSACTION} {socket.gethostname()} yes no\n',
        )

    def new_host_in_place(self):
        """The re-enrollment committed: a new install owns the setup directory."""
        self.base.mkdir(mode=0o700)
        owner = self.base / '.bootstrap-owner'
        owner.write_text('5' * 32 + '\n')
        owner.chmod(0o600)

    def test_a_commit_deletes_the_old_install_and_its_key(self):
        # D337: no set-aside copy is kept once the machine has joined.
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('supersede_stuck_install').returncode, 0)
        aside = Path(f'{self.base}.bootstrap-superseded-{TRANSACTION}')
        self.assertTrue((aside / 'state/identity.json').exists(), 'kept until the commit, for rollback')
        self.new_host_in_place()
        commit = self.run_shell('\nretire_set_aside\n')
        self.assertEqual(commit.returncode, 0, commit.stderr.decode())
        self.assertFalse(aside.exists())

    def test_check_deletes_an_old_install_a_crash_left_beside_a_new_host(self):
        # D337: a crash between the commit and its delete leaves the old
        # install beside the new one; the next Check deletes it.
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('supersede_stuck_install').returncode, 0)
        aside = Path(f'{self.base}.bootstrap-superseded-{TRANSACTION}')
        self.new_host_in_place()
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, b'INFRATERNAL_SETUP_CLEAR\n')
        self.assertFalse(aside.exists(), 'the old install and its key are gone')

    def test_several_set_aside_installs_are_refused_by_name(self):
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('supersede_stuck_install').returncode, 0)
        other = Path(f'{self.base}.bootstrap-superseded-{"6" * 32}')
        shutil.copytree(f'{self.base}.bootstrap-superseded-{TRANSACTION}', other, symlinks=True)
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, b'INFRATERNAL_SETUP_REFUSED aside\n')

    def test_restore_refuses_while_a_new_install_is_in_place(self):
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('supersede_stuck_install').returncode, 0)
        self.base.mkdir(mode=0o700)
        restore = self.run_shell(f'\nrestore_superseded_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 72, restore.stderr.decode())
        self.assertTrue(Path(f'{self.base}.bootstrap-superseded-{TRANSACTION}').exists())

    def test_a_connected_upgrade_is_finished_not_replaced(self):
        stage, _ = self.make_upgrade_fixture()
        result = self.confirm('finish_stuck_upgrade')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(stage.exists(), 'the lost commit is finished (#305 P2-2)')
        self.assertTrue((self.base / 'bin/live').exists())
        self.assertEqual(self.mutating_calls(), [], 'the running service is never touched')

    def stop_service(self):
        """As a set-aside that stopped the service and then died leaves it."""
        (self.unit.parent / 'default.target.wants/infraternal-agent.service').unlink()
        self.manager_active.unlink()

    def test_a_retried_set_aside_keeps_the_service_state_first_found(self):
        # #305 P3-1: an earlier set-aside stopped the service and was killed
        # before its move; no trap ran. The retry must put back what that one
        # found, not the stopped service it left.
        stage, _ = self.make_upgrade_fixture()
        found = stage / 'found-service'
        found.write_text('yes yes\n')
        found.chmod(0o600)
        self.stop_service()
        self.assertEqual(self.confirm('supersede_stuck_install').returncode, 0)
        aside = Path(f'{self.base}.bootstrap-superseded-{TRANSACTION}')
        self.assertEqual((aside / '.superseded-service').read_text(), 'yes yes\n')
        restore = self.run_shell(f'\nrestore_superseded_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 0, restore.stderr.decode())
        self.assertEqual(self.service_state(), (True, True), 'enabled and running, as first found')

    def test_a_replace_beside_a_pending_replaced_journal_carries_its_service_state(self):
        # #305 P3-1: Replace tx1 stopped the service and its restore never ran;
        # a newer upgrade tx2 got stuck too. Replacing tx2 records what tx1 found.
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        newer = '4' * 32
        self.make_upgrade_fixture(transaction=newer)
        self.stop_service()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        self.assertEqual(Path(f'{self.base}.bootstrap-replaced-{newer}/found-service').read_text(), 'yes yes\n')
        restore = self.run_shell(f'\nrestore_replaced_install {newer}\n')
        self.assertEqual(restore.returncode, 0, restore.stderr.decode())
        self.assertEqual(self.service_state(), (True, True), 'enabled and running, as first found')

    def test_finishing_a_newer_upgrade_retires_a_replaced_journal(self):
        # #305 P2-3: a Replace set journal tx1 aside; the new upgrade tx2
        # reached START and lost its commit, so the next add-host finishes it.
        # That is a commit: tx1 must go, or the healthy host is offered "Put
        # it back" and gets the stale journal planted into it.
        self.make_upgrade_fixture()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        replaced = Path(f'{self.base}.bootstrap-replaced-{TRANSACTION}')
        self.assertTrue(replaced.exists())
        newer = '4' * 32
        self.make_upgrade_fixture(transaction=newer)
        result = self.confirm('finish_stuck_upgrade')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(replaced.exists(), 'Finish is a commit and retires the replaced journal')
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, b'INFRATERNAL_SETUP_CLEAR\n')

    def test_a_replaced_journal_beside_an_active_agent_is_never_offered_or_put_back(self):
        # #305 P2-3: something newer is serving (a commit that predates
        # retire_set_aside, or a manual start). Check stays CLEAR and the
        # restore refuses rather than make a healthy host stuck again.
        stage, _ = self.make_upgrade_fixture()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        replaced = Path(f'{self.base}.bootstrap-replaced-{TRANSACTION}')
        self.manager_active.touch()
        restore = self.run_shell(f'\nrestore_replaced_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 72, restore.stderr.decode())
        self.assertTrue(replaced.exists())
        self.assertFalse(stage.exists(), 'the stale journal is not planted into the live install')
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, b'INFRATERNAL_SETUP_CLEAR\n')
        self.assertFalse(replaced.exists(), 'and Check deletes it: no set-aside copy is kept (D337)')

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

    def make_fresh_connect_stage(self):
        """A fresh attempt that stopped at Connect: D291 key preparation copied
        state into the lock and the payload cache link was published (#305)."""
        self.listener.close()
        self.receipt.unlink()
        stage = self.base / '.bootstrap-lock'
        stage.mkdir(mode=0o700)
        for name, value in [('transaction', TRANSACTION + '\n'), ('kind', 'fresh\n'), ('lease', '99999999 1\n')]:
            item = stage / name
            item.write_text(value)
            item.chmod(0o600)
        payload = stage / 'payload'
        shutil.copyfile(os.environ['INFRATERNAL_TEST_RUNTIME_HELPER'], payload)
        payload.chmod(0o700)
        cache = stage / 'cache'
        cache.mkdir(mode=0o700)
        os.link(payload, cache / 'payload')
        owner = cache / 'owner'
        owner.write_text('INFRATERNAL_PAYLOAD_CACHE_V1\n')
        owner.chmod(0o600)
        state = stage / 'state'
        state.mkdir(mode=0o700)
        key = state / 'join-key.der'
        key.write_bytes(b'synthetic')
        key.chmod(0o600)
        return stage

    def test_fresh_attempt_stopped_at_connect_is_recoverable(self):
        stage = self.make_fresh_connect_stage()
        result = self.run_shell('\ninspect_previous')
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        self.assertEqual(result.stdout.decode(), f'INFRATERNAL_SETUP_STALE {HOST} {TRANSACTION} {self.identity} 1\n')
        self.assertEqual(self.recover().returncode, 0)
        self.assertFalse(stage.exists())
        self.assertFalse(self.base.exists())

    def test_check_names_the_refusal_cause_without_mutating(self):
        stage = self.make_fresh_connect_stage()
        foreign = stage / 'personal.txt'
        foreign.write_text('foreign data')
        checked = self.run_shell('\nsetup_check=yes\ninspect_previous')
        self.assertEqual(checked.returncode, 0)
        self.assertEqual(checked.stdout.decode(), 'INFRATERNAL_SETUP_REFUSED entry\n')
        # Mutating callers keep the fail-closed status.
        self.assertEqual(self.run_shell('\ninspect_previous').returncode, 75)
        self.assertEqual(self.recover('unused').returncode, 75)
        self.assertEqual(foreign.read_text(), 'foreign data')
        self.assertTrue((stage / 'state/join-key.der').exists())

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
