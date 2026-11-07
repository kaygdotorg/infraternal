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
# A Take over's own token: names its set-aside and its cancel (D359).
TAKEOVER = '7' * 32
# The fresh install that follows a Take over: its own host id and transaction.
NEW_HOST, NEW_TRANSACTION = '6' * 32, '8' * 32

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
up_root_base="{getattr(self, 'up_root_base', '/var/lib/infraternal')}"
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

    def installed(self, host=HOST, takeover='unproven'):
        """The check's record for a finished install (#394, D359): its host
        id, the root's identity, whether its agent runs, and whether Take
        over may act on it."""
        stat = self.base.stat()
        live = 'live' if self.manager_active.exists() else 'idle'
        return f'INFRATERNAL_SETUP_INSTALLED {host} {stat.st_dev}:{stat.st_ino} {live} {takeover}\n'.encode()

    def service_state(self):
        """(enabled, active) as the mock service manager holds it."""
        wants = self.unit.parent / 'default.target.wants/infraternal-agent.service'
        return wants.is_symlink(), self.manager_active.exists()

    def recover(self, expected=None, prefix=''):
        if expected is None:
            expected = self.run_shell(prefix + '\ninspect_previous').stdout.decode().strip()
        body = prefix + f'\nsetup_guard\nobserved=$(inspect_previous)\n[ "$observed" = "{expected}" ] || exit 75\nnot_live\nstop_activated_agent\n'
        body += 'for entry in "$base/sessions"/*.sock "$base/sessions/sessions"/*.sock; do [ ! -S "$entry" ] || rm -- "$entry"; done\n'
        body += CONSTANTS['FRESH_CLEANUP'] + CONSTANTS['ROLLBACK_TRANSACTION']
        return self.run_shell(body)

    def make_activated_fresh_fixture(self):
        """J257's field shape (#305): a fresh setup interrupted after activation.

        The journal (kind fresh, activating plus the replacing-* markers) has no
        live lease, the binary, state, unit and launcher are installed, and the
        agent it started still runs from bin/live holding the runtime lifetime
        lock. Returns (stage, agent processes); the agent is `flock` on the lock
        running a copy of sleep as bin/live, so it holds what a real one holds.
        """
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
        for name, value in [('transaction', TRANSACTION + '\n'), ('kind', 'fresh\n'), ('lease', '99999999 1\n')]:
            (stage / name).write_text(value)
            (stage / name).chmod(0o600)
        for name in ('activating', 'creating-alias', 'replacing-binary', 'replacing-launcher',
                     'replacing-state', 'replacing-unit', 'stopping'):
            (stage / name).touch(mode=0o600)
            (stage / name).chmod(0o600)
        binary_dir = self.base / 'bin'
        binary_dir.mkdir(mode=0o700)
        live = binary_dir / 'live'
        # The stand-in agent is one process running from bin/live and holding the
        # lifetime lock, as the real one: a copy of flock (its sleep child closes
        # the lock with -o and holds nothing of the install).
        shutil.copyfile(shutil.which('flock'), live)
        live.chmod(0o700)
        (binary_dir / 'current').symlink_to(live)
        self.launcher.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.launcher.unlink(missing_ok=True)
        self.launcher.symlink_to(binary_dir / 'current')
        alias = self.launcher.parent / 'infra'
        alias.unlink(missing_ok=True)
        alias.symlink_to('infraternal')
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
        (state / 'identity.json').write_text('{"endpoint":"127.0.0.1:7443"}\n')
        (state / 'identity.json').chmod(0o600)
        runtime = self.base / 'sessions'
        (runtime / 'sessions').mkdir(parents=True, mode=0o700)
        runtime.chmod(0o700)
        lifetime = runtime / '.lifetime-lock'
        lifetime.touch(mode=0o600)
        lifetime.chmod(0o600)
        # As on the VM: the setup's terminal probe left its readiness marker.
        readiness = runtime / 'sessions' / ('4' * 32 + '.readiness')
        readiness.touch(mode=0o600)
        readiness.chmod(0o600)
        self.manager_log.unlink(missing_ok=True)
        self.manager_active.touch()
        agent = subprocess.Popen([str(live), '-o', str(lifetime), 'sleep', '60'])
        self.children.append(agent)
        for _ in range(100):
            children = Path(f'/proc/{agent.pid}/task/{agent.pid}/children')
            pids = children.read_text().split() if children.exists() else []
            if pids:
                break
            time.sleep(0.05)
        self.assertTrue(pids, 'the stand-in agent did not start')
        self.agent_main = str(agent.pid)
        return stage, [str(agent.pid)] + pids

    def hidden_process(self, cwd):
        """A non-dumpable stand-in shim: exec'ing a file its owner cannot read
        leaves the process non-dumpable, so its exe and fds are hidden from its
        own user, as for every real infraternal shim (#305, J272)."""
        standin = Path.cwd() / self.temp / 'hidden-shim'
        if not standin.exists():
            shutil.copyfile('/usr/bin/sleep', standin)
            standin.chmod(0o111)
        child = subprocess.Popen([str(standin), '60'], cwd=cwd)
        self.children.append(child)
        # Until exec, the child is still a (dumpable) copy of this interpreter.
        for _ in range(250):
            if Path(f'/proc/{child.pid}/cmdline').read_bytes().startswith(str(standin).encode()):
                break
            time.sleep(0.02)
        with self.assertRaises(PermissionError, msg='precondition: the stand-in must hide its exe'):
            os.readlink(f'/proc/{child.pid}/exe')
        return child, standin

    def as_agent_unit(self, pids, spawn_on_stop=None):
        """Shell prefix: these processes are the agent unit's (its main process
        is the stand-in agent), and stopping the unit ends them, as systemd's
        cgroup and `stop` would. With `spawn_on_stop` (a hidden stand-in path),
        `stop` also starts that process in the unit, as a shim the agent
        started in that window, and lists it in the unit's cgroup.procs."""
        names = ' '.join(pids)
        cgroup = Path.cwd() / self.temp / 'cgroup'
        procs = cgroup / 'app.slice/infraternal-agent.service/cgroup.procs'
        procs.parent.mkdir(parents=True, exist_ok=True)
        procs.write_text('\n'.join(pids) + '\n')
        self.spawned_pid_file = Path.cwd() / self.temp / 'spawned.pid'
        spawn = ''
        marker = ''
        if spawn_on_stop:
            spawn = f'"{spawn_on_stop}" 60 </dev/null >/dev/null 2>&1 & printf "%s\\n" "$!" >| "{self.spawned_pid_file}"; printf "%s\\n" "$!" >| "{procs}"; '
            marker = f'case "$(tr "\\0" " " < "$1/cmdline" 2>/dev/null)" in "{spawn_on_stop} "*) return 0;; esac; '
        return f'''
agent_cgroup_root="{cgroup}"
agent_unit_process() {{ {marker}case " {names} " in *" ${{1##*/}} "*) return 0;; esac; return 1; }}
mock_manager() {{
 printf '%s\\n' "$*" >> "$manager_log"
 mock_wants="${{unit%/*}}/default.target.wants/infraternal-agent.service"
 case "$1" in
  is-enabled) [ -L "$mock_wants" ];;
  is-active) [ -e "$manager_active" ];;
  show) case "$3" in MainPID) printf '%s\\n' {self.agent_main};; ControlGroup) printf '/app.slice/infraternal-agent.service\\n';; esac;;
  disable) rm -f "$mock_wants";;
  stop) kill {names} 2>/dev/null || :; for p in {names}; do while [ -e /proc/$p/exe ] && [ "$(cut -d" " -f3 /proc/$p/stat 2>/dev/null)" != Z ]; do sleep 0.05; done; done; : >| "{procs}"; {spawn}rm -f "$manager_active";;
 esac
}}
'''

    def kill_spawned(self):
        if self.spawned_pid_file.exists():
            try:
                os.kill(int(self.spawned_pid_file.read_text()), 9)
            except ProcessLookupError:
                pass

    def test_an_interrupted_activation_whose_agent_is_its_only_holder_is_offered_and_cleaned(self):
        # #305 (J257): before, every add exited 73 ("Setup is already running") forever.
        stage, pids = self.make_activated_fresh_fixture()
        prefix = self.as_agent_unit(pids)
        inspected = self.run_shell(prefix + '\ninspect_previous')
        self.assertEqual(inspected.returncode, 0, inspected.stdout.decode() + inspected.stderr.decode())
        self.assertTrue(inspected.stdout.decode().startswith(f'INFRATERNAL_SETUP_STALE {HOST} {TRANSACTION} '), inspected.stdout)
        self.assertEqual(self.mutating_calls(), [], 'inspection must not stop anything')
        result = self.recover(prefix=prefix)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        self.assertFalse(self.base.exists(), 'leftovers remain')
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.launcher.is_symlink())
        self.assertFalse((self.launcher.parent / 'infra').is_symlink())
        self.assertEqual(self.service_state(), (False, False))
        self.assertIn('stop infraternal-agent.service', self.mutating_calls())

    def test_an_interrupted_activation_still_refuses_while_its_setup_holds_the_journal(self):
        import fcntl
        stage, pids = self.make_activated_fresh_fixture()
        held = os.open(stage, os.O_RDONLY)
        try:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_shell(self.as_agent_unit(pids) + '\ninspect_previous')
        finally:
            os.close(held)
        # A held journal is a running setup: reported as LOCKED ("setup running"),
        # never offered as leftovers, and nothing is changed.
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(result.stdout.decode().startswith('INFRATERNAL_SETUP_LOCKED '), result.stdout)
        self.assertTrue(stage.exists())
        self.assertEqual(self.mutating_calls(), [])

    def test_an_interrupted_activation_still_refuses_a_process_outside_its_unit(self):
        # A terminal shim (or anything else) running from or holding the install.
        stage, pids = self.make_activated_fresh_fixture()
        outside = Path.cwd() / self.temp / 'outside.lock'
        outside.touch()
        other = subprocess.Popen([str(self.base / 'bin/live'), '-o', str(outside), 'sleep', '60'])
        self.children.append(other)
        result = self.run_shell(self.as_agent_unit(pids) + '\ninspect_previous')
        self.assertEqual(result.returncode, 73, result.stdout.decode())
        self.assertTrue(stage.exists())
        self.assertEqual(self.mutating_calls(), [])

    def test_an_interrupted_activation_refuses_a_hidden_shim_in_its_unit_before_stopping_anything(self):
        # J272 (#305): a non-dumpable shim the agent started sits in the agent's
        # cgroup with no socket. Skipping the whole cgroup let Start fresh delete
        # the install it runs from; only the unit's main process may be skipped.
        stage, pids = self.make_activated_fresh_fixture()
        shim, _ = self.hidden_process(self.base / 'sessions')
        prefix = self.as_agent_unit(pids + [str(shim.pid)])
        inspected = self.run_shell(prefix + '\ninspect_previous')
        self.assertEqual(inspected.returncode, 73, inspected.stdout.decode())
        self.assertEqual(self.recover(prefix=prefix).returncode, 73)
        self.assertEqual(self.mutating_calls(), [], 'nothing may be stopped before the refusal')
        self.assertTrue((self.base / 'bin/live').exists())
        self.assertIsNone(shim.poll())

    def test_start_fresh_refuses_a_shim_that_appears_while_the_agent_stops(self):
        # J272 (#305): KillMode=process leaves anything else in the unit running.
        # A shim started after the checks before the stop must still refuse, and
        # the install it runs from stays.
        stage, pids = self.make_activated_fresh_fixture()
        _, standin = self.hidden_process(self.temp)
        self.children[-1].kill()
        prefix = self.as_agent_unit(pids, spawn_on_stop=standin)
        try:
            inspected = self.run_shell(prefix + '\ninspect_previous')
            self.assertEqual(inspected.returncode, 0, inspected.stderr.decode())
            result = self.recover(prefix=prefix)
            self.assertEqual(result.returncode, 73, result.stdout.decode() + result.stderr.decode())
            self.assertIn('stop infraternal-agent.service', self.mutating_calls())
            self.assertTrue((self.base / 'bin/live').exists(), 'the install was removed under a live shim')
            self.assertTrue(stage.exists())
        finally:
            self.kill_spawned()

    def test_a_hidden_process_unrelated_to_the_install_does_not_block_it(self):
        # Non-dumpable processes of the same account that are not this install's
        # (its SSH session process, key agents) cannot be read either; they are
        # neither in the unit nor started from the install, and never block.
        stage, pids = self.make_activated_fresh_fixture()
        self.hidden_process(self.temp)
        prefix = self.as_agent_unit(pids)
        result = self.recover(prefix=prefix)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        self.assertFalse(self.base.exists())

    def make_no_install(self):
        """An account with no infraternal install at all: no base, unit or
        launcher (D355: the add's own check proves it, as on `code` today)."""
        if self.listener:
            self.listener.close()
            self.listener = None
        self.receipt.unlink(missing_ok=True)
        shutil.rmtree(self.base, ignore_errors=True)
        self.unit.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.launcher.parent.mkdir(parents=True, mode=0o700, exist_ok=True)

    def test_check_proves_an_account_with_no_install(self):
        # D355 (widened): only this report lets the server drop stale entries
        # without a Start fresh.
        self.make_no_install()
        result = self.run_shell('\ninspect_previous')
        self.assertEqual((result.returncode, result.stdout), (0, b'INFRATERNAL_SETUP_ABSENT\n'), result.stderr)

    def test_any_trace_of_an_install_is_not_absence(self):
        # A unit or launcher left behind, or a base still present, is "clear",
        # never proof that nothing is installed.
        for leftover in ('unit', 'launcher', 'base'):
            with self.subTest(leftover=leftover):
                self.make_no_install()
                if leftover == 'unit':
                    self.unit.write_text('[Unit]\n')
                elif leftover == 'launcher':
                    self.launcher.symlink_to(self.base / 'bin/current')
                else:
                    self.base.mkdir(mode=0o700)
                    self.owner.write_text(HOST + '\n')
                    self.owner.chmod(0o600)
                result = self.run_shell('\ninspect_previous')
                self.assertNotEqual(result.stdout, b'INFRATERNAL_SETUP_ABSENT\n', leftover)
                self.unit.unlink(missing_ok=True)
                self.launcher.unlink(missing_ok=True)
                if self.base.exists():
                    shutil.rmtree(self.base)

    def test_absence_that_cannot_be_read_is_not_proven(self):
        # A path the account cannot search (permission denied) proves nothing.
        self.make_no_install()
        units = self.unit.parent
        units.chmod(0o000)
        try:
            result = self.run_shell('\ninspect_previous')
        finally:
            units.chmod(0o700)
        self.assertNotEqual(result.stdout, b'INFRATERNAL_SETUP_ABSENT\n')

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

    def test_upgrade_beside_a_current_shims_cleanup_endpoint_is_classified(self):
        # A current shim binds <id>.stop beside <id>.sock (infraternal-shim
        # cleanup.rs). It is the shim's, not an unknown file (71), and not a
        # second terminal.
        self.make_upgrade_fixture()
        previous = Path.cwd()
        listeners = []
        try:
            os.chdir(self.socket.parent)
            for name in (self.socket.name, '3' * 32 + '.stop'):
                listener = socket.socket(socket.AF_UNIX)
                listener.bind(name)
                os.chmod(name, 0o600)
                listener.listen()
                listeners.append(listener)
        finally:
            os.chdir(previous)
        try:
            result = self.run_shell('\ninspect_previous')
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            fields = result.stdout.decode().strip().split(' ')
            self.assertEqual((fields[0], fields[8]), ('INFRATERNAL_SETUP_UPGRADE', '1'), result.stdout)
        finally:
            for listener in listeners:
                listener.close()

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

    def restore_first_then_set_aside(self, action, restore):
        # J202 P2: the cancelled attempt's restore takes the guard before the
        # set-aside sshd keeps running; the set-aside must then never start.
        stage, _ = self.make_upgrade_fixture()
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        token = '7' * 32
        first = self.run_shell(f'\n{restore} {TRANSACTION} {token}\n')
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(first.stdout, b'untouched\n')
        late = self.run_shell(f'\n{action} "{expected}" {token}\n')
        self.assertEqual(late.returncode, 75, late.stderr.decode())
        self.assertEqual(self.mutating_calls(), [], 'nothing is stopped or disabled')
        self.assertEqual(self.service_state(), (True, True))
        self.assertTrue(stage.exists(), 'the install stays where it was')
        self.assertFalse(Path(f'{self.base}.bootstrap-cancel-{token}').exists(), 'the token is spent')
        # Another attempt, with its own token, is not held back.
        other = self.run_shell(f'\n{action} "{expected}" {"8" * 32}\n')
        self.assertEqual(other.returncode, 0, other.stderr.decode())

    def test_a_reenroll_whose_restore_ran_first_never_sets_the_install_aside(self):
        self.restore_first_then_set_aside('supersede_stuck_install', 'restore_superseded_install')

    def test_a_replace_whose_restore_ran_first_never_moves_the_journal(self):
        self.restore_first_then_set_aside('replace_stuck_install', 'restore_replaced_install')

    def test_a_commit_clears_cancel_tokens_whose_set_aside_never_came(self):
        self.make_upgrade_fixture()
        token = '7' * 32
        self.run_shell(f'\nrestore_replaced_install {TRANSACTION} {token}\n')
        marker = Path(f'{self.base}.bootstrap-cancel-{token}')
        self.assertTrue(marker.exists())
        commit = self.run_shell('\nretire_set_aside\n')
        self.assertEqual(commit.returncode, 0, commit.stderr.decode())
        self.assertFalse(marker.exists())

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
        # Nothing to offer: the new host's finished install is named (#394).
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed('5' * 32))
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

    def test_only_roots_up_base_may_be_0711(self):
        # #263: `infraternal up` makes root's /var/lib/infraternal 0711; a stuck
        # root install there must still be recognised. The oracle runs as a
        # normal user, so `id` stands in for root and up_root_base for the path.
        self.make_upgrade_fixture()
        # set -e would end the script on a refusal before it could report it.
        body = '\n{}if private_base_mode; then echo rc=0; else echo rc=1; fi\n'
        as_root = 'id() { echo 0; }\n'
        self.base.chmod(0o711)
        self.up_root_base = str(self.base)
        self.assertEqual(self.run_shell(body.format(as_root)).stdout, b'rc=0\n', 'root up base at 0711')
        self.assertEqual(self.run_shell(body.format('')).stdout, b'rc=1\n', 'a rootless base stays 0700')
        self.up_root_base = '/var/lib/infraternal'
        self.assertEqual(self.run_shell(body.format(as_root)).stdout, b'rc=1\n', 'only that path')
        self.base.chmod(0o755)
        self.up_root_base = str(self.base)
        self.assertEqual(self.run_shell(body.format(as_root)).stdout, b'rc=1\n', 'and only 0711')
        self.base.chmod(0o700)
        self.assertEqual(self.run_shell(body.format('')).stdout, b'rc=0\n')

    def test_a_finish_whose_agent_stopped_since_the_check_keeps_the_rollback_state(self):
        # J202 P2: the server saw the agent online and chose Finish; the agent
        # stops before the host command runs. Nothing may be deleted.
        stage, _ = self.make_upgrade_fixture()
        previous = stage / 'previous-binary'
        previous.write_bytes(b'old agent')
        previous.chmod(0o700)
        expected = self.run_shell('\ninspect_previous').stdout.decode().strip()
        self.assertTrue(expected.endswith(' live'), expected)
        self.manager_active.unlink()
        result = self.run_shell(f'\nfinish_stuck_upgrade "{expected}"\n')
        self.assertEqual(result.returncode, 75, result.stderr.decode())
        self.assertTrue(stage.exists(), 'the journal stays')
        self.assertEqual(previous.read_bytes(), b'old agent', 'the rollback copy stays')

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
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed())

    def test_a_replaced_journal_beside_an_active_agent_is_never_offered_or_put_back(self):
        # #305 P2-3: something newer is serving (a commit that predates
        # retire_set_aside, or a manual start). Check offers nothing and the
        # restore refuses rather than make a healthy host stuck again.
        stage, _ = self.make_upgrade_fixture()
        self.assertEqual(self.confirm('replace_stuck_install').returncode, 0)
        replaced = Path(f'{self.base}.bootstrap-replaced-{TRANSACTION}')
        self.manager_active.touch()
        restore = self.run_shell(f'\nrestore_replaced_install {TRANSACTION}\n')
        self.assertEqual(restore.returncode, 72, restore.stderr.decode())
        self.assertTrue(replaced.exists())
        self.assertFalse(stage.exists(), 'the stale journal is not planted into the live install')
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed())
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

    def make_committed_fixture(self):
        """#394's field shape: a finished install (no journal) whose
        `.bootstrap-owner` names a host id this attempt does not carry, such as
        an install an earlier server or an earlier attempt committed."""
        stage, _ = self.make_upgrade_fixture()
        shutil.rmtree(stage)

    def stage_as(self, host):
        """Run the upload step's staging prologue as a new attempt for `host`."""
        body = f'\nhost={host}\n' + CONSTANTS['STAGE_TRANSACTION']
        return self.run_shell(body)

    def test_a_finished_install_for_another_host_id_is_never_reported_clear(self):
        # #394: the check said CLEAR, then staging refused at the owner line
        # with exit 71 on every retry, and Start fresh was never offered.
        self.make_committed_fixture()
        check = self.run_shell('\nsetup_check=yes\ninspect_previous')
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual(check.stdout, self.installed())
        self.assertEqual(self.mutating_calls(), [], 'the check changes nothing')

    def test_staging_refuses_a_finished_install_for_another_host_id(self):
        # The refusal itself stays: staging never adopts another host's install.
        self.make_committed_fixture()
        self.assertEqual(self.stage_as('6' * 32).returncode, 71)
        self.assertEqual((self.base / '.bootstrap-owner').read_text(), HOST + '\n')


    # ── D359: Take over a finished install another server enrolled ──────────

    def make_takeover_fixture(self):
        """#394's owner shape on root's own base (D359): a finished install,
        enabled and running, whose owner names a host this server does not
        know. The oracle runs unprivileged, so the fixture's base stands in for
        root's /var/lib/infraternal. Returns the record Check reports."""
        self.make_committed_fixture()
        self.up_root_base = str(self.base)
        self.manager_log.unlink(missing_ok=True)
        return self.run_shell('\nsetup_check=yes\ninspect_previous').stdout.decode().strip()

    def install_snapshot(self, root):
        """Every entry under `root`, with its mode and its content or target."""
        import stat as kinds
        entries = {}
        for directory, names, files in os.walk(root):
            for path in [Path(directory)] + [Path(directory) / name for name in files]:
                info = path.lstat()
                if path.is_symlink():
                    what = ('link', os.readlink(path))
                elif kinds.S_ISDIR(info.st_mode):
                    what = ('dir',)
                elif kinds.S_ISSOCK(info.st_mode):
                    what = ('socket',)
                else:
                    what = ('file', path.read_bytes())
                entries[str(path.relative_to(root))] = (oct(info.st_mode), *what)
            for name in names:
                path = Path(directory) / name
                if path.is_symlink():
                    entries[str(path.relative_to(root))] = (oct(path.lstat().st_mode), 'link', os.readlink(path))
        return entries

    def found_install(self):
        """The old install as Take over must leave it or put it back: its
        files, the same directory (moved, never copied), its unit, its
        launcher and its service state."""
        return (
            self.install_snapshot(self.base),
            self.base.stat().st_ino,
            self.unit.read_text(),
            oct(self.unit.stat().st_mode),
            os.readlink(self.launcher),
            self.service_state(),
        )

    def takeover_aside(self, token=TAKEOVER):
        return Path(f'{self.base}.bootstrap-takeover-{token}')

    def take_over(self, expected, token=TAKEOVER, prefix=''):
        return self.run_shell(f'{prefix}\ntake_over_finished_install "{expected}" {token}\n')

    def killing(self, at, writes=False):
        """Shell lines that SIGKILL the script right after its `at`-th change:
        every directory, move, copy, delete, link and service-manager call,
        and with `writes` every printf too (each file the script writes).
        SIGKILL runs no trap, as with a power loss."""
        printf = 'printf() { command printf "$@"; kill_step; }' if writes else ''
        return f'''
kill_steps=0
kill_step() {{ kill_steps=$((kill_steps + 1)); [ "$kill_steps" != {at} ] || kill -KILL $$; }}
{printf}
mkdir() {{ command mkdir "$@"; kill_step; }}
mv() {{ command mv "$@"; kill_step; }}
cp() {{ command cp "$@"; kill_step; }}
rm() {{ command rm "$@"; kill_step; }}
ln() {{ command ln "$@"; kill_step; }}
kill_manager() {{ mock_manager "$@"; case "$1" in is-active|is-enabled|show) ;; *) kill_step;; esac; }}
manager=kill_manager
'''

    def test_check_offers_take_over_for_roots_own_proven_install(self):
        record = self.make_takeover_fixture()
        self.assertEqual((record + '\n').encode(), self.installed(takeover='ready'))
        self.assertEqual(self.mutating_calls(), [], 'the check changes nothing')
        self.manager_active.unlink()
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed(takeover='ready'))

    def test_a_rootless_install_is_never_taken_over(self):
        # D359: rootless adds still refuse. Even a forged "ready" record
        # changes nothing outside root's own base.
        self.make_committed_fixture()
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed())
        result = self.take_over(self.installed(takeover='ready').decode().strip())
        self.assertEqual(result.returncode, 71, result.stderr.decode())
        self.assertTrue((self.base / 'state/identity.json').exists())
        self.assertTrue(self.unit.exists())
        self.assertEqual(self.mutating_calls(), [])
        self.assertFalse(self.takeover_aside().exists())

    def test_anything_not_proven_infraternals_is_never_offered(self):
        def foreign_header():
            self.unit.write_text(self.unit.read_text().replace(f'# infraternal bootstrap {HOST}', '# someone else'))
        def extra_file():
            extra = self.base / 'notes.txt'
            extra.write_text('mine\n')
            extra.chmod(0o600)
        def launcher_elsewhere():
            self.launcher.unlink()
            self.launcher.symlink_to('/bin/true')
        def changed_command():
            self.unit.write_text(self.unit.read_text().replace(' run\n', ' run --other\n'))
        for change in (foreign_header, extra_file, launcher_elsewhere, changed_command):
            with self.subTest(change=change.__name__):
                record = self.make_takeover_fixture()
                change()
                self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed(takeover='unproven'))
                result = self.take_over(record)
                self.assertEqual(result.returncode, 75, result.stderr.decode())
                self.assertEqual(self.mutating_calls(), [], 'nothing is stopped')
                self.assertTrue(self.base.exists())

    def hold_a_file(self):
        """Start a process outside the agent's unit that keeps a file of the install open."""
        holder = subprocess.Popen(['/bin/sh', '-c', f'exec 3< "{self.identity_path}"; exec sleep 30'])
        self.children.append(holder)
        for _ in range(500):
            if Path(f'/proc/{holder.pid}/fd/3').exists():
                break
            time.sleep(0.01)
        return holder

    def test_a_real_finished_root_install_is_ready(self):
        # J315, real root on compute01: a finished install's bin/live is the
        # payload cache's own inode (setup reuses the verified payload), and
        # the root agent keeps its mesh state in sessions/. Both are ours.
        self.make_takeover_fixture()
        live = self.base / 'bin/live'
        cache = Path(f'{self.base}.bootstrap-cache/payload')
        live.unlink()
        os.link(cache, live)
        for name in ('mesh-public.json', 'mesh-routes.json', 'mesh-interface.json', 'mesh-key-rotation.bin', 'mesh-engine.json', 'mesh-private-key'):
            state = self.base / 'sessions' / name
            state.write_text('{}\n')
            state.chmod(0o600)
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed(takeover='ready'))
        def other_link():
            live.unlink()
            shutil.copyfile(cache, live)
            live.chmod(0o700)
            os.link(live, Path(self.temp).resolve() / 'elsewhere')
        def stray_state():
            stray = self.base / 'sessions/mesh-private-key.4242.new'
            stray.write_text('x')
            stray.chmod(0o600)
        for change in (other_link, stray_state):
            with self.subTest(change=change.__name__):
                change()
                self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed(takeover='unproven'))
                self.make_takeover_fixture()
                live.unlink()
                os.link(cache, live)

    def test_a_container_running_its_own_install_does_not_make_it_busy(self):
        # J315, real root on compute01: a container's own infraternal names
        # the same path, in its own mount namespace. Not a holder of this
        # install; a process holding this install's file still is.
        self.make_takeover_fixture()
        ready = subprocess.run(['unshare', '-Urm', 'true'], capture_output=True)
        if ready.returncode != 0:
            self.skipTest('no unprivileged mount namespaces here')
        marker = Path(self.temp).resolve() / 'container-ready'
        container = subprocess.Popen(['unshare', '-Urm', 'sh', '-c',
            f'mount -t tmpfs none "{self.base}" && mkdir -p "{self.base}/state" && : > "{self.identity_path}" '
            f'&& exec 3< "{self.identity_path}" && : > "{marker}" && exec sleep 30'])
        self.children.append(container)
        for _ in range(500):
            if marker.exists():
                break
            time.sleep(0.01)
        self.assertTrue(marker.exists())
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed(takeover='ready'))
        self.hold_a_file()
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed(takeover='busy'))

    def test_an_install_another_process_uses_is_busy_and_never_stopped(self):
        record = self.make_takeover_fixture()
        self.hold_a_file()
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed(takeover='busy'))
        result = self.take_over(record)
        self.assertEqual(result.returncode, 73, result.stderr.decode())
        self.assertEqual(self.mutating_calls(), [], 'nothing is stopped')
        self.assertTrue((self.base / 'state/identity.json').exists())
        self.assertFalse(self.takeover_aside().exists())

    def test_take_over_sets_the_install_aside_whole_where_only_root_can_reach_it(self):
        record = self.make_takeover_fixture()
        found = self.found_install()
        result = self.take_over(record)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        aside = self.takeover_aside()
        self.assertFalse(self.base.exists(), 'the setup directory is free for the new install')
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.launcher.is_symlink())
        self.assertEqual(aside.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.install_snapshot(aside / 'install'), found[0], 'nothing is deleted')
        self.assertEqual((aside / 'install').stat().st_ino, found[1], 'moved, never copied')
        self.assertEqual((aside / 'owner').read_text(), HOST + '\n', 'it names the old install')
        self.assertEqual((aside / 'service').read_text(), 'yes yes\n')
        self.assertEqual((aside / 'unit').read_text(), found[2])
        self.assertEqual(self.mutating_calls(), [
            'stop infraternal-agent.service',
            'disable infraternal-agent.service',
            'daemon-reload',
        ])
        self.assertEqual(self.service_state(), (False, False))
        self.assertFalse(Path(f'{self.base}.bootstrap-taking-{TAKEOVER}').exists())

    def test_a_failed_new_install_gets_the_old_one_back_exactly(self):
        record = self.make_takeover_fixture()
        found = self.found_install()
        self.assertEqual(self.take_over(record).returncode, 0)
        restore = self.run_shell(f'\nrestore_taken_over_install {TAKEOVER}\n')
        self.assertEqual(restore.returncode, 0, restore.stderr.decode())
        self.assertEqual(restore.stdout, b'restored\n')
        self.assertEqual(self.found_install(), found)
        self.assertFalse(self.takeover_aside().exists())

    def test_a_stopped_disabled_install_is_put_back_stopped_and_disabled(self):
        self.make_takeover_fixture()
        self.manager_active.unlink()
        (self.unit.parent / 'default.target.wants/infraternal-agent.service').unlink()
        record = self.run_shell('\nsetup_check=yes\ninspect_previous').stdout.decode().strip()
        found = self.found_install()
        self.assertEqual(self.take_over(record).returncode, 0)
        self.assertEqual((self.takeover_aside() / 'service').read_text(), 'no no\n')
        self.assertEqual(self.run_shell(f'\nrestore_taken_over_install {TAKEOVER}\n').returncode, 0)
        self.assertEqual(self.found_install(), found)

    def test_check_offers_put_back_for_an_install_taken_over_and_never_restored(self):
        record = self.make_takeover_fixture()
        self.assertEqual(self.take_over(record).returncode, 0)
        result = self.run_shell('\nsetup_check=yes\ninspect_previous')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            result.stdout.decode(),
            f'INFRATERNAL_SETUP_SET_ASIDE taken_over {HOST} {TAKEOVER} {socket.gethostname()} yes yes\n',
        )

    def test_a_commit_deletes_the_install_taken_over(self):
        # D359: deleted only after the new install has committed.
        record = self.make_takeover_fixture()
        self.assertEqual(self.take_over(record).returncode, 0)
        self.new_host_in_place()
        commit = self.run_shell('\nretire_set_aside\n')
        self.assertEqual(commit.returncode, 0, commit.stderr.decode())
        self.assertFalse(self.takeover_aside().exists())

    def test_check_deletes_a_taken_over_install_a_crash_left_beside_the_new_host(self):
        record = self.make_takeover_fixture()
        self.assertEqual(self.take_over(record).returncode, 0)
        self.new_host_in_place()
        self.assertEqual(self.run_shell('\nsetup_check=yes\ninspect_previous').stdout, self.installed('5' * 32))
        self.assertFalse(self.takeover_aside().exists(), 'the new install committed; no copy is kept')

    def test_restore_refuses_while_the_new_install_is_in_place(self):
        record = self.make_takeover_fixture()
        self.assertEqual(self.take_over(record).returncode, 0)
        self.base.mkdir(mode=0o700)
        restore = self.run_shell(f'\nrestore_taken_over_install {TAKEOVER}\n')
        self.assertEqual(restore.returncode, 72, restore.stderr.decode())
        self.assertTrue((self.takeover_aside() / 'install/state/identity.json').exists())

    def test_an_install_that_changed_since_the_confirmation_is_refused(self):
        self.make_takeover_fixture()
        self.manager_active.unlink()
        idle = self.run_shell('\nsetup_check=yes\ninspect_previous').stdout.decode().strip()
        host, identity = idle.split(' ')[1:3]
        for name, record, prepare in (
            ('started since', idle, self.manager_active.touch),
            ('another root', idle.replace(identity, '1:1'), lambda: None),
            ('another owner', idle.replace(host, '6' * 32), lambda: None),
        ):
            with self.subTest(name=name):
                self.manager_active.unlink(missing_ok=True)
                prepare()
                self.manager_log.unlink(missing_ok=True)
                result = self.take_over(record)
                self.assertEqual(result.returncode, 75, result.stderr.decode())
                self.assertEqual(self.mutating_calls(), [])
                self.assertTrue(self.base.exists())

    def test_a_restore_that_runs_first_keeps_the_take_over_from_starting(self):
        # A cancelled attempt's restore and its take over are exclusive,
        # whichever reaches the host first (#305, J202 P2).
        record = self.make_takeover_fixture()
        restore = self.run_shell(f'\nrestore_taken_over_install {TAKEOVER}\n')
        self.assertEqual(restore.stdout, b'untouched\n', restore.stderr.decode())
        result = self.take_over(record)
        self.assertEqual(result.returncode, 75, result.stderr.decode())
        self.assertEqual(self.mutating_calls(), [])
        self.assertTrue(self.base.exists())

    def test_a_holder_that_appears_during_the_stop_is_refused_and_put_back(self):
        record = self.make_takeover_fixture()
        found = self.found_install()
        pid_file = Path(self.temp).resolve() / 'holder.pid'
        result = self.take_over(record, prefix=f'''
holding_manager() {{
 mock_manager "$@"
 if [ "$1" = stop ]; then
  (exec 3< "{self.identity_path}"; exec sleep 30) >/dev/null 2>&1 &
  printf '%s\\n' "$!" > "{pid_file}"
  sleep 0.2
 fi
}}
manager=holding_manager''')
        try:
            self.assertEqual(result.returncode, 73, result.stderr.decode())
            self.assertEqual(self.found_install(), found, 'put back, enabled and running, as found')
            self.assertFalse(self.takeover_aside().exists())
        finally:
            os.kill(int(pid_file.read_text()), 15)

    def test_a_termination_after_the_stop_still_puts_it_back(self):
        record = self.make_takeover_fixture()
        found = self.found_install()
        result = self.take_over(record, prefix='''
terminating_manager() {
 mock_manager "$@"
 [ "$1" != disable ] || kill -TERM $$
}
manager=terminating_manager''')
        self.assertEqual(result.returncode, 143, result.stderr.decode())
        self.assertEqual(self.found_install(), found)
        self.assertFalse(self.takeover_aside().exists())

    def test_a_take_over_killed_at_any_step_keeps_the_old_install_and_puts_it_back(self):
        # D359: a crash at any step leaves the old install or the new one,
        # never neither. Kill after each change in turn: the old install is
        # whole in exactly one place, Check names it, and the restore puts
        # it back exactly as it was found.
        step = 0
        while True:
            step += 1
            token = f'{step:032x}'
            record = self.make_takeover_fixture()
            found = self.found_install()
            result = self.take_over(record, token=token, prefix=self.killing(step))
            if result.returncode == 0:
                break
            self.assertEqual(result.returncode, -9, (step, result.stderr.decode()))
            aside = self.takeover_aside(token)
            in_place = self.base.exists() and self.install_snapshot(self.base) == found[0]
            moved = (aside / 'install').exists() and self.install_snapshot(aside / 'install') == found[0]
            self.assertTrue(in_place != moved, f'step {step}: the old install is whole in exactly one place')
            check = self.run_shell('\nsetup_check=yes\ninspect_previous')
            self.assertEqual(check.returncode, 0, (step, check.stderr.decode()))
            self.assertRegex(check.stdout, rb'^INFRATERNAL_SETUP_(INSTALLED|SET_ASIDE taken_over) ', step)
            restore = self.run_shell(f'\nrestore_taken_over_install {token}\n')
            self.assertEqual(restore.returncode, 0, (step, restore.stderr.decode()))
            self.assertIn(restore.stdout, (b'restored\n', b'untouched\n'), step)
            self.assertEqual(self.found_install(), found, f'step {step}: put back exactly')
            self.assertFalse(aside.exists(), step)
            self.assertFalse(Path(f'{self.base}.bootstrap-taking-{token}').exists(), step)
        self.assertGreater(step, 8, 'every change of the take over was interrupted once')

    def stage_new_attempt(self, prefix=''):
        """The upload step's staging as the fresh install that follows a Take
        over: a new host id and a new transaction (STAGE_TRANSACTION)."""
        return self.run_shell(f'{prefix}\nhost={NEW_HOST}\ntransaction={NEW_TRANSACTION}\n' + CONSTANTS['STAGE_TRANSACTION'])

    def roll_back_new_attempt(self):
        """The server's rollback of that attempt (Installation::rollback)."""
        return self.run_shell(f'\nhost={NEW_HOST}\ntransaction={NEW_TRANSACTION}\n' + CONSTANTS['FRESH_CLEANUP'] + '\npreserve_session=no\n' + CONSTANTS['ROLLBACK_TRANSACTION'])

    def test_staging_cut_at_any_step_after_a_take_over_never_loses_the_old_install(self):
        # J342 P1-1, reproduced as real root: staging cut right after it wrote
        # the new owner record left a base with nothing else in it; the next
        # Check read that as a finished install and deleted the set-aside, so
        # neither install was left. Cut the staging after every change and
        # every write: Check never deletes the old install, and the server's
        # rollback then restore put it back exactly.
        step = 0
        while True:
            step += 1
            record = self.make_takeover_fixture()
            found = self.found_install()
            self.assertEqual(self.take_over(record).returncode, 0)
            aside = self.takeover_aside()
            result = self.stage_new_attempt(self.killing(step, writes=True))
            finished = result.returncode == 0
            if not finished:
                self.assertEqual(result.returncode, -9, (step, result.stderr.decode()))
            check = self.run_shell('\nsetup_check=yes\ninspect_previous')
            self.assertTrue((aside / 'install').is_dir(), f'step {step}: Check {check.stdout!r} deleted the old install')
            rollback = self.roll_back_new_attempt()
            self.assertEqual(rollback.returncode, 0, (step, rollback.stderr.decode()))
            restore = self.run_shell(f'\nrestore_taken_over_install {TAKEOVER}\n')
            self.assertEqual(restore.returncode, 0, (step, restore.stderr.decode()))
            self.assertEqual(restore.stdout, b'restored\n', step)
            self.assertEqual(self.found_install(), found, f'step {step}: put back exactly')
            self.assertFalse(Path(f'{self.base}.bootstrap-new-{NEW_TRANSACTION}').exists(), step)
            self.assertFalse(Path(f'{self.base}.bootstrap-rollback-{NEW_TRANSACTION}').exists(), step)
            if finished:
                break
        self.assertGreater(step, 4, 'every change and write of the staging was cut once')

    def test_a_restore_killed_at_any_step_finishes_when_run_again(self):
        step = 0
        while True:
            step += 1
            token = f'{step:032x}'
            record = self.make_takeover_fixture()
            found = self.found_install()
            self.assertEqual(self.take_over(record, token=token).returncode, 0)
            result = self.run_shell(self.killing(step) + f'\nrestore_taken_over_install {token}\n')
            if result.returncode == 0:
                break
            self.assertEqual(result.returncode, -9, (step, result.stderr.decode()))
            again = self.run_shell(f'\nrestore_taken_over_install {token}\n')
            self.assertEqual(again.returncode, 0, (step, again.stderr.decode()))
            self.assertEqual(self.found_install(), found, f'step {step}: put back exactly')
            self.assertFalse(self.takeover_aside(token).exists(), step)
        self.assertGreater(step, 4)

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
