#!/usr/bin/env python3
"""Fixture tests for the privileged integration row (D351, #344).

They check what decides *what* runs (areas from a diff, which ignored tests
count, which build provides each binary) and, where the host allows
unprivileged user namespaces, that the sandbox really contains planted escapes
while the same probes succeed outside it.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid


def load(name):
    """Import an extension-less script from this directory as a module."""
    loader = importlib.machinery.SourceFileLoader(name.replace('-', '_'), str(Path(__file__).with_name(name)))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


p = load('verify-privileged')


def userns_available():
    """True when this host lets an unprivileged user create the sandbox's namespaces."""
    probe = subprocess.run(['unshare', '--user', '--map-root-user', '--net', '--mount', '--pid', '--fork', 'true'],
                           capture_output=True)
    return probe.returncode == 0


class PrivilegedAreas(unittest.TestCase):
    """Trigger the namespace tests only for relevant code paths."""

    def test_scopes(self):
        """Cover production files, fixtures, shared manifests and harmless docs."""
        for path, expected in (
            ('crates/infraternal/src/install.rs', {'install'}),
            ('crates/plugins/ssh/src/install/setup_scripts.rs', {'install'}),
            ('crates/plugins/remote/src/uninstall.rs', {'install'}),
            ('crates/plugins/proxy/src/cgroup.rs', {'proxy'}),
            ('crates/plugins/mesh/tests/kernel.rs', {'mesh'}),
            ('crates/infraternal-mesh/src/lib.rs', {'mesh'}),
            ('crates/infraternal-server/src/mesh_api_tests/identity.rs', {'mesh'}),
            ('crates/infraternal/src/main.rs', {'install'}),
            ('crates/infraternal-shim/src/pty.rs', {'shim'}),
            ('docs/ENGINEERING.md', set()),
            ('apps/tracer/src/main.ts', set()),
            ('Cargo.toml', {'install', 'proxy', 'mesh', 'shim'}),
            ('scripts/verify-privileged', {'install', 'proxy', 'mesh', 'shim'}),
        ):
            self.assertEqual(p.areas([path]), expected, path)

    def test_gaps_are_named(self):
        """Real-root behaviour the row cannot reach is stated, not silently skipped."""
        self.assertTrue(all(p.NOT_COVERED.get(area) for area in ('proxy', 'install', 'shim')))


class IgnoredSelection(unittest.TestCase):
    """Pick ignored tests by their written reason, not by a hand-kept list."""

    def test_reasons(self):
        """Namespace and root reasons run; perf, Docker and fixture-server reasons do not."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'pkg/src').mkdir(parents=True)
            (root / 'pkg/tests/split').mkdir(parents=True)
            (root / 'pkg/src/lib.rs').write_text(
                '#[test]\n#[ignore = "Run as root in a disposable network namespace."]\nfn in_lib() {}\n')
            (root / 'pkg/tests/kernel.rs').write_text(
                '#[test]\n#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]\nfn alone() {}\n'
                '#[tokio::test]\n#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]\n'
                '#[allow(dead_code)]\nasync fn with_attr() {}\n'
                '#[test]\n#[ignore = "Run only on the perf VM, in a disposable network namespace"]\nfn perf() {}\n'
                '#[test]\n#[ignore = "requires sudo -n Docker and the local debian:trixie-slim image"]\nfn docker() {}\n'
                '#[test]\n#[ignore = "timing measurement runs on the perf VM"]\nfn timing() {}\n')
            (root / 'pkg/tests/split/part.rs').write_text(
                '#[test]\n#[ignore = "requires an isolated user/network namespace"]\nfn nested() {}\n')
            found = p.privileged_ignored(root, 'pkg', 'pkg')
            self.assertEqual({target: set(names) for target, names in found.items()},
                             {'lib': {'in_lib'}, 'test:kernel': {'alone', 'with_attr'}, 'test:split': {'nested'}})

    def test_binary_only_package(self):
        """Unit tests of a package without src/lib.rs live in its binary target."""
        self.assertEqual(p.target_of('src/install.rs', 'bin:infraternal'), 'bin:infraternal')
        self.assertIsNone(p.target_of('fuzz/fuzz_targets/x.rs', 'lib'))

    def test_real_tree_finds_mesh_namespace_tests(self):
        """The real mesh package yields its kernel and namespace tests, so the scan is not dead."""
        root = Path(__file__).resolve().parents[1]
        found = p.privileged_ignored(root, 'infraternal-plugin-mesh', 'crates/plugins/mesh')
        for target in ('test:kernel', 'test:proxy_ingress_namespace', 'test:review_retire_ownership'):
            self.assertIn(target, found)

    def test_dns_spike_only_for_dns(self):
        """The default-off resolver feature applies to the DNS target alone."""
        shared = dict((name, f) for name, _, f in p.PACKAGES['mesh'])['infraternal-plugin-mesh']
        self.assertNotIn('mesh-dns-spike', shared)
        self.assertIn('mesh-dns-spike', p.TARGET_FEATURES[('infraternal-plugin-mesh', 'test:dns')])


class Builds(unittest.TestCase):
    """Binaries come from the workspace build unless a package or target needs its own features."""

    def test_build_order(self):
        """Workspace first, then explicit package builds, then single-target builds."""
        result = p.builds({'install', 'proxy', 'mesh', 'shim'})
        self.assertEqual(result[0], (['--workspace'], None))
        provided = [provides for _, provides in result]
        self.assertIn('infraternal-plugin-mesh', provided)
        self.assertEqual(provided[-1], ('infraternal-plugin-mesh', 'test:dns'))
        self.assertNotIn('infraternal-plugin-remote', provided)

    def test_executable_mapping(self):
        """Later builds replace only what they provide; non-test artifacts are ignored."""
        root = Path('/clone')

        def artifact(directory, kind, name, exe, test=True):
            """One cargo compiler-artifact message."""
            manifest = f'{directory}/Cargo.toml' if directory.startswith('/') else f'/clone/{directory}/Cargo.toml'
            return json.dumps({'reason': 'compiler-artifact', 'manifest_path': manifest,
                               'target': {'kind': [kind], 'name': name}, 'profile': {'test': test},
                               'executable': exe})

        outputs = iter([
            '\n'.join([artifact('crates/plugins/mesh', 'test', 'kernel', '/w/kernel'),
                       artifact('crates/plugins/mesh', 'test', 'dns', '/w/dns-without-feature'),
                       artifact('crates/plugins/proxy', 'lib', 'proxy', '/w/proxy'),
                       artifact('crates/plugins/mesh', 'example', 'kernel_node', '/w/example', test=False),
                       artifact('/elsewhere', 'lib', 'x', '/w/outside')]),
            '\n'.join([artifact('crates/plugins/mesh', 'test', 'kernel', '/m/kernel'),
                       artifact('crates/plugins/proxy', 'lib', 'proxy', '/m/not-mesh')]),
            artifact('crates/plugins/mesh', 'test', 'dns', '/d/dns'),
        ])
        calls = []

        def fake_run(command, **_kwargs):
            """Answer test builds from `outputs`; record the example uplift builds."""
            calls.append(command)
            stdout = next(outputs) if command[1] == 'test' else ''
            return subprocess.CompletedProcess(command, 0, stdout, '')

        with mock.patch.object(p.subprocess, 'run', side_effect=fake_run):
            found = p.executables(root, {'mesh', 'proxy'})
        # The explicit mesh build is followed by `cargo build --examples`.
        uplift = [c for c in calls if c[1] == 'build']
        self.assertEqual(len(uplift), 1)
        self.assertIn('--examples', uplift[0])
        self.assertNotIn('--tests', uplift[0])
        self.assertEqual(found, {('crates/plugins/mesh', 'test:kernel'): '/m/kernel',
                                 ('crates/plugins/mesh', 'test:dns'): '/d/dns',
                                 ('crates/plugins/proxy', 'lib'): '/w/proxy'})


class SandboxShape(unittest.TestCase):
    """The command line asks for every namespace and never for privilege."""

    def command(self):
        """One sandbox argv and its setup script."""
        command = p.sandboxed(['/t/debug/deps/x', '--exact', 'y'], {'A': '1', 'BAD\nKEY': 'x', 'M': 'two\nlines'},
                              Path('/c'), Path('/s'), Path('/t'))
        return command, command[command.index('-c') + 1]

    def test_outer_namespace(self):
        """User, net, mount and PID namespaces; --kill-child; no sudo; explicit environment."""
        command, _ = self.command()
        self.assertEqual(command[:9], ['unshare', '--user', '--map-root-user', '--net', '--mount', '--pid',
                                       '--fork', '--kill-child', '--mount-proc'])
        self.assertNotIn('sudo', command)
        self.assertEqual(command[command.index('env') + 1], '-i')
        self.assertIn('A=1', command)
        self.assertIn('CARGO_TARGET_DIR=/tmp/ut', command)
        self.assertNotIn('M=two\nlines', command)
        self.assertEqual(command[-3:], ['/t/debug/deps/x', '--exact', 'y'])

    def test_test_runs_one_namespace_down(self):
        """The test runs in a nested user namespace, after pivot_root, with --kill-child (79752 P1)."""
        _, setup = self.command()
        for step in ('ro=recursive', 'pivot_root . .', 'umount -l .'):
            self.assertIn(step, setup)
        inner = setup.index('exec unshare --user --map-root-user --net --mount --pid --fork --kill-child')
        self.assertGreater(inner, setup.index('pivot_root . .'))
        self.assertNotIn('single', setup)

    def test_tmpfs_sizes(self):
        """Every tmpfs the sandbox mounts carries a size cap (79752 P3-2)."""
        _, setup = self.command()
        tmpfs = [line for line in setup.splitlines() if 'mount -t tmpfs' in line]
        self.assertGreaterEqual(len(tmpfs), 6)
        for line in tmpfs:
            self.assertRegex(line, r'size=\d+[kmg]')

    def test_minimal_dev(self):
        """/dev is a fresh tmpfs with a private devpts, mounted before /dev/shm, and the nix socket is covered."""
        _, setup = self.command()
        dev = setup.index('tmpfs "$new/dev"\n')
        self.assertLess(dev, setup.index('"$new/dev/shm"\n'))
        self.assertIn('-o newinstance', setup)
        self.assertNotIn('--rbind /dev', setup)
        self.assertIn('"$new/nix/var/nix/daemon-socket"', setup)


class Lifecycle(unittest.TestCase):
    """Decisions around a sandbox run that need no namespaces to check."""

    def test_memory_scope_when_user_manager_answers(self):
        """With a working user manager each sandbox gets its own MemoryMax scope."""
        with mock.patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            scope = p.memory_scope()
        self.assertEqual(scope[:3], ['systemd-run', '--user', '--scope'])
        self.assertIn(f'MemoryMax={p.SANDBOX_MEMORY_MAX}', scope)
        self.assertIn('MemorySwapMax=0', scope)

    def test_memory_scope_absent_without_user_manager(self):
        """Without one the prefix is empty, so the tmpfs caps are the only bound."""
        with mock.patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
            self.assertEqual(p.memory_scope(), [])

    def test_list_runs_inside_the_sandbox(self):
        """Test discovery executes the branch's binary, so it goes through run_sandboxed (79752 P2-3)."""
        calls = []

        def fake(command, *_args, **_kwargs):
            """Record the command and answer like a libtest listing."""
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, 'kernel::up: test\nother: test\n', '')

        binaries = {('crates/plugins/mesh', 'test:kernel'): '/b/kernel'}
        with mock.patch.object(p, 'run_sandboxed', side_effect=fake), \
                mock.patch.object(p, 'privileged_ignored', return_value={'test:kernel': {'up': 'namespace'}}), \
                mock.patch.object(p.subprocess, 'run', side_effect=AssertionError('unsandboxed run')):
            runs, missing = p.plan(Path('/clone'), {'mesh'}, binaries, {}, Path('/s'), Path('/t'), [])
        self.assertEqual(missing, [])
        self.assertIn('--list', calls[0])
        self.assertEqual([run[0] for run in runs], ['infraternal-plugin-mesh test:kernel kernel::up'])

    def test_fails_closed_when_the_sandbox_cannot_start(self):
        """A sandbox that exits early or prints nothing counts as an escape, never as contained."""
        broken = subprocess.CompletedProcess([], 1, '', 'unshare: unshare failed: Operation not permitted')
        with mock.patch.object(p, 'run_sandboxed', return_value=broken):
            escaped = p.self_check(Path('/nonexistent-scratch'), Path('/t'), Path('/c'), [])
        self.assertTrue(any('did not start cleanly' in line for line in escaped))

    def test_partial_probe_output_fails_closed(self):
        """Exit 0 with missing probe lines still fails: every probe must report contained."""
        partial = subprocess.CompletedProcess([], 0, 'contained: write /etc\n', '')
        with mock.patch.object(p, 'run_sandboxed', return_value=partial):
            escaped = p.self_check(Path('/nonexistent-scratch'), Path('/t'), Path('/c'), [])
        self.assertTrue(escaped)


def survivors(marker):
    """PIDs of this user's processes whose environment holds VP_MARKER=`marker` exactly.

    Marking by environment, not argv[0], keeps multicall binaries (nix
    coreutils picks its tool from argv[0]) working inside the sandbox.
    """
    wanted = f'VP_MARKER={marker}'.encode()
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid == os.getuid() and wanted in (entry / 'environ').read_bytes().split(b'\0'):
                found.append(int(entry.name))
        except OSError:
            continue
    return found


def reap(pids):
    """Kill leftover test processes by PID only."""
    for pid in pids:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass


@unittest.skipUnless(userns_available(), 'unprivileged user namespaces unavailable on this host')
class RealSandbox(unittest.TestCase):
    """Run the real sandbox: escapes are contained, hangs are killed, nothing outlives the runner."""

    def setUp(self):
        """A throwaway home, checkout, target and scratch under ~/.cache."""
        if not shutil.which('ip'):
            self.skipTest('iproute2 is not on PATH (run inside the dev shell)')
        self.home = Path(tempfile.mkdtemp(prefix='vp-home-', dir=Path.home() / '.cache'))
        self.checkout, self.target = self.home / 'checkout', self.home / 'target'
        (self.target / 'debug').mkdir(parents=True)
        self.checkout.mkdir()
        self.scratch = self.home / 'scratch'
        (self.scratch / 'root').mkdir(parents=True)

    def tearDown(self):
        """Remove the throwaway tree."""
        shutil.rmtree(self.home, ignore_errors=True)

    def test_planted_escapes(self):
        """Every escape probe is contained, and the persistence marker never appears outside."""
        with mock.patch.object(p.Path, 'home', return_value=self.home):
            escaped = p.self_check(self.scratch, self.target, self.checkout, [])
        self.assertEqual(escaped, [])
        # The same writes succeed outside, so "contained" is not a broken write.
        for directory in (self.home, self.checkout, self.target):
            probe = directory / '.privileged-escape'
            probe.touch()
            self.assertTrue(probe.exists())
        self.assertEqual(sorted(path.name for path in (self.scratch / 'root').iterdir()), [])

    def test_hang_timeout_kills_the_namespace(self):
        """A test that outlives the hang guard is killed with every process in its sandbox."""
        marker = f'vp-hang-{uuid.uuid4().hex[:8]}'
        command = ['bash', '-c', 'sleep 300 & exec sleep 300']
        try:
            result = p.run_sandboxed(command, {'PATH': os.environ['PATH'], 'VP_MARKER': marker}, '/',
                                     self.scratch, self.target, [], capture=True, timeout=3)
            self.assertEqual(result.returncode, 124)
            time.sleep(1)  # sleep: give the kernel a moment to finish tearing down the PID namespace
            self.assertEqual(survivors(marker), [])
        finally:
            reap(survivors(marker))

    def test_killing_the_runner_kills_the_sandbox(self):
        """SIGKILL of the runner process leaves no sandboxed process behind (79752 P2-2)."""
        marker = f'vp-orphan-{uuid.uuid4().hex[:8]}'
        runner = (
            'import importlib.machinery, importlib.util, os, sys\n'
            'from pathlib import Path\n'
            f'l = importlib.machinery.SourceFileLoader("vp", {str(Path(__file__).with_name("verify-privileged"))!r})\n'
            'm = importlib.util.module_from_spec(importlib.util.spec_from_loader("vp", l)); l.exec_module(m)\n'
            'cmd = ["bash", "-c", "trap \\"\\" TERM; (trap \\"\\" TERM HUP; sleep 300) & sleep 300"]\n'
            f'm.run_sandboxed(cmd, {{"PATH": os.environ["PATH"], "VP_MARKER": {marker!r}}}, "/", '
            f'Path({str(self.scratch)!r}), Path({str(self.target)!r}), [])\n'
        )
        process = subprocess.Popen([sys.executable, '-c', runner])
        try:
            for _ in range(100):
                if len(survivors(marker)) >= 3:
                    break
                time.sleep(0.1)  # sleep: polling until the sandboxed sleepers have started
            # The inner bash (PID 1) and its two sleepers carry the marker.
            self.assertGreaterEqual(len(survivors(marker)), 3)
            process.kill()
            process.wait()
            for _ in range(50):
                if not survivors(marker):
                    break
                time.sleep(0.1)  # sleep: polling until the namespace is torn down
            self.assertEqual(survivors(marker), [])
        finally:
            reap(survivors(marker))
            if process.poll() is None:
                process.kill()


if __name__ == '__main__':
    unittest.main()
