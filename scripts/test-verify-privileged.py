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
import tempfile
import unittest
from unittest import mock


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

    def test_command(self):
        """User, net, mount and PID namespaces; read-only root; no sudo; explicit environment."""
        command = p.sandboxed(['/t/debug/deps/x', '--exact', 'y'], {'A': '1', 'BAD\nKEY': 'x', 'M': 'two\nlines'},
                              Path('/c'), Path('/s'), Path('/t'))
        self.assertEqual(command[:8], ['unshare', '--user', '--map-root-user', '--net', '--mount', '--pid',
                                       '--fork', '--mount-proc'])
        self.assertNotIn('sudo', command)
        self.assertIn('env', command)
        self.assertEqual(command[command.index('env') + 1], '-i')
        self.assertIn('A=1', command)
        self.assertIn('CARGO_TARGET_DIR=/tmp/ut', command)
        self.assertNotIn('M=two\nlines', command)
        self.assertEqual(command[-3:], ['/t/debug/deps/x', '--exact', 'y'])
        setup = command[command.index('-c') + 1]
        for step in ('ro=recursive', 'pivot_root . .', 'umount -l .'):
            self.assertIn(step, setup)
        self.assertNotIn('exec "$@"', setup)


@unittest.skipUnless(userns_available(), 'unprivileged user namespaces unavailable on this host')
class Containment(unittest.TestCase):
    """Planted escapes fail inside the sandbox and succeed outside it."""

    def test_planted_escapes(self):
        """Every escape probe is contained, and the persistence marker never appears outside."""
        if not shutil.which('ip'):
            self.skipTest('iproute2 is not on PATH (run inside the dev shell)')
        home = tempfile.mkdtemp(prefix='vp-home-', dir=Path.home() / '.cache')
        try:
            checkout, target = Path(home) / 'checkout', Path(home) / 'target'
            (target / 'debug').mkdir(parents=True)
            checkout.mkdir()
            scratch = Path(home) / 'scratch'
            (scratch / 'root').mkdir(parents=True)
            with mock.patch.object(p.Path, 'home', return_value=Path(home)):
                escaped = p.self_check(scratch, target, checkout)
            self.assertEqual(escaped, [])
            # Control: the same writes succeed outside, so "contained" is not
            # just a broken probe.
            for directory in (Path(home), checkout, target):
                probe = directory / '.privileged-escape'
                probe.touch()
                self.assertTrue(probe.exists())
            self.assertEqual(sorted(path.name for path in (scratch / 'root').iterdir()), [])
        finally:
            shutil.rmtree(home, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
