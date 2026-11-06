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
guard = load('elf-runpath-guard')
slot_hold = load('root-slot-hold')


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

    def test_dependency_crate_selects_its_area(self):
        """A diff touching only infraternal-linux-tun selects the mesh (TUN) area (J266 P2-2)."""
        graph = {'infraternal-plugin-mesh': ('crates/plugins/mesh', {'infraternal-linux-tun', 'infraternal-protocol'}),
                 'infraternal-linux-tun': ('crates/infraternal-linux-tun', set()),
                 'infraternal-protocol': ('crates/infraternal-protocol', set()),
                 'unrelated': ('crates/unrelated', set())}
        root = Path(__file__).resolve().parents[1]
        dirs = p.dependency_directories(root, graph)
        self.assertIn('crates/infraternal-linux-tun', dirs['mesh'])
        self.assertEqual(p.areas(['crates/infraternal-linux-tun/src/lib.rs']), set())
        self.assertEqual(p.areas(['crates/infraternal-linux-tun/src/lib.rs'], dirs), {'mesh'})
        self.assertEqual(p.areas(['crates/unrelated/src/lib.rs'], dirs), set())
        # A sibling directory sharing a prefix is not inside the crate.
        self.assertEqual(p.areas(['crates/infraternal-linux-tunnel/x.rs'], dirs), set())

    def test_real_graph_covers_the_reviewed_crates(self):
        """On the real workspace, the four crates J266 listed select the mesh area."""
        root = Path(__file__).resolve().parents[1]
        if not shutil.which('cargo'):
            self.skipTest('cargo is not on PATH')
        dirs = p.dependency_directories(root, p.workspace_graph(root))
        for path in ('crates/infraternal-linux-tun/src/lib.rs', 'crates/plugins/relay/src/lib.rs',
                     'crates/infraternal-protocol/src/lib.rs', 'crates/infraternal-plugin-api/src/lib.rs'):
            self.assertIn('mesh', p.areas([path], dirs), path)
        self.assertEqual(p.areas(['docs/ENGINEERING.md'], dirs), set())

    def test_skip_exits_with_the_skip_code(self):
        """With nothing selected the row exits 77, which the gate prints as SKIP (J266 P2-2)."""
        with mock.patch.object(p.subprocess, 'check_output', side_effect=['base\n', b'docs/x.md\0', b'']), \
                mock.patch.object(p, 'workspace_graph', return_value={}), \
                mock.patch.object(sys, 'argv', ['verify-privileged']), \
                self.assertRaises(SystemExit) as stop:
            p.main()
        self.assertEqual(stop.exception.code, p.SKIP_EXIT)

    def test_gate_prints_skip_for_77(self):
        """Only an opted-in row records 77 as SKIP; an ordinary row records FAIL (77) (J270 P3-2)."""
        rust = Path(__file__).resolve().parent / 'verify.d/rust.sh'
        script = ('source "$1"; rust_run_gate_skippable skipped bash -c "exit 77"; rust_run_gate ok true; '
                  'echo "failed=$RUST_GATE_FAILED"; rust_run_gate plain bash -c "exit 77"; '
                  'echo "failed=$RUST_GATE_FAILED"; printf "%s\\n" "${RUST_GATE_ROWS[@]}"')
        out = subprocess.run(['bash', '-c', script, 'gate', str(rust)], capture_output=True, text=True).stdout
        self.assertIn('skipped|SKIP', out)
        self.assertIn('ok|PASS', out)
        self.assertIn('plain|FAIL (77)', out)
        self.assertLess(out.index('failed=0'), out.index('failed=1'))

    def test_only_the_privileged_row_is_skippable(self):
        """The privileged row opts in; no other row in the gate does."""
        rust = (Path(__file__).resolve().parent / 'verify.d/rust.sh').read_text()
        calls = [line.strip() for line in rust.splitlines() if line.strip().startswith('rust_run_gate_skippable ')]
        self.assertEqual(calls, ['rust_run_gate_skippable "privileged integration" verify_privileged'])

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

    def test_child_only_fixtures_are_not_selected(self):
        """A child half returns at once when run alone; selecting it would be a pass that tests nothing (J266 P2-1)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'pkg/tests').mkdir(parents=True)
            (root / 'pkg/tests/split.rs').write_text(
                '#[test]\n#[ignore = "Run in a disposable user/network namespace."]\nfn parent() {}\n'
                '#[test]\n#[ignore = "Child-only fixture: started by parent inside its namespace; does nothing alone."]\n'
                'fn child() {}\n')
            self.assertEqual(set(p.privileged_ignored(root, 'pkg', 'pkg')['test:split']), {'parent'})

    def test_child_halves_use_the_one_prefix(self):
        """Every ignore reason that names a child fixture starts with the shared prefix, so the rule holds."""
        root = Path(__file__).resolve().parents[1]
        listed = subprocess.run(['git', 'grep', '-h', '-o', '-E', r'#\[ignore = "[^"]*[Cc]hild[^"]*"\]', '--', 'crates'],
                                cwd=root, capture_output=True, text=True).stdout.splitlines()
        self.assertTrue(listed)
        for attribute in listed:
            reason = attribute.split('"')[1]
            if 'fixture' in reason.lower() or 'inside the namespace prepared' in reason.lower():
                self.assertRegex(reason, p.CHILD_ONLY, attribute)

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


class RealRootProof(unittest.TestCase):
    """The real-root TUN proof lets nothing the shared build account can write reach root (J270, 81345)."""

    def test_guard_refuses_a_claude_writable_library_path(self):
        """A RUNPATH into the claude build tree (what the dev shell produced) is refused."""
        reasons = guard.problems('/nix/store/abc-glibc/lib/ld-linux-x86-64.so.2',
                                 ['/home/claude/worktrees/tun/outputs/out/lib:/nix/store/abc-glibc/lib'], [])
        self.assertEqual(len(reasons), 1)
        self.assertIn('/home/claude/worktrees/tun/outputs/out/lib', reasons[0])

    def test_guard_refuses_unsafe_interpreters_and_relative_entries(self):
        """A host or user interpreter, $ORIGIN, relative and empty entries are all refused."""
        self.assertTrue(guard.problems('/home/claude/ld.so', [], []))
        for entry in ('$ORIGIN/lib', 'lib', '', '/tmp/libs', '/nix/store/../../home/claude'):
            self.assertTrue(guard.problems('/nix/store/x/ld.so', [entry], []), entry)

    def test_guard_allows_store_and_root_owned_dirs_only(self):
        """/nix/store passes; an --allow dir passes only if it and its parents are root-owned and not writable by others."""
        self.assertEqual(guard.problems('/nix/store/x/ld.so', ['/nix/store/a/lib:/nix/store/b/lib'], []), [])
        with tempfile.TemporaryDirectory() as directory:
            # A temp dir under /tmp is not a root-owned chain for a non-root test user.
            mine = Path(directory) / 'out/lib'
            mine.mkdir(parents=True)
            if os.geteuid() != 0:
                self.assertTrue(guard.problems('/nix/store/x/ld.so', [str(mine)], [directory]))

    def test_guard_reads_a_real_binary(self):
        """The ELF reader parses this interpreter's own executable."""
        interpreter, search = guard.read_elf(os.path.realpath(sys.executable))
        self.assertTrue(interpreter is None or interpreter.startswith('/'))
        self.assertIsInstance(search, list)

    def test_guard_cli_refuses_a_built_binary_with_a_user_runpath(self):
        """End to end: link a tiny program with a RUNPATH under a user dir; the guard exits 1."""
        compiler = shutil.which('cc') or shutil.which('gcc')
        if not compiler:
            self.skipTest('no C compiler on PATH')
        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / 'p.c', Path(directory) / 'p'
            source.write_text('int main(void) { return 0; }\n')
            built = subprocess.run([compiler, str(source), '-o', str(binary),
                                    '-Wl,--enable-new-dtags,-rpath,/home/claude/worktrees/x/outputs/out/lib'],
                                   capture_output=True)
            if built.returncode:
                self.skipTest('could not link the probe program')
            with mock.patch.object(sys, 'stderr', new=__import__('io').StringIO()) as err:
                self.assertEqual(guard.main([str(binary)]), 1)
            self.assertIn('/home/claude/worktrees/x/outputs/out/lib', err.getvalue())

    def proof_code(self):
        """The proof script without its comment lines."""
        script = (Path(__file__).resolve().parent / 'tun-real-root-proof').read_text()
        return '\n'.join(line for line in script.splitlines() if not line.lstrip().startswith('#'))

    def test_proof_runs_with_a_private_tmp(self):
        """The test sees a fresh tmpfs /tmp, and its copy lives outside /tmp (J277 P3-1)."""
        code = self.proof_code()
        namespace = code[code.index('unshare --net'):]
        self.assertIn("mount -t tmpfs -o mode=1777,size=256m tmpfs /tmp;", namespace)
        self.assertLess(namespace.index('mount -t tmpfs'), namespace.index('"$@"'))
        self.assertIn('run=$(mktemp -d /var/lib/tun-proof-run.', code)
        self.assertNotIn('mktemp -d /tmp/', code)

    def test_proof_sweeps_leftovers_only_under_the_lock(self):
        """Stale proof dirs are removed after flock and before mktemp; only root-owned real dirs (J277 P3-2)."""
        code = self.proof_code()
        sweep = code.index('for stale in /root/tun-proof.* /var/lib/tun-proof-run.* /tmp/tun-proof-run.*')
        self.assertLess(code.index('flock 9'), sweep)
        self.assertLess(sweep, code.index('work=$(mktemp -d /root/tun-proof.'))
        self.assertIn('! -L $stale', code)
        self.assertIn('$(stat -c %u "$stale") == 0', code)

    def test_slot_holder_gives_claude_no_file_of_roots(self):
        """claude's waiter gets pipes only: stderr /dev/null, other fds closed (J277 P3-3)."""
        waiter = mock.MagicMock()
        waiter.stdout.readline.return_value = slot_hold.READY
        with mock.patch.object(slot_hold.subprocess, 'Popen', return_value=waiter) as popen, \
                mock.patch.object(slot_hold.subprocess, 'run',
                                  return_value=subprocess.CompletedProcess([], 3)) as run:
            self.assertEqual(slot_hold.hold(['cargo', 'build']), 3)
        argv, kwargs = popen.call_args
        self.assertEqual(argv[0][:4], ['runuser', '-u', 'claude', '--'])
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertIs(kwargs['stdout'], subprocess.PIPE)
        self.assertIs(kwargs['stdin'], subprocess.PIPE)
        self.assertTrue(kwargs['close_fds'])
        self.assertEqual(run.call_args[0][0], ['nice', '-n', '10', 'cargo', 'build'])
        waiter.stdin.write.assert_called_once()

    def test_slot_holder_runs_nothing_without_a_slot(self):
        """If claude's side never reports ready, root's command does not run."""
        waiter = mock.MagicMock()
        waiter.stdout.readline.return_value = b''
        with mock.patch.object(slot_hold.subprocess, 'Popen', return_value=waiter), \
                mock.patch.object(slot_hold.subprocess, 'run', side_effect=AssertionError('ran without a slot')):
            self.assertEqual(slot_hold.hold(['true']), 1)

    def test_proof_uses_the_reviewed_slot_holder(self):
        """The proof runs the commit's own root-slot-hold, not a host-only helper, and escapes its log tail."""
        code = self.proof_code()
        self.assertIn('/usr/bin/python3 "$work/src/scripts/root-slot-hold" nix develop', code)
        self.assertNotIn('/root/.cache/root-build-slot', code)
        self.assertIn('tail -20 "$work/build.log" | cat -v', code)

    def test_proof_scrubs_roots_environment(self):
        """Root's side runs under env -i with exactly PATH, HOME and LANG (J277 P3-4)."""
        code = self.proof_code()
        line = next(line for line in code.splitlines() if line.startswith('root_env=('))
        words = line[len('root_env=('):-1].split()
        self.assertEqual(words[:2], ['env', '-i'])
        self.assertEqual(sorted(word.split('=', 1)[0] for word in words[2:]), ['HOME', 'LANG', 'PATH'])
        self.assertIn('ssh "root@$host" "${root_env[@]}" bash -s -- "$commit"', code)

    def test_env_allowlist_really_clears_the_rest(self):
        """The same env -i form, run here, drops a planted variable such as INFRATERNAL_SCCACHE_DIR."""
        code = self.proof_code()
        line = next(line for line in code.splitlines() if line.startswith('root_env=('))
        words = line[len('root_env=('):-1].split()
        out = subprocess.run([*words, '/bin/sh', '-c', 'env'], capture_output=True, text=True,
                             env=dict(os.environ, INFRATERNAL_SCCACHE_DIR='/home/claude/cache',
                                      RUSTC_WRAPPER='sccache')).stdout
        names = sorted(entry.split('=', 1)[0] for entry in out.splitlines() if '=' in entry)
        self.assertNotIn('INFRATERNAL_SCCACHE_DIR', names)
        self.assertNotIn('RUSTC_WRAPPER', names)
        self.assertTrue({'PATH', 'HOME', 'LANG'} <= set(names))

    def test_proof_script_keeps_claude_out_of_roots_process(self):
        """No ssh as claude, a root fetch of a full commit id, root-owned dirs, a lock, a trap and the guard."""
        script = (Path(__file__).resolve().parent / 'tun-real-root-proof').read_text()
        code = '\n'.join(line for line in script.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('claude@', code)
        self.assertNotIn('/home/claude', code)
        for needle in ('^[0-9a-f]{40}$', 'git clone -q --no-checkout "$repository"', 'mktemp -d /root/tun-proof.',
                       'flock 9', 'trap cleanup EXIT', 'scripts/elf-runpath-guard" "$binary" --allow "$work"',
                       '$binary == "$work"/target/*', 'CARGO_HOME=/root/.cache/'):
            self.assertIn(needle, code, needle)
        self.assertLess(code.index('elf-runpath-guard'), code.index('unshare --net'))


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

    def test_examples_never_replace_the_lib_test(self):
        """`cargo test --examples` builds examples in test mode; they must not land on the lib key (#285, 80225)."""
        self.assertEqual(p.target_key({'target': {'kind': ['lib'], 'name': 'm'}}), 'lib')
        self.assertEqual(p.target_key({'target': {'kind': ['rlib', 'cdylib'], 'name': 'm'}}), 'lib')
        self.assertEqual(p.target_key({'target': {'kind': ['example'], 'name': 'coordinator_fixture'}}),
                         'example:coordinator_fixture')
        root = Path('/clone')
        lines = '\n'.join(json.dumps({'reason': 'compiler-artifact', 'manifest_path': '/clone/crates/plugins/mesh/Cargo.toml',
                                      'target': {'kind': [kind], 'name': name}, 'profile': {'test': True},
                                      'executable': exe})
                          for kind, name, exe in (('lib', 'mesh', '/w/lib'), ('example', 'coordinator_fixture', '/w/ex')))

        def fake_run(command, **_kwargs):
            """Answer every build with the same two artifacts."""
            return subprocess.CompletedProcess(command, 0, lines if command[1] == 'test' else '', '')

        with mock.patch.object(p.subprocess, 'run', side_effect=fake_run):
            found = p.executables(root, {'mesh'})
        self.assertEqual(found[('crates/plugins/mesh', 'lib')], '/w/lib')

    def test_build_failure_shows_the_compiler_error(self):
        """A failed test build prints rustc's rendered error and fails the row by name, not as a traceback."""
        error = json.dumps({'reason': 'compiler-message', 'message': {'level': 'error',
                            'rendered': 'error[E0063]: missing field `access_ssh`\n'}})
        warning = json.dumps({'reason': 'compiler-message', 'message': {'level': 'warning', 'rendered': 'unused\n'}})
        self.assertEqual(p.rendered_errors('\n'.join([warning, error, 'not json'])),
                         'error[E0063]: missing field `access_ssh`\n')
        broken = subprocess.CompletedProcess([], 101, error, '')
        with mock.patch.object(p.subprocess, 'run', return_value=broken), \
                self.assertRaises(SystemExit) as stop:
            p.executables(Path('/clone'), {'mesh'})
        self.assertIn('build failed: cargo test --workspace', str(stop.exception))

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
                mock.patch.object(p.subprocess, 'run', side_effect=AssertionError('unsandboxed run')), \
                mock.patch.object(p, 'NOT_COVERED_TESTS', {}):
            runs, missing = p.plan(Path('/clone'), {'mesh'}, binaries, {}, Path('/s'), Path('/t'), [])
        self.assertEqual(missing, [])
        self.assertIn('--list', calls[0])
        self.assertEqual([run[0] for run in runs], ['infraternal-plugin-mesh test:kernel kernel::up'])

    def plan_with(self, listing, candidates, not_covered=None):
        """Run plan() against one fake binary listing and a fake candidate scan."""
        def fake(command, *_args, **_kwargs):
            """Answer `--list` with the given libtest listing."""
            return subprocess.CompletedProcess(command, 0, listing, '')

        binaries = {('crates/plugins/mesh', target): '/b/' + target for target in candidates}
        with mock.patch.object(p, 'run_sandboxed', side_effect=fake), \
                mock.patch.object(p, 'privileged_ignored', return_value=candidates), \
                mock.patch.object(p, 'NOT_COVERED_TESTS', not_covered or {}):
            return p.plan(Path('/clone'), {'mesh'}, binaries, {}, Path('/s'), Path('/t'), [])

    def test_unlisted_candidate_fails_by_name(self):
        """A selected test the binary does not list fails the row by name (#285, 80225)."""
        runs, missing = self.plan_with('node::other: test\n', {'lib': {'nft_restart_fences': 'namespace'}})
        self.assertEqual(runs, [])
        self.assertEqual(missing, ['infraternal-plugin-mesh lib nft_restart_fences (selected but not in the test binary)'])

    def test_every_listed_candidate_runs(self):
        """Candidates the binary lists all become runs, with nothing reported missing."""
        runs, missing = self.plan_with('node::rotation_tests::a: test\nnode::b: test\nnode::c: test\n',
                                       {'lib': {'a': 'namespace', 'b': 'namespace'}})
        self.assertEqual(missing, [])
        self.assertEqual(sorted(run[0] for run in runs), ['infraternal-plugin-mesh lib node::b',
                                                          'infraternal-plugin-mesh lib node::rotation_tests::a'])

    def test_not_covered_test_is_skipped_not_missing(self):
        """A test on the explicit not-covered list is neither run nor reported missing."""
        entry = ('infraternal-plugin-mesh', 'test:gotatun_tun_owner', 'second_uid')
        runs, missing = self.plan_with('second_uid: test\nother: test\n',
                                       {'test:gotatun_tun_owner': {'second_uid': 'namespace', 'other': 'namespace'}},
                                       {entry: 'needs a second uid'})
        self.assertEqual(missing, [])
        self.assertEqual([run[0] for run in runs], ['infraternal-plugin-mesh test:gotatun_tun_owner other'])

    def test_stale_not_covered_entry_fails(self):
        """An entry whose test no longer exists fails the row, so the list only shrinks."""
        entry = ('infraternal-plugin-mesh', 'test:gone', 'removed_test')
        runs, missing = self.plan_with('', {}, {entry: 'reason'})
        self.assertEqual(missing, ['infraternal-plugin-mesh test:gone removed_test '
                                   '(listed in NOT_COVERED_TESTS but no longer a candidate)'])

    def test_real_not_covered_entries_name_real_tests(self):
        """Each real NOT_COVERED_TESTS entry is a current candidate with a written reason."""
        root = Path(__file__).resolve().parents[1]
        directories = {package: directory for area in p.PACKAGES.values() for package, directory, _ in area}
        for (package, target, name), reason in p.NOT_COVERED_TESTS.items():
            self.assertTrue(reason)
            self.assertIn(name, p.privileged_ignored(root, package, directories[package]).get(target, {}),
                          f'{package} {target} {name}')

    def test_self_check_command_line(self):
        """`verify-privileged --self-check` runs the escape probes and exits 0 when contained (J266 P3-1)."""
        contained = subprocess.CompletedProcess([], 0, ''.join(f'contained: {label}\n' for label in p.ESCAPES)
                                                + 'contained: wrote only to the sandbox tmpfs\n', '')
        with mock.patch.object(p, 'run_sandboxed', return_value=contained) as run, \
                mock.patch.object(p, 'memory_scope', return_value=['scope-prefix']), \
                mock.patch.object(sys, 'argv', ['verify-privileged', '--self-check']), \
                self.assertRaises(SystemExit) as stop:
            p.main()
        self.assertIn(stop.exception.code, (0, None))
        self.assertEqual(run.call_args[0][5], ['scope-prefix'])

    def test_self_check_command_line_fails_on_escape(self):
        """An escape reported by the probes makes `--self-check` exit non-zero, naming it."""
        escaped = subprocess.CompletedProcess([], 0, 'ESCAPED: write /etc\n', '')
        with mock.patch.object(p, 'run_sandboxed', return_value=escaped), \
                mock.patch.object(p, 'memory_scope', return_value=[]), \
                mock.patch.object(sys, 'argv', ['verify-privileged', '--self-check']), \
                self.assertRaises(SystemExit) as stop:
            p.main()
        self.assertIn('ESCAPED: write /etc', str(stop.exception.code))

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
