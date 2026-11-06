#!/usr/bin/env python3
"""Fixture tests for the nightly fuzz runner (D351, #344).

The crash reporter runs against a small in-process fake of the Forgejo API
that keeps real state (issues, comments, attachments), so retries, lost
responses and per-target grouping are tested end to end with synthetic data
and a synthetic token.
"""
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('nightly_fuzz', Path(__file__).with_name('nightly-fuzz.py'))
fuzz = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fuzz)


def load_script(name):
    """Import an extension-less script next to this file."""
    import importlib.machinery
    loader = importlib.machinery.SourceFileLoader(name.replace('-', '_'), str(Path(__file__).with_name(name)))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


installer = load_script('install-nightly-fuzz')
service = load_script('nightly-fuzz-service')


class FakeForgejo:
    """Just enough of the issue API to exercise the reporter, with failure switches.

    `drop_next_create` stores the next issue but closes the connection before
    answering, which is how a create request can succeed while the client
    sees an error.
    """

    def __init__(self):
        """Start an HTTP server on a free loopback port."""
        self.issues, self.comments, self.assets, self.requests = {}, {}, {}, []
        self.drop_next_create = False
        fake = self

        class Handler(BaseHTTPRequestHandler):
            """Route the handful of endpoints the reporter uses."""

            def reply(self, payload, status=200):
                """Send one JSON response."""
                self.send_response(status)
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())

            def do_GET(self):
                """Issue state, open-issue listing and comment listing."""
                fake.requests.append(('GET', self.path, self.headers.get('Authorization')))
                path = self.path.split('?')[0]
                if m := re.fullmatch(r'/api/v1/repos/[^/]+/[^/]+/issues/(\d+)/comments', path):
                    return self.reply([c for c in fake.comments.values() if c['issue'] == int(m[1])])
                if m := re.fullmatch(r'/api/v1/repos/[^/]+/[^/]+/issues/(\d+)', path):
                    return self.reply(fake.issues[int(m[1])])
                if path.endswith('/issues'):
                    return self.reply([i for i in fake.issues.values() if i['state'] == 'open'])
                return self.reply({}, 404)

            def do_POST(self):
                """Create issues and comments, and accept attachments."""
                data = self.rfile.read(int(self.headers['Content-Length']))
                fake.requests.append(('POST', self.path, self.headers.get('Authorization')))
                if self.path.endswith('/issues'):
                    number = 345 + len(fake.issues)
                    fake.issues[number] = dict(json.loads(data), number=number, state='open')
                    if fake.drop_next_create:
                        fake.drop_next_create = False
                        self.close_connection = True
                        self.connection.close()
                        return None
                    return self.reply(fake.issues[number], 201)
                if m := re.search(r'/issues/(\d+)/comments$', self.path):
                    comment = 900 + len(fake.comments)
                    fake.comments[comment] = dict(json.loads(data), id=comment, issue=int(m[1]))
                    return self.reply(fake.comments[comment], 201)
                if m := re.search(r'/issues/comments/(\d+)/assets$', self.path):
                    fake.assets.setdefault(int(m[1]), []).append(data)
                    return self.reply({'id': 1}, 201)
                return self.reply({}, 404)

            def log_message(self, *_args):
                """Keep request logs (and the synthetic token) out of test output."""

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.api = f'http://127.0.0.1:{self.server.server_port}'

    def creates(self):
        """How many issue-create requests the reporter has sent."""
        return sum(1 for method, path, _ in self.requests if method == 'POST' and path.endswith('/issues'))

    def close(self):
        """Stop the server thread."""
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


class FakeLibFuzzer:
    """Stands in for `subprocess.run` of cargo-fuzz, so the runner's real fuzz/re-check/file path runs in tests.

    A fuzz run (it has `-max_total_time`) writes `writes` into the artifact
    prefix and prints libFuzzer's `Test unit written to` line for each. A
    re-check (one input, no budget) prints `Executed <input> in <ms> ms` and
    exits with `recheck_exit`. Every command is recorded in `commands`.
    """

    def __init__(self, writes=None, recheck_exit=0, recheck_ms=0):
        """Configure what the fuzz run leaves behind and how re-checks end."""
        self.writes, self.recheck_exit, self.recheck_ms = writes or {}, recheck_exit, recheck_ms
        self.commands = []

    def __call__(self, command, cwd, env, stdout, stderr):
        """Play one cargo-fuzz invocation, writing its output to the runner's log."""
        self.commands.append(command)
        flags = command[command.index('--') + 1:]
        prefix = next(flag for flag in flags if flag.startswith('-artifact_prefix='))[len('-artifact_prefix='):]
        if any(flag.startswith('-max_total_time=') for flag in flags):
            for name, data in self.writes.items():
                path = Path(prefix) / name
                path.write_bytes(data)
                stdout.write(f"artifact_prefix='{prefix}'; Test unit written to {path}\n")
            return subprocess.CompletedProcess(command, 70 if self.writes else 0)
        stdout.write(f"Executed {command[command.index('--') - 1]} in {self.recheck_ms} ms\n")
        return subprocess.CompletedProcess(command, self.recheck_exit)


class NightlyFuzz(unittest.TestCase):
    """Keep bounded scheduling and authenticated crash attachments working."""

    def setUp(self):
        """A fresh fake API, state directory and synthetic token per test."""
        self.fake = FakeForgejo()
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name).resolve()
        self.token = self.state / 'token'
        self.token.write_text('synthetic-test-token\n')

    def tearDown(self):
        """Stop the fake and remove the state."""
        self.fake.close()
        self.directory.cleanup()

    def crash(self, name, data):
        """Write one synthetic failing input."""
        path = self.state / name
        path.write_bytes(data)
        return path

    def report(self, crash, target='wire_frame_decode'):
        """File one input through the real reporter."""
        fuzz.report_crash(self.fake.api, 'kayg/infraternal', self.token, self.state, target, crash, 'a' * 40)

    def test_existing_targets_and_budget(self):
        """Every declared harness receives its share of the nightly hour."""
        root = Path(__file__).resolve().parents[1]
        names = fuzz.targets(root)
        self.assertEqual(set(names), {path.stem for path in (root / 'fuzz/fuzz_targets').glob('*.rs')})
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(fuzz.target_budget(3600, names), 3600 // len(names))
        with self.assertRaises(ValueError):
            fuzz.target_budget(0, names)
        # mesh_node_json only builds with its required feature.
        self.assertIn('mesh-node', fuzz.required_features(root))

    def test_attachment_and_dedup(self):
        """Upload the exact bytes in a zip, inline small inputs, and never file one input twice."""
        crash = self.crash('crash-input', b'\x00\xffcrashing input\n')
        self.report(crash)
        (issue,) = self.fake.issues.values()
        self.assertEqual(issue['title'], 'fuzz: wire_frame_decode found a failing input')
        self.assertIn('Input (base64): `AP9jcmFzaGluZyBpbnB1dAo=`', issue['body'])
        self.assertIn(fuzz.issue_marker('wire_frame_decode'), issue['body'])
        ((upload,),) = self.fake.assets.values()
        self.assertIn(b'.zip"', upload)
        archive = zipfile.ZipFile(io.BytesIO(upload[upload.index(b'PK'):]))
        self.assertEqual(archive.read(archive.namelist()[0]), crash.read_bytes())
        self.assertTrue(all(auth == 'token synthetic-test-token' for _, _, auth in self.fake.requests))
        before = len(self.fake.requests)
        self.report(crash)
        self.assertEqual(len(self.fake.requests), before)

    def test_grouping_per_target(self):
        """Later inputs comment on the open issue; after it closes, a new issue opens."""
        self.report(self.crash('one', b'one'))
        self.report(self.crash('two', b'two'))
        self.assertEqual(self.fake.creates(), 1)
        self.assertEqual(len(self.fake.comments), 2)
        self.fake.issues[345]['state'] = 'closed'
        self.report(self.crash('three', b'three'))
        self.assertEqual(self.fake.creates(), 2)

    def test_lost_create_response_does_not_duplicate(self):
        """A create that succeeded server-side but lost its response is found on retry (79565)."""
        crash = self.crash('lost', b'lost response')
        self.fake.drop_next_create = True
        with self.assertRaises(OSError):
            self.report(crash)
        self.assertEqual(len(self.fake.issues), 1)
        self.report(crash)
        self.assertEqual(self.fake.creates(), 1)
        self.assertEqual(len(self.fake.issues), 1)
        self.assertEqual(len(self.fake.comments), 1)
        self.assertEqual(len(self.fake.assets), 1)

    def test_lost_target_record_still_groups(self):
        """Even without the local `.issue` file, the marker finds the target's open issue."""
        self.report(self.crash('one', b'one'))
        (self.state / 'reports' / 'wire_frame_decode.issue').unlink()
        self.report(self.crash('two', b'two'))
        self.assertEqual(self.fake.creates(), 1)

    def test_refound_input_is_a_finding(self):
        """A known input found again rewrites the same SHA-1-named file; it is still a finding (79752 P3-1)."""
        artifacts = self.state / 'artifacts'
        artifacts.mkdir()
        known = artifacts / 'crash-2ca3ce7494fb298a60da37b58c1be73bc15a8b94'
        known.write_bytes(b'0X.A-1')
        log = ("==1== ERROR: libFuzzer: deadly signal\n"
               f"artifact_prefix='{artifacts}/'; Test unit written to {known}\nBase64: MFguQS0x\n")
        self.assertEqual(fuzz.written_inputs(log, artifacts), [known])

    def test_build_failure_is_not_a_finding(self):
        """A failed run that wrote no unit has no findings, so it counts as broken."""
        artifacts = self.state / 'artifacts'
        artifacts.mkdir()
        (artifacts / 'crash-old').write_bytes(b'old')
        log = 'error: target `mesh_node_json` requires the features: `mesh-node`\n'
        self.assertEqual(fuzz.written_inputs(log, artifacts), [])

    def timeout_fixture(self):
        """An artifact directory with #370's empty timeout input next to an ordinary crash."""
        artifacts = self.state / 'artifacts'
        artifacts.mkdir()
        timeout = artifacts / 'timeout-da39a3ee5e6b4b0d3255bfef95601890afd80709'
        timeout.write_bytes(b'')
        crash = artifacts / 'crash-2ca3ce7494fb298a60da37b58c1be73bc15a8b94'
        crash.write_bytes(b'0X.A-1')
        return artifacts, timeout, crash

    def test_timeout_that_does_not_recur_is_not_filed(self):
        """#370: a host-load timeout that passes in isolation is set aside, not filed; crashes skip the re-check."""
        artifacts, timeout, crash = self.timeout_fixture()
        checked = []
        unconfirmed = self.state / 'unconfirmed' / 'ssh_auth_once_decode'
        kept = fuzz.confirmed_inputs(sorted(artifacts.iterdir()), unconfirmed,
                                     lambda path: checked.append(path.name) or False)
        self.assertEqual(kept, [crash])
        self.assertEqual(checked, [timeout.name])
        self.assertFalse(timeout.exists())
        self.assertEqual((unconfirmed / timeout.name).read_bytes(), b'')
        # Set aside means gone from the artifact directory, so the next night neither files nor re-checks it.
        self.assertEqual(sorted(artifacts.iterdir()), [crash])

    def test_timeout_that_recurs_is_filed(self):
        """A timeout that happens again in isolation is a real finding and stays in place."""
        artifacts, timeout, crash = self.timeout_fixture()
        kept = fuzz.confirmed_inputs(sorted(artifacts.iterdir()), self.state / 'unconfirmed', lambda _path: True)
        self.assertEqual(kept, [crash, timeout])
        self.assertTrue(timeout.exists())

    def fuzzer(self, fake):
        """A Fuzzer over an empty checkout whose processes are played by `fake`."""
        checkout = self.state / 'checkout'
        checkout.mkdir(exist_ok=True)
        return fuzz.Fuzzer(checkout, 'rustup', ('--features', 'mesh-node'), {}, run=fake)

    def test_recheck_exit_rule(self):
        """Only a clean exit sets a timeout aside; a second timeout (70), a crash (77) or a tool error (1) files it."""
        crash = self.crash('timeout-input', b'')
        for code, expected in [(0, False), (70, True), (77, True), (1, True)]:
            fake = FakeLibFuzzer(recheck_exit=code)
            self.assertEqual(fuzz.reproduces(self.fuzzer(fake), self.state, 'release_channel', crash), expected, code)

    def test_recheck_runs_the_input_alone_under_the_time_limit(self):
        """The re-check carries the fuzz run's -timeout and the input path, and no fuzzing budget."""
        crash = self.crash('timeout-input', b'')
        fake = FakeLibFuzzer()
        fuzz.reproduces(self.fuzzer(fake), self.state, 'release_channel', crash)
        (command,) = fake.commands
        self.assertIn(f'-timeout={fuzz.TIMEOUT_SECONDS}', command)
        self.assertIn(str(crash), command)
        self.assertFalse([flag for flag in command if flag.startswith('-max_total_time')])

    def test_run_target_sets_aside_a_timeout_that_passes_alone(self):
        """#370 end to end: the fuzz run leaves a timeout and a crash; only the crash is filed."""
        fake = FakeLibFuzzer(writes={'timeout-da39a3ee': b'', 'crash-2ca3ce74': b'0X.A-1'}, recheck_exit=0)
        filed = []
        entry = fuzz.run_target(self.fuzzer(fake), self.state, 'ssh_auth_once_decode', 5,
                                lambda _name, crash: filed.append(crash.name))
        self.assertEqual(filed, ['crash-2ca3ce74'])
        self.assertEqual(entry['unconfirmed'], 1)
        self.assertTrue((self.state / 'unconfirmed/ssh_auth_once_decode/timeout-da39a3ee').exists())
        # One fuzz run plus one re-check, of the timeout only.
        self.assertEqual(len(fake.commands), 2)

    def test_run_target_files_a_timeout_that_recurs(self):
        """A timeout that happens again alone is filed with the crash."""
        fake = FakeLibFuzzer(writes={'timeout-da39a3ee': b'', 'crash-2ca3ce74': b'0X.A-1'}, recheck_exit=70)
        filed = []
        entry = fuzz.run_target(self.fuzzer(fake), self.state, 'ssh_auth_once_decode', 5,
                                lambda _name, crash: filed.append(crash.name))
        self.assertEqual(filed, ['crash-2ca3ce74', 'timeout-da39a3ee'])
        self.assertEqual(entry['unconfirmed'], 0)

    def test_report_errors_are_caught_types(self):
        """HTTP and network failures are OSError subclasses, so the loop's catch covers them."""
        import urllib.error
        self.assertTrue(issubclass(urllib.error.HTTPError, OSError))
        self.assertTrue(issubclass(urllib.error.URLError, OSError))
        self.assertTrue(issubclass(TimeoutError, OSError))


class SeparateAccount(unittest.TestCase):
    """The token and the fuzz run live in their own account, not claude's (79752 P2-3)."""

    def test_units(self):
        """System units, a root-owned fixed helper, and nothing under claude's home."""
        unit = installer.service_unit()
        self.assertIn(f'ExecStart={installer.SERVICE_HELPER}', unit)
        self.assertNotIn('/home/claude', unit)
        self.assertNotIn('token', unit)
        self.assertIn('OnCalendar=*-*-* 02:00:00 Asia/Kolkata', installer.timer_unit())
        self.assertEqual(str(installer.HOME), service.HOME)
        self.assertEqual(installer.USER, service.USER)

    def test_service_drops_privileges_before_any_repository_code(self):
        """The slot is taken as claude through runuser; the fuzz pass runs via setpriv as the fuzz user."""
        from unittest import mock
        import subprocess
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = service.READY
        with mock.patch.object(service.subprocess, 'Popen', return_value=holder) as popen, \
                mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(service.main(), 0)
        slot = popen.call_args[0][0]
        self.assertEqual(slot[:4], ['runuser', '-u', 'claude', '--'])
        fuzz_run = run.call_args[0][0]
        self.assertEqual(fuzz_run[:2], ['setpriv', '--reuid=infraternal-fuzz'])
        self.assertIn('--reset-env', fuzz_run)
        self.assertEqual(run.call_args[1]['cwd'], '/var/lib/infraternal-fuzz/checkout')
        holder.stdin.write.assert_called_once()

    def test_no_slot_means_no_run(self):
        """If the slot holder never reports ready, no fuzz code runs and the unit fails."""
        from unittest import mock
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = b''
        with mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                mock.patch.object(service.subprocess, 'run', side_effect=AssertionError('ran without a slot')):
            self.assertEqual(service.main(), 1)


if __name__ == '__main__':
    unittest.main()
