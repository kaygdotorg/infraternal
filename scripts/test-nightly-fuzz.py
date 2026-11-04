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
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('nightly_fuzz', Path(__file__).with_name('nightly-fuzz.py'))
fuzz = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fuzz)


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


class NightlyFuzz(unittest.TestCase):
    """Keep bounded scheduling and authenticated crash attachments working."""

    def setUp(self):
        """A fresh fake API, state directory and synthetic token per test."""
        self.fake = FakeForgejo()
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name)
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

    def test_report_errors_are_caught_types(self):
        """HTTP and network failures are OSError subclasses, so the loop's catch covers them."""
        import urllib.error
        self.assertTrue(issubclass(urllib.error.HTTPError, OSError))
        self.assertTrue(issubclass(urllib.error.URLError, OSError))
        self.assertTrue(issubclass(TimeoutError, OSError))


if __name__ == '__main__':
    unittest.main()
