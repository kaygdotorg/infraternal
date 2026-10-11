#!/usr/bin/env python3
"""Local release-bucket/signer stand-ins test publication, immutability and verification [224]."""
import hashlib
import http.server
import os
import json
import urllib.parse
from pathlib import Path
import shutil
import subprocess
import threading
import tempfile
import unittest
import tomllib

ROOT = Path(__file__).resolve().parents[2]

class ReleaseScripts(unittest.TestCase):
    def test_scripts_exist(self):
        for name in ('build', 'publish', 'verify'):
            self.assertTrue((ROOT / 'scripts/release' / name).is_file(), name)

    def test_release_json_rejects_duplicates_at_every_depth(self):
        # The same decoder checks storage preflight, upload answers and Worker
        # answers; nested objects must be as unambiguous as the outer envelope.
        for mode, body in (
            ('empty-prefix', '{"success":true,"result":[{"key":"existing"}],"result":[]}'),
            ('empty-prefix', '{"success":false,"success":true,"result":[]}'),
            ('empty-prefix', '{"success":true,"result":[],"result_info":{"is_truncated":true,"is_truncated":false}}'),
            ('uploaded', '{"success":true,"result":{"key":"first","key":"second"}}'),
            ('signed', '{"version":"first","version":"second"}'),
            ('signed', '{"index":[{"version":"first","version":"second"}]}'),
        ):
            with self.subTest(mode=mode, body=body):
                result = subprocess.run(
                    ['python3', str(ROOT / 'scripts/release/response.py'), mode],
                    input=body, text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'duplicate JSON fields in the release response\n')

    def test_local_publication_is_verified_and_immutable(self):
        scratch = Path(os.environ.get('CARGO_TARGET_DIR', Path.home() / '.cache/codex-scratch/release-pipeline/target'))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            repo = Path(directory)
            shutil.copytree(ROOT / 'scripts/release', repo / 'scripts/release')
            shutil.copy(ROOT / 'Cargo.toml', repo / 'Cargo.toml')
            (repo / 'release').mkdir()
            key = repo / 'key'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            public = key.with_suffix('.pub').read_text().split()
            (repo / 'release/allowed_signers').write_text('release@infraternal.com namespaces="infraternal-release" ' + ' '.join(public[:2]) + ' test\n')
            # Only this isolated copy trusts the generated fixture key.
            version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
            target = repo / 'target'
            bundle = target / 'releases' / version
            bundle.mkdir(parents=True)
            files = {name: ('synthetic ' + name).encode() for name in ('infraternal', 'infraternal-x86_64-musl', 'infraternal-aarch64-musl')}
            files["VERSION"] = (version + "\n").encode()
            for name, body in files.items():
                (bundle / name).write_bytes(body)
            store = {}
            requests = []
            error = [None]
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass
                def respond(self, status, body=b''):
                    self.send_response(status)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    if self.command != 'HEAD':
                        self.wfile.write(body)
                def object_name(self):
                    return self.path.split('/releases/')[-1]
                def do_HEAD(self):
                    requests.append(('HEAD', self.path))
                    self.respond(200 if self.object_name() in store else 404)
                def do_PUT(self):
                    requests.append(('PUT', self.path))
                    if self.headers.get('Authorization') != 'Bearer fixture-cloudflare+/~=' or not self.headers.get('User-Agent'):
                        self.respond(401)
                        return
                    name = self.object_name()
                    if name in store:
                        self.respond(409)
                        return
                    store[name] = self.rfile.read(int(self.headers['Content-Length']))
                    self.respond(200, json.dumps({"success": True, "result": {"key": "releases/" + name}}).encode())
                def do_POST(self):
                    requests.append(('POST', self.path))
                    if self.headers.get('Authorization') != 'Bearer fixture-caller+/~=' or not self.headers.get('User-Agent'):
                        self.respond(401)
                        return
                    body = self.rfile.read(int(self.headers['Content-Length']))
                    if json.loads(body) != {'version': version}:
                        error[0] = 'wrong version requested'
                        self.respond(400)
                        return
                    manifest = ''.join(hashlib.sha256(store[version + '/' + name]).hexdigest() + '  ' + name + '\n' for name in sorted(files)).encode()
                    sums = repo / 'SHA256SUMS'
                    sums.write_bytes(manifest)
                    subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'infraternal-release', str(sums)], check=True, capture_output=True)
                    store[version + '/SHA256SUMS'] = manifest
                    store[version + '/SHA256SUMS.sig'] = sums.with_suffix('.sig').read_bytes()
                    self.respond(200, b'{}')
                def do_GET(self):
                    requests.append(('GET', self.path))
                    parsed = urllib.parse.urlsplit(self.path)
                    if parsed.path.startswith('/api/') and parsed.path.endswith('/objects'):
                        prefix = urllib.parse.parse_qs(parsed.query)['prefix'][0].removeprefix('releases/')
                        result = [{"key": name} for name in store if name.startswith(prefix)][:1]
                        self.respond(200, json.dumps({"success": True, "result": result}).encode())
                        return
                    body = store.get(self.object_name())
                    self.respond(200 if body is not None else 404, body or b'')
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            env = dict(os.environ, CARGO_TARGET_DIR=str(target), CLOUDFLARE_ACCOUNT_ID='fixture', CLOUDFLARE_API_TOKEN='fixture-cloudflare+/~=', RELEASE_CALLER_TOKEN='fixture-caller+/~=', RELEASE_TEST_ORIGIN=f'http://127.0.0.1:{server.server_port}')
            def run(script, requested=version):
                return subprocess.run([str(repo / 'scripts/release' / script), requested], env=env, capture_output=True, text=True)
            try:
                (bundle / "VERSION").write_bytes(b"999.999.999\n")
                self.assertNotEqual(run('publish').returncode, 0)
                self.assertFalse(any(method in ('PUT', 'POST') for method, _ in requests), "wrong local version must fail before publication")
                (bundle / "VERSION").write_bytes((version + "\n").encode())
                result = run('publish')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Published and verified', result.stdout)
                self.assertIsNone(error[0])
                self.assertFalse(any(method == "HEAD" for method, _ in requests))
                self.assertEqual(len([r for r in requests if r[0] == 'PUT']), 4)
                before = len(requests)
                self.assertNotEqual(run('publish').returncode, 0)
                self.assertFalse(any(r[0] in ('PUT', 'POST') for r in requests[before:]))
                self.assertEqual(run('verify').returncode, 0)
                store[version + '/infraternal-aarch64-musl'] = b'tampered'
                self.assertNotEqual(run('verify').returncode, 0)
                self.assertNotEqual(run('verify', '999.999.999').returncode, 0)
                self.assertNotEqual(run('publish', '999.999.999').returncode, 0)
                del store[version + '/SHA256SUMS.sig']
                self.assertNotEqual(run('verify').returncode, 0)
            finally:
                server.shutdown()
                server.server_close()
                worker.join()
            self.assertNotEqual(run('verify').returncode, 0)

if __name__ == '__main__':
    unittest.main()
