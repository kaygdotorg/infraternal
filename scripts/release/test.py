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
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
LICENSE_NOTICE_PATHS = (
    'licenses/libghostty-vt/README.md',
    'licenses/libghostty-vt/Unicode-3.0.txt',
    'licenses/libghostty-vt/aro-MIT.txt',
    'licenses/libghostty-vt/highway-Apache-2.0.txt',
    'licenses/libghostty-vt/highway-BSD-3-Clause.txt',
    'licenses/libghostty-vt/libghostty-vt-MIT.txt',
    'licenses/libghostty-vt/simdutf-Apache-2.0.txt',
    'licenses/libghostty-vt/simdutf-MIT.txt',
    'licenses/libghostty-vt/translate_c-MIT.txt',
    'licenses/libghostty-vt/uucode-MIT.txt',
    'licenses/libghostty-vt/wuffs-Apache-2.0.txt',
    'licenses/libghostty-vt/wuffs-MIT.txt',
)

class ReleaseScripts(unittest.TestCase):
    def test_version_grammar_and_explicit_build_channel(self):
        scratch = Path(os.environ.get('CARGO_TARGET_DIR', Path.home() / '.cache/codex-scratch/release-channels/target'))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            repo = Path(directory)
            shutil.copytree(ROOT / 'scripts/release', repo / 'scripts/release')
            shutil.copy(ROOT / 'Cargo.toml', repo / 'Cargo.toml')
            shutil.copytree(ROOT / 'licenses/libghostty-vt', repo / 'licenses/libghostty-vt')
            (repo / 'scripts/release/traefik_component.py').write_text('''import argparse, hashlib, json
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("--release-version", required=True); p.add_argument("--os", required=True); p.add_argument("--arch", required=True); p.add_argument("--output", type=Path, required=True); a=p.parse_args()
name=f"traefik_v3.7.17_{a.os}_{a.arch}.tar.gz"; relative=f"components/{a.release_version}/proxy/{a.os}/{a.arch}/{name}"; payload=f"fixture:{a.os}:{a.arch}".encode(); destination=a.output/relative; destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(payload)
manifest={"component":"traefik","version":"3.7.17","release_version":a.release_version,"os":a.os,"arch":a.arch,"archive_filename":name,"archive_url":f"https://github.com/traefik/traefik/releases/download/v3.7.17/{name}","mirror_path":relative,"archive_sha256":hashlib.sha256(payload).hexdigest(),"archive_size":len(payload),"executable":"traefik","executable_sha256":"0"*64,"executable_size":1,"license":"MIT"}
(a.output/f"proxy-traefik-{a.os}-{a.arch}.json").write_text(json.dumps(manifest)+"\\n")
''')
            # This isolated packaging stand-in observes build inputs; real binaries are checked separately.
            for name, body in (
                ('auth-toolchain', '#!/usr/bin/env bash\nexit 0\n'),
                ('package-release', '#!/usr/bin/env bash\nset -eu\n[[ "$INFRATERNAL_RELEASE_BUILD" == 1 ]]\nmkdir -p "$1"\nfor name in infraternal infraternal-x86_64-musl infraternal-aarch64-musl infraternal-x86_64-session-musl infraternal-aarch64-session-musl; do printf "%s\\n" "$INFRATERNAL_RELEASE_VERSION" > "$1/$name"; done\n'),
            ):
                script = repo / 'scripts' / name
                script.write_text(body)
                if name == 'package-release':
                    script.write_text(script.read_text().replace(
                        'mkdir -p "$1"\n',
                        'mkdir -p "$1/licenses/libghostty-vt"\n'
                        'cp -R "$(dirname -- "$0")/../licenses/libghostty-vt/." "$1/licenses/libghostty-vt/"\n',
                    ))
                script.chmod(0o755)
            env = dict(os.environ, CARGO_TARGET_DIR=str(repo / 'target'))
            def build(*args):
                return subprocess.run([str(repo / 'scripts/release/build'), *args], env=env, text=True, capture_output=True)
            for args in ((), ('--channel',), ('--channel','other'), ('--channel','stable','extra')):
                result = build(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
            stable = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
            for channel in ('stable', 'edge'):
                started = datetime.now(timezone.utc).replace(microsecond=0)
                result = build('--channel',channel)
                finished = datetime.now(timezone.utc)
                self.assertEqual(result.returncode, 0, result.stderr)
                bundles = list((repo / 'target/releases').iterdir())
                bundle = next(p for p in bundles if (p.name.startswith('edge-')) == (channel == 'edge'))
                if channel == 'stable': self.assertEqual(bundle.name, stable)
                else:
                    self.assertRegex(bundle.name, r'^edge-[0-9]{8}T[0-9]{6}Z$')
                    stamp = datetime.strptime(bundle.name, 'edge-%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
                    self.assertGreaterEqual(stamp, started)
                    self.assertLessEqual(stamp, finished)
                for name in ('VERSION','infraternal','infraternal-x86_64-musl','infraternal-aarch64-musl','infraternal-x86_64-session-musl','infraternal-aarch64-session-musl'):
                    self.assertEqual((bundle / name).read_text(), bundle.name+'\n')
                targets = [('linux', 'amd64'), ('linux', 'arm64'), ('darwin', 'amd64'), ('darwin', 'arm64')]
                for os_name, arch in targets:
                    name = f'traefik_v3.7.17_{os_name}_{arch}.tar.gz'
                    relative = Path('components') / bundle.name / 'proxy' / os_name / arch / name
                    self.assertTrue((bundle / f'proxy-traefik-{os_name}-{arch}.json').is_file())
                    self.assertTrue((bundle / relative).is_file())
                checksums = (bundle / 'SHA256SUMS').read_text().splitlines()
                self.assertEqual(
                    {line.split()[1] for line in checksums},
                    {
                        str(p.relative_to(bundle)) for p in bundle.rglob('*')
                        if p.is_file() and p.name != 'SHA256SUMS' and p.relative_to(bundle).parts[0] != 'components'
                    },
                )
                self.assertTrue(set(LICENSE_NOTICE_PATHS).issubset({line.split()[1] for line in checksums}))
                self.assertEqual(subprocess.run(['sha256sum', '--strict', '--check', 'SHA256SUMS'], cwd=bundle, capture_output=True).returncode, 0)
                if channel == 'stable':
                    self.assertNotEqual(build('--channel',channel).returncode, 0)
            for version in ('1.2','1.2.3-rc1','edge-20261011t071500Z','edge-20261011T071500z','../1.2.3','1.2.3\n'):
                for name in ('publish','verify'):
                    result = subprocess.run([str(repo / 'scripts/release' / name),version],env=env,text=True,capture_output=True)
                    self.assertEqual(result.returncode,2,result.stderr)

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
        self.local_publication(tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version'])

    def test_edge_publication_is_verified_and_immutable(self):
        self.local_publication('edge-20261011T071500Z')

    def test_signed_session_images_are_verified(self):
        self.local_publication('0.1.0', verification_only=True)

    def test_older_signed_releases_without_session_images_are_verified(self):
        self.local_publication('0.1.0', include_sessions=False, verification_only=True)

    def test_new_publication_requires_both_session_images_before_upload(self):
        for arch in ('x86_64', 'aarch64'):
            with self.subTest(architecture=arch):
                self.local_publication('0.1.0', missing_session=arch)

    def test_new_publication_requires_all_engine_and_dependency_notices_before_upload(self):
        """Reject a new signed bundle before any network request if one notice is absent."""
        self.local_publication('0.1.0', missing_license=LICENSE_NOTICE_PATHS[1])

    def local_publication(self, version, include_sessions=True, verification_only=False, missing_session=None, missing_license=None):
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
            target = repo / 'target'
            bundle = target / 'releases' / version
            bundle.mkdir(parents=True)
            files = {name: ('synthetic ' + name).encode() for name in ('infraternal', 'infraternal-x86_64-musl', 'infraternal-aarch64-musl')}
            if include_sessions:
                for arch in ('x86_64', 'aarch64'):
                    name = f'infraternal-{arch}-session-musl'
                    files[name] = ('synthetic ' + name).encode()
            if not verification_only:
                for name in LICENSE_NOTICE_PATHS:
                    if name != missing_license:
                        files[name] = (ROOT / name).read_bytes()
            component_archives = {}
            for os_name, arch in [('linux', 'amd64'), ('linux', 'arm64'), ('darwin', 'amd64'), ('darwin', 'arm64')]:
                filename = f'traefik_v3.7.17_{os_name}_{arch}.tar.gz'
                relative = f'components/{version}/proxy/{os_name}/{arch}/{filename}'
                payload = f'synthetic archive {os_name} {arch}'.encode()
                manifest = {
                    'component': 'traefik', 'version': '3.7.17', 'release_version': version,
                    'os': os_name, 'arch': arch, 'archive_filename': filename,
                    'archive_url': f'https://github.com/traefik/traefik/releases/download/v3.7.17/{filename}',
                    'mirror_path': relative, 'archive_sha256': hashlib.sha256(payload).hexdigest(),
                    'archive_size': len(payload), 'executable': 'traefik',
                    'executable_sha256': hashlib.sha256(b'synthetic executable').hexdigest(),
                    'executable_size': len(b'synthetic executable'), 'license': 'MIT',
                }
                files[f'proxy-traefik-{os_name}-{arch}.json'] = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
                component_archives[relative] = payload
            files["VERSION"] = (version + "\n").encode()
            for name, body in files.items():
                path = bundle / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
            for relative, body in component_archives.items():
                path = bundle / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
            store = {}
            requests = []
            error = [None]
            def sign_store():
                # Hash the uploaded objects, matching the real signer rather than
                # assuming the publisher included every locally built artifact.
                manifest = ''.join(hashlib.sha256(store[version + '/' + name]).hexdigest() + '  ' + name + '\n' for name in sorted(files) if version + '/' + name in store).encode()
                sums = repo / 'SHA256SUMS'
                sums.write_bytes(manifest)
                signature = sums.with_suffix('.sig')
                signature.unlink(missing_ok=True)
                subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'infraternal-release', str(sums)], check=True, capture_output=True)
                store[version + '/SHA256SUMS'] = manifest
                store[version + '/SHA256SUMS.sig'] = signature.read_bytes()
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
                    sign_store()
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
            env = dict(os.environ, CARGO_TARGET_DIR=str(target), XDG_STATE_HOME=str(repo / 'state'), CLOUDFLARE_ACCOUNT_ID='fixture', CLOUDFLARE_API_TOKEN='fixture-cloudflare+/~=', RELEASE_CALLER_TOKEN='fixture-caller+/~=', RELEASE_TEST_ORIGIN=f'http://127.0.0.1:{server.server_port}')
            def run(script, requested=version):
                return subprocess.run([str(repo / 'scripts/release' / script), requested], env=env, capture_output=True, text=True)
            try:
                if missing_session:
                    (bundle / f'infraternal-{missing_session}-session-musl').unlink()
                    self.assertNotEqual(run('publish').returncode, 0)
                    self.assertFalse(requests, "an incomplete new bundle must fail before network work")
                    return
                if missing_license:
                    result = run('publish')
                    self.assertNotEqual(result.returncode, 0, "an incomplete notice bundle must not be published")
                    self.assertFalse(requests, "an incomplete notice bundle must fail before network work")
                    return
                if verification_only:
                    store.update({version + '/' + name: body for name, body in files.items()})
                    sign_store()
                    verified = run('verify')
                    self.assertEqual(verified.returncode, 0, verified.stderr)
                    if include_sessions:
                        for arch in ('x86_64', 'aarch64'):
                            name = f'infraternal-{arch}-session-musl'
                            store[version + '/' + name] = b'tampered'
                            self.assertNotEqual(run('verify').returncode, 0)
                            store[version + '/' + name] = files[name]
                        del store[version + '/infraternal-aarch64-session-musl']
                        self.assertNotEqual(run('verify').returncode, 0)
                    return
                (bundle / "VERSION").write_bytes(b"999.999.999\n")
                self.assertNotEqual(run('publish').returncode, 0)
                self.assertFalse(any(method in ('PUT', 'POST') for method, _ in requests), "wrong local version must fail before publication")
                (bundle / "VERSION").write_bytes((version + "\n").encode())
                result = run('publish')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Published and verified', result.stdout)
                self.assertIsNone(error[0])
                self.assertFalse(any(method == "HEAD" for method, _ in requests))
                puts = {path.split(f'/releases/{version}/', 1)[-1] for method, path in requests if method == 'PUT'}
                self.assertEqual(len(puts), len(files) + len(component_archives))
                self.assertEqual(puts, set(files) | set(component_archives))
                signed_names = {line.split()[1] for line in store[version + '/SHA256SUMS'].decode().splitlines()}
                self.assertTrue(set(LICENSE_NOTICE_PATHS).issubset(signed_names), "signed release manifest omits engine or dependency notices")
                published_names = {
                    key[len(version) + 1:] for key in store
                    if key.startswith(version + '/') and key not in (version + '/SHA256SUMS', version + '/SHA256SUMS.sig')
                }
                self.assertTrue(set(LICENSE_NOTICE_PATHS).issubset(published_names), "published release objects omit engine or dependency notices")
                downloaded_names = {
                    path.split(f'/releases/{version}/', 1)[-1]
                    for method, path in requests if method == 'GET' and f'/releases/{version}/' in path
                }
                self.assertTrue(set(LICENSE_NOTICE_PATHS).issubset(downloaded_names), "public verification did not download every signed notice")
                before = len(requests)
                self.assertNotEqual(run('publish').returncode, 0)
                self.assertFalse(any(r[0] in ('PUT', 'POST') for r in requests[before:]))
                self.assertEqual(run('verify').returncode, 0)
                missing_notice = LICENSE_NOTICE_PATHS[1]
                notice_key = f'{version}/{missing_notice}'
                notice_body = store.pop(notice_key)
                self.assertNotEqual(run('verify').returncode, 0, "public verification must fail if a signed notice is missing")
                store[notice_key] = b'tampered notice'
                self.assertNotEqual(run('verify').returncode, 0, "public verification must fail if a signed notice is changed")
                store[notice_key] = notice_body
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
