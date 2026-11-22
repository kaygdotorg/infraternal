#!/usr/bin/env python3
"""Local release-bucket/signer stand-ins test publication, immutability and verification [224]."""
import hashlib
import hmac
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

ACCESS_KEY = 'FIXTUREACCESSKEY0123456789abcdef'
SECRET_KEY = 'fixture-secret+/~=0123456789abcdefABCDEF'


def sigv4_problem(handler, body, secret=SECRET_KEY, access=ACCESS_KEY):
    """Recompute curl's SigV4 signature; return why it is wrong, or None.

    The loopback origin is only a faithful stand-in when it rejects what R2
    would reject: wrong scope, unsigned host/date/payload hash, bad signature.
    """
    header = handler.headers.get('Authorization', '')
    match = __import__('re').fullmatch(
        r'AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/auto/s3/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})', header)
    if not match:
        return 'authorization header shape'
    key, day, signed, signature = match.groups()
    if key != access or not handler.headers.get('User-Agent'):
        return 'access key or user agent'
    names = signed.split(';')
    for required in ('host', 'x-amz-date'):
        if required not in names:
            return 'unsigned ' + required
    if handler.headers['x-amz-date'][:8] != day:
        return 'date scope'
    payload = handler.headers.get('x-amz-content-sha256')
    if handler.command == 'PUT' and (payload != hashlib.sha256(body).hexdigest() or 'x-amz-content-sha256' not in names):
        return 'payload hash'
    url = urllib.parse.urlsplit(handler.path)
    query = sorted((urllib.parse.quote(k, safe='-_.~'), urllib.parse.quote(v, safe='-_.~'))
                   for k, v in urllib.parse.parse_qsl(url.query, keep_blank_values=True))
    canonical = '\n'.join([
        handler.command, url.path, '&'.join(f'{k}={v}' for k, v in query),
        ''.join(f'{n}:{handler.headers[n].strip()}\n' for n in names), signed,
        payload or hashlib.sha256(b'').hexdigest()])
    scope = f'{day}/auto/s3/aws4_request'
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', handler.headers['x-amz-date'], scope, hashlib.sha256(canonical.encode()).hexdigest()])
    derived = ('AWS4' + secret).encode()
    for part in (day, 'auto', 's3', 'aws4_request'):
        derived = hmac.new(derived, part.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(hmac.new(derived, to_sign.encode(), hashlib.sha256).hexdigest(), signature):
        return 'signature mismatch'
    return None


def curl_argv_leaks(port):
    """Return argv of live curl children aimed at this port that carry a secret."""
    leaks = []
    seen = 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if not argv or Path(argv[0].decode(errors='replace')).name != 'curl' or f'127.0.0.1:{port}'.encode() not in b' '.join(argv):
            continue
        seen += 1
        joined = b' '.join(argv)
        if any(secret.encode() in joined for secret in (SECRET_KEY, ACCESS_KEY, 'fixture-caller+/~=')):
            leaks.append(joined)
    return seen, leaks


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
            # The web build stand-in: a tiny archive, so the test needs no bun (#211 S6).
            (repo / 'scripts/release/web-archive').write_text('#!/usr/bin/env bash\nset -eu\nprintf "web-fixture\\n" > "$1"\n')
            (repo / 'scripts/release/web-archive').chmod(0o755)
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
                self.assertEqual((bundle / 'infraternal-web.tar').read_text(), 'web-fixture\n')
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
            self.darwin_bundle(repo, build, stable)
            for version in ('1.2','1.2.3-rc1','edge-20261011t071500Z','edge-20261011T071500z','../1.2.3','1.2.3\n'):
                for name in ('publish','verify'):
                    result = subprocess.run([str(repo / 'scripts/release' / name),version],env=env,text=True,capture_output=True)
                    self.assertEqual(result.returncode,2,result.stderr)

    def darwin_bundle(self, repo, build, stable):
        """--darwin adds the Mac binary under its own stamped version, and refuses a wrong one (#483)."""
        header = bytes.fromhex('cffaedfe0c000001')
        def darwin(name, version, body=None):
            directory = repo / name
            directory.mkdir()
            (directory / 'VERSION').write_text(version + '\n')
            (directory / 'infraternal-aarch64-darwin').write_bytes(body if body is not None else header + b'\0' * 24 + version.encode())
            return str(directory)
        version = 'edge-20261110T010203Z'
        result = build('--channel', 'edge', '--darwin', darwin('mac-edge', version))
        self.assertEqual(result.returncode, 0, result.stderr)
        bundle = repo / 'target/releases' / version
        self.assertEqual((bundle / 'infraternal-x86_64-musl').read_text(), version + '\n', 'Linux payloads take the Mac build version')
        self.assertEqual((bundle / 'infraternal-aarch64-darwin').read_bytes(), (repo / 'mac-edge/infraternal-aarch64-darwin').read_bytes())
        self.assertIn('infraternal-aarch64-darwin', {line.split()[1] for line in (bundle / 'SHA256SUMS').read_text().splitlines()})
        self.assertEqual(subprocess.run(['sha256sum', '--strict', '--check', 'SHA256SUMS'], cwd=bundle, capture_output=True).returncode, 0)
        refusals = (
            ('stable', darwin('mac-stable-edge', 'edge-20261110T010204Z')),
            ('edge', darwin('mac-edge-stable', stable)),
            ('edge', darwin('mac-elf', 'edge-20261110T010205Z', b'\x7fELF' + b'\0' * 60 + b'edge-20261110T010205Z')),
            ('edge', darwin('mac-unstamped', 'edge-20261110T010206Z', header + b'\0' * 24 + b'edge-20261110T010207Z')),
            ('edge', darwin('mac-bad-version', '../1.2.3')),
            ('edge', str(repo / 'mac-missing')),
        )
        for channel, directory in refusals:
            with self.subTest(channel=channel, directory=directory):
                result = build('--channel', channel, '--darwin', directory)
                self.assertNotEqual(result.returncode, 0, directory)
        self.assertEqual(build('--channel', 'edge', '--other', darwin('mac-flag', 'edge-20261110T010208Z')).returncode, 2)

    def test_scripts_exist(self):
        for name in ('build', 'publish', 'verify'):
            self.assertTrue((ROOT / 'scripts/release' / name).is_file(), name)

    def test_release_json_rejects_duplicates_at_every_depth(self):
        # The Worker's answer is decoded strictly: nested objects must be as
        # unambiguous as the outer envelope.
        for body in (
            '{"version":"first","version":"second"}',
            '{"index":[{"version":"first","version":"second"}]}',
        ):
            with self.subTest(body=body):
                result = subprocess.run(
                    ['python3', str(ROOT / 'scripts/release/response.py'), 'signed'],
                    input=body, text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'duplicate JSON fields in the release response\n')

    def test_s3_list_pages_are_parsed_strictly(self):
        ns = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
        def page(extra='', name='infraternal-builds', prefix='releases/1/', count='0', truncated='false'):
            return (f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult {ns}><Name>{name}</Name>'
                    f'<Prefix>{prefix}</Prefix><KeyCount>{count}</KeyCount><MaxKeys>10</MaxKeys>'
                    f'<IsTruncated>{truncated}</IsTruncated>{extra}</ListBucketResult>')
        def check(body):
            return subprocess.run(['python3', str(ROOT / 'scripts/release/response.py'), 's3-empty-prefix', 'infraternal-builds', 'releases/1/'],
                                  input=body, text=True, capture_output=True)
        ok = check(page())
        self.assertEqual((ok.returncode, ok.stdout), (0, ''))
        more = check(page(extra='<NextContinuationToken>1abc+/=</NextContinuationToken>', truncated='true'))
        self.assertEqual((more.returncode, more.stdout), (0, '1abc+/=\n'))
        for label, body in (
            ('object', page(extra='<Contents><Key>releases/1/x</Key></Contents>', count='1')),
            ('object hidden behind a zero count', page(extra='<Contents><Key>releases/1/x</Key></Contents>')),
            ('folder', page(extra='<CommonPrefixes><Prefix>releases/1/a/</Prefix></CommonPrefixes>')),
            ('duplicate field', page(extra='<KeyCount>0</KeyCount>')),
            ('wrong bucket', page(name='other')),
            ('wrong prefix', page(prefix='releases/')),
            ('truncated without token', page(truncated='true')),
            ('token on a final page', page(extra='<NextContinuationToken>a</NextContinuationToken>')),
            ('bad token bytes', page(extra='<NextContinuationToken>a&amp;b</NextContinuationToken>', truncated='true')),
            ('unknown element', page(extra='<Surprise/>')),
            ('entity', '<!DOCTYPE x [<!ENTITY e "x">]>' + page()),
            ('not xml', 'nope'),
            ('json', '{"success":true,"result":[]}'),
            ('wrong root', '<Error><Code>AccessDenied</Code></Error>'),
            ('too large', page(extra='<Delimiter>' + 'a' * 1_100_000 + '</Delimiter>')),
        ):
            with self.subTest(label):
                result = check(body)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'release exists or the release response cannot be verified\n')

    def test_local_publication_is_verified_and_immutable(self):
        self.local_publication(tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version'])

    def test_edge_publication_is_verified_and_immutable(self):
        self.local_publication('edge-20261011T071500Z')

    def test_signed_session_images_are_verified(self):
        self.local_publication('0.1.0', verification_only=True)

    def test_signed_macos_binary_is_published_and_verified(self):
        """A bundle built with --darwin publishes the Mac binary under the signed manifest (#483)."""
        self.local_publication('edge-20261110T010203Z', include_darwin=True)

    def test_signed_macos_binary_is_checked_on_verification(self):
        self.local_publication('0.1.0', verification_only=True, include_darwin=True)

    def test_older_signed_releases_without_session_images_are_verified(self):
        self.local_publication('0.1.0', include_sessions=False, verification_only=True)

    def test_existing_or_partial_objects_refuse_publication(self):
        for name in ('infraternal', 'components/0.1.0/proxy/linux/amd64/partial'):
            with self.subTest(name=name):
                self.local_publication('0.1.0', preexisting=name)

    def test_truncated_empty_list_pages_are_followed(self):
        self.local_publication('0.1.0', truncated_pages=True)

    def test_new_publication_requires_both_session_images_before_upload(self):
        for arch in ('x86_64', 'aarch64'):
            with self.subTest(architecture=arch):
                self.local_publication('0.1.0', missing_session=arch)

    def test_new_publication_requires_all_engine_and_dependency_notices_before_upload(self):
        """Reject a new signed bundle before any network request if one notice is absent."""
        self.local_publication('0.1.0', missing_license=LICENSE_NOTICE_PATHS[1])

    def local_publication(self, version, include_sessions=True, verification_only=False, missing_session=None, missing_license=None, include_darwin=False, truncated_pages=False, preexisting=None):
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
            if include_darwin:
                files['infraternal-aarch64-darwin'] = b'synthetic infraternal-aarch64-darwin'
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
            signature_problems = []
            curl_seen = [0]
            curl_leaks = []
            truncated_empty_pages = [truncated_pages]
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
                    body = self.rfile.read(int(self.headers['Content-Length']))
                    self.check_curl_argv()
                    problem = sigv4_problem(self, body)
                    if problem or not self.path.startswith('/s3/infraternal-builds/releases/'):
                        signature_problems.append(problem or 'path')
                        self.respond(403)
                        return
                    if self.headers.get('If-None-Match') != '*':
                        signature_problems.append('missing If-None-Match')
                        self.respond(400)
                        return
                    name = self.object_name()
                    if name in store:
                        self.respond(412)
                        return
                    store[name] = body
                    self.respond(200)
                def check_curl_argv(self):
                    seen, leaks = curl_argv_leaks(server.server_port)
                    curl_seen[0] += seen
                    curl_leaks.extend(leaks)
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
                    if parsed.path == '/s3/infraternal-builds':
                        self.check_curl_argv()
                        problem = sigv4_problem(self, b'')
                        query = urllib.parse.parse_qs(parsed.query)
                        if problem or query.get('list-type') != ['2']:
                            signature_problems.append(problem or 'list shape')
                            self.respond(403)
                            return
                        prefix = query['prefix'][0].removeprefix('releases/')
                        keys = [name for name in store if name.startswith(prefix)]
                        page = ''
                        token = query.get('continuation-token', [None])[0]
                        if truncated_empty_pages[0] and token is None:
                            page = '<NextContinuationToken>tok1</NextContinuationToken>'
                            truncated, keys = 'true', []
                        else:
                            truncated = 'false'
                        if truncated_empty_pages[0] and token not in (None, 'tok1'):
                            self.respond(403)
                            return
                        contents = ''.join(f'<Contents><Key>releases/{k}</Key></Contents>' for k in keys[:1])
                        self.respond(200, (f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                                           f'<Name>infraternal-builds</Name><Prefix>releases/{prefix}</Prefix><KeyCount>{min(len(keys), 1)}</KeyCount>'
                                           f'<MaxKeys>10</MaxKeys><IsTruncated>{truncated}</IsTruncated>{page}{contents}</ListBucketResult>').encode())
                        return
                    body = store.get(self.object_name())
                    self.respond(200 if body is not None else 404, body or b'')
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            env = dict(os.environ, CARGO_TARGET_DIR=str(target), XDG_STATE_HOME=str(repo / 'state'), CLOUDFLARE_ACCOUNT_ID='fixture', R2_ACCESS_KEY_ID=ACCESS_KEY, R2_SECRET_ACCESS_KEY=SECRET_KEY, RELEASE_CALLER_TOKEN='fixture-caller+/~=', RELEASE_TEST_ORIGIN=f'http://127.0.0.1:{server.server_port}')
            env.pop('CLOUDFLARE_API_TOKEN', None)
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
                        store[version + '/infraternal-aarch64-session-musl'] = files['infraternal-aarch64-session-musl']
                        sign_store()
                    if include_darwin:
                        name = version + '/infraternal-aarch64-darwin'
                        self.assertEqual(run('verify').returncode, 0)
                        store[name] = b'tampered'
                        self.assertNotEqual(run('verify').returncode, 0, 'a changed signed Mac binary must fail verification')
                        del store[name]
                        self.assertNotEqual(run('verify').returncode, 0, 'an advertised Mac binary must be downloadable')
                    return
                if preexisting:
                    # A partial or unrelated object under the prefix refuses publication.
                    store[f'{version}/{preexisting}'] = b'old'
                    result = run('publish')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(any(m in ('PUT', 'POST') for m, _ in requests), 'an existing object must stop publication before any write')
                    self.assertEqual(signature_problems, [])
                    return
                for name in ('R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY'):
                    saved = env.pop(name)
                    self.assertEqual(run('publish').returncode, 1, name)
                    env[name] = saved
                self.assertFalse(requests, 'missing credentials must fail before network work')
                env['R2_SECRET_ACCESS_KEY'] = 'wrong-secret'
                self.assertNotEqual(run('publish').returncode, 0)
                self.assertFalse(any(m in ('PUT', 'POST') for m, _ in requests), 'a bad signature must stop publication')
                env['R2_SECRET_ACCESS_KEY'] = SECRET_KEY
                signature_problems.clear()
                del requests[:]
                (bundle / "VERSION").write_bytes(b"999.999.999\n")
                self.assertNotEqual(run('publish').returncode, 0)
                self.assertFalse(any(method in ('PUT', 'POST') for method, _ in requests), "wrong local version must fail before publication")
                (bundle / "VERSION").write_bytes((version + "\n").encode())
                result = run('publish')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Published and verified', result.stdout)
                self.assertEqual(signature_problems, [], 'every S3 request carries a valid SigV4 signature')
                self.assertGreater(curl_seen[0], 0, 'the live curl children were inspected')
                self.assertEqual(curl_leaks, [], 'no secret may appear in curl argv')
                for secret in (SECRET_KEY, ACCESS_KEY, 'fixture-caller+/~='):
                    self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertFalse(any('api' in path.split('/')[1:2] for _, path in requests), 'the REST objects API is no longer used')
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
