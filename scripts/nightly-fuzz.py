#!/usr/bin/env python3
"""Run the existing parser fuzz targets within D351's nightly budget on dev-02.

The systemd service reserves a build slot before calling this script. Crashing
inputs are synthetic fuzz data, retained locally and attached to Forgejo issues.
Authentication is read from a private file, never placed in a child command or
logged. Reruns resume incomplete uploads and deduplicate by target and input hash.

Exit status: 0 when every target ran, including nights that found and filed
failing inputs (findings are the point, not a service failure); 1 when
something did not work: a target that failed without leaving an input, or a
report that could not be filed.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import time
import tomllib
import urllib.request
import uuid
import zipfile


def targets(root):
    """Read every existing top-level cargo-fuzz harness from its manifest."""
    return [entry['name'] for entry in tomllib.loads((root / 'fuzz/Cargo.toml').read_text())['bin']]


def required_features(root):
    """Union of the harnesses' `required-features`, so every target builds.

    One shared feature set keeps `cargo fuzz build` and each `cargo fuzz run`
    on the same build instead of rebuilding per target (mesh_node_json needs
    `mesh-node`, and without it the run failed to build).
    """
    bins = tomllib.loads((root / 'fuzz/Cargo.toml').read_text())['bin']
    return sorted({feature for entry in bins for feature in entry.get('required-features', [])})


def target_budget(seconds, names):
    """Divide the nightly mutation budget evenly, refusing an empty run."""
    if not names or seconds < len(names):
        raise ValueError('budget must allow at least one second per target')
    return seconds // len(names)


def api_get(api, route, token):
    """Read one API object, with the same header-only credential handling as posts."""
    request = urllib.request.Request(api.rstrip('/') + '/api/v1/' + route, headers={'Authorization': 'token ' + token})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def api_post(api, route, token, payload, content_type='application/json'):
    """Send credentials in an HTTP header without exposing them in argv or logs."""
    request = urllib.request.Request(api.rstrip('/') + '/api/v1/' + route,
        data=payload, headers={'Authorization': 'token ' + token, 'Content-Type': content_type})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def issue_marker(name):
    """A hidden, deterministic marker that identifies the open issue for one target."""
    return f'<!-- infraternal-fuzz-target: {name} -->'


def find_open_issue(api, route, token, name):
    """The number of an open issue carrying this target's marker, or None.

    Looking the issue up before creating one closes the window where the create
    request succeeded but its response was lost: the retry finds that issue
    instead of opening a duplicate (review finding 79565). Listing reads the
    database directly; the search indexer could lag behind a fresh issue.
    """
    marker = issue_marker(name)
    for page in range(1, 41):
        issues = api_get(api, route + f'/issues?state=open&type=issues&limit=50&page={page}', token)
        for issue in issues:
            if marker in (issue.get('body') or ''):
                return issue['number']
        if len(issues) < 50:
            return None
    return None


def find_comment(api, route, token, issue, digest):
    """The id of an existing comment on `issue` that reports this input digest, or None."""
    for page in range(1, 41):
        comments = api_get(api, route + f'/issues/{issue}/comments?limit=50&page={page}', token)
        for comment in comments:
            if f'SHA-256 `{digest}`' in (comment.get('body') or ''):
                return comment['id']
        if len(comments) < 50:
            return None
    return None


def zipped(name, data):
    """Wrap the exact input in a zip so Forgejo accepts it as an attachment.

    Forgejo only takes listed file types (.zip, .txt, ...), and refused a raw
    `.bin` with HTTP 422 on the first real report (#353). A zip keeps the bytes
    exact, whatever they are, and is on the default allow list.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def report_crash(api, repo, token_file, state, name, crash, head):
    """File a failing input on the target's open issue, or open one, and attach its bytes.

    One open issue per target: a parser bug usually turns up under many inputs,
    one a night, so later inputs become comments on the same issue until it is
    closed. After that, the next input opens a new issue.

    Store the issue and comment identifiers before uploading. If the network
    fails midway, the next run resumes that report instead of filing the same
    input again. A completion marker follows a successful upload.
    """
    data = crash.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    reports = state / 'reports'
    reports.mkdir(parents=True, exist_ok=True)
    record_path = reports / f'{name}-{digest}.json'
    record = json.loads(record_path.read_text()) if record_path.exists() else {}
    if record.get('attached'):
        return
    token = token_file.read_text().strip()
    if not token:
        raise ValueError('empty Forgejo token file')
    route = f'repos/{repo}'
    # Small inputs also go inline as base64, so the report stays useful even
    # if the attachment upload keeps failing.
    inline = f'\nInput (base64): `{base64.b64encode(data).decode()}`\n' if len(data) <= 1024 else ''
    target_issue = reports / f'{name}.issue'
    if 'issue' not in record and target_issue.exists():
        number = int(target_issue.read_text())
        if api_get(api, route + f'/issues/{number}', token).get('state') == 'open':
            record['issue'] = number
            record_path.write_text(json.dumps(record))
    if 'issue' not in record:
        # Issues opened before the marker existed are found via `.issue` above.
        record['issue'] = find_open_issue(api, route, token, name)
    if record.get('issue') is None:
        body = {'title': f'fuzz: {name} found a failing input',
                'body': f'Nightly parser fuzzing (D351, #344).\n\nTarget: `{name}`\nSource: `{head}`\nInput SHA-256: `{digest}`\n{inline}\nReproduce with `cargo +nightly fuzz run {name} <input>`, after unzipping the input attached to the report comment.\n\n{issue_marker(name)}'}
        record['issue'] = api_post(api, route + '/issues', token, json.dumps(body).encode())['number']
    record_path.write_text(json.dumps(record))
    target_issue.write_text(str(record['issue']))
    if 'comment' not in record:
        record['comment'] = find_comment(api, route, token, record['issue'], digest)
    if record.get('comment') is None:
        body = json.dumps({'body': f'Failing input for `{name}` from source `{head}`, SHA-256 `{digest}`.\n{inline}'}).encode()
        record['comment'] = api_post(api, route + f"/issues/{record['issue']}/comments", token, body)['id']
        record_path.write_text(json.dumps(record))
    boundary = 'fuzz-' + uuid.uuid4().hex
    payload = (f'--{boundary}\r\nContent-Disposition: form-data; name="attachment"; filename="{name}-{digest}.zip"\r\nContent-Type: application/zip\r\n\r\n').encode() + zipped(f'{name}-{digest}', data) + f'\r\n--{boundary}--\r\n'.encode()
    api_post(api, route + f"/issues/comments/{record['comment']}/assets", token, payload, 'multipart/form-data; boundary=' + boundary)
    record['attached'] = True
    record_path.write_text(json.dumps(record))
    print(f"filed fuzz input: issue #{record['issue']} target={name} sha256={digest}", flush=True)


def main():
    """Build once, then run every harness serially with bounded memory and time."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--budget-seconds', type=int, default=3600)
    parser.add_argument('--state', type=Path, default=Path.home() / '.local/state/infraternal-fuzz')
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--api', default='https://git.kayg.org')
    parser.add_argument('--repo', default='kayg/infraternal')
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(__file__).resolve().parents[1]
    state = args.state.resolve()
    state.mkdir(parents=True, exist_ok=True)
    names = targets(root)
    budget = target_budget(args.budget_seconds, names)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    tool_root = Path.home() / '.local/share/infraternal-fuzz'
    environment = dict(os.environ, CARGO_PROFILE_RELEASE_LTO='false', CARGO_BUILD_JOBS='3',
                       RUSTUP_HOME=str(tool_root / 'rustup'), CARGO_HOME=str(tool_root / 'cargo'))
    # The dev shell's rustup shim supports only its pinned compiler, not nightly.
    rustup = '/usr/local/bin/rustup'
    environment['PATH'] = str(tool_root / 'cargo/bin') + ':/usr/local/bin:' + environment['PATH']
    environment['RUSTC'] = subprocess.check_output([rustup, 'which', '--toolchain', 'nightly', 'rustc'], text=True, env=environment).strip()
    environment['RUSTDOC'] = subprocess.check_output([rustup, 'which', '--toolchain', 'nightly', 'rustdoc'], text=True, env=environment).strip()
    # Build failures are infrastructure failures: never create a parser-crash issue for them.
    features = ['--features', ','.join(required_features(root))] if required_features(root) else []
    subprocess.run([rustup, 'run', 'nightly', 'cargo', 'fuzz', 'build', '--fuzz-dir', 'fuzz', *features], cwd=root, env=environment, check=True)
    failed = False
    findings = 0
    summary = []
    for name in names:
        corpus = state / 'corpus' / name
        artifacts = state / 'artifacts' / name
        corpus.mkdir(parents=True, exist_ok=True)
        artifacts.mkdir(parents=True, exist_ok=True)
        # Keep the repository's synthetic seeds without changing tracked files.
        for seed in (root / 'fuzz/corpus' / name).glob('*'):
            destination = corpus / seed.name
            if seed.is_file() and not destination.exists():
                destination.write_bytes(seed.read_bytes())
        command = [rustup, 'run', 'nightly', 'cargo', 'fuzz', 'run', '--fuzz-dir', 'fuzz', *features, name, str(corpus), '--',
                   f'-max_total_time={budget}', '-timeout=10', '-rss_limit_mb=2048', '-max_len=1048580', f'-artifact_prefix={artifacts}/']
        started = time.monotonic()
        before = {path.name for path in artifacts.iterdir()}
        with (state / f'{name}.log').open('w') as log:
            result = subprocess.run(command, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT)
        crashes = sorted(path for path in artifacts.iterdir() if path.is_file())
        found = [path for path in crashes if path.name not in before]
        unreported = 0
        for crash in crashes:
            # A reporting failure must not cost the remaining targets their
            # fuzzing time. The record on disk resumes the report next run.
            try:
                report_crash(args.api, args.repo, args.token_file, state, name, crash, head)
            except (OSError, ValueError, KeyError) as error:
                unreported += 1
                print(f'fuzz report FAILED target={name} input={crash.name}: {type(error).__name__}: {error}', flush=True)
        # libFuzzer exits non-zero when it finds an input; that is a finding.
        # A non-zero exit that left no new input is a build or harness error.
        broken = result.returncode != 0 and not found
        failed |= broken or unreported > 0
        findings += len(found)
        summary.append({'target': name, 'exit': result.returncode, 'seconds': round(time.monotonic() - started, 3),
                        'artifacts': len(crashes), 'new_inputs': len(found), 'broken': broken, 'unreported': unreported})
        (state / 'last-run.json').write_text(json.dumps({'head': head, 'budget_seconds': args.budget_seconds, 'targets': summary}, indent=2) + '\n')
        print(f'fuzz target={name} exit={result.returncode} budget_s={budget} artifacts={len(crashes)}', flush=True)
    print(f'FUZZ_DONE targets={len(summary)} new_inputs={findings} failed={failed} head={head}', flush=True)
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
