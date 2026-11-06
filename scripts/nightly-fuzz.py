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

Timeouts are checked before they are filed: a `timeout-*` input is run again
on its own and filed if it fails again or still takes at least half the time
limit (#370).
"""
import argparse
from dataclasses import dataclass
import base64
import hashlib
import io
import json
import os
import re
import shutil
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


def written_inputs(log_text, artifacts):
    """Artifacts libFuzzer reports writing this run, by its `Test unit written to` line.

    libFuzzer names an artifact after the SHA-1 of its bytes, so re-finding a
    known input rewrites the same file and a before/after name diff sees
    nothing new (review 79752 P3-1). The log line is printed on every write.
    """
    found = []
    for match in re.finditer(r'Test unit written to (\S+)', log_text):
        path = Path(match[1])
        if path.parent == artifacts and path.is_file() and path not in found:
            found.append(path)
    return found


# libFuzzer's per-input time limit, shared by the fuzz run and the timeout re-check
# so both apply the same bar.
TIMEOUT_SECONDS = 10

# A re-check that passes but needs at least this long still files the input:
# an input that takes 7-9 s alone trips the limit under load, and it is a real
# performance bug even when a quiet re-check stays under the limit (#370 review).
SLOW_RECHECK_MS = TIMEOUT_SECONDS * 1000 // 2


def confirmed_inputs(crashes, unconfirmed, reproduces):
    """The artifacts worth filing; timeouts that do not happen again move to `unconfirmed`.

    A panic is a property of the input. A timeout can also be a property of
    the host: libFuzzer measures wall-clock time, and dev-02 is shared with
    build gates. On 2026-11-05 the run started under heavy IO pressure, and
    libFuzzer's opening empty-input call passed the 10 s limit. That input
    then runs in 0 ms on its own (#370).
    `reproduces(path)` runs one input in isolation and says whether it still
    has to be filed (see `reproduces`). Anything that cannot be confirmed is kept on disk, out of the
    artifact directory, so it is neither filed nor re-checked every night.
    A re-check that cannot run at all counts as reproduced, so a real hang is
    never dropped because of a build or tool error.
    """
    kept = []
    for crash in crashes:
        if crash.name.startswith('timeout-') and not reproduces(crash):
            unconfirmed.mkdir(parents=True, exist_ok=True)
            crash.replace(unconfirmed / crash.name)
            print(f'fuzz timeout not reproduced in isolation, not filed: {unconfirmed / crash.name}', flush=True)
            continue
        kept.append(crash)
    return kept


@dataclass(frozen=True)
class Fuzzer:
    """How this checkout starts cargo-fuzz: the toolchain, the shared feature set and the process runner.

    `run` defaults to `subprocess.run`. Tests pass a stand-in that plays
    libFuzzer, so the fuzz, re-check and filing path is exercised without a
    compiler.
    """

    root: Path
    rustup: str
    features: tuple
    environment: dict
    run: object = subprocess.run

    def command(self, name, inputs, flags):
        """`cargo fuzz run` for one harness on a corpus directory or a single input, with libFuzzer flags."""
        return [self.rustup, 'run', 'nightly', 'cargo', 'fuzz', 'run', '--fuzz-dir', 'fuzz', *self.features, name, str(inputs), '--', *flags]

    def execute(self, command, log_path, mode):
        """Run `command` in the checkout with output appended (`a`) or written (`w`) to `log_path`."""
        with log_path.open(mode) as log:
            return self.run(command, cwd=self.root, env=self.environment, stdout=log, stderr=subprocess.STDOUT)


def recheck_flags(recheck):
    """libFuzzer flags for running one input alone: the fuzz run's own time and memory limits, no fuzzing budget.

    The separate artifact prefix keeps the re-check from writing into the
    artifact directory it is judging.
    """
    return [f'-timeout={TIMEOUT_SECONDS}', '-rss_limit_mb=2048', f'-artifact_prefix={recheck}/']


def executed_ms(output, crash):
    """How long libFuzzer says one input ran, from its `Executed <input> in <N> ms` line, or None without one."""
    match = re.search(rf'Executed {re.escape(str(crash))} in (\d+) ms', output)
    return int(match[1]) if match else None


def reproduces(fuzzer, state, name, crash):
    """Run one timeout input alone and say whether it still has to be filed.

    It counts as reproduced on any non-zero exit: a second timeout
    (libFuzzer exits 70), a crash, or a re-check that could not run at all.
    It also counts when it passed but took at least SLOW_RECHECK_MS, or when
    libFuzzer reported no time for it. The time is libFuzzer's own measure
    of the unit, without process start or cargo's checks, so a host that is
    slow to start processes does not file a 0 ms input. Only a quick, clean
    run sets an input aside.
    The output goes to the target's log, after the fuzz run's own output.
    Whatever the re-check writes as artifacts is a copy of an input already
    on disk, so its directory starts empty and is removed afterwards.
    """
    recheck = state / 'recheck' / name
    shutil.rmtree(recheck, ignore_errors=True)
    recheck.mkdir(parents=True)
    log_path = state / f'{name}.log'
    with log_path.open('a') as log:
        log.write(f'\n== re-check of {crash.name} in isolation\n')
    offset = log_path.stat().st_size
    try:
        result = fuzzer.execute(fuzzer.command(name, crash, recheck_flags(recheck)), log_path, 'a')
    finally:
        shutil.rmtree(recheck, ignore_errors=True)
    with log_path.open('rb') as log:
        log.seek(offset)
        elapsed = executed_ms(log.read().decode(errors='replace'), crash)
    return result.returncode != 0 or elapsed is None or elapsed >= SLOW_RECHECK_MS


def run_target(fuzzer, state, name, budget, report):
    """Fuzz one harness for `budget` seconds, re-check its timeouts, file what remains and summarise the run.

    `report(name, crash)` files one input and raises OSError, ValueError or
    KeyError when it cannot. Such a failure is counted, not raised, so it
    does not cost the remaining targets their fuzzing time; the record on
    disk resumes the report next run.
    """
    corpus = state / 'corpus' / name
    artifacts = state / 'artifacts' / name
    corpus.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    # Keep the repository's synthetic seeds without changing tracked files.
    for seed in (fuzzer.root / 'fuzz/corpus' / name).glob('*'):
        destination = corpus / seed.name
        if seed.is_file() and not destination.exists():
            destination.write_bytes(seed.read_bytes())
    flags = [f'-max_total_time={budget}', f'-timeout={TIMEOUT_SECONDS}', '-rss_limit_mb=2048', '-max_len=1048580',
             f'-artifact_prefix={artifacts}/']
    started = time.monotonic()
    result = fuzzer.execute(fuzzer.command(name, corpus, flags), state / f'{name}.log', 'w')
    found = written_inputs((state / f'{name}.log').read_text(errors='replace'), artifacts.resolve())
    before = sorted(path for path in artifacts.iterdir() if path.is_file())
    crashes = confirmed_inputs(before, state / 'unconfirmed' / name, lambda crash: reproduces(fuzzer, state, name, crash))
    unreported = 0
    for crash in crashes:
        try:
            report(name, crash)
        except (OSError, ValueError, KeyError) as error:
            unreported += 1
            print(f'fuzz report FAILED target={name} input={crash.name}: {type(error).__name__}: {error}', flush=True)
    # libFuzzer exits non-zero when it finds an input; that is a finding.
    # A non-zero exit that left no new input is a build or harness error.
    broken = result.returncode != 0 and not found
    set_aside = set(before) - set(crashes)
    # libFuzzer stops at the first input it writes, so a timeout ends this
    # target's fuzzing for the night, even one that was then set aside. Saying
    # so keeps the lost coverage visible when nothing is filed.
    cut_short = any(path.name.startswith('timeout-') for path in found)
    return {'target': name, 'exit': result.returncode, 'seconds': round(time.monotonic() - started, 3),
            'artifacts': len(crashes), 'new_inputs': len([path for path in found if path not in set_aside]),
            'unconfirmed': len(set_aside), 'cut_short_by_timeout': cut_short,
            'broken': broken, 'unreported': unreported}


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
    fuzzer = Fuzzer(root, rustup, tuple(features), environment)

    def report(name, crash):
        """File one input on the target's issue, from this run's checkout."""
        report_crash(args.api, args.repo, args.token_file, state, name, crash, head)

    for name in names:
        entry = run_target(fuzzer, state, name, budget, report)
        failed |= entry['broken'] or entry['unreported'] > 0
        findings += entry['new_inputs']
        summary.append(entry)
        (state / 'last-run.json').write_text(json.dumps({'head': head, 'budget_seconds': args.budget_seconds, 'targets': summary}, indent=2) + '\n')
        cut = f" CUT_SHORT_BY_TIMEOUT after {entry['seconds']}s" if entry['cut_short_by_timeout'] else ''
        print(f"fuzz target={name} exit={entry['exit']} budget_s={budget} artifacts={entry['artifacts']}{cut}", flush=True)
    cut_short = sum(entry['cut_short_by_timeout'] for entry in summary)
    print(f'FUZZ_DONE targets={len(summary)} new_inputs={findings} cut_short={cut_short} failed={failed} head={head}', flush=True)
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
