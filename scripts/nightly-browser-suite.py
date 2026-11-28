#!/usr/bin/env python3
"""Run the full tracer browser suite on the latest dev, and report failing specs (D373, #443).

The nightly fuzz (D361, `nightly-fuzz.py`) is the pattern: a systemd timer on
dev-02 holds a build slot, a run produces results, and a reporter files
Forgejo issues with a token read from a private file. Two subcommands keep the
token away from the code under test:

- `run` builds the tracer for production and runs the whole Playwright suite
  (`bun x playwright test` in apps/tracer) with the JSON reporter. It executes
  the checked-out dev code, which nobody has reviewed yet, so it runs in an
  account that cannot read the Forgejo token.
- `report` reads what `run` left behind and talks to Forgejo. It is installed
  as a root-owned copy of a reviewed commit and runs in the token's account.

Reporting rules, one issue per failing spec *file* (`docs-palette.spec.ts`):
- A failing spec with an open issue carrying its hidden marker gets no second
  issue, so a red that lasts a month is one issue, not thirty.
- A spec that passes again gets one "passes again" comment. The issue stays
  open: only the owner closes issues. If it fails again afterwards, it gets
  one "failing again" comment.
- The state is read back from the issue's own comments (the newest hidden
  state marker wins), so a lost local file or a retried night never repeats a
  comment.
- A run that produced no usable results (build failure, crashed server, no
  JSON) is an infrastructure failure: exit status 1, no spec issues.
- At most MAX_NEW_ISSUES new issues a night and MAX_OPEN_ISSUES open at once.
  More, or a mostly red suite, becomes one roll-up issue.
- The suite's output is hostile data (see `report`): hashed markers, validated
  names, bounded fields, Markdown fences no content can close, and only
  markers written by the token's own account are believed.

Exit status of `run`: 0 when results were written, even if specs failed; 1 when
the build or the suite could not run at all. Exit status of `report`: 0 when
every issue and comment was filed, 1 when a request failed.
"""
import argparse
import collections
import datetime
import functools
import hashlib
import json
import os
import re
import math
import shutil
import statistics
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

# The suite's own test-server port. verify_latency defaults to 4621, which other
# jobs on the shared build VM may be using at the same moment.
TEST_PORT = '4731'

# How many Playwright shards the nightly runs side by side, each with its own test server, build folder and build slot.
# The service helper takes this many slots; a test keeps the two numbers equal.
SHARDS = 2
# Tests tagged with this (frame budgets, benchmarks) run on the performance VM, not on shared hosts, so the nightly leaves them out.
PERF_TAG = '@perf'
# The previous night's seconds per spec file, kept next to the runs, so the next night can balance its shards.
FILE_TIMES = 'file-times.json'
MAX_SHARD = 16

# How many finished runs `run` keeps next to the new one; older ones are removed.
KEEP_RUNS = 7

# Where the operator-readable runs are published on dev-02. The reporter builds
# evidence and log paths from this and the validated run name, never from a path
# the suite wrote.
BROWSER_RUNS = '/var/lib/infraternal-browser-pub'

# A run directory is `<UTC stamp>-<first seven hex of the commit>`.
RUN_NAME = re.compile(r'\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{7}\Z', re.ASCII)
HEAD = re.compile(r'\A[0-9a-f]{40}\Z', re.ASCII)
# A spec file as Playwright names it, relative to the test folder. Anything
# else (spaces, `-->`, newlines, `..`) is pooled under UNPARSEABLE.
SPEC_NAME = re.compile(r'\A(?!.*\.\.)[A-Za-z0-9._/-]{1,120}\.spec\.ts\Z', re.ASCII)
UNPARSEABLE = '(unparseable spec names)'
ROLLUP = '(roll-up)'

# More new red specs than this in one night, or a mostly red suite, is filed as
# one roll-up issue: it is more likely a dead test server than that many bugs.
MAX_NEW_ISSUES = 10
# The most suite issues kept open at once; with that many open, new reds go to the roll-up
# instead, so dev code that fails fresh names every night cannot grow the list without end.
MAX_OPEN_ISSUES = 30
ROLLUP_MIN_FAILING = 5

# Byte caps for what the reporter will read, and text caps for what it will write.
# Exit status when Forgejo refuses the token (401 or 403): distinct, so the journal and the unit say so.
TOKEN_REFUSED_EXIT = 77
# A Forgejo account name as the reporter accepts it (it is compared with issue and comment authors).
LOGIN = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z', re.ASCII)
MAX_RESULTS_BYTES = 32 << 20
MAX_JSONL_BYTES = 32 << 20
MAX_MERGED_REPORT_BYTES = 32 << 20
MAX_JSONL_LINES = 200000
MAX_PLANNED_TESTS = 50000
MAX_UNRUN_FILES_IN_NOTE = 40
DEADLINE_REASON = 'deadline-0745-ist'
TIMEOUT_LABEL = re.compile(r'\A[0-9]{1,3}h\Z', re.ASCII)
MAX_LOG_BYTES = 16 << 20
MAX_META_BYTES = 64 << 10
MAX_LINE = 300
MAX_ERROR = 3000
MAX_BODY = 60000

SPEC_MARKER = re.compile(r'<!-- infraternal-browser-spec: ([0-9a-f]{16}) -->')
STATE_MARKER = re.compile(r'<!-- infraternal-browser-state: (failing|fixed) -->')
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def spec_marker(spec):
    """The hidden marker that ties an issue to one spec file: a hash of the name, so no odd character can break it."""
    return f'<!-- infraternal-browser-spec: {hashlib.sha256(spec.encode()).hexdigest()[:16]} -->'


def state_marker(state):
    """The hidden marker a comment carries so the issue's own history says what was last reported."""
    return f'<!-- infraternal-browser-state: {state} -->'


def read_regular(path, cap, tail=False):
    """Read a regular file of at most `cap` bytes, refusing links, pipes and devices.

    The file is opened without following a final symlink and without blocking
    (so a FIFO cannot hang the reader), then checked with `fstat` on the open
    descriptor, so nothing can be swapped in after the check. With `tail=True`
    an oversized file yields its last `cap` bytes instead of an error.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f'{path} is not a plain regular file with a single name')
        if info.st_size > cap:
            if not tail:
                raise ValueError(f'{path} is larger than {cap} bytes')
            os.lseek(descriptor, info.st_size - cap, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), 'rb') as handle:
            return handle.read(cap + 1)[:cap]
    finally:
        os.close(descriptor)


# ---------------------------------------------------------------- run side


def run_step(command, cwd, log, env=None):
    """Run one step with its output appended to `log`; return its exit status."""
    with log.open('a') as handle:
        handle.write(f'\n== {" ".join(command)}\n')
        handle.flush()
        return subprocess.run(command, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT).returncode


def prune_runs(runs, keep):
    """Delete all but the newest `keep` run directories (names start with a UTC stamp)."""
    old = sorted(path for path in runs.iterdir() if path.is_dir())[:-keep]
    for path in old:
        shutil.rmtree(path, ignore_errors=True)


def atomic_write_bytes(path, data):
    """Publish complete bytes through a same-directory temporary file and rename.

    The file is synced before it becomes visible, then its directory is synced
    so a completed report survives a host restart. A unique temporary name
    also means a previous retry cannot leave a partial file at the public name.
    """
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.tmp', dir=path.parent)
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        os.fsync(directory)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        os.close(directory)


def atomic_write_json(path, value):
    """Write one JSON document with the durable, atomic publication rule."""
    atomic_write_bytes(path, (json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode())


def load_times(runs):
    """Seconds per spec file from the previous night, or {} when there is nothing usable.

    The file is only a hint for balancing the shards, so anything wrong with it
    (missing, a link, too big, not JSON, bad names or numbers) just means "no
    times". Entries with a bad name or a negative or non-finite number are dropped.
    """
    try:
        data = json.loads(read_regular(runs / FILE_TIMES, 1 << 20))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {name: float(seconds) for name, seconds in data.items()
            if SPEC_NAME.fullmatch(name) and isinstance(seconds, (int, float)) and not isinstance(seconds, bool)
            and math.isfinite(seconds) and seconds >= 0}


def assign(files, times, shards):
    """Split `files` into `shards` groups, longest first, each file to the least loaded group.

    Files without a recorded time weigh the median of the known ones. If no
    file has a time yet, each file weighs one second and the explicit split
    still records which shard owns it; a report can then name an unstarted
    shard's files instead of guessing what Playwright assigned.
    """
    known = [times[name] for name in files if name in times]
    fill = statistics.median(known) if known else 1.0
    weight = {name: times.get(name, fill) for name in files}
    groups, loads = [[] for _ in range(shards)], [0.0] * shards
    for name in sorted(files, key=lambda name: (-weight[name], name)):
        index = loads.index(min(loads))
        groups[index].append(name)
        loads[index] += weight[name]
    return [sorted(group) for group in groups]


def start_shard(command, cwd, env, log, lock, label):
    """Start one Playwright shard; its output is copied, line by line, into the shared `log` with a `[label]` prefix.

    Returns `(process, pump thread)`. The shards write into one `suite.log`
    live (so a run that is stopped still has its log), and the lock keeps their
    lines whole.
    """
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors='replace', bufsize=1)

    def pump():
        """Copy the shard's output into the shared log until it closes."""
        for line in process.stdout:
            with lock, log.open('a') as handle:
                handle.write(f'[{label}] {line}')
    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    return process, thread


def base_port(environment):
    """The first port of the shards' range: 4731, or `NIGHTLY_BASE_PORT` (1024-65000) to run beside another run on the same host."""
    raw = environment.get('NIGHTLY_BASE_PORT')
    if raw is None:
        return int(TEST_PORT)
    if not re.fullmatch(r'[0-9]{4,5}', raw, re.ASCII) or not 1024 <= int(raw) <= 65000:
        raise ValueError('NIGHTLY_BASE_PORT must be a TCP port between 1024 and 65000')
    return int(raw)


def shard_env(base, out, jsonl, shard, shards, first_port=int(TEST_PORT)):
    """The environment of one shard: its own port pair, build folder, evidence folder and JSON report; the shared jsonl and its number."""
    port = first_port + 2 * (shard - 1)
    return dict(base, TRACER_TEST_PORT=str(port), TRACER_BACKEND_PORT=str(port + 1), TRACER_DIST=str(out / f'shard{shard}' / 'dist'),
                INFRATERNAL_EVIDENCE_DIR=str(out / 'evidence' / f'shard{shard}'),
                PLAYWRIGHT_JSON_OUTPUT_NAME=str(out / f'shard{shard}' / 'results.json'),
                NIGHTLY_JSONL=str(jsonl), NIGHTLY_SHARD=str(shard), NIGHTLY_SHARDS=str(shards))


def record_times(runs, jsonl_data, files):
    """Write `file-times.json` from the merged jsonl: summed seconds per spec file, only for files that still exist."""
    seconds = {}
    for line in jsonl_data.decode(errors='replace').splitlines()[:MAX_JSONL_LINES]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if (isinstance(item, dict) and item.get('kind') == 'test'
                and isinstance(item.get('ms'), (int, float)) and not isinstance(item.get('ms'), bool)):
            file = clean_name(item.get('file'))
            name = file.removeprefix('test/')
            if name in files:
                seconds[name] = seconds.get(name, 0.0) + item['ms'] / 1000
    atomic_write_json(runs / FILE_TIMES, {name: round(value, 3) for name, value in seconds.items()})


def run(root, runs, shards=SHARDS):
    """Build the tracer, run the whole suite in `shards` parallel shards, and leave a durable run manifest and raw results.

    The run directory is `<runs>/<UTC stamp>-<sha7>`. Its name goes into
    `<runs>/latest` (the bare run name) and a first `meta.json` is written
    *before* the suite starts, so that if the suite is stopped by its time
    budget the helper still knows where to find the partial results and the
    spec files assigned to each shard.

    Each shard is its own `playwright test` with its own test server (a port
    pair), build folder and evidence folder, because the specs of one server
    share a single test double (#377). The spec files are split longest-first
    by the previous night's seconds (`file-times.json`), or by Playwright's
    explicit equal-weight files when there are no usable times. The custom reporter
    (`apps/tracer/nightly-reporter.ts`) of every shard appends one line per
    finished test to the *one* `results.jsonl`, tagged with its shard number, so
    the file is merged by construction and a stopped run still leaves it. When a
    shard ends, this function appends a `shard` line with its exit status. All
    output goes to one `suite.log`, each line prefixed `[s1]`, `[s2]`.

    Returns 0 when at least one shard streamed results (a crashed shard is
    described in the report instead of hiding the others), 1 when none did.
    """
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = runs / f'{stamp}-{head[:7]}'
    (out / 'evidence').mkdir(parents=True)
    log = out / 'suite.log'
    tracer = root / 'apps/tracer'
    jsonl = out / 'results.jsonl'
    jsonl.write_text('')
    env = dict(os.environ, TRACER_TEST_PORT=TEST_PORT, INFRATERNAL_EVIDENCE_DIR=str(out / 'evidence'))
    files = sorted(path.name for path in (tracer / 'test').glob('*.spec.ts'))
    groups = assign(files, load_times(runs), shards) if shards > 1 else [files]
    meta = {
        'schema': 2,
        'head': head,
        'evidence': str(out / 'evidence'),
        'log': str(log),
        'playwright_exit': None,
        'shards': [{'shard': number, 'of': shards, 'exit': None, 'seconds': None,
                    'files': ['test/' + name for name in groups[number - 1]]}
                   for number in range(1, shards + 1)],
    }
    atomic_write_json(out / 'meta.json', meta)
    atomic_write_bytes(runs / 'latest', (out.name + '\n').encode())
    # Build failures are infrastructure failures: no spec issue is opened for them. (Each shard builds its own copy.)
    check_env = dict(env, TRACER_DIST=str(out / 'build-check'))
    for command in (['bun', 'install', '--frozen-lockfile'], ['bun', 'run', 'build'],
                    ['bun', 'x', 'playwright', 'install', 'chromium']):
        if run_step(command, tracer, log, check_env) != 0:
            print(f'browser suite: {" ".join(command)} failed, see {log}', flush=True)
            return 1
    shutil.rmtree(out / 'build-check', ignore_errors=True)
    first_port = base_port(os.environ)
    lock = threading.Lock()
    started = []
    for shard in range(1, shards + 1):
        # `list` keeps readable progress in the log, `json` is the shard's full report, and the custom reporter streams a line per test.
        command = ['bun', 'x', 'playwright', 'test', '--reporter=list,json,./nightly-reporter.ts', f'--grep-invert={PERF_TAG}']
        if shards > 1:
            command.extend('test/' + re.escape(name) + '$' for name in groups[shard - 1])
        (out / f'shard{shard}').mkdir()
        started.append((shard, time.monotonic(), *start_shard(command, tracer, shard_env(env, out, jsonl, shard, shards, first_port), log, lock, f's{shard}')))
    for shard, began, process, thread in started:
        code = process.wait()
        thread.join(10)
        seconds = round(time.monotonic() - began)
        entry = {'kind': 'shard', 'shard': shard, 'of': shards, 'exit': code, 'seconds': seconds,
                 'files': ['test/' + name for name in groups[shard - 1]]}
        with lock, jsonl.open('a') as handle:
            handle.write(json.dumps(entry) + '\n')
        meta['shards'][shard - 1].update(exit=code, seconds=seconds)
        atomic_write_json(out / 'meta.json', meta)
    data = read_regular(jsonl, MAX_JSONL_BYTES, tail=True)
    summary = shard_summary(data)
    if not any(info['planned'] is not None for info in summary.values()):
        print(f'browser suite: no shard started a run (exits {[m["exit"] for m in meta["shards"]]}), see {log}', flush=True)
        return 1
    record_times(runs, data, set(files))
    meta['playwright_exit'] = max(m['exit'] for m in meta['shards'])
    atomic_write_json(out / 'meta.json', meta)
    prune_runs(runs, KEEP_RUNS)
    print(f'BROWSER_SUITE_DONE shards={[m["exit"] for m in meta["shards"]]} head={head} out={out}', flush=True)
    return 0


# ------------------------------------------------------------ report side
#
# Everything under `results` was written by the unreviewed suite, so it is
# treated as hostile data: bounded reads, validated names, and no path, SHA or
# link taken from it. The service helper additionally copies the three files
# into a staging folder owned by this account (see nightly-browser-suite-service).


def clean_name(name):
    """The spec file name if it is well formed, else the pooled UNPARSEABLE name."""
    return name if isinstance(name, str) and SPEC_NAME.fullmatch(name) else UNPARSEABLE


def collect(report):
    """Sort a Playwright JSON report's spec files into failing and passing.

    Returns `(failing, passing)`: `failing` maps a spec file to its failed
    tests as `(title, error text)`; `passing` is the set of files that ran at
    least one test and failed none. A file with only skipped tests is neither,
    so skipping a spec never reads as a fix. A test counts as failed when its
    final status is `unexpected` (this covers timeouts); `flaky` passed on a
    retry and counts as passing. Names that are not well-formed spec files all
    land under UNPARSEABLE, which can fail but never counts as fixed.
    """
    failing, ran = {}, set()

    def walk(suite):
        """Visit one suite and its children."""
        for spec in suite.get('specs', []):
            name = clean_name(spec.get('file') or suite.get('file'))
            for test in spec.get('tests', []):
                if test.get('status') == 'unexpected':
                    failing.setdefault(name, []).append((str(spec.get('title', '?'))[:MAX_LINE], failure_text(test)))
                elif test.get('status') in ('expected', 'flaky'):
                    ran.add(name)
        for child in suite.get('suites', []):
            walk(child)

    for suite in report.get('suites', []):
        walk(suite)
    return failing, ran - set(failing) - {UNPARSEABLE}


def shard_key(item):
    """The shard number of a streamed line: 1..MAX_SHARD, else 0 (an unsharded run, or a number nobody should trust)."""
    shard = item.get('shard')
    return shard if isinstance(shard, int) and not isinstance(shard, bool) and 1 <= shard <= MAX_SHARD else 0


def shard_summary(data, meta=None):
    """What each shard did, from the streamed lines: `{shard: {planned, finished, exit, of, files}}`.

    `planned` is the total its reporter announced (None if it never began),
    `finished` the tests it streamed, `exit` and `files` come from the `shard`
    line the run appends when the shard ends (None when it never did, which is
    what a run stopped by its budget looks like). Shard 0 stands for lines
    without a usable shard number. Lines are untrusted: bad ones are skipped.
    """
    summary = {}
    manifest = meta.get('shards', []) if isinstance(meta, dict) else []
    if isinstance(manifest, list):
        for shard in manifest[:MAX_SHARD]:
            if not isinstance(shard, dict):
                continue
            number = shard.get('shard')
            if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= MAX_SHARD:
                continue
            files = shard.get('files')
            summary[number] = {
                'planned': None,
                'finished': 0,
                'exit': shard.get('exit') if isinstance(shard.get('exit'), int) and not isinstance(shard.get('exit'), bool) else None,
                'of': shard.get('of') if isinstance(shard.get('of'), int) and not isinstance(shard.get('of'), bool) else None,
                'files': len(files) if isinstance(files, list) else None,
            }
    for line in data.decode(errors='replace').splitlines()[:MAX_JSONL_LINES]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        info = summary.setdefault(shard_key(item), {'planned': None, 'finished': 0, 'exit': None, 'of': None, 'files': None})
        if (item.get('kind') == 'begin' and isinstance(item.get('total'), int) and not isinstance(item.get('total'), bool)
                and 0 <= item['total'] <= 10 ** 7):
            info['planned'] = item['total']
        elif item.get('kind') == 'test':
            info['finished'] += 1
        elif item.get('kind') == 'shard':
            if isinstance(item.get('exit'), int) and not isinstance(item.get('exit'), bool):
                info['exit'] = item['exit']
            if isinstance(item.get('files'), list):
                info['files'] = len(item['files'])
        if isinstance(item.get('of'), int) and not isinstance(item.get('of'), bool) and 1 <= item['of'] <= MAX_SHARD:
            info['of'] = item['of']
    return summary


def spec_shards(data):
    """Which shard ran each spec file: `{file: sorted shard numbers}` (only numbered shards)."""
    found = {}
    for line in data.decode(errors='replace').splitlines()[:MAX_JSONL_LINES]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and item.get('kind') == 'test' and shard_key(item):
            found.setdefault(clean_name(item.get('file')), set()).add(shard_key(item))
    return {name: sorted(numbers) for name, numbers in found.items()}


def merged_report(meta, data):
    """Merge shard plans and streamed outcomes into one explicit report.

    A test is passing only when it appears in a shard's plan and completed
    with an expected or flaky outcome. Missing, skipped, interrupted or
    mismatched test events remain in `not_run`; the reporter never treats a
    partly executed spec file as fixed.
    """
    plans, outcomes, duplicate_shards, duplicate_results, duplicate_failures = {}, {}, set(), set(), {}
    for line in data.decode(errors='replace').splitlines()[:MAX_JSONL_LINES]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        shard = shard_key(item)
        if item.get('kind') == 'begin' and shard:
            raw_tests = item.get('tests')
            if not isinstance(raw_tests, list) or len(raw_tests) > MAX_PLANNED_TESTS:
                duplicate_shards.add(shard)
                continue
            planned = {}
            valid = True
            for test in raw_tests:
                if not isinstance(test, dict):
                    valid = False
                    break
                identifier = test.get('id')
                file = test.get('file')
                if (not isinstance(identifier, int) or isinstance(identifier, bool) or identifier < 0
                        or identifier in planned or not isinstance(file, str)):
                    valid = False
                    break
                title = test.get('title')
                planned[identifier] = {
                    'file': clean_name(file),
                    'title': str(title if title is not None else '?')[:MAX_LINE],
                }
            if not valid or shard in plans:
                duplicate_shards.add(shard)
            else:
                plans[shard] = planned
        elif item.get('kind') == 'test' and shard:
            identifier = item.get('id')
            if not isinstance(identifier, int) or isinstance(identifier, bool) or identifier < 0:
                continue
            key = (shard, identifier)
            if key in outcomes:
                duplicate_results.add(key)
                if item.get('outcome') == 'unexpected':
                    duplicate_failures.setdefault(key, []).append(item)
            else:
                outcomes[key] = item

    manifest = meta.get('shards', []) if isinstance(meta, dict) else []
    assigned, exits = {}, {}
    if isinstance(manifest, list):
        for shard in manifest[:MAX_SHARD]:
            if not isinstance(shard, dict):
                continue
            number = shard.get('shard')
            if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= MAX_SHARD:
                continue
            raw_files = shard.get('files')
            if isinstance(raw_files, list):
                assigned[number] = sorted({clean_name(name) for name in raw_files if isinstance(name, str)})
            if isinstance(shard.get('exit'), int) and not isinstance(shard.get('exit'), bool):
                exits[number] = shard['exit']

    summaries = shard_summary(data, meta)
    tests, not_run, failed, per_file = [], [], {}, {}
    shard_numbers = sorted(set(plans) | set(assigned) | set(summaries))
    for shard in shard_numbers:
        planned = plans.get(shard)
        if planned is None:
            for file in assigned.get(shard, []):
                item = {'shard': shard, 'file': file, 'title': None, 'state': 'not_run', 'reason': 'shard did not start'}
                not_run.append(item)
                per_file.setdefault(file, []).append('not_run')
            continue
        for identifier, plan in sorted(planned.items()):
            file, title = plan['file'], plan['title']
            event = outcomes.get((shard, identifier))
            reason, outcome, error, state = None, None, '', 'not_run'
            if shard in duplicate_shards or (shard, identifier) in duplicate_results:
                reason = 'ambiguous shard result'
            elif event is None:
                reason = 'test did not finish'
            elif clean_name(event.get('file')) != file or str(event.get('title', '?'))[:MAX_LINE] != title:
                reason = 'result did not match the shard plan'
            else:
                outcome = event.get('outcome')
                if outcome in ('expected', 'flaky'):
                    state = 'passed'
                elif outcome == 'unexpected':
                    state = 'failed'
                    error = clip_lines(ANSI.sub('', str(event.get('error', ''))).strip(), MAX_ERROR)
                else:
                    reason = 'test was skipped or interrupted'
            result = {'shard': shard, 'file': file, 'title': title, 'state': state, 'outcome': outcome}
            if error:
                result['error'] = error
            if reason:
                result['reason'] = reason
                not_run.append(result)
            tests.append(result)
            per_file.setdefault(file, []).append(state)
    for key, event in outcomes.items():
        candidates = [event, *duplicate_failures.get(key, [])]
        for candidate in candidates:
            if candidate.get('outcome') != 'unexpected':
                continue
            file = clean_name(candidate.get('file'))
            title = str(candidate.get('title', '?'))[:MAX_LINE]
            message = ANSI.sub('', str(candidate.get('error', ''))).strip()
            failed.setdefault(file, []).append((title, clip_lines(message, MAX_ERROR)))

    passing = {file for file, states in per_file.items()
               if file != UNPARSEABLE and states and all(state == 'passed' for state in states)}
    shard_rows = []
    for shard in shard_numbers:
        info = summaries.get(shard, {})
        states = [test['state'] for test in tests if test['shard'] == shard]
        shard_rows.append({
            'shard': shard,
            'of': info.get('of'),
            'exit': exits.get(shard, info.get('exit')),
            'assigned_files': assigned.get(shard, []),
            'planned_tests': len(plans[shard]) if shard in plans else None,
            'reported_tests': info.get('finished', 0),
            'passed_tests': states.count('passed'),
            'failed_tests': states.count('failed'),
            'not_run_tests': states.count('not_run') + sum(1 for item in not_run if item['shard'] == shard and item.get('title') is None),
        })
    planned_count = sum(row['planned_tests'] for row in shard_rows if row['planned_tests'] is not None)
    total_known = all(row['planned_tests'] is not None for row in shard_rows)
    reported_count = sum(info.get('finished', 0) for shard, info in summaries.items() if shard)
    abnormal = any(row['exit'] not in (0, 1) for row in shard_rows)
    counts_match = all(row['planned_tests'] == row['reported_tests']
                       for row in shard_rows if row['planned_tests'] is not None)
    complete = total_known and counts_match and not not_run and not abnormal and all(row['exit'] in (0, 1) for row in shard_rows)
    has_plan = bool(plans or assigned)
    report = {
        'schema': 1,
        'head': meta.get('head') if isinstance(meta, dict) else None,
        'status': 'partial' if has_plan and not complete else ('failed' if failed else 'passed') if has_plan else 'unknown',
        'shards': shard_rows,
        'tests': tests,
        'not_run': not_run,
        'failed_files': sorted(failed),
        'passing_files': sorted(passing),
        'reported_tests': reported_count,
        'planned_tests': planned_count if total_known else None,
    }
    return report, failed, passing, reported_count, (planned_count if total_known else None)


def collect_jsonl(data, meta=None):
    """Read the streamed per-test lines of a run; return `(failing, passing, finished, total)`.

    Same shape as `collect`, plus how many tests finished and how many the run
    planned (None if unknown; with shards, the sum of what each shard
    announced). Only a test whose outcome is `unexpected` counts as failed. A
    spec with no finished test is neither failing nor passing, so a stopped
    suite never reports a spec fixed that it did not reach, and an
    `interrupted` test (cut off by the stop) is not a failure. The lines are
    untrusted: bad lines are skipped, names are cleaned, text is cut.
    """
    merged, failing, passing, finished, total = merged_report(meta or {}, data)
    if merged['status'] != 'unknown':
        return failing, passing, finished, total
    failing, ran, finished = {}, set(), 0
    for line in data.decode(errors='replace').splitlines()[:MAX_JSONL_LINES]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if item.get('kind') == 'test':
            finished += 1
            name = clean_name(item.get('file'))
            if item.get('outcome') == 'unexpected':
                failing.setdefault(name, []).append((str(item.get('title', '?'))[:MAX_LINE],
                                                     clip_lines(ANSI.sub('', str(item.get('error', ''))).strip(), MAX_ERROR)))
            elif item.get('outcome') in ('expected', 'flaky'):
                ran.add(name)
    planned = [info['planned'] for info in shard_summary(data, meta).values() if info['planned'] is not None]
    return failing, ran - set(failing) - {UNPARSEABLE}, finished, (sum(planned) if planned else None)


def failure_text(test):
    """The last attempt's error message, colour codes removed and each line cut to MAX_LINE."""
    results = test.get('results') or [{}]
    last = results[-1]
    errors = last.get('errors') or ([last['error']] if last.get('error') else [])
    return clip_lines(ANSI.sub('', '\n'.join(str(error.get('message', '')) for error in errors)).strip(), MAX_ERROR)


def clip_lines(text, total, per_line=MAX_LINE):
    """Cut every line to `per_line` characters and the whole text to `total`."""
    return '\n'.join(line[:per_line] for line in text.splitlines())[:total]


def log_tail(log_text, spec, lines=30):
    """The last `lines` log lines that mention the spec file, each cut short."""
    mentioned = [line for line in ANSI.sub('', log_text).splitlines() if spec in line]
    return clip_lines('\n'.join(mentioned[-lines:]), lines * MAX_LINE)


def fence_for(*texts):
    """A code fence longer than any run of backticks in any of the texts, so none of them can close it."""
    longest = max((len(run) for text in texts for run in re.findall('`+', text)), default=0)
    return '`' * max(3, longest + 1)


class TokenRefused(Exception):
    """Forgejo answered 401 or 403: the token may not do this. Not an OSError, so no per-spec handler swallows it."""


def api(base, route, token, payload=None):
    """One Forgejo API call. The token travels only in a header, never in argv or logs.

    A 401 or 403 raises TokenRefused with the status, the route and Forgejo's own
    message (which names a missing scope), because every later call would fail the same way.
    """
    request = urllib.request.Request(base.rstrip('/') + '/api/v1/' + route,
                                     data=None if payload is None else json.dumps(payload).encode(),
                                     headers={'Authorization': 'token ' + token, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code not in (401, 403):
            raise
        try:
            detail = str(json.load(error).get('message', ''))
        except (ValueError, AttributeError, OSError):
            detail = ''
        detail = ''.join(ch for ch in detail if ch.isprintable())[:200]
        raise TokenRefused(f'HTTP {error.code} on {"GET" if payload is None else "POST"} {route} ({detail or "no message"})') from None


def post_as(base, route, token, payload, login):
    """POST one issue or comment and check that it was written under the configured `login`.

    The author comes back on the response itself, so no permission beyond issue
    write is needed. A different author means the configured login is not this
    token's account: markers would be matched against the wrong name, so stop
    (ValueError) before more is filed.
    """
    result = api(base, route, token, payload)
    author = (result.get('user') or {}).get('login') if isinstance(result, dict) else None
    if author is not None and author != login:
        raise ValueError(f'the configured Forgejo login is {login!r}, but this token posts as {author!r}')
    return result


def pages(base, route, token):
    """Every item of a paginated list route (50 per page, at most 40 pages).

    Fails closed: if the last allowed page is still full, there may be more
    items that the caller would deduplicate against, so this raises instead of
    returning a partial list.
    """
    joiner = '&' if '?' in route else '?'
    for page in range(1, 41):
        items = api(base, f'{route}{joiner}limit=50&page={page}', token)
        yield from items
        if len(items) < 50:
            return
    raise RuntimeError(f'{route} has more than 2000 items; refusing to deduplicate against a partial list')


def written_by(item, login):
    """Whether an issue or comment was written by the token's own account."""
    return (item.get('user') or {}).get('login') == login


def open_issues(base, repo, token, login):
    """Map each spec marker hash to the number of its open issue.

    Only issues written by the token's own account count: anyone who can file
    an issue could otherwise copy a marker and mute a spec. One listing serves
    the whole night; it reads the database directly (the search index can lag).
    """
    found = {}
    for issue in pages(base, f'repos/{repo}/issues?state=open&type=issues', token):
        match = SPEC_MARKER.search(issue.get('body') or '')
        if match and written_by(issue, login):
            found.setdefault(match[1], issue['number'])
    return found


def issue_comments(base, repo, token, number):
    """All comments of one issue, oldest first, each id once.

    Forgejo ignores `limit` and `page` on this route and returns the whole
    list every time, so it is fetched with a single request: paging it would
    repeat the same list until the page limit and stop the night's report.
    """
    unique = {}
    for comment in api(base, f'repos/{repo}/issues/{number}/comments', token):
        unique.setdefault(comment['id'], comment)
    return list(unique.values())


def last_state(base, repo, token, login, number):
    """`fixed` or `failing`: what the newest hidden marker in the account's own comments says (the issue body counts as `failing`)."""
    state = 'failing'
    for comment in issue_comments(base, repo, token, number):
        match = STATE_MARKER.search(comment.get('body') or '')
        if match and written_by(comment, login):
            state = match[1]
    return state


def note_pooled(base, repo, token, login, number, new, run_name, head, runs_root):
    """Comment on the open roll-up with the failing specs it has not listed yet, once per name.

    The roll-up's own body and the account's earlier comments are the memory:
    a name already written there is not repeated, so a rerun adds nothing.
    """
    post = functools.partial(post_as, login=login)
    issue = api(base, f'repos/{repo}/issues/{number}', token)
    seen = (issue.get('body') or '') if written_by(issue, login) else ''
    for comment in issue_comments(base, repo, token, number):
        if written_by(comment, login):
            seen += '\n' + (comment.get('body') or '')
    fresh = [name for name in sorted(new) if name not in seen]
    if fresh:
        listed = '\n'.join(fresh[:200])
        post(base, f'repos/{repo}/issues/{number}/comments', token,
            {'body': f'{len(fresh)} more spec files failed on `{head}` and are pooled here (evidence `{runs_root}/{run_name}/evidence`):\n\n{fence_for(listed)}\n{listed}\n{fence_for(listed)}'[:MAX_BODY]})
        print(f'roll-up #{number}: {len(fresh)} more names', flush=True)


def issue_body(marker, intro, blocks, run_name, head, runs_root):
    """The text of a new issue. `blocks` are (heading, untrusted text) pairs, all inside one fence that no content can close.

    Only validated values appear outside the fence: the SHA, the paths built
    from the run name, and the spec name. The markers come first so cutting the
    body to MAX_BODY can never remove them.
    """
    fence = fence_for(*(text for _, text in blocks))
    shown = '\n\n'.join(f'### {heading}\n{fence}\n{text}\n{fence}' for heading, text in blocks)
    body = (f"{marker}\n{state_marker('failing')}\nNightly browser suite on dev (D373, #443).\n\n{intro}\n"
            f"Source: `{head}`\nEvidence: `{runs_root}/{run_name}/evidence` on infraternal-dev-02-std (the newest seven nights are kept)\n"
            f"Full log: `{runs_root}/{run_name}/suite.log`\n\n{shown}\n")
    return body[:MAX_BODY]


def spec_issue(spec, failures, tail, run_name, head, runs_root, shard=None):
    """Title and body of the issue for one failing spec file; `shard` is a line like `1 of 2` when the night ran in shards."""
    # Titles come from the suite, so they sit inside the fence like the error text; the headings are fixed.
    blocks = [(f'Failing test {number}', f'{title}\n{text}') for number, (title, text) in enumerate(failures[:5], 1)] + [('Log tail for this spec', tail)]
    more = f'\n(and {len(failures) - 5} more failing tests)\n' if len(failures) > 5 else ''
    where = f'Shard: {shard}\n' if shard else ''
    test_file = spec if spec.startswith('test/') else f'test/{spec}'
    intro = f"Spec: `{spec}`\n{where}{more}Rerun with `cd apps/tracer && bun x playwright test {test_file}`.\n"
    return {'title': f'browser suite: {spec} fails on dev',
            'body': issue_body(spec_marker(spec), intro, blocks, run_name, head, runs_root)}


def timeout_marker(run_name):
    """The hidden marker of the timeout note for one run, so a rerun of the same night adds no second note."""
    return f'<!-- infraternal-browser-timeout: {run_name} -->'


def timeout_note(suite_timeout, finished, total):
    """The one sentence a timed-out night adds to the roll-up."""
    reason = ('stopped at deadline (07:45 IST)' if suite_timeout == DEADLINE_REASON
              else f'suite timed out after {suite_timeout[:-1]} h')
    return f'{reason}; {finished} of {"?" if total is None else total} tests ran'


def shard_note(shards):
    """One clause per shard saying what it ran, and whether any shard ended abnormally: `(text or None, abnormal)`."""
    numbered = {number: info for number, info in shards.items() if number}
    clauses, abnormal = [], False
    for number in sorted(numbered):
        info = numbered[number]
        of = info['of'] or len(numbered)
        who = f'shard {number} of {of}'
        if info['planned'] is None:
            abnormal = True
            files = f'{info["files"]} assigned' if info['files'] is not None else 'assigned'
            clauses.append(f'{who}: crashed (exit {info["exit"]}): none of its {files} spec files ran' if info['exit'] is not None
                           else f'{who}: never started, none of its {files} spec files ran')
            continue
        ran = f'{who}: {info["finished"]} of {info["planned"]} tests ran'
        if info['exit'] in (0, 1) and info['finished'] == info['planned']:
            clauses.append(f'{ran}, finished (exit {info["exit"]})')
        elif info['exit'] in (0, 1) and info['finished'] < info['planned']:
            abnormal = True
            clauses.append(f'{ran}, did not finish (exit {info["exit"]})')
        elif info['exit'] is None:
            abnormal = True
            clauses.append(f'{ran}, did not finish')
        elif info['exit'] not in (0, 1):
            abnormal = True
            clauses.append(f'{ran}, crashed (exit {info["exit"]})')
        else:
            abnormal = True
            clauses.append(f'{ran}, test stream did not match the plan (exit {info["exit"]})')
    return ('; '.join(clauses) if clauses else None), abnormal


def shard_label(numbers, shards):
    """`1 of 2` for a spec that ran in shard 1 of 2, or None when the night was not sharded or the spec's shard is unknown."""
    if not numbers:
        return None
    of = max([info['of'] or 0 for info in shards.values()] + [len([k for k in shards if k])])
    return f'{" and ".join(str(n) for n in numbers)} of {of}'


def run_note(suite_timeout, finished, total, shards, unrun_files=()):
    """The one note a night adds when the suite timed out or its test stream did not finish as planned, else None.

    It says which shard ran what. The first sentence is the timeout note,
    unchanged, so a night without shards reads as before.
    """
    clauses, abnormal = shard_note(shards)
    if not suite_timeout and not abnormal:
        return None
    parts = [timeout_note(suite_timeout, finished, total)] if suite_timeout else []
    if clauses:
        parts.append(f'Shards: {clauses}')
    names = sorted(set(unrun_files))
    if names:
        shown = ', '.join(names[:MAX_UNRUN_FILES_IN_NOTE])
        remainder = f' (+{len(names) - MAX_UNRUN_FILES_IN_NOTE} more)' if len(names) > MAX_UNRUN_FILES_IN_NOTE else ''
        parts.append(f'Spec files not fully run: {shown}{remainder}')
    return '. '.join(parts)


def rollup_issue(names, total, run_name, head, runs_root, note=None):
    """Title and body of the single issue that stands for a night with too many new failures, or a suite that timed out."""
    listed = '\n'.join(sorted(names)[:200]) or '(none pooled tonight)'
    intro = (f'{len(names)} new spec files failed out of {total} that ran. That is more than {MAX_NEW_ISSUES} new issues '
             f'or a mostly red suite, so it is filed once, not per spec: look for a dead test server or a broken build first.\n')
    title = f'browser suite: {len(names)} spec files fail on dev (roll-up)'
    if note and not names:
        intro, title = '', ('browser suite: the suite timed out (roll-up)' if note.startswith('suite timed out') else 'browser suite: a shard did not finish (roll-up)')
    if note:
        intro += f'\nNote: {note}.\n{timeout_marker(run_name)}\n'
    return {'title': title,
            'body': issue_body(spec_marker(ROLLUP), intro, [('Failing spec files (names as Playwright reported them)', listed)],
                               run_name, head, runs_root)}


def note_timeout(base, repo, token, login, number, note, run_name):
    """Comment the timeout note on the roll-up `number`, once per run (its body or one of our comments may already carry it)."""
    marker = timeout_marker(run_name)
    issue = api(base, f'repos/{repo}/issues/{number}', token)
    if written_by(issue, login) and marker in (issue.get('body') or ''):
        return
    if any(marker in (c.get('body') or '') for c in issue_comments(base, repo, token, number) if written_by(c, login)):
        return
    post_as(base, f'repos/{repo}/issues/{number}/comments', token, {'body': f'Note: {note}.\n\n{marker}'}, login)
    print(f'timeout note on roll-up #{number}: {note}', flush=True)


def report(base, repo, token, results, run_name, runs_root=BROWSER_RUNS, suite_timeout=None, login=None):
    """File the night's results and return the number of requests that failed.

    New red specs open an issue (or one roll-up issue when there are too many),
    specs that came back get one comment, and everything else is left alone
    (see the module doc). Raises ValueError when the inputs are not what the
    suite should have written, and RuntimeError when the issue list is too long.
    `login` is the Forgejo account the token belongs to, configured by the
    installer. Whose markers to believe cannot be asked of Forgejo (`/user` needs
    the `read:user` scope, which the token deliberately lacks); every issue or
    comment this function posts is checked against it, so a wrong value stops the night.
    `suite_timeout` (like `9h`) says the suite was stopped by its time budget:
    the streamed `results.jsonl` is merged with the durable shard manifest, and
    the roll-up names spec files whose planned tests did not all finish. The
    merged JSON is atomically published before any Forgejo request is made.
    """
    if not isinstance(login, str) or not LOGIN.fullmatch(login):
        raise ValueError('no valid Forgejo login configured')
    post = functools.partial(post_as, login=login)
    if suite_timeout not in (None, DEADLINE_REASON) and not TIMEOUT_LABEL.fullmatch(suite_timeout):
        raise ValueError('bad suite timeout label')
    if not RUN_NAME.fullmatch(run_name):
        raise ValueError('bad run name')
    meta = json.loads(read_regular(results / 'meta.json', MAX_META_BYTES))
    head = meta.get('head') if isinstance(meta, dict) else None
    if not isinstance(head, str) or not HEAD.fullmatch(head) or not head.startswith(run_name[-7:]):
        raise ValueError('meta.json: head is not the commit named by the run folder')
    finished, total = 0, None
    jsonl = results / 'results.jsonl'
    jsonl_data = read_regular(jsonl, MAX_JSONL_BYTES) if jsonl.exists() else b''
    shards = shard_summary(jsonl_data, meta)
    where = spec_shards(jsonl_data)
    has_playwright_json = (results / 'results.json').exists()
    if jsonl_data:
        merged, streamed_failing, streamed_passing, finished, total = merged_report(meta, jsonl_data)
        if merged['status'] == 'unknown':
            if has_playwright_json:
                failing, passing = collect(json.loads(read_regular(results / 'results.json', MAX_RESULTS_BYTES)))
            else:
                failing, passing, finished, total = collect_jsonl(jsonl_data, meta)
            merged['status'] = 'failed' if failing else 'passed'
            merged['failed_files'] = sorted(failing)
            merged['passing_files'] = sorted(passing)
        else:
            failing, passing = streamed_failing, streamed_passing
    elif has_playwright_json:
        failing, passing = collect(json.loads(read_regular(results / 'results.json', MAX_RESULTS_BYTES)))
        merged = {'schema': 1, 'head': head, 'status': 'failed' if failing else 'passed', 'shards': [],
                  'tests': [], 'not_run': [], 'failed_files': sorted(failing), 'passing_files': sorted(passing),
                  'reported_tests': None, 'planned_tests': None}
    elif suite_timeout is not None and isinstance(meta.get('shards'), list) and meta['shards']:
        merged, failing, passing, finished, total = merged_report(meta, b'')
        if not merged['not_run']:
            raise ValueError('the timed-out run has no reportable shard plan')
    else:
        raise ValueError('the run left neither results.json nor results.jsonl')
    if suite_timeout == DEADLINE_REASON:
        merged['status'] = 'partial'
        merged['stop_reason'] = 'stopped at deadline (07:45 IST)'
    merged_bytes = (json.dumps(merged, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    if len(merged_bytes) > MAX_MERGED_REPORT_BYTES:
        raise ValueError(f'merged report is larger than {MAX_MERGED_REPORT_BYTES} bytes')
    atomic_write_bytes(results / 'merged-report.json', merged_bytes)
    unrun_files = sorted({item['file'] for item in merged.get('not_run', [])
                          if isinstance(item, dict) and isinstance(item.get('file'), str)
                          and item.get('reason') != 'test was skipped or interrupted'})
    log_text = read_regular(results / 'suite.log', MAX_LOG_BYTES, tail=True).decode(errors='replace')
    known = open_issues(base, repo, token, login)
    new = sorted(spec for spec in failing if hashlib.sha256(spec.encode()).hexdigest()[:16] not in known)
    errors = 0
    rollup = None
    timeout_done = False
    # A mostly red suite is a dead server, not that many bugs.
    pool = len(new) > MAX_NEW_ISSUES or len(known) + len(new) > MAX_OPEN_ISSUES or (len(failing) >= ROLLUP_MIN_FAILING and len(failing) * 2 >= len(failing) + len(passing))
    if pool and new:
        try:
            rollup = known.get(hashlib.sha256(ROLLUP.encode()).hexdigest()[:16])
            if rollup is None:
                note = run_note(suite_timeout, finished, total, shards, unrun_files)
                rollup = post(base, f'repos/{repo}/issues', token,
                             rollup_issue(new, len(failing) + len(passing), run_name, head, runs_root, note))['number']
                print(f'opened roll-up issue #{rollup} specs={len(new)} head={head}', flush=True)
                timeout_done = True
            else:
                note_pooled(base, repo, token, login, rollup, new, run_name, head, runs_root)
        except OSError as error:
            errors += 1
            print(f'report FAILED roll-up: {type(error).__name__}: {error}', flush=True)
    for spec in sorted(failing):
        marker = hashlib.sha256(spec.encode()).hexdigest()[:16]
        try:
            if marker not in known:
                if pool:
                    continue
                number = post(base, f'repos/{repo}/issues', token,
                             spec_issue(spec, failing[spec], log_tail(log_text, spec), run_name, head, runs_root, shard_label(where.get(spec), shards)))['number']
                print(f'opened issue #{number} spec={spec} head={head}', flush=True)
            elif last_state(base, repo, token, login, known[marker]) == 'fixed':
                post(base, f'repos/{repo}/issues/{known[marker]}/comments', token,
                    {'body': f"`{spec}` fails again on `{head}`.\n\nEvidence: `{runs_root}/{run_name}/evidence`\n\n{state_marker('failing')}"})
                print(f'failing again: issue #{known[marker]} spec={spec}', flush=True)
        except OSError as error:
            errors += 1
            print(f'report FAILED spec={spec}: {type(error).__name__}: {error}', flush=True)
    for spec in sorted(passing):
        marker = hashlib.sha256(spec.encode()).hexdigest()[:16]
        if marker not in known:
            continue
        try:
            if last_state(base, repo, token, login, known[marker]) == 'fixed':
                continue
            post(base, f'repos/{repo}/issues/{known[marker]}/comments', token,
                {'body': f"`{spec}` passes again on `{head}`. Closing is left to the owner.\n\n{state_marker('fixed')}"})
            print(f'passes again: issue #{known[marker]} spec={spec}', flush=True)
        except OSError as error:
            errors += 1
            print(f'report FAILED spec={spec}: {type(error).__name__}: {error}', flush=True)
    note = run_note(suite_timeout, finished, total, shards, unrun_files)
    if note:
        # One note per timed-out or shard-broken run, on the roll-up (opened here if none is open yet).
        try:
            rollup = rollup or known.get(hashlib.sha256(ROLLUP.encode()).hexdigest()[:16])
            if rollup is None:
                rollup = post(base, f'repos/{repo}/issues', token, rollup_issue([], len(failing) + len(passing), run_name, head, runs_root, note))['number']
                print(f'opened roll-up issue #{rollup} for the timeout note head={head}', flush=True)
            elif not timeout_done:
                note_timeout(base, repo, token, login, rollup, note, run_name)
        except OSError as error:
            errors += 1
            print(f'report FAILED timeout note: {type(error).__name__}: {error}', flush=True)
    # `failing` and `passing` count spec FILES, not tests. The first night read "152 passing, 22 failing" against a plan of 1719 tests and
    # looked like a run that stopped early (#443); say both units, so the line cannot be misread.
    tests = [item for item in merged.get('tests', []) if isinstance(item, dict)]
    states = collections.Counter(item.get('state') for item in tests)
    by_test = (f' (failing and passing count spec files) tests_passed={states["passed"]} tests_failed={states["failed"]} '
               f'tests_not_run={states["not_run"]} tests_planned={merged.get("planned_tests")}') if tests else ''
    print(f'BROWSER_REPORT_DONE failing={len(failing)} passing={len(passing)} request_errors={errors} head={head}{by_test}', flush=True)
    return errors


def staged_info(results):
    """What the helper wrote beside the staged files: `{"run_name": ..., "suite_timeout": ...}` (read as untrusted data)."""
    info = json.loads(read_regular(results / 'staged.json', 4096))
    if not isinstance(info, dict):
        raise ValueError('staged.json is not an object')
    return info.get('run_name'), info.get('suite_timeout')


def main():
    """Command line: `run --runs-dir D` or `report --results D --token-file F --login NAME [--run-name N]`."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    runner = sub.add_parser('run', help='build and run the suite (no token needed)')
    runner.add_argument('--runs-dir', type=Path, required=True)
    runner.add_argument('--shards', type=int, default=SHARDS, help='how many Playwright shards to run side by side')
    reporter = sub.add_parser('report', help='file issues from a finished run')
    reporter.add_argument('--results', type=Path, required=True, help='staging folder with meta.json, results.json or results.jsonl, and suite.log')
    reporter.add_argument('--run-name', default=None, help='the validated run folder name, e.g. 20261109T061806Z-c751e99 (default: from staged.json)')
    reporter.add_argument('--runs-root', default=BROWSER_RUNS, help='where those runs live, for the paths printed in issues')
    reporter.add_argument('--suite-timeout', default=None, help='the suite was stopped by its budget, e.g. 9h: report what finished')
    reporter.add_argument('--login', required=True, help='the Forgejo account the token belongs to (configured by the installer)')
    reporter.add_argument('--token-file', type=Path, required=True)
    reporter.add_argument('--api', default='https://git.kayg.org')
    reporter.add_argument('--repo', default='kayg/infraternal')
    args = parser.parse_args()
    if args.command == 'run':
        args.runs_dir.mkdir(parents=True, exist_ok=True)
        if not 1 <= args.shards <= MAX_SHARD:
            parser.error('--shards must be between 1 and %d' % MAX_SHARD)
        return run(Path(__file__).resolve().parents[1], args.runs_dir.resolve(), args.shards)
    try:
        token = read_regular(args.token_file, 4096).decode().strip()
        if not token:
            print('empty Forgejo token file', file=sys.stderr)
            return 1
        run_name, suite_timeout = args.run_name, args.suite_timeout
        if run_name is None:
            run_name, staged_timeout = staged_info(args.results)
            suite_timeout = suite_timeout or staged_timeout
        if not isinstance(run_name, str):
            raise ValueError('no run name')
        return int(report(args.api, args.repo, token, args.results, run_name, args.runs_root, suite_timeout, args.login) > 0)
    except TokenRefused as error:
        print(f'nightly browser suite: TOKEN LACKS PERMISSION: {error}. Nothing was lost: the staged files stay in {args.results}. '
              'Once the token is fixed, re-run only the reporter with: sudo /usr/local/libexec/infraternal-browser-suite-service '
              f'--report-only --run-name {args.run_name or "<run name>"}', file=sys.stderr)
        return TOKEN_REFUSED_EXIT
    except (ValueError, RuntimeError, OSError) as error:
        print(f'browser suite report refused: {type(error).__name__}: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
