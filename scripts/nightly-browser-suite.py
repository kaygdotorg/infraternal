#!/usr/bin/env python3
"""Run the full tracer browser suite on the latest dev, and report failing specs (D373, #443).

The nightly fuzz (D361, `nightly-fuzz.py`) is the pattern: a systemd timer on
dev-02 holds a build slot, a run produces results, and a reporter files
Forgejo issues with a token read from a private file. Two subcommands keep the
token away from the code under test:

- `run` builds the tracer for production and runs the whole Playwright suite
  (the browser phase of `verify_latency`) with the JSON reporter. It executes
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

Exit status of `run`: 0 when results were written, even if specs failed; 1 when
the build or the suite could not run at all. Exit status of `report`: 0 when
every issue and comment was filed, 1 when a request failed.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

# The suite's own test-server port. verify_latency defaults to 4621, which other
# jobs on the shared build VM may be using at the same moment.
TEST_PORT = '4731'

# How many finished runs `run` keeps next to the new one; older ones are removed.
KEEP_RUNS = 7

SPEC_MARKER = re.compile(r'<!-- infraternal-browser-spec: (\S+) -->')
STATE_MARKER = re.compile(r'<!-- infraternal-browser-state: (failing|fixed) -->')
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def spec_marker(spec):
    """The hidden, deterministic marker that ties an issue to one spec file."""
    return f'<!-- infraternal-browser-spec: {spec} -->'


def state_marker(state):
    """The hidden marker a comment carries so the issue's own history says what was last reported."""
    return f'<!-- infraternal-browser-state: {state} -->'


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


def run(root, runs):
    """Build the tracer, run the whole suite, and leave `results.json`, `suite.log` and `meta.json`.

    The run directory is `<runs>/<UTC stamp>-<sha7>`; its path goes into
    `<runs>/latest` once the suite has produced a report. The evidence folder
    inside it is where specs and the Playwright output directory write
    screenshots and other raw receipts, outside the checkout.
    """
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = runs / f'{stamp}-{head[:7]}'
    (out / 'evidence').mkdir(parents=True)
    log = out / 'suite.log'
    tracer = root / 'apps/tracer'
    env = dict(os.environ, TRACER_TEST_PORT=TEST_PORT, INFRATERNAL_EVIDENCE_DIR=str(out / 'evidence'),
               PLAYWRIGHT_JSON_OUTPUT_NAME=str(out / 'results.json'))
    # Build failures are infrastructure failures: no spec issue is opened for them.
    for command in (['bun', 'install', '--frozen-lockfile'], ['bun', 'run', 'build'],
                    ['bun', 'x', 'playwright', 'install', 'chromium']):
        if run_step(command, tracer, log, env) != 0:
            print(f'browser suite: {" ".join(command)} failed, see {log}', flush=True)
            return 1
    # `list` keeps readable progress in the log; `json` is what the reporter reads.
    status = run_step(['bun', 'x', 'playwright', 'test', '--reporter=list,json'], tracer, log, env)
    results = out / 'results.json'
    if not results.is_file():
        print(f'browser suite: no report written (playwright exit {status}), see {log}', flush=True)
        return 1
    (out / 'meta.json').write_text(json.dumps({'head': head, 'evidence': str(out / 'evidence'), 'log': str(log),
                                               'playwright_exit': status}) + '\n')
    (runs / 'latest').write_text(str(out) + '\n')
    prune_runs(runs, KEEP_RUNS)
    print(f'BROWSER_SUITE_DONE playwright_exit={status} head={head} out={out}', flush=True)
    return 0


# ------------------------------------------------------------ report side


def collect(report):
    """Sort a Playwright JSON report's spec files into failing and passing.

    Returns `(failing, passing)`: `failing` maps a spec file to its failed
    tests as `(title, error text)`; `passing` is the set of files that ran at
    least one test and failed none. A file with only skipped tests is neither,
    so skipping a spec never reads as a fix. A test counts as failed when its
    final status is `unexpected` (this covers timeouts); `flaky` passed on a
    retry and counts as passing.
    """
    failing, ran = {}, set()

    def walk(suite):
        """Visit one suite and its children."""
        for spec in suite.get('specs', []):
            name = spec.get('file') or suite.get('file') or '?'
            for test in spec.get('tests', []):
                if test.get('status') == 'unexpected':
                    failing.setdefault(name, []).append((spec.get('title', '?'), failure_text(test)))
                elif test.get('status') in ('expected', 'flaky'):
                    ran.add(name)
        for child in suite.get('suites', []):
            walk(child)

    for suite in report.get('suites', []):
        walk(suite)
    return failing, ran - set(failing)


def failure_text(test):
    """The last attempt's error message, colour codes removed."""
    results = test.get('results') or [{}]
    last = results[-1]
    errors = last.get('errors') or ([last['error']] if last.get('error') else [])
    return ANSI.sub('', '\n'.join(error.get('message', '') for error in errors)).strip()


def log_tail(log_text, spec, lines=30):
    """The last `lines` log lines that mention the spec file; the list reporter prints one per test and its errors."""
    mentioned = [line for line in ANSI.sub('', log_text).splitlines() if spec in line]
    return '\n'.join(mentioned[-lines:])


def api(base, route, token, payload=None):
    """One Forgejo API call. The token travels only in a header, never in argv or logs."""
    request = urllib.request.Request(base.rstrip('/') + '/api/v1/' + route,
                                     data=None if payload is None else json.dumps(payload).encode(),
                                     headers={'Authorization': 'token ' + token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def pages(base, route, token):
    """Every item of a paginated list route (50 per page, at most 40 pages)."""
    joiner = '&' if '?' in route else '?'
    for page in range(1, 41):
        items = api(base, f'{route}{joiner}limit=50&page={page}', token)
        yield from items
        if len(items) < 50:
            return


def open_issues(base, repo, token):
    """Map each spec file to the number of its open issue, found by hidden marker.

    Listing reads the database directly (the search index can lag behind a
    fresh issue), and one listing serves the whole night.
    """
    found = {}
    for issue in pages(base, f'repos/{repo}/issues?state=open&type=issues', token):
        match = SPEC_MARKER.search(issue.get('body') or '')
        if match:
            found.setdefault(match[1], issue['number'])
    return found


def last_state(base, repo, token, number):
    """`fixed` or `failing`: what the newest hidden marker in the issue's comments says (the issue body counts as `failing`)."""
    state = 'failing'
    for comment in pages(base, f'repos/{repo}/issues/{number}/comments', token):
        match = STATE_MARKER.search(comment.get('body') or '')
        if match:
            state = match[1]
    return state


def issue_body(spec, failures, meta, tail):
    """The text of a new issue: what failed, on which commit, where the evidence is, and how to rerun it."""
    shown = '\n\n'.join(f'### {title}\n```\n{text[:3000]}\n```' for title, text in failures[:5])
    more = f'\n\n(and {len(failures) - 5} more failing tests)' if len(failures) > 5 else ''
    return (f"Nightly browser suite on dev (D373, #443).\n\nSpec: `{spec}`\nSource: `{meta['head']}`\n"
            f"Evidence: `{meta['evidence']}` on infraternal-dev-02-std (the newest seven nights are kept)\n"
            f"Full log: `{meta['log']}`\n\n{shown}{more}\n\nLog tail for this spec:\n```\n{tail}\n```\n\n"
            f"Rerun with `cd apps/tracer && bun x playwright test test/{spec}`.\n\n"
            f"{spec_marker(spec)}\n{state_marker('failing')}")


def report(base, repo, token, results):
    """File the night's results and return the number of requests that failed.

    New red specs open an issue, specs that came back get one comment, and
    everything else is left alone (see the module doc).
    """
    meta = json.loads((results / 'meta.json').read_text())
    failing, passing = collect(json.loads((results / 'results.json').read_text()))
    log_text = (results / 'suite.log').read_text(errors='replace')
    known = open_issues(base, repo, token)
    errors = 0
    for spec in sorted(failing):
        try:
            if spec not in known:
                number = api(base, f'repos/{repo}/issues', token,
                             {'title': f'browser suite: {spec} fails on dev',
                              'body': issue_body(spec, failing[spec], meta, log_tail(log_text, spec))})['number']
                print(f'opened issue #{number} spec={spec} head={meta["head"]}', flush=True)
            elif last_state(base, repo, token, known[spec]) == 'fixed':
                api(base, f'repos/{repo}/issues/{known[spec]}/comments', token,
                    {'body': f"`{spec}` fails again on `{meta['head']}`.\n\nEvidence: `{meta['evidence']}`\n\n{state_marker('failing')}"})
                print(f'failing again: issue #{known[spec]} spec={spec}', flush=True)
        except OSError as error:
            errors += 1
            print(f'report FAILED spec={spec}: {type(error).__name__}: {error}', flush=True)
    for spec in sorted(passing & known.keys()):
        try:
            if last_state(base, repo, token, known[spec]) == 'fixed':
                continue
            api(base, f'repos/{repo}/issues/{known[spec]}/comments', token,
                {'body': f"`{spec}` passes again on `{meta['head']}`. Closing is left to the owner.\n\n{state_marker('fixed')}"})
            print(f'passes again: issue #{known[spec]} spec={spec}', flush=True)
        except OSError as error:
            errors += 1
            print(f'report FAILED spec={spec}: {type(error).__name__}: {error}', flush=True)
    print(f'BROWSER_REPORT_DONE failing={len(failing)} passing={len(passing)} request_errors={errors} head={meta["head"]}', flush=True)
    return errors


def main():
    """Command line: `run --runs-dir D` or `report --results D --token-file F`."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    runner = sub.add_parser('run', help='build and run the suite (no token needed)')
    runner.add_argument('--runs-dir', type=Path, required=True)
    reporter = sub.add_parser('report', help='file issues from a finished run')
    reporter.add_argument('--results', type=Path, required=True)
    reporter.add_argument('--token-file', type=Path, required=True)
    reporter.add_argument('--api', default='https://git.kayg.org')
    reporter.add_argument('--repo', default='kayg/infraternal')
    args = parser.parse_args()
    if args.command == 'run':
        args.runs_dir.mkdir(parents=True, exist_ok=True)
        return run(Path(__file__).resolve().parents[1], args.runs_dir.resolve())
    token = args.token_file.read_text().strip()
    if not token:
        print('empty Forgejo token file', file=sys.stderr)
        return 1
    return int(report(args.api, args.repo, token, args.results) > 0)


if __name__ == '__main__':
    raise SystemExit(main())
