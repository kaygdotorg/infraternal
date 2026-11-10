#!/usr/bin/env python3
"""Fixture tests for the nightly browser suite reporter (D373, #443).

The reporter runs against the in-process fake Forgejo from
`test-nightly-fuzz.py` (real state: issues, comments) with a synthetic token
and hand-written Playwright JSON reports, so filing, deduplication and the
"passes again" comments are tested end to end without a browser.
"""
import contextlib
import importlib.machinery
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


def load_script(name):
    """Import a script next to this file, whatever its extension."""
    path = Path(__file__).with_name(name)
    loader = importlib.machinery.SourceFileLoader(name.replace('-', '_').removesuffix('.py'), str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


suite = load_script('nightly-browser-suite.py')
fuzz_tests = load_script('test-nightly-fuzz.py')
service = load_script('nightly-browser-suite-service')
installer = load_script('install-nightly-browser-suite')
TOKEN = 'synthetic-token'
REAL_RUN_IS_FROM_TONIGHT = service.run_is_from_tonight
RUN_NAME = '20261109T061806Z-aaaaaaa'


def playwright_report(**outcomes):
    """A minimal Playwright JSON report: each keyword is a spec file, its value the test statuses in it."""
    suites = []
    for file, statuses in outcomes.items():
        specs = [{'title': f'test {i}', 'file': file,
                  'tests': [{'status': status, 'results': [{'status': 'failed' if status == 'unexpected' else 'passed',
                                                            'errors': [{'message': '\x1b[31mexpected 1 got 2\x1b[39m'}]
                                                            if status == 'unexpected' else []}]}]}
                 for i, status in enumerate(statuses)]
        suites.append({'file': file, 'suites': [{'title': 'inner', 'specs': specs}]})
    return {'suites': suites}


class Reporter(unittest.TestCase):
    """Issue per failing spec, deduplicated, with a comment when the spec is green again."""

    def setUp(self):
        """Start the fake Forgejo and a results directory."""
        self.forgejo = fuzz_tests.FakeForgejo()
        self.addCleanup(self.forgejo.close)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.results = Path(self.temp.name)
        (self.results / 'suite.log').write_text('  x docs-palette.spec.ts:12 opens\n  ok toast.spec.ts:3 stacks\n')

    def night(self, head='a' * 40, **outcomes):
        """File one night's results and return the request-error count."""
        (self.results / 'results.json').write_text(json.dumps(playwright_report(**outcomes)))
        (self.results / 'meta.json').write_text(json.dumps({'head': head, 'evidence': '/attacker/chosen/path',
                                                            'log': str(self.results / 'suite.log')}))
        return suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results, f'20261109T061806Z-{head[:7]}', login=self.forgejo.login)

    def test_collect_sorts_files(self):
        """Failures name their file; skipped-only files are neither failing nor passing."""
        failing, passing = suite.collect(playwright_report(**{
            'a.spec.ts': ['expected', 'unexpected'], 'b.spec.ts': ['expected'], 'c.spec.ts': ['skipped'],
            'd.spec.ts': ['flaky']}))
        self.assertEqual(sorted(failing), ['a.spec.ts'])
        self.assertEqual(passing, {'b.spec.ts', 'd.spec.ts'})
        self.assertEqual(failing['a.spec.ts'], [('test 1', 'expected 1 got 2')])

    def test_one_issue_per_failing_spec_with_details(self):
        """Two red specs open two issues carrying SHA, evidence path, error and log tail."""
        self.assertEqual(self.night(**{'docs-palette.spec.ts': ['unexpected'], 'toast-stack.spec.ts': ['unexpected', 'expected'],
                                       'ok.spec.ts': ['expected']}), 0)
        self.assertEqual(self.forgejo.creates(), 2)
        body = next(i['body'] for i in self.forgejo.issues.values() if 'docs-palette' in i['title'])
        for expected in ('a' * 40, suite.BROWSER_RUNS + '/' + RUN_NAME + '/evidence', 'expected 1 got 2', 'docs-palette.spec.ts:12 opens',
                         suite.spec_marker('docs-palette.spec.ts')):
            self.assertIn(expected, body)
        self.assertNotIn('\x1b', body)

    def test_second_night_does_not_duplicate(self):
        """The same red spec the next night opens nothing and comments nothing."""
        self.night(**{'docs-palette.spec.ts': ['unexpected']})
        self.night(head='b' * 40, **{'docs-palette.spec.ts': ['unexpected']})
        self.assertEqual(self.forgejo.creates(), 1)
        self.assertEqual(self.forgejo.comments, {})

    def test_fixed_spec_gets_one_comment_and_is_never_closed(self):
        """Green again: one comment, however many green nights follow; the issue stays open."""
        self.night(**{'docs-palette.spec.ts': ['unexpected']})
        self.night(head='b' * 40, **{'docs-palette.spec.ts': ['expected']})
        self.night(head='c' * 40, **{'docs-palette.spec.ts': ['expected']})
        self.assertEqual(len(self.forgejo.comments), 1)
        comment = next(iter(self.forgejo.comments.values()))['body']
        self.assertIn('passes again', comment)
        self.assertIn('b' * 40, comment)
        self.assertEqual({i['state'] for i in self.forgejo.issues.values()}, {'open'})
        self.assertFalse([r for r in self.forgejo.requests if r[0] in ('PATCH', 'DELETE')])

    def test_skipped_spec_is_not_a_fix(self):
        """A spec that only skipped tonight does not claim to be fixed."""
        self.night(**{'docs-palette.spec.ts': ['unexpected']})
        self.night(**{'docs-palette.spec.ts': ['skipped']})
        self.assertEqual(self.forgejo.comments, {})

    def test_fails_again_after_fix_comments_once(self):
        """Red, green, red, red: the second red is announced once on the same issue."""
        for status in ('unexpected', 'expected', 'unexpected', 'unexpected'):
            self.night(**{'docs-palette.spec.ts': [status]})
        self.assertEqual(self.forgejo.creates(), 1)
        bodies = [c['body'] for c in self.forgejo.comments.values()]
        self.assertEqual(len(bodies), 2)
        self.assertIn('passes again', bodies[0])
        self.assertIn('fails again', bodies[1])

    def test_token_only_in_header(self):
        """The synthetic token is sent as an Authorization header on every request."""
        self.night(**{'docs-palette.spec.ts': ['unexpected']})
        self.assertTrue(self.forgejo.requests)
        self.assertEqual({auth for _, _, auth in self.forgejo.requests}, {'token ' + TOKEN})

    def bodies(self):
        """Every issue body and comment body the reporter wrote, in one list."""
        return [i['body'] for i in self.forgejo.issues.values()] + [c['body'] for c in self.forgejo.comments.values()]

    def test_token_in_a_symlinked_log_is_not_published(self):
        """Review PoC: a spec named `a` and a log full of other text must not pull in unrelated lines (the token)."""
        (self.results / 'suite.log').write_text(f'a line with {TOKEN} in it\n')
        self.night(**{'a': ['unexpected']})
        self.assertFalse([b for b in self.bodies() if TOKEN in b])

    def test_issue_storm_becomes_one_roll_up(self):
        """Review PoC: 501 invented failing names open one roll-up issue, not 501 issues."""
        self.night(**{f'spec{i}.spec.ts': ['unexpected'] for i in range(501)})
        self.assertEqual(self.forgejo.creates(), 1)
        self.night(**{f'spec{i}.spec.ts': ['unexpected'] for i in range(501)})
        self.assertEqual(self.forgejo.creates(), 1)
        self.assertLess(max(len(b) for b in self.bodies()), 70000)

    def test_cap_on_new_issues_per_night(self):
        """Eleven new red specs, among many green ones, are a roll-up; ten are ten issues."""
        green = {f'ok{i}.spec.ts': ['expected'] for i in range(60)}
        self.night(**green, **{f'r{i}.spec.ts': ['unexpected'] for i in range(10)})
        self.assertEqual(self.forgejo.creates(), 10)
        self.night(head='b' * 40, **green, **{f'n{i}.spec.ts': ['unexpected'] for i in range(11)})
        self.assertEqual(self.forgejo.creates(), 11)
        self.assertIn('roll-up', next(reversed(self.forgejo.issues.values()))['title'])

    def test_a_crashed_server_is_one_roll_up(self):
        """Everything red at once reads as an infrastructure failure: a single roll-up."""
        self.night(**{f'r{i}.spec.ts': ['unexpected'] for i in range(8)})
        self.assertEqual(self.forgejo.creates(), 1)
        self.assertIn('roll-up', next(iter(self.forgejo.issues.values()))['title'])

    def test_spec_names_with_spaces_cannot_bypass_dedupe(self):
        """Review PoC: a name with spaces or `-->` goes to one bucket and is deduplicated like any other."""
        green = {f'ok{i}.spec.ts': ['expected'] for i in range(60)}
        for night in range(3):
            self.night(**green, **{'x --> y z.spec.ts': ['unexpected']})
        self.assertEqual(self.forgejo.creates(), 1)
        self.assertNotIn('x --> y', self.forgejo.issues[345]['body'])

    def test_marker_is_a_hash_of_the_name(self):
        """The hidden marker has no raw name in it."""
        self.assertRegex(suite.spec_marker('docs-palette.spec.ts'), r'^<!-- infraternal-browser-spec: [0-9a-f]{16} -->$')

    def test_markdown_cannot_break_out_of_the_fence(self):
        """Review PoC: a line of three backticks, then a mention and an image, stays inside the code block."""
        hostile = 'oops\n```\n@everyone ![x](http://evil.example/p.png) [click](http://evil.example)\n````\n@victim'
        report = playwright_report(**{'ok.spec.ts': ['expected'], 'bad.spec.ts': ['unexpected']})
        report['suites'][1]['suites'][0]['specs'][0]['tests'][0]['results'][0]['errors'] = [{'message': hostile}]
        (self.results / 'suite.log').write_text('bad.spec.ts ' + hostile.replace('\n', ' ') + '\n' + 'bad.spec.ts ```\n@victim2\n')
        self.night_from(report)
        body = self.forgejo.issues[345]['body']
        # Every line that holds the hostile text sits between a fence longer than the longest backtick run in it.
        fence = max(re.findall(r'^`{3,}', body, re.M), key=len)
        self.assertGreaterEqual(len(fence), 5)
        outside = re.sub(re.escape(fence) + r'.*?' + re.escape(fence), '', body, flags=re.S)
        for hostile_text in ('@everyone', '@victim', '![x]', 'evil.example'):
            self.assertNotIn(hostile_text, outside)

    def night_from(self, report, head='a' * 40, meta=None):
        """File a hand-built Playwright report."""
        (self.results / 'results.json').write_text(json.dumps(report))
        (self.results / 'meta.json').write_text(json.dumps(meta or {'head': head}))
        return suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results, f'20261109T061806Z-{head[:7]}', login=self.forgejo.login)

    def test_fields_are_bounded_and_the_head_is_validated(self):
        """Review: a 5000-character `head` is refused, and long log lines are cut."""
        report = playwright_report(**{'bad.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        with self.assertRaises(ValueError):
            self.night_from(report, meta={'head': 'z' * 5000})
        (self.results / 'suite.log').write_text('bad.spec.ts ' + 'w' * 100000 + '\n')
        self.night_from(report)
        self.assertLess(len(self.forgejo.issues[345]['body']), 20000)

    def test_only_the_token_owners_markers_count(self):
        """Review: someone else's issue carrying the marker does not mute the spec."""
        self.forgejo.issues[300] = {'number': 300, 'state': 'open', 'title': 'x', 'user': {'login': 'somebody-else'},
                                    'body': suite.spec_marker('docs-palette.spec.ts')}
        self.night(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.assertEqual(self.forgejo.creates(), 1)

    def test_a_forged_fixed_comment_is_ignored(self):
        """Review: a comment by another user with the 'fixed' marker does not decide the issue's state."""
        self.night(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.forgejo.comments[1] = {'id': 1, 'issue': 345, 'body': suite.state_marker('fixed'), 'user': {'login': 'somebody-else'}}
        self.night(head='b' * 40, **{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.assertEqual(len(self.forgejo.comments), 1)

    def test_more_than_two_thousand_open_issues_fails_closed(self):
        """Review: when the listing hits the page limit, the reporter stops instead of deduplicating blindly."""
        full = [{'number': n, 'body': '', 'user': {'login': self.forgejo.login}} for n in range(50)]
        with mock.patch.object(suite, 'api', return_value=full):
            with self.assertRaises(RuntimeError):
                list(suite.pages('x', 'repos/a/b/issues', TOKEN))

    def test_test_titles_cannot_inject_markdown(self):
        """Round-3 PoC: a title with a newline, a mention, an image and a fake state marker stays inside the fence."""
        report = playwright_report(**{'ok.spec.ts': ['expected'], 'bad.spec.ts': ['unexpected']})
        report['suites'][1]['suites'][0]['specs'][0]['title'] = 'ok\n\n@kayg ![beacon](https://evil.example/p.png)\n' + suite.state_marker('fixed')
        self.night_from(report)
        body = self.forgejo.issues[345]['body']
        fence = max(re.findall(r'^`{3,}', body, re.M), key=len)
        outside = re.sub(re.escape(fence) + r'.*?' + re.escape(fence), '', body, flags=re.S)
        for text in ('@kayg', 'beacon', 'evil.example', 'state: fixed'):
            self.assertNotIn(text, outside)
        self.assertEqual(body.count('infraternal-browser-state'), 2)  # the real marker, and the title's copy inside the fence

    def test_names_are_ascii_and_end_at_the_end(self):
        """Round-3 PoC: a trailing newline or non-ASCII digits make neither a spec name nor a run name."""
        self.assertIsNone(suite.SPEC_NAME.fullmatch('d.spec.ts\n'))
        self.assertEqual(suite.clean_name('d.spec.ts\n'), suite.UNPARSEABLE)
        self.assertEqual(suite.clean_name('d\u00e9.spec.ts'), suite.UNPARSEABLE)
        self.assertIsNone(suite.RUN_NAME.fullmatch('\u0662\u0660\u0662\u0666' + '1109T061806Z-aaaaaaa'))
        self.assertIsNone(suite.RUN_NAME.fullmatch('20261109T061806Z-aaaaaaa\n'))
        self.assertIsNone(service.RUN_NAME.fullmatch('20261109T061806Z-aaaaaaa\n'))
        self.assertIsNone(suite.HEAD.fullmatch('a' * 40 + '\n'))

    def test_open_issue_budget_pools_new_reds(self):
        """Round-3 PoC: with 30 suite issues already open, fresh reds go to the roll-up, not 10 new issues a night."""
        green = {f'ok{i}.spec.ts': ['expected'] for i in range(80)}
        for night in range(3):
            self.night(head=str(night) * 40, **green, **{f'n{night}_{i}.spec.ts': ['unexpected'] for i in range(10)})
        self.assertEqual(self.forgejo.creates(), 30)
        for night in range(3, 6):
            self.night(head=str(night) * 40, **green, **{f'n{night}_{i}.spec.ts': ['unexpected'] for i in range(10)})
        self.assertEqual(self.forgejo.creates(), 31)
        self.assertIn('roll-up', next(reversed(self.forgejo.issues.values()))['title'])

    def test_issue_with_many_comments_does_not_stop_the_night(self):
        """Round-4 PoC: Forgejo ignores limit/page on comments and returns them all every time; 120 comments must not abort."""
        self.night(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        for n in range(119):
            self.forgejo.comments[5000 + n] = {'id': 5000 + n, 'issue': 345, 'body': f'chatter {n}', 'user': {'login': 'somebody'}}
        self.assertEqual(self.night(head='b' * 40, **{'docs-palette.spec.ts': ['expected'], 'ok.spec.ts': ['expected']}), 0)
        self.assertTrue([c for c in self.forgejo.comments.values() if 'passes again' in c['body']])
        # The newest state marker still wins when the same comments come back more than once.
        self.assertEqual(self.night(head='c' * 40, **{'docs-palette.spec.ts': ['expected'], 'ok.spec.ts': ['expected']}), 0)
        self.assertEqual(len([c for c in self.forgejo.comments.values() if 'passes again' in c['body']]), 1)

    def test_later_reds_leave_a_trace_on_the_roll_up(self):
        """Round-4: once the roll-up is open, names it has not listed yet are added as one comment, once."""
        green = {f'ok{i}.spec.ts': ['expected'] for i in range(60)}
        first = {f'r{i}.spec.ts': ['unexpected'] for i in range(12)}
        self.night(**green, **first)
        self.assertEqual(self.forgejo.creates(), 1)
        self.assertEqual(self.forgejo.comments, {})
        later = {**first, 'late1.spec.ts': ['unexpected'], 'late2.spec.ts': ['unexpected']}
        self.night(head='b' * 40, **green, **later)
        self.night(head='b' * 40, **green, **later)
        self.assertEqual(self.forgejo.creates(), 1)
        self.assertEqual(len(self.forgejo.comments), 1)
        comment = next(iter(self.forgejo.comments.values()))['body']
        self.assertIn('late1.spec.ts', comment)
        self.assertIn('late2.spec.ts', comment)
        self.assertNotIn('r3.spec.ts', comment)

    def test_jsonl_collect_counts_only_real_failures(self):
        """Follow-up 2: from the streamed per-test lines, only tests that really failed make a spec red."""
        lines = [{'kind': 'begin', 'total': 9},
                 {'kind': 'test', 'file': 'a.spec.ts', 'title': 'one', 'outcome': 'expected'},
                 {'kind': 'test', 'file': 'a.spec.ts', 'title': 'two', 'outcome': 'unexpected', 'error': '\x1b[31mboom\x1b[39m'},
                 {'kind': 'test', 'file': 'b.spec.ts', 'title': 'ok', 'outcome': 'expected'},
                 {'kind': 'test', 'file': 'c.spec.ts', 'title': 'skip', 'outcome': 'skipped'},
                 {'kind': 'test', 'file': 'bad name.spec.ts', 'title': 'x', 'outcome': 'unexpected'},
                 {'kind': 'test', 'file': 'd.spec.ts', 'title': 'interrupted', 'outcome': 'interrupted'}]
        data = ('\n'.join(json.dumps(line) for line in lines) + '\nnot json\n[1, 2]\n{"kind": "begin", "total": "many"}\n').encode()
        failing, passing, finished, total = suite.collect_jsonl(data)
        self.assertEqual(sorted(failing), sorted(['a.spec.ts', suite.UNPARSEABLE]))
        self.assertEqual(failing['a.spec.ts'], [('two', 'boom')])
        self.assertEqual(passing, {'b.spec.ts'})
        self.assertEqual((finished, total), (6, 9))

    def partial_night(self, lines, head='a' * 40, timeout='9h'):
        """File a timed-out night: only meta.json, suite.log and the streamed lines exist."""
        (self.results / 'results.json').unlink(missing_ok=True)
        (self.results / 'results.jsonl').write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        (self.results / 'meta.json').write_text(json.dumps({'head': head}))
        return suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results, f'20261109T061806Z-{head[:7]}', suite_timeout=timeout, login=self.forgejo.login)

    def test_timed_out_suite_files_the_failures_it_saw_and_one_note(self):
        """Follow-up 2: issues for tests that really failed, plus one roll-up note 'timed out after 9 h; M of K tests ran'."""
        lines = [{'kind': 'begin', 'total': 10}] + [{'kind': 'test', 'file': 'docs-palette.spec.ts', 'title': 'opens', 'outcome': 'unexpected', 'error': 'bad'}] \
            + [{'kind': 'test', 'file': 'ok.spec.ts', 'title': f't{i}', 'outcome': 'expected'} for i in range(3)]
        self.assertEqual(self.partial_night(lines), 0)
        titles = [i['title'] for i in self.forgejo.issues.values()]
        self.assertEqual(len(titles), 2, titles)
        self.assertTrue([t for t in titles if 'docs-palette.spec.ts' in t])
        rollup = next(i for i in self.forgejo.issues.values() if 'roll-up' in i['title'])
        self.assertIn('suite timed out after 9 h; 4 of 10 tests ran', rollup['body'])
        # The same night again adds nothing.
        self.partial_night(lines)
        self.assertEqual(self.forgejo.creates(), 2)
        self.assertEqual(self.forgejo.comments, {})

    def test_timeout_note_goes_on_the_open_roll_up_once(self):
        """Follow-up 2: with a roll-up already open, the note is one comment on it, not a new issue."""
        green = {f'ok{i}.spec.ts': ['expected'] for i in range(60)}
        self.night(**green, **{f'r{i}.spec.ts': ['unexpected'] for i in range(12)})
        self.assertEqual(self.forgejo.creates(), 1)
        lines = [{'kind': 'begin', 'total': 50}, {'kind': 'test', 'file': 'ok0.spec.ts', 'title': 't', 'outcome': 'expected'}]
        self.partial_night(lines, head='b' * 40)
        self.partial_night(lines, head='b' * 40)
        self.assertEqual(self.forgejo.creates(), 1)
        notes = [c['body'] for c in self.forgejo.comments.values()]
        self.assertEqual(len(notes), 1)
        self.assertIn('suite timed out after 9 h; 1 of 50 tests ran', notes[0])

    def test_specs_that_never_ran_are_not_reported_fixed(self):
        """Follow-up 2: a red spec the timed-out suite never reached gets no 'passes again' comment."""
        self.night(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.partial_night([{'kind': 'begin', 'total': 5}, {'kind': 'test', 'file': 'ok.spec.ts', 'title': 't', 'outcome': 'expected'}], head='b' * 40)
        self.assertFalse([c for c in self.forgejo.comments.values() if 'passes again' in c['body']])

    def test_suite_timeout_argument_is_validated(self):
        """The timeout label is inserted into issues, so only a plain number of hours is accepted."""
        self.partial_night([{'kind': 'begin', 'total': 1}], timeout='9h')
        for bad in ('9', '9h\n@x', '999999h', 'nine'):
            with self.subTest(bad), self.assertRaises(ValueError):
                self.partial_night([{'kind': 'begin', 'total': 1}], timeout=bad)

    def test_run_streams_results_and_announces_its_folder_first(self):
        """Follow-up 2: the suite streams one line per test, and `latest` and meta.json exist before the first test runs."""
        runs = Path(self.temp.name) / 'streams'
        runs.mkdir()
        seen = {}

        def fake_step(command, cwd, log, env=None):
            if command[:4] == ['bun', 'x', 'playwright', 'test']:
                seen['command'], seen['env'] = command, env
                seen['latest'] = (runs / 'latest').read_text().strip()
                seen['meta'] = json.loads((runs / seen['latest'] / 'meta.json').read_text())
            return 0
        with mock.patch.object(suite, 'run_step', side_effect=fake_step), mock.patch.object(suite.subprocess, 'check_output', return_value='f' * 40 + '\n'):
            suite.run(Path(self.temp.name), runs)
        self.assertIn('--reporter=list,json,./nightly-reporter.ts', seen['command'])
        self.assertEqual(seen['env']['NIGHTLY_JSONL'], str(runs / seen['latest'] / 'results.jsonl'))
        self.assertEqual(seen['meta']['head'], 'f' * 40)
        reporter = Path(suite.__file__ if hasattr(suite, '__file__') else Path(__file__).with_name('nightly-browser-suite.py')).resolve().parents[1] / 'apps/tracer/nightly-reporter.ts'
        text = reporter.read_text()
        for needle in ('NIGHTLY_JSONL', 'appendFileSync', 'onTestEnd', 'onBegin', 'outcome()'):
            self.assertIn(needle, text)

    def test_no_request_needs_the_user_scope(self):
        """Round-5 PoC: a token without read:user gets 403 on /user. The reporter never asks, and a whole night is filed."""
        self.forgejo.deny = lambda method, path: 403 if path == '/api/v1/user' else None
        green = {f'ok{i}.spec.ts': ['expected'] for i in range(60)}
        self.assertEqual(self.night(**green, **{'docs-palette.spec.ts': ['unexpected']}), 0)
        self.assertEqual(self.night(head='b' * 40, **green, **{'docs-palette.spec.ts': ['expected']}), 0)
        self.assertFalse([r for r in self.forgejo.requests if r[1].split('?')[0].endswith('/api/v1/user')], 'the reporter must not call /user')
        self.assertEqual(self.forgejo.creates(), 1)
        self.assertEqual(len(self.forgejo.comments), 1)

    def test_own_issues_are_recognised_by_the_configured_login(self):
        """Round-5: a marker counts only when its author is the configured login; a response from another author stops the night."""
        self.forgejo.issues[300] = {'number': 300, 'state': 'open', 'title': 'x', 'user': {'login': 'somebody-else'}, 'body': suite.spec_marker('d.spec.ts')}
        self.night(**{'d.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.assertEqual(self.forgejo.creates(), 1)
        # The configured login is wrong for this token: the reporter's own post comes back under another name.
        self.forgejo.login = self.forgejo.author = 'the-token-owner'
        with self.assertRaises(ValueError):
            suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results, '20261109T061806Z-aaaaaaa', login='configured-other')

    def test_a_login_is_required_and_validated(self):
        """No login configured means no night: the reporter refuses rather than guess whose markers to believe."""
        (self.results / 'results.json').write_text(json.dumps(playwright_report(**{'ok.spec.ts': ['expected']})))
        (self.results / 'meta.json').write_text(json.dumps({'head': 'a' * 40}))
        for bad in (None, '', 'a b', 'x\n', 'a' * 80):
            with self.subTest(bad), self.assertRaises(ValueError):
                suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results, '20261109T061806Z-aaaaaaa', login=bad)

    def run_cli(self, *args, token=TOKEN):
        """Run the reporter's command line against the fake; return (exit code, stderr text)."""
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        token_file = Path(other.name) / 'token'
        token_file.write_text(token)
        err = io.StringIO()
        argv = ['nightly-browser-suite.py', 'report', '--results', str(self.results), '--token-file', str(token_file), '--api', self.forgejo.api, *args]
        with mock.patch.object(suite.sys, 'argv', argv), mock.patch.object(suite.sys, 'stderr', err):
            return suite.main(), err.getvalue()

    def stage_old_style(self, name='20261109T134307Z-c442500'):
        """The staging folder the first real run left: meta.json, results.json and suite.log, with no staged.json."""
        head = name[-7:] + 'd' * 33
        (self.results / 'results.json').write_text(json.dumps(playwright_report(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})))
        (self.results / 'meta.json').write_text(json.dumps({'head': head, 'evidence': '/old/path', 'log': '/old/log', 'playwright_exit': 1}))
        return name, head

    def test_forbidden_token_is_said_plainly_and_the_staged_files_stay(self):
        """Round-5: a 403 on a write ends the night with one clear line (token lacks permission), exit 77, files kept, and a re-run files it."""
        name, head = self.stage_old_style()
        self.forgejo.deny = lambda method, path: 403 if method == 'POST' and path.endswith('/issues') else None
        code, err = self.run_cli('--login', self.forgejo.login, '--run-name', name)
        self.assertEqual(code, suite.TOKEN_REFUSED_EXIT)
        lines = [l for l in err.splitlines() if 'TOKEN LACKS PERMISSION' in l]
        self.assertEqual(len(lines), 1, err)
        self.assertIn('HTTP 403', lines[0])
        self.assertIn('--report-only', lines[0])
        self.assertNotIn(TOKEN, err)
        self.assertEqual(sorted(p.name for p in self.results.iterdir()), ['meta.json', 'results.json', 'suite.log'])
        self.forgejo.deny = None
        self.assertEqual(self.run_cli('--login', self.forgejo.login, '--run-name', name)[0], 0)
        self.assertEqual(len(self.forgejo.issues), 1)

    def test_report_only_reads_the_run_name_from_staged_info(self):
        """Round-5: without --run-name, the reporter takes it (and the timeout label) from the staged.json the helper wrote."""
        name, head = self.stage_old_style('20261109T061806Z-aaaaaaa')
        (self.results / 'meta.json').write_text(json.dumps({'head': 'a' * 40}))
        self.assertEqual(self.run_cli('--login', self.forgejo.login)[0], 1, 'no run name anywhere is refused')
        (self.results / 'staged.json').write_text(json.dumps({'run_name': name, 'suite_timeout': None}))
        self.assertEqual(self.run_cli('--login', self.forgejo.login)[0], 0)
        self.assertEqual(self.forgejo.creates(), 1)
        (self.results / 'staged.json').write_text(json.dumps({'run_name': '../x', 'suite_timeout': None}))
        self.assertEqual(self.run_cli('--login', self.forgejo.login)[0], 1)

    def test_run_without_report_is_an_infrastructure_failure(self):
        """`run` exits 1 and opens nothing when a build step fails or no report exists."""
        runs = Path(self.temp.name) / 'runs'
        runs.mkdir()
        with mock.patch.object(suite, 'run_step', return_value=1), \
                mock.patch.object(suite.subprocess, 'check_output', return_value='f' * 40 + '\n'):
            self.assertEqual(suite.run(Path(self.temp.name), runs), 1)
        with mock.patch.object(suite, 'run_step', return_value=0), \
                mock.patch.object(suite.subprocess, 'check_output', return_value='f' * 40 + '\n'):
            (second := Path(self.temp.name) / 'runs2').mkdir()
            self.assertEqual(suite.run(Path(self.temp.name), second), 1)
        self.assertEqual(self.forgejo.creates(), 0)

    def test_prune_keeps_newest(self):
        """Only the newest runs stay."""
        runs = Path(self.temp.name) / 'prune'
        for name in ('20260101T000000Z-a', '20260102T000000Z-b', '20260103T000000Z-c'):
            (runs / name).mkdir(parents=True)
        suite.prune_runs(runs, 2)
        self.assertEqual(sorted(p.name for p in runs.iterdir()), ['20260102T000000Z-b', '20260103T000000Z-c'])


class SeparateAccount(unittest.TestCase):
    """The suite runs without the token; only the reviewed reporter sees it."""

    def setUp(self):
        """Every helper run needs a configured login: give each test a root-owned-looking one."""
        self.login_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.login_dir.cleanup)
        stack = self.login_file(self.login_dir.name)
        stack.enter_context(mock.patch.object(service, 'run_is_from_tonight', return_value=True))  # fixture folders carry old stamps
        stack.__enter__()
        self.addCleanup(stack.__exit__, None, None, None)

    def test_units(self):
        """Fixed root-owned helper, no token in the unit, 05:00 IST after the 02:00 fuzz."""
        unit = installer.service_unit()
        self.assertIn(f'ExecStart={installer.SERVICE_HELPER}', unit)
        self.assertNotIn('token', unit)
        self.assertNotIn('/home/claude', unit)
        timer = installer.timer_unit()
        self.assertIn('OnCalendar=*-*-* 05:00:00 Asia/Kolkata', timer)
        self.assertNotIn('02:00', timer)
        self.assertEqual(str(installer.HOME), service.BROWSER_HOME)
        self.assertEqual(installer.USER, service.BROWSER_USER)
        self.assertEqual(str(installer.REPORTER), service.REPORTER)

    def login_file(self, temp):
        """Patch in a root-owned-looking login file (owned by the current user in tests)."""
        Path(temp, 'login').write_text('kayg\n')
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(service, 'LOGIN_FILE', str(Path(temp) / 'login')))
        stack.enter_context(mock.patch.object(service, 'LOGIN_OWNER', os.getuid()))
        return stack

    def run_dir(self, temp, name='20261109T061806Z-aaaaaaa'):
        """A well-formed run folder under `temp/runs`, as the unprivileged suite would leave it."""
        runs = Path(temp) / 'runs'
        (runs / name).mkdir(parents=True)
        (runs / name / 'meta.json').write_text(json.dumps({'head': 'a' * 40}))
        (runs / name / 'results.json').write_text('{"suites": []}')
        (runs / name / 'suite.log').write_text('ok\n')
        (runs / 'latest').write_text(name + '\n')
        return runs, name

    def test_token_account_never_runs_repository_code(self):
        """The suite step runs as the browser account; the token account runs only the root-owned reporter on staged copies."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = service.READY
        with tempfile.TemporaryDirectory() as temp:
            self.run_dir(temp)
            with mock.patch.object(service, 'BROWSER_HOME', temp), mock.patch.object(service, 'REPORT_HOME', temp + '/report'), self.login_file(temp), \
                    mock.patch.object(service, 'ids', return_value=(os.getuid(), os.getgid())), \
                    mock.patch.object(service.os, 'chown'), mock.patch.object(service.os, 'fchown'), \
                    mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                    mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                Path(temp, 'report').mkdir()
                self.assertEqual(service.main([]), 0)
        steps = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(steps), 4)
        for step in steps[:3]:
            self.assertEqual(step[1], '--reuid=infraternal-browser')
            self.assertNotIn('forgejo-token', ' '.join(step))
        self.assertIn('nice', steps[1])
        # Round 4: leftover suite processes are killed (as the suite account) before staging and reporting.
        self.assertEqual(steps[2][steps[2].index('/usr/bin/python3'):], service.KILL_COMMAND)
        self.assertEqual(steps[3][1], '--reuid=infraternal-fuzz')
        self.assertIn(service.REPORTER, steps[3])
        self.assertIn('-I', steps[3])
        self.assertIn('--run-name', steps[3])
        self.assertNotIn('nightly-browser-suite.py', ' '.join(steps[3]))
        self.assertNotIn(temp + '/runs', ' '.join(steps[3]))
        # Round 4: root never chdirs through the suite-owned checkout; env -C does it after privileges are dropped.
        for call in run.call_args_list[:3]:
            self.assertEqual(call.kwargs['cwd'], '/')
        for step in steps[:2]:
            self.assertIn('-C', step)
            self.assertLess(step.index('env'), step.index('-C'))
            self.assertLess(step.index('-C'), step.index('nice') if 'nice' in step else step.index('sh'))
        holder.stdin.write.assert_called_once()

    def test_queue_wait_timeout_is_its_own_failure(self):
        """Follow-up PoC: a build-slot queue that never frees ends the night with one clear line and no suite, staging or report."""
        import threading
        release = threading.Event()
        holder = mock.MagicMock()
        holder.stdout.readline.side_effect = lambda: (release.wait(10), b'')[1]
        holder.stdin.close.side_effect = release.set
        err = io.StringIO()
        with mock.patch.object(service, 'QUEUE_WAIT_SECONDS', 0.2), mock.patch.object(service, 'stop_holder', side_effect=lambda h: release.set()), \
                mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                mock.patch.object(service.subprocess, 'run', side_effect=AssertionError('ran without a slot')), \
                mock.patch.object(service.sys, 'stderr', err):
            self.assertEqual(service.main([]), service.QUEUE_TIMEOUT_EXIT)
        self.assertEqual(len([l for l in err.getvalue().splitlines() if 'QUEUE WAIT TIMEOUT' in l]), 1)
        self.assertNotIn('SUITE TIMEOUT', err.getvalue())
        self.assertNotEqual(service.QUEUE_TIMEOUT_EXIT, service.SUITE_TIMEOUT_EXIT)

    def timed_out_main(self, temp, fresh=True):
        """Run the helper's main with the suite step timing out (exit 124); return (exit code, stderr text, steps run)."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = service.READY
        err = io.StringIO()
        with mock.patch.object(service, 'BROWSER_HOME', temp), mock.patch.object(service, 'REPORT_HOME', temp + '/report'), self.login_file(temp), \
                mock.patch.object(service, 'ids', return_value=(os.getuid(), os.getgid())), \
                mock.patch.object(service.os, 'chown'), mock.patch.object(service.os, 'fchown'), \
                mock.patch.object(service, 'run_is_from_tonight', return_value=fresh), \
                mock.patch.object(service.subprocess, 'Popen', return_value=holder), mock.patch.object(service.sys, 'stderr', err), \
                mock.patch.object(service.subprocess, 'run', side_effect=lambda cmd, **k: subprocess.CompletedProcess(cmd, 124 if 'nix' in cmd else 0)) as run:
            Path(temp, 'report').mkdir(exist_ok=True)
            code = service.main([])
        return code, err.getvalue(), [call.args[0] for call in run.call_args_list]

    def test_suite_budget_starts_after_the_slot_is_granted(self):
        """The 9 h bound wraps only the suite command, and a timeout is reported as a suite timeout."""
        with tempfile.TemporaryDirectory() as temp:
            self.run_dir(temp)
            code, err, steps = self.timed_out_main(temp)
        self.assertEqual(code, service.SUITE_TIMEOUT_EXIT)
        suite_step = next(step for step in steps if 'nix' in step)
        at = suite_step.index('timeout')
        self.assertEqual(suite_step[at:at + 3], ['timeout', '--kill-after=60', '9h'])
        self.assertEqual(suite_step[at + 3], 'nix')
        self.assertEqual(len([l for l in err.splitlines() if 'SUITE TIMEOUT' in l]), 1)
        self.assertNotIn('QUEUE WAIT', err)
        self.assertLess(service.QUEUE_WAIT_SECONDS / 3600 + int(service.SUITE_BUDGET[:-1]), 24, 'TimeoutStartSec=24h stays a backstop')

    def test_a_timed_out_suite_still_reports_what_it_finished(self):
        """Follow-up 2: after a suite timeout the partial results are staged and reported, flagged with the budget."""
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            (runs / name / 'results.json').unlink()
            (runs / name / 'results.jsonl').write_text('{"kind": "begin", "total": 3}\n')
            code, err, steps = self.timed_out_main(temp)
            self.assertTrue((Path(temp) / 'report' / 'browser-staging' / 'results.jsonl').is_file())
        self.assertEqual(code, service.SUITE_TIMEOUT_EXIT)
        reporter = next(step for step in steps if service.REPORTER in step)
        self.assertEqual(reporter[reporter.index('--suite-timeout') + 1], '9h')
        self.assertEqual(reporter[1], '--reuid=infraternal-fuzz')

    def test_a_stale_run_folder_is_not_reported_as_tonights_partial_results(self):
        """Follow-up 2: if the suite died before it made its own run folder, last night's `latest` is not reported again."""
        with tempfile.TemporaryDirectory() as temp:
            self.run_dir(temp)
            code, err, steps = self.timed_out_main(temp, fresh=False)
        self.assertEqual(code, service.SUITE_TIMEOUT_EXIT)
        self.assertFalse([step for step in steps if service.REPORTER in step])

    def test_run_folder_freshness(self):
        """A run folder counts as tonight's only if its stamp is not older than the helper's start."""
        from datetime import datetime, timedelta, timezone
        now = datetime(2026, 11, 10, 0, 30, tzinfo=timezone.utc)
        self.assertTrue(REAL_RUN_IS_FROM_TONIGHT('20261110T003100Z-aaaaaaa', now))
        self.assertTrue(REAL_RUN_IS_FROM_TONIGHT('20261110T002900Z-aaaaaaa', now))  # one minute of slack
        self.assertFalse(REAL_RUN_IS_FROM_TONIGHT('20261109T134307Z-c442500', now))
        self.assertFalse(REAL_RUN_IS_FROM_TONIGHT('garbage', now))

    def test_staging_accepts_partial_results_but_not_none(self):
        """results.json may be missing when results.jsonl is there; with neither, the run is refused."""
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            (runs / name / 'results.json').unlink()
            with self.assertRaises(service.Refused):
                self.stage(temp)
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            (runs / name / 'results.json').unlink()
            (runs / name / 'results.jsonl').write_text('{"kind": "begin", "total": 1}\n')
            _, dest = self.stage(temp)
            self.assertEqual(sorted(p.name for p in dest.iterdir()), ['meta.json', 'results.jsonl', 'suite.log'])
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            (runs / name / 'results.jsonl').symlink_to('/etc/hostname')
            with self.assertRaises(service.Refused):
                self.stage(temp)

    def test_login_comes_from_a_root_owned_file(self):
        """Round-5: the helper reads the Forgejo login from a root-owned config file and passes it to the reporter; no file, no night."""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'login'
            path.write_text('kayg\n')
            self.assertEqual(service.read_login(path, os.getuid()), 'kayg')
            with self.assertRaises(service.Refused):
                service.read_login(path, os.getuid() + 1)       # not owned by root (here: by someone else)
            for bad in ('', 'a b\n', 'x' * 80, '-x', '../etc'):
                path.write_text(bad)
                with self.assertRaises(service.Refused):
                    service.read_login(path, os.getuid())
            with self.assertRaises(service.Refused):
                service.read_login(Path(temp) / 'missing', os.getuid())
            (Path(temp) / 'link').symlink_to(path)
            with self.assertRaises(service.Refused):
                service.read_login(Path(temp) / 'link', os.getuid())

    def reporter_step(self, argv, temp, login='kayg\n'):
        """Run the helper's main with `argv`, everything mocked; return (exit code, steps run, Popen mock)."""
        Path(temp, 'login').write_text(login)
        with mock.patch.object(service, 'LOGIN_FILE', str(Path(temp) / 'login')), mock.patch.object(service, 'LOGIN_OWNER', os.getuid()), \
                mock.patch.object(service, 'REPORT_HOME', temp + '/report'), \
                mock.patch.object(service.subprocess, 'Popen') as popen, \
                mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            code = service.main(argv)
        return code, [call.args[0] for call in run.call_args_list], popen

    def test_report_only_reruns_just_the_reporter_on_staged_files(self):
        """Round-5: `--report-only --run-name N` takes no slot, runs no suite, stages nothing, and runs only the reporter."""
        with tempfile.TemporaryDirectory() as temp:
            code, steps, popen = self.reporter_step(['--report-only', '--run-name', '20261109T134307Z-c442500'], temp)
        self.assertEqual(code, 0)
        popen.assert_not_called()
        self.assertEqual(len(steps), 1)
        step = steps[0]
        self.assertEqual(step[1], '--reuid=infraternal-fuzz')
        self.assertIn(service.REPORTER, step)
        self.assertEqual(step[step.index('--run-name') + 1], '20261109T134307Z-c442500')
        self.assertEqual(step[step.index('--login') + 1], 'kayg')
        self.assertIn('/browser-staging', step[step.index('--results') + 1])
        self.assertNotIn('nix', step)

    def test_report_only_refuses_bad_arguments_and_a_missing_login(self):
        """A run name that is not a run folder name, an unknown flag, or no configured login stops it before any step."""
        for argv in (['--report-only', '--run-name', '../x'], ['--report-only', '--run-name', '20261109T134307Z-C442500'], ['--bogus']):
            with self.subTest(argv), tempfile.TemporaryDirectory() as temp, self.assertRaises(SystemExit):
                self.reporter_step(argv, temp)
        with tempfile.TemporaryDirectory() as temp:
            code, steps, popen = self.reporter_step(['--report-only'], temp, login='')
            self.assertEqual(code, 1)
            self.assertEqual(steps, [])

    def test_a_normal_night_stops_early_without_a_login(self):
        """No login file: the unit fails at once, before it waits for a slot or runs the suite."""
        with tempfile.TemporaryDirectory() as temp:
            code, steps, popen = self.reporter_step([], temp, login='')
        self.assertEqual(code, 1)
        popen.assert_not_called()
        self.assertEqual(steps, [])

    def test_cleanup_kill_command_works_for_real(self):
        """Follow-up: the cleanup kill is a command the real interpreter runs. (procps `kill -s KILL -- -1` printed its usage and killed nothing.)"""
        child = subprocess.Popen(['sleep', '60'])
        self.addCleanup(child.kill)
        command = service.KILL_COMMAND[:-1] + [str(child.pid)]
        self.assertEqual(subprocess.run(command).returncode, 0)
        self.assertEqual(child.wait(10), -9)
        # Nobody left to signal is a success; an argument that is not a process id is a failure.
        self.assertEqual(subprocess.run(service.KILL_COMMAND[:-1] + ['4000000']).returncode, 0)
        self.assertNotEqual(subprocess.run(service.KILL_COMMAND[:-1] + ['not-a-pid'], stderr=subprocess.DEVNULL).returncode, 0)
        self.assertEqual(service.KILL_COMMAND[-1], '-1')

    @unittest.skipUnless(subprocess.run(['unshare', '-Urpf', '--mount-proc', 'true'], capture_output=True).returncode == 0
                         if shutil.which('unshare') else False, 'needs unprivileged user and pid namespaces')
    def test_cleanup_kill_reaches_every_process_of_the_account(self):
        """Follow-up: inside a throwaway pid namespace the exact helper command (pid -1) kills a bystander and the call succeeds."""
        script = 'sleep 60 & P=$!; ' + ' '.join(shlex.quote(a) for a in service.KILL_COMMAND) + '; echo kill-exit=$?; wait $P; echo bystander-status=$?'
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(['unshare', '-Urpf', '--mount-proc', 'sh', '-c', script, 'sh', str(Path(temp) / 'pid')],
                                    capture_output=True, text=True, timeout=60)
        self.assertIn('kill-exit=0', result.stdout, result.stdout + result.stderr)
        self.assertIn('bystander-status=137', result.stdout, result.stdout + result.stderr)
        self.assertNotIn('Usage', result.stdout + result.stderr)

    def test_a_cleanup_that_cannot_run_stops_the_night(self):
        """Follow-up: if the cleanup kill fails, nothing is staged or reported (fail closed) and the journal says why."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = service.READY
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as temp:
            self.run_dir(temp)
            with mock.patch.object(service, 'BROWSER_HOME', temp), mock.patch.object(service, 'REPORT_HOME', temp + '/report'), self.login_file(temp), \
                    mock.patch.object(service, 'ids', return_value=(os.getuid(), os.getgid())), mock.patch.object(service.os, 'chown'), \
                    mock.patch.object(service.subprocess, 'Popen', return_value=holder), mock.patch.object(service.sys, 'stderr', err), \
                    mock.patch.object(service.subprocess, 'run', side_effect=lambda cmd, **k: subprocess.CompletedProcess(cmd, 1 if service.KILL_SNIPPET in cmd else 0)) as run:
                Path(temp, 'report').mkdir()
                self.assertEqual(service.main([]), 1)
        steps = [call.args[0] for call in run.call_args_list]
        self.assertFalse([step for step in steps if service.REPORTER in step])
        self.assertEqual(len([l for l in err.getvalue().splitlines() if 'could not stop' in l]), 1)

    def stage(self, temp, **kwargs):
        """Stage the run folder in `temp` the way the helper does, as the current user."""
        dest = Path(temp) / 'stage'
        dest.mkdir(exist_ok=True)
        descriptor = os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return service.stage(Path(temp) / 'runs', '20261109T061806Z-aaaaaaa', descriptor, kwargs.pop('owner', os.getuid()), None), dest
        finally:
            os.close(descriptor)

    def test_staging_copies_a_good_run(self):
        """The three files arrive as private regular copies."""
        with tempfile.TemporaryDirectory() as temp:
            self.run_dir(temp)
            _, dest = self.stage(temp)
            self.assertEqual(sorted(p.name for p in dest.iterdir()), ['meta.json', 'results.json', 'suite.log'])
            self.assertEqual((dest / 'suite.log').stat().st_mode & 0o777, 0o600)

    def test_staging_refuses_a_symlinked_log_to_a_secret(self):
        """Review PoC: suite.log -> a file only the token account can read is refused, and nothing is copied out of it."""
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            secret = Path(temp) / 'forgejo-token'
            secret.write_text(TOKEN)
            (runs / name / 'suite.log').unlink()
            (runs / name / 'suite.log').symlink_to(secret)
            with self.assertRaises(service.Refused):
                self.stage(temp)
            self.assertFalse([p for p in (Path(temp) / 'stage').iterdir() if TOKEN in p.read_text()])

    def test_staging_refuses_a_hard_linked_file(self):
        """Round-3 PoC: a file with a second name is refused, even when the suite account owns it."""
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            os.link(runs / name / 'suite.log', Path(temp) / 'other-name')
            with self.assertRaises(service.Refused):
                self.stage(temp)
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'a').write_text('x')
            os.link(Path(temp) / 'a', Path(temp) / 'b')
            with self.assertRaises(ValueError):
                suite.read_regular(Path(temp) / 'a', 100)

    def test_staging_folder_is_created_without_following_links(self):
        """Round-3 PoC: a symlink where the staging folder goes is never chowned; the old tree is removed by descriptor."""
        with tempfile.TemporaryDirectory() as temp:
            victim = Path(temp) / 'victim'
            victim.mkdir(mode=0o755)
            home = Path(temp) / 'home'
            home.mkdir()
            (home / 'browser-staging').symlink_to(victim)
            with mock.patch.object(service.os, 'fchown') as fchown, mock.patch.object(service.os, 'chown') as chown:
                descriptor = service.fresh_staging(home, (1, 1))
                os.close(descriptor)
            chown.assert_not_called()
            self.assertEqual(victim.stat().st_mode & 0o777, 0o755)
            self.assertFalse((home / 'browser-staging').is_symlink())
            self.assertTrue((home / 'browser-staging').is_dir())
            self.assertEqual((home / 'browser-staging').stat().st_mode & 0o777, 0o700)
            fchown.assert_called()

    def test_staging_refuses_pipes_devices_and_oversize_files(self):
        """Review PoC: a FIFO, a link to /dev/zero and a file over the cap are refused without hanging or filling memory."""
        for make in ('fifo', 'zero', 'big', 'dir'):
            with self.subTest(make), tempfile.TemporaryDirectory() as temp:
                runs, name = self.run_dir(temp)
                target = runs / name / 'results.json'
                target.unlink()
                if make == 'fifo':
                    os.mkfifo(target)
                elif make == 'zero':
                    target.symlink_to('/dev/zero')
                elif make == 'big':
                    with target.open('wb') as handle:
                        handle.truncate(service.CAPS['results.json'] + 1)
                else:
                    target.mkdir()
                with self.assertRaises(service.Refused):
                    self.stage(temp)

    def test_staging_refuses_files_not_owned_by_the_suite_account(self):
        """A file owned by someone else (a hard link to a root file, say) is not read."""
        with tempfile.TemporaryDirectory() as temp:
            self.run_dir(temp)
            with self.assertRaises(service.Refused):
                self.stage(temp, owner=os.getuid() + 1)

    def test_staging_refuses_a_symlinked_run_folder_and_pointer(self):
        """Neither the run folder nor `latest` may be a link, and the name must have the run-folder shape."""
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            real = runs / (name + '-real')
            (runs / name).rename(real)
            (runs / name).symlink_to(real)
            with self.assertRaises(service.Refused):
                self.stage(temp)
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            (runs / 'latest').unlink()
            (runs / 'latest').symlink_to('/etc/passwd')
            with self.assertRaises(service.Refused):
                service.latest_name(runs, os.getuid())
        for bad in ('../../etc', '/etc', 'x\n20261109T061806Z-aaaaaaa', ''):
            with tempfile.TemporaryDirectory() as temp:
                runs, _ = self.run_dir(temp)
                (runs / 'latest').write_text(bad)
                with self.assertRaises(service.Refused):
                    service.latest_name(runs, os.getuid())

    def test_a_refused_run_never_reaches_the_reporter(self):
        """If staging refuses, the unit fails and the token account runs nothing."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = service.READY
        with tempfile.TemporaryDirectory() as temp:
            runs, name = self.run_dir(temp)
            (runs / name / 'suite.log').unlink()
            (runs / name / 'suite.log').symlink_to('/etc/hostname')
            with mock.patch.object(service, 'BROWSER_HOME', temp), mock.patch.object(service, 'REPORT_HOME', temp + '/report'), self.login_file(temp), \
                    mock.patch.object(service, 'ids', return_value=(os.getuid(), os.getgid())), mock.patch.object(service.os, 'chown'), mock.patch.object(service.os, 'fchown'), \
                    mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                    mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                Path(temp, 'report').mkdir()
                self.assertEqual(service.main([]), 1)
        self.assertEqual(run.call_count, 3)

    def test_hooks_are_off_for_the_suite_checkout(self):
        """Round-4: the nightly fetch runs with hooks and fsmonitor disabled."""
        text = Path(__file__).with_name('nightly-browser-suite-service').read_text()
        self.assertIn('core.hooksPath=/dev/null', text)
        self.assertIn('core.fsmonitor=false', text)

    def test_the_reporter_itself_refuses_links_in_its_input(self):
        """Defence in depth: even a staging folder with a link in it is not followed by the reporter."""
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'real').write_text(TOKEN)
            (Path(temp) / 'link').symlink_to(Path(temp) / 'real')
            os.mkfifo(Path(temp) / 'pipe')
            for name in ('link', 'pipe'):
                with self.assertRaises((OSError, ValueError)):
                    suite.read_regular(Path(temp) / name, 1000)

    def test_no_slot_means_no_run(self):
        """Without a build slot nothing runs."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = b''
        with mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                mock.patch.object(service.subprocess, 'run', side_effect=AssertionError('ran without a slot')):
            self.assertEqual(service.main([]), 1)


class Installer(unittest.TestCase):
    """The root-owned copies come from a reviewed commit fetched into a fresh root-owned folder, never from the suite's checkout."""

    def make_repo(self, temp):
        """A tiny git repository with the two installable scripts; returns (path, commit sha)."""
        repo = Path(temp) / 'origin'
        (repo / 'scripts').mkdir(parents=True)
        for name in ('nightly-browser-suite-service', 'nightly-browser-suite.py'):
            (repo / 'scripts' / name).write_text('# reviewed\n')
        git = ['git', '-C', str(repo), '-c', 'user.name=t', '-c', 'user.email=t@example.com']
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        subprocess.run([*git, 'add', '.'], check=True)
        subprocess.run([*git, 'commit', '-q', '-m', 'one'], check=True)
        return repo, subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip()

    def test_installs_only_the_pinned_commit(self):
        """The tree is a fresh private folder at exactly the commit given on the command line."""
        with tempfile.TemporaryDirectory() as temp:
            repo, sha = self.make_repo(temp)
            with mock.patch.object(installer, 'REPOSITORY', str(repo)):
                tree = installer.reviewed_tree(sha)
            try:
                self.assertEqual(subprocess.check_output(['git', '-C', str(tree), 'rev-parse', 'HEAD'], text=True).strip(), sha)
                self.assertEqual(tree.stat().st_mode & 0o777, 0o700)
                self.assertEqual(tree.stat().st_uid, os.geteuid())
            finally:
                installer.shutil.rmtree(tree.parent)

    def test_refuses_an_abbreviated_or_unknown_commit(self):
        """A short name, a branch name or a SHA the repository does not have is not a pin."""
        with tempfile.TemporaryDirectory() as temp:
            repo, sha = self.make_repo(temp)
            with mock.patch.object(installer, 'REPOSITORY', str(repo)):
                for bad in (sha[:12], 'master', 'dev', '0' * 40, ''):
                    with self.subTest(bad), self.assertRaises(SystemExit):
                        installer.reviewed_tree(bad)

    def test_refuses_a_symlink_where_a_script_should_be(self):
        """Review PoC: scripts/nightly-browser-suite.py -> the token must never be copied into /usr/local/libexec."""
        with tempfile.TemporaryDirectory() as temp:
            secret = Path(temp) / 'token'
            secret.write_text(TOKEN)
            link = Path(temp) / 'script'
            link.symlink_to(secret)
            destination = Path(temp) / 'out' / 'copy'
            with self.assertRaises(SystemExit):
                installer.install_file(link, destination)
            self.assertFalse(destination.exists())
            real = Path(temp) / 'real'
            real.write_text('# ok\n')
            with mock.patch.object(installer.os, 'chown'):
                installer.install_file(real, destination)
            self.assertEqual(destination.read_text(), '# ok\n')
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)

    def test_never_installs_from_the_browser_checkout(self):
        """Review P1: no installed file is sourced from the suite account's home."""
        text = Path(installer.__file__ if hasattr(installer, '__file__') else Path(__file__).with_name('install-nightly-browser-suite')).read_text()
        self.assertNotIn("checkout(args.ref)\n    install_file(source", text)
        self.assertIn('reviewed_tree(args.ref)', text)

    def test_git_runs_without_hooks_and_stdio(self):
        """Round-4: the root clone and the suite-account git steps disable hooks and fsmonitor, and the account's steps get no terminal."""
        seen = []
        with tempfile.TemporaryDirectory() as temp:
            repo, sha = self.make_repo(temp)
            real_run = installer.run
            with mock.patch.object(installer, 'REPOSITORY', str(repo)), \
                    mock.patch.object(installer, 'run', side_effect=lambda *a, **k: (seen.append((a, k)), real_run(*a, **k))[1]):
                tree = installer.reviewed_tree(sha)
            installer.shutil.rmtree(tree.parent)
        git_calls = [(a, k) for a, k in seen if a[0] == 'git']
        self.assertTrue(git_calls)
        for args, kwargs in git_calls:
            self.assertIn('core.hooksPath=/dev/null', args)
            self.assertEqual(kwargs['env']['GIT_CONFIG_NOSYSTEM'], '1')
        with mock.patch.object(installer, 'run') as run:
            installer.as_user('git', 'status')
        self.assertEqual(run.call_args.kwargs['stdin'], installer.subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['stdout'], installer.subprocess.DEVNULL)

    def test_reinstall_does_not_run_git_in_the_suite_checkout(self):
        """Round-4: when the suite checkout exists, the installer leaves it alone (the nightly moves it to dev)."""
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / 'home'
            (home / 'checkout' / '.git').mkdir(parents=True)
            calls = []
            with mock.patch.object(installer, 'HOME', home), mock.patch.object(installer, 'as_user', side_effect=lambda *a, **k: calls.append(a)):
                installer.checkout('a' * 40)
            self.assertEqual([c for c in calls if c[0] == 'git'], [])
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / 'home'
            home.mkdir()
            calls = []
            with mock.patch.object(installer, 'HOME', home), mock.patch.object(installer, 'as_user', side_effect=lambda *a, **k: calls.append(a)):
                installer.checkout('a' * 40)
            self.assertTrue([c for c in calls if c[:2] == ('git', '-c') and 'core.hooksPath=/dev/null' in c])

    def test_checkout_never_chowns_a_path_the_suite_controls(self):
        """Round-3 PoC: `runs` replaced by a link to a root directory is not chowned or chmodded by the installer."""
        with tempfile.TemporaryDirectory() as temp:
            victim = Path(temp) / 'libexec'
            victim.mkdir(mode=0o755)
            home = Path(temp) / 'home'
            (home / 'checkout' / '.git').mkdir(parents=True)
            (home / 'runs').symlink_to(victim)
            calls = []
            with mock.patch.object(installer, 'HOME', home), mock.patch.object(installer, 'as_user', side_effect=lambda *a, **k: calls.append(a)), \
                    mock.patch.object(installer, 'run', side_effect=lambda *a, **k: calls.append(a)):
                installer.checkout('a' * 40)
            self.assertEqual(victim.stat().st_mode & 0o777, 0o755)
            self.assertEqual(victim.stat().st_uid, os.getuid())
            self.assertFalse([c for c in calls if c and c[0] in ('chown', 'chmod')])
            # The folder is made by the suite account itself.
            self.assertIn(('mkdir', '-p', '-m', '0700', str(home / 'runs')), calls)

    def test_home_is_secured_through_a_descriptor(self):
        """Round-3: the browser home is opened without following links before it is chowned and chmodded."""
        with tempfile.TemporaryDirectory() as temp:
            victim = Path(temp) / 'victim'
            victim.mkdir(mode=0o755)
            link = Path(temp) / 'home'
            link.symlink_to(victim)
            entry = mock.MagicMock(pw_uid=os.getuid(), pw_gid=os.getgid())
            with mock.patch.object(installer, 'HOME', link), self.assertRaises(OSError):
                installer.secure_home(entry)
            self.assertEqual(victim.stat().st_mode & 0o777, 0o755)
            real = Path(temp) / 'real'
            real.mkdir(mode=0o755)
            with mock.patch.object(installer, 'HOME', real):
                installer.secure_home(entry)
            self.assertEqual(real.stat().st_mode & 0o777, 0o700)

    def test_unit_keeps_the_slot_queue_but_not_the_shared_tmp(self):
        """Round-3: private /tmp with only the build-slot queue bound in, and no new privileges."""
        unit = installer.service_unit()
        self.assertIn('NoNewPrivileges=yes', unit)
        self.assertIn('PrivateTmp=yes', unit)
        self.assertIn('BindPaths=/tmp/infraternal-build-slots', unit)
        self.assertNotIn('BindPaths=-', unit)
        writable = next(line for line in unit.splitlines() if line.startswith('ReadWritePaths='))
        self.assertNotRegex(writable, r'(^|[= ])/(var/)?tmp( |$)')
        self.assertEqual(installer.tmpfiles_config(), 'd /tmp/infraternal-build-slots 0775 claude claude -\n')
        self.assertNotIn('777', installer.tmpfiles_config())

    def test_login_file_is_written_root_owned_and_validated(self):
        """Round-5: the installer writes the account name the helper reads; a bad name is refused, a good one lands 0644 by rename."""
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(installer, 'LOGIN_FILE', Path(temp) / 'login'), mock.patch.object(installer.os, 'chown'):
            for bad in ('', 'a b', 'x' * 80, '-x', 'a\nb'):
                with self.subTest(bad), self.assertRaises(SystemExit):
                    installer.write_login(bad)
            installer.write_login('kayg')
            self.assertEqual((Path(temp) / 'login').read_text(), 'kayg\n')
            self.assertEqual((Path(temp) / 'login').stat().st_mode & 0o777, 0o644)
            self.assertEqual(service.read_login(Path(temp) / 'login', os.getuid()), 'kayg')

    def test_unit_hardening_and_umask(self):
        """The unit confines the helper as far as the suite tolerates, with the fuzz's 0077 umask."""
        unit = installer.service_unit()
        for line in ('UMask=0077', 'ProtectSystem=strict', 'ProtectHome=read-only', 'ProtectKernelTunables=yes',
                     'ProtectKernelModules=yes', 'ProtectControlGroups=yes', 'RestrictSUIDSGID=yes', 'LockPersonality=yes',
                     'TimeoutStartSec=24h'):
            self.assertIn(line, unit)
        self.assertRegex(unit, r'ReadWritePaths=.*/var/lib/infraternal-browser')
        self.assertRegex(unit, r'ReadWritePaths=.*/var/lib/infraternal-fuzz')


if __name__ == '__main__':
    unittest.main()
