#!/usr/bin/env python3
"""Fixture tests for the nightly browser suite reporter (D373, #443).

The reporter runs against the in-process fake Forgejo from
`test-nightly-fuzz.py` (real state: issues, comments) with a synthetic token
and hand-written Playwright JSON reports, so filing, deduplication and the
"passes again" comments are tested end to end without a browser.
"""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
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
        (self.results / 'meta.json').write_text(json.dumps({'head': head, 'evidence': '/var/lib/x/evidence',
                                                            'log': str(self.results / 'suite.log')}))
        return suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results)

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
        for expected in ('a' * 40, '/var/lib/x/evidence', 'expected 1 got 2', 'docs-palette.spec.ts:12 opens',
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

    def test_token_account_never_runs_repository_code(self):
        """The suite step runs as the browser account; the token account runs only the root-owned reporter."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = service.READY
        with tempfile.TemporaryDirectory() as temp:
            runs = Path(temp) / 'runs'
            (runs / 'one').mkdir(parents=True)
            (runs / 'latest').write_text(str(runs / 'one') + '\n')
            with mock.patch.object(service, 'BROWSER_HOME', temp), \
                    mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                    mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                self.assertEqual(service.main(), 0)
        steps = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(steps), 3)
        for step in steps[:2]:
            self.assertEqual(step[1], '--reuid=infraternal-browser')
            self.assertNotIn('forgejo-token', ' '.join(step))
        self.assertIn('nice', steps[1])
        self.assertEqual(steps[2][1], '--reuid=infraternal-fuzz')
        self.assertIn(service.REPORTER, steps[2])
        self.assertNotIn('nightly-browser-suite.py', ' '.join(steps[2]))
        holder.stdin.write.assert_called_once()

    def test_results_path_must_stay_in_runs(self):
        """A pointer written by the unprivileged run cannot aim the reporter elsewhere."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = service.READY
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'runs').mkdir()
            (Path(temp) / 'runs/latest').write_text('/etc\n')
            with mock.patch.object(service, 'BROWSER_HOME', temp), \
                    mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                    mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                self.assertEqual(service.main(), 1)
        self.assertEqual(run.call_count, 2)

    def test_no_slot_means_no_run(self):
        """Without a build slot nothing runs."""
        holder = mock.MagicMock()
        holder.stdout.readline.return_value = b''
        with mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                mock.patch.object(service.subprocess, 'run', side_effect=AssertionError('ran without a slot')):
            self.assertEqual(service.main(), 1)


if __name__ == '__main__':
    unittest.main()
