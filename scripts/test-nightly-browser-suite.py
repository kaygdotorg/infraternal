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
import os
from pathlib import Path
import re
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
        return suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results, f'20261109T061806Z-{head[:7]}')

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
        return suite.report(self.forgejo.api, 'kayg/infraternal', TOKEN, self.results, f'20261109T061806Z-{head[:7]}')

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
        self.forgejo.author = 'somebody-else'
        self.night(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.forgejo.author = self.forgejo.login
        self.night(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.assertEqual(self.forgejo.creates(), 2)

    def test_a_forged_fixed_comment_is_ignored(self):
        """Review: a comment by another user with the 'fixed' marker does not decide the issue's state."""
        self.night(**{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.forgejo.author = 'somebody-else'
        self.forgejo.comments[1] = {'id': 1, 'issue': 345, 'body': suite.state_marker('fixed'), 'user': {'login': 'somebody-else'}}
        self.forgejo.author = self.forgejo.login
        self.night(head='b' * 40, **{'docs-palette.spec.ts': ['unexpected'], 'ok.spec.ts': ['expected']})
        self.assertEqual(len(self.forgejo.comments), 1)

    def test_more_than_two_thousand_open_issues_fails_closed(self):
        """Review: when the listing hits the page limit, the reporter stops instead of deduplicating blindly."""
        full = [{'number': n, 'body': '', 'user': {'login': self.forgejo.login}} for n in range(50)]
        with mock.patch.object(suite, 'api', return_value=full):
            with self.assertRaises(RuntimeError):
                list(suite.pages('x', 'repos/a/b/issues', TOKEN))

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
            with mock.patch.object(service, 'BROWSER_HOME', temp), mock.patch.object(service, 'REPORT_HOME', temp + '/report'), \
                    mock.patch.object(service, 'ids', return_value=(os.getuid(), os.getgid())), \
                    mock.patch.object(service.os, 'chown'), \
                    mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                    mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                Path(temp, 'report').mkdir()
                self.assertEqual(service.main(), 0)
        steps = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(steps), 3)
        for step in steps[:2]:
            self.assertEqual(step[1], '--reuid=infraternal-browser')
            self.assertNotIn('forgejo-token', ' '.join(step))
        self.assertIn('nice', steps[1])
        self.assertEqual(steps[2][1], '--reuid=infraternal-fuzz')
        self.assertIn(service.REPORTER, steps[2])
        self.assertIn('-I', steps[2])
        self.assertIn('--run-name', steps[2])
        self.assertNotIn('nightly-browser-suite.py', ' '.join(steps[2]))
        self.assertNotIn(temp + '/runs', ' '.join(steps[2]))
        holder.stdin.write.assert_called_once()

    def stage(self, temp, **kwargs):
        """Stage the run folder in `temp` the way the helper does, as the current user."""
        dest = Path(temp) / 'stage'
        dest.mkdir(exist_ok=True)
        return service.stage(Path(temp) / 'runs', '20261109T061806Z-aaaaaaa', dest, kwargs.pop('owner', os.getuid()), None), dest

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
            with mock.patch.object(service, 'BROWSER_HOME', temp), mock.patch.object(service, 'REPORT_HOME', temp + '/report'), \
                    mock.patch.object(service, 'ids', return_value=(os.getuid(), os.getgid())), mock.patch.object(service.os, 'chown'), \
                    mock.patch.object(service.subprocess, 'Popen', return_value=holder), \
                    mock.patch.object(service.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                Path(temp, 'report').mkdir()
                self.assertEqual(service.main(), 1)
        self.assertEqual(run.call_count, 2)

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
            self.assertEqual(service.main(), 1)


if __name__ == '__main__':
    unittest.main()
