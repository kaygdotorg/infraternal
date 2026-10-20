"""Role: verify Mac measurement consent ownership and compositor coordinates without launching the browser (#146)."""
import ast
import ctypes
import io
import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

SCRATCH = pathlib.Path.home() / '.cache/codex-scratch/review-app-windows-r3b/python-tests'


class RecordingTypingTests(unittest.TestCase):
    """Earlier latency samples cannot conceal missing letters in the recording."""

    def incomplete(self, count, frames=True):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        guard = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                     and any(isinstance(child, ast.Raise) and 'demo typing or recording incomplete' in ast.unparse(child) for child in node.body))
        return eval(compile(ast.Expression(body=guard.test), str(source), 'eval'),
                    {'typed_count': count, 'typed_before': 16,
                     'demo_text': ('infraternal demo', ' typing'), 'frames': [1] if frames else []})

    def test_only_the_complete_recorded_burst_passes(self):
        for count in (16, 22, 38, 40):
            with self.subTest(count=count): self.assertTrue(self.incomplete(count))
        self.assertFalse(self.incomplete(39))

    def test_no_recording_is_not_a_pass(self):
        self.assertTrue(self.incomplete(39, frames=False))


class CapturePipelineTests(unittest.TestCase):
    """The requested diagnostic route must map to the helper's actual mode."""

    def configure(self, pipeline, inherited):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'capture_environment')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        return namespace['capture_environment'](pipeline, inherited)

    def test_default_clears_stale_overrides_and_uses_the_production_route(self):
        env = self.configure('default', {'INFRATERNAL_DESKTOP_SURFACE': '1',
                                         'INFRATERNAL_DESKTOP_OWNED': '1', 'PATH': '/bin'})
        self.assertEqual(env, {'PATH': '/bin'})

    def test_owned_selects_the_copied_pixel_diagnostic_route(self):
        env = self.configure('owned', {'INFRATERNAL_DESKTOP_SURFACE': '1', 'PATH': '/bin'})
        self.assertEqual(env, {'INFRATERNAL_DESKTOP_OWNED': '1', 'PATH': '/bin'})

    def test_surface_alias_uses_the_current_production_route(self):
        env = self.configure('surface', {'INFRATERNAL_DESKTOP_OWNED': '1', 'PATH': '/bin'})
        self.assertEqual(env, {'PATH': '/bin'})

    def test_unknown_pipeline_is_refused(self):
        with self.assertRaises(ValueError):
            self.configure('other', {})


class FirstPictureTests(unittest.TestCase):
    """Capture refusal and the first-picture deadline stop capture before cleanup."""

    def wait(self, result=None, error=None):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'first_picture')
        calls = []
        def wait_for_function(expression, **kwargs):
            calls.append(kwargs)
            if error: raise error
            return SimpleNamespace(json_value=lambda: result)
        namespace = {'page': SimpleNamespace(wait_for_function=wait_for_function), 'stop_capture': lambda: calls.append('stopped')}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        return namespace['first_picture'], calls

    def test_live_picture_keeps_capture(self):
        wait, calls = self.wait('live')
        wait('old-window')
        self.assertEqual(calls, [{'arg': 'old-window', 'timeout': 10000}])

    def test_refusal_never_retries_or_waits_for_another_picture(self):
        for state in ('permission', 'failed', 'closed', 'unsupported'):
            with self.subTest(state=state):
                wait, calls = self.wait(state)
                with self.assertRaises(RuntimeError): wait()
                self.assertEqual(calls, [{'arg': None, 'timeout': 10000}, 'stopped'])

    def test_deadline_stops_capture_before_propagating(self):
        wait, calls = self.wait(error=TimeoutError())
        with self.assertRaises(TimeoutError): wait()
        self.assertEqual(calls, [{'arg': None, 'timeout': 10000}, 'stopped'])


class CaptureRetirementTests(unittest.TestCase):
    """Refusal seals new launches before signals and never signals a reused PID."""

    def test_refusal_stops_only_recorded_live_helpers(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'stop_capture')
        actions = []
        class Marker:
            sealed = False
            def __truediv__(self, name): return self
            def touch(self): self.sealed = True; actions.append('sealed')
            def open(self, mode):
                self.assert_mode(mode)
                if self.sealed: raise FileExistsError()
                self.sealed = True
                actions.append('sealed')
                return io.StringIO()
            def assert_mode(self, mode):
                if mode != 'x': raise AssertionError('atomic refusal marker required')
        namespace = {
            'runtime': Marker(), 'signal': signal,
            'source': SimpleNamespace(send_signal=lambda value: actions.append(('source', value))),
            'helper_births': {101: (101, 10, 1), 202: (202, 11, 1), 303: (303, 10, 1)},
            'capture_helpers': {101, 202},
            'process_identity': lambda pid: (pid, 10, 1) if pid in (101, 303) else (pid, 12, 1),
            'os': SimpleNamespace(kill=lambda pid, value: actions.append((pid, value))),
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['stop_capture']()
        namespace['stop_capture']()
        self.assertEqual(actions, ['sealed', ('source', signal.SIGINT), (101, signal.SIGTERM)])

    def test_refusal_marker_blocks_a_later_capture_launch(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        stop = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'stop_capture')
        wrapper = next(node for node in ast.walk(tree)
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                       and node.func.attr == 'write_text' and node.args
                       and 'bridge to an independently launched signed app' in ast.unparse(node.args[0]))
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temporary:
            runtime = pathlib.Path(temporary)
            stopped = []
            namespace = {
                'runtime': runtime, 'signal': signal,
                'source': SimpleNamespace(send_signal=lambda value: stopped.append(value)),
                'capture_helpers': set(), 'helper_births': {}, 'subprocess': subprocess, 'os': os,
            }
            exec(compile(ast.Module(body=[stop], type_ignores=[]), str(source), 'exec'), namespace)
            namespace['stop_capture']()
            self.assertEqual(stopped, [signal.SIGINT])

            marker_output = runtime / 'capture-started'
            script = eval(compile(ast.Expression(body=wrapper.args[0]), str(source), 'eval'), {
                'runtime': runtime, 'shlex': shlex,
                'argv': ['/usr/bin/touch', str(marker_output)], 'args': {},
            })
            executable = runtime / 'native'
            executable.write_text(script)
            executable.chmod(0o700)
            result = subprocess.run(['/bin/sh', str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(marker_output.exists())

    def test_same_second_pid_reuse_is_not_signalled(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'stop_capture')
        actions = []
        start = (101, 1792436400, 123000)
        reused = (101, 1792436400, 124000)
        namespace = {
            'runtime': pathlib.Path('/unused'), 'signal': signal,
            'source': SimpleNamespace(send_signal=lambda value: actions.append(('source', value))),
            'helper_births': {101: start}, 'capture_helpers': {101},
            # The PID is reused in the same second, but the kernel start microseconds differ.
            'process_identity': lambda pid: reused,
            'os': SimpleNamespace(kill=lambda pid, value: actions.append((pid, value))),
        }
        class Marker:
            def __truediv__(self, name): return self
            def open(self, mode):
                if mode != 'x': raise AssertionError('atomic refusal marker required')
                return io.StringIO()
        namespace['runtime'] = Marker()
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['stop_capture']()
        self.assertEqual(actions, [('source', signal.SIGINT)])

    def test_resource_collection_includes_independent_helpers_by_identity(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'live_helpers')
        namespace = {
            'helper_births': {101: (101, 10, 1), 202: (202, 11, 1)},
            'process_identity': lambda pid: (pid, 10, 1),
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertEqual(namespace['live_helpers'](), {101})


class ProcessIdentityTests(unittest.TestCase):
    """The cleanup fence uses the kernel PID and microsecond start fields."""

    def test_identity_reads_subsecond_start_time_and_checks_the_pid(self):
        source = pathlib.Path(__file__).with_name('process_identity.py')
        tree = ast.parse(source.read_text())
        nodes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ProcBsdInfo']
        nodes.extend(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'process_identity')
        query_results = {'pid': 101, 'bytes': None}

        class Query:
            def __call__(self, pid, flavor, argument, buffer, size):
                self.args = (pid, flavor, argument)
                info = ctypes.cast(buffer, ctypes.POINTER(namespace['ProcBsdInfo'])).contents
                info.pid = query_results['pid']
                info.start_seconds = 1792436400
                info.start_microseconds = 123456
                return size if query_results['bytes'] is None else query_results['bytes']

        query = Query()
        namespace = {'ctypes': ctypes, 'sys': SimpleNamespace(platform='darwin')}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
        self.assertEqual(ctypes.sizeof(namespace['ProcBsdInfo']), 136)
        library = SimpleNamespace(proc_pidinfo=query)
        with mock.patch('ctypes.CDLL', return_value=library):
            self.assertEqual(namespace['process_identity'](101), (101, 1792436400, 123456))
            self.assertEqual(query.args, (101, 3, 0))
            query_results['pid'] = 202
            self.assertIsNone(namespace['process_identity'](101))


class RunDeadlineTests(unittest.TestCase):
    """A single bounded measurement run owns cleanup without cross-run state."""

    def test_mac_runner_has_a_fixed_deadline_and_cleanup_reserve(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py').read_text()
        tree = ast.parse(source)
        timeout = next(
            node.value for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'RUN_TIMEOUT_SECONDS' for target in node.targets)
        )
        reserve = next(
            node.value for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'CLEANUP_RESERVE_SECONDS' for target in node.targets)
        )
        self.assertEqual(ast.literal_eval(timeout), 900)
        self.assertEqual(ast.literal_eval(reserve), 30)
        self.assertIn('signal.alarm(RUN_TIMEOUT_SECONDS)', source)
        self.assertIn('run_deadline_at-time.monotonic()-CLEANUP_RESERVE_SECONDS', source)

    def test_old_cross_run_budget_inputs_and_receipts_are_absent(self):
        root = pathlib.Path(__file__).parents[4]
        paths = [
            root / 'apps/tracer/test/appwin/measure.ts',
            root / 'apps/tracer/test/appwin/measure-mac.py',
            root / 'scripts/app-window-owner-preview',
            root / 'docs/operations/app-window-owner-test.md',
        ]
        retired_markers = (
            'APP_WINDOW_SCREEN_LEDGER_JOB', 'APP_WINDOW_SCREEN_BUDGET_SECONDS',
            'screen_ledger_job', 'screen_budget', 'on-screen-ledger.json',
            'remaining screen allowance', 'screen ledger',
        )
        for path in paths:
            contents = path.read_text().lower()
            for marker in retired_markers:
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker.lower(), contents)

    def test_owner_launcher_keeps_its_fifteen_minute_cap(self):
        launcher = pathlib.Path(__file__).parents[4] / 'scripts/app-window-owner-preview'
        self.assertIn('APP_WINDOW_OWNER_PREVIEW_SECONDS=900', launcher.read_text())

    def test_measurement_plan_collects_forty_inputs_and_ten_minutes(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py').read_text()
        tree = ast.parse(source)
        constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {
                        'INPUT_SAMPLE_COUNT', 'STABILITY_SECONDS', 'RECONNECT_ITERATION', 'REOPEN_ITERATION',
                    }:
                        constants[target.id] = eval(compile(ast.Expression(body=node.value), str(source), 'eval'), {'args': {}})
        self.assertEqual(constants, {
            'INPUT_SAMPLE_COUNT': 40,
            'STABILITY_SECONDS': 600,
            'RECONNECT_ITERATION': 3,
            'REOPEN_ITERATION': 6,
        })



class ContinuousSoakTests(unittest.TestCase):
    """A ten-minute soak proves the exact known text, including ordering."""

    def functions(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        names = {'known_soak_text', 'soak_burst', 'soak_input_matches'}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        namespace = {}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
        return namespace

    def test_ten_minutes_sends_exactly_240_characters_in_order(self):
        functions = self.functions()
        expected = functions['known_soak_text']()
        self.assertEqual(len(expected), 240)
        bursts = [functions['soak_burst'](step) for step in range(60)]
        self.assertEqual(''.join(bursts), expected)
        self.assertEqual(sum(bool(burst) for burst in bursts), 40)
        self.assertTrue(all(len(burst) in (0, 6) for burst in bursts))

    def test_same_count_with_reordered_keys_fails(self):
        matches = self.functions()['soak_input_matches']
        rows = [{'kind': 'input', 'characters': c} for c in 'abdc']
        self.assertFalse(matches(rows, 'abcd'))
        rows[2:] = [{'kind': 'draw'}, {'kind': 'input', 'characters': 'c'}, {'kind': 'input', 'characters': 'd'}]
        self.assertTrue(matches(rows, 'abcd'))

    def test_missing_duplicate_or_unstamped_keys_fail(self):
        matches = self.functions()['soak_input_matches']
        for values in ('abc', 'aabcd', 'abcc'):
            self.assertFalse(matches([{'kind': 'input', 'characters': c} for c in values], 'abcd'))
        self.assertFalse(matches([{'kind': 'input'}] * 4, 'abcd'))


class LaunchMonitorTests(unittest.TestCase):
    """Only signed-app launches use birth identities; short-lived rows are skipped."""

    def test_monitor_skips_a_permission_preflight_that_exits_before_the_first_poll(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name == 'watch_launches')
        identity_parser = next(node for node in ast.walk(tree)
                               if isinstance(node, ast.FunctionDef) and node.name == 'logged_capture_identity')

        class StopMonitor:
            def __init__(self):
                self.waits = 0

            def wait(self, _timeout):
                self.waits += 1
                return self.waits > 1

        class PidLog:
            def read_text(self):
                return 'preflight 101 10 1\n'

        errors, stopped, checks = [], [], []
        namespace = {
            'stop_monitor': StopMonitor(),
            'pidlog': PidLog(),
            'process_identity': lambda _pid: None,
            'logged_capture_identity': None,
            'capture_helpers': set(),
            'helper_births': {},
            'consent_errors': errors,
            'stop_capture': lambda: stopped.append(True),
            'consent_check': lambda: checks.append(True),
        }
        parser_namespace = {}
        exec(compile(ast.Module(body=[identity_parser], type_ignores=[]), str(source), 'exec'), parser_namespace)
        namespace['logged_capture_identity'] = parser_namespace['logged_capture_identity']
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['watch_launches']()
        self.assertEqual(errors, [])
        self.assertEqual(stopped, [])
        self.assertEqual(checks, [True])

    def test_monitor_records_only_a_matching_signed_app_identity(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name == 'watch_launches')
        parser = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.FunctionDef) and node.name == 'logged_capture_identity')

        class StopMonitor:
            def __init__(self): self.waits = 0
            def wait(self, _timeout):
                self.waits += 1
                return self.waits > 1

        class PidLog:
            def read_text(self): return 'capture-bridge 88\ncapture-launcher 89\ncapture 101 10 1\n'

        errors, stopped, checks = [], [], []
        namespace = {
            'stop_monitor': StopMonitor(), 'pidlog': PidLog(),
            'process_identity': lambda pid: (pid, 10, 1),
            'capture_helpers': set(), 'helper_births': {}, 'consent_errors': errors,
            'stop_capture': lambda: stopped.append(True), 'consent_check': lambda: checks.append(True),
        }
        parser_namespace = {}
        exec(compile(ast.Module(body=[parser], type_ignores=[]), str(source), 'exec'), parser_namespace)
        namespace['logged_capture_identity'] = parser_namespace['logged_capture_identity']
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['watch_launches']()
        self.assertEqual(errors, [])
        self.assertEqual(stopped, [])
        self.assertEqual(namespace['helper_births'], {101: (101, 10, 1)})
        self.assertEqual(namespace['capture_helpers'], {101})

    def test_monitor_skips_a_retired_inventory_helper_before_its_first_poll(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name == 'watch_launches')
        parser = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.FunctionDef) and node.name == 'logged_capture_identity')

        class StopMonitor:
            def __init__(self): self.waits = 0
            def wait(self, _timeout):
                self.waits += 1
                return self.waits > 1

        class PidLog:
            def read_text(self): return 'native 101 10 1\n'

        errors, stopped, checks = [], [], []
        namespace = {
            'stop_monitor': StopMonitor(), 'pidlog': PidLog(),
            'process_identity': lambda _pid: None,
            'capture_helpers': set(), 'helper_births': {}, 'consent_errors': errors,
            'stop_capture': lambda: stopped.append(True), 'consent_check': lambda: checks.append(True),
        }
        parser_namespace = {}
        exec(compile(ast.Module(body=[parser], type_ignores=[]), str(source), 'exec'), parser_namespace)
        namespace['logged_capture_identity'] = parser_namespace['logged_capture_identity']
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['watch_launches']()
        self.assertEqual(errors, [])
        self.assertEqual(stopped, [])
        self.assertEqual(namespace['helper_births'], {})
        self.assertEqual(checks, [True])

    def test_monitor_does_not_adopt_a_reused_capture_pid(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name == 'watch_launches')
        parser = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.FunctionDef) and node.name == 'logged_capture_identity')

        class StopMonitor:
            def __init__(self): self.waits = 0
            def wait(self, _timeout):
                self.waits += 1
                return self.waits > 1

        class PidLog:
            def read_text(self): return 'capture 101 10 1\n'

        errors, stopped, checks = [], [], []
        namespace = {
            'stop_monitor': StopMonitor(), 'pidlog': PidLog(),
            # The PID has been reused within the same second.
            'process_identity': lambda _pid: (101, 10, 2),
            'capture_helpers': set(), 'helper_births': {}, 'consent_errors': errors,
            'stop_capture': lambda: stopped.append(True), 'consent_check': lambda: checks.append(True),
        }
        parser_namespace = {}
        exec(compile(ast.Module(body=[parser], type_ignores=[]), str(source), 'exec'), parser_namespace)
        namespace['logged_capture_identity'] = parser_namespace['logged_capture_identity']
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['watch_launches']()
        self.assertEqual(errors, [])
        self.assertEqual(stopped, [])
        self.assertEqual(namespace['helper_births'], {})
        self.assertEqual(namespace['capture_helpers'], set())
        self.assertEqual(checks, [True])


class ConsentTests(unittest.TestCase):
    """Execute only the consent guard, without importing or launching the browser driver."""

    def check_prompt(self, controls, *, own_helper=True, title=None, prompt_text='requesting to bypass'):
        source = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'consent_check')
        calls = []

        def cua(name, params):
            calls.append(name)
            if name == 'list_windows':
                return {'windows': [{'title': title or ('InfraternalCaptureHelper' if own_helper else 'Unrelated application'), 'pid': 101, 'window_id': 202}]}
            if name == 'get_window_state':
                return {'text': prompt_text, 'controls': controls}
            if name == 'get_desktop_state':
                return {}
            return {}

        namespace = {'cua': cua, 'json': json, 'E': pathlib.Path('unused'), 'emit': lambda value: None}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        refused = False
        try:
            namespace['consent_check']()
        except RuntimeError:
            refused = True
        return refused, calls

    def test_new_helper_permission_requires_owner_without_clicks(self):
        refused, calls = self.check_prompt([{'role': 'button', 'title': 'Allow', 'element_token': 'allow'}])
        self.assertTrue(refused)
        self.assertNotIn('click', calls)

    def test_helper_password_sheet_never_receives_input(self):
        refused, calls = self.check_prompt([{'role': 'secure text field'}, {'role': 'button', 'title': 'Cancel', 'element_token': 'cancel'}])
        self.assertTrue(refused)
        self.assertNotIn('click', calls)

    def test_foreign_capture_prompt_stops_without_clicking(self):
        refused, calls = self.check_prompt([{'role': 'button', 'title': 'Allow'}],
                                          title='netbird is requesting to bypass the system private window picker')
        self.assertTrue(refused)
        self.assertNotIn('click', calls)

    def test_system_capture_consent_title_is_refused_for_other_identities(self):
        refused, calls = self.check_prompt([{'role': 'button', 'title': 'Allow'}],
                                          own_helper=False, title='Screen & System Audio Recording')
        self.assertTrue(refused)
        self.assertNotIn('click', calls)

    def test_a_document_title_about_recording_is_not_inspected(self):
        refused, calls = self.check_prompt([{'role': 'button', 'title': 'Allow'}],
                                          own_helper=False, title='Notes about screen recording')
        self.assertFalse(refused)
        self.assertEqual(calls, ['list_windows'])

    def test_another_application_prompt_is_ignored(self):
        refused, calls = self.check_prompt([{'role': 'button', 'title': 'Allow', 'element_token': 'allow'}], own_helper=False)
        self.assertFalse(refused)
        self.assertEqual(calls, ['list_windows'])

    def test_helper_prompt_text_variant_without_requesting_or_bypass_is_refused(self):
        refused, calls = self.check_prompt(
            [{'role': 'button', 'title': 'Allow', 'element_token': 'allow'}],
            title='InfraternalCaptureHelper would like to record the screen',
            prompt_text='InfraternalCaptureHelper would like to record the screen',
        )
        self.assertTrue(refused)
        self.assertNotIn('click', calls)


class CompositorGeometryTests(unittest.TestCase):
    """A moving canvas must supply a current, visible target to compositor sampling."""

    def target(self, name='compositor_target'):
        source = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        return namespace[name]

    def test_current_bounds_replace_the_initial_window_shape(self):
        class Surface:
            rectangle = {'x': 100, 'y': 100, 'width': 200, 'height': 200}
            def bounding_box(self): return self.rectangle.copy()
        surface = Surface()
        target = self.target()
        before = target(surface, {'width': 832, 'height': 720})
        surface.rectangle = {'x': 300, 'y': 200, 'width': 100, 'height': 100}
        after = target(surface, {'width': 832, 'height': 720})
        self.assertEqual(before['x'], 250 / 832)
        self.assertEqual(after['x'], 375 / 832)
        self.assertEqual(after['y'], 275 / 720)

    def test_copy_uses_device_metadata_when_the_window_exceeds_the_emulated_viewport(self):
        target = {'x': 506 / 832, 'y': 294 / 720, 'viewport': {'width': 832, 'height': 720}}
        metadata = {'deviceWidth': 2502, 'deviceHeight': 1291, 'offsetTop': 0, 'pageScaleFactor': 1}
        self.assertEqual(self.target('compositor_pixel')(target, metadata, 1280, 660), (259, 150))

    def test_an_offscreen_centre_is_refused_instead_of_reading_an_unrelated_pixel(self):
        class Surface:
            def bounding_box(self): return {'x': 100, 'y': -1000, 'width': 200, 'height': 600}
        with self.assertRaises(RuntimeError):
            self.target()(Surface(), {'width': 832, 'height': 720})


if __name__ == '__main__':
    # The optional first argument is the baseline source used for the red run.
    unittest.main(argv=[sys.argv[0]])
