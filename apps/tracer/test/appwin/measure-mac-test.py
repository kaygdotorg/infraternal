"""Role: verify Mac measurement consent ownership and compositor coordinates without launching the browser (#146)."""
import ast
import ctypes
import io
import json
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

SCRATCH = pathlib.Path.home() / '.cache/codex-scratch/app-windows-r7-measure/python-tests'


class PickerSelectionTests(unittest.TestCase):
    """Window fixture selection uses the title field's full boundary."""

    def test_concurrent_opens_share_one_browser_turn_and_keep_native_identities(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next((node for node in ast.parse(source.read_text()).body
                         if isinstance(node, ast.FunctionDef) and node.name == 'open_concurrent_fixture_windows'), None)
        self.assertIsNotNone(function, 'concurrent fixture opener is missing')
        calls = []
        page = SimpleNamespace(wait_for_function=lambda script, **kwargs: calls.append(('ready', kwargs['arg'])),
                               evaluate=lambda script, argument: calls.append(('open', argument)))
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['open_concurrent_fixture_windows'](page, 'fixture-host', 900, list(range(501, 511)))
        actions = ['fixture-host/w-900-' + str(i) for i in range(501, 511)]
        self.assertEqual(calls, [('ready', actions), ('open', actions)])

    def test_first_picture_environment_includes_machine_load(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        body = next(node.body for node in tree.body if isinstance(node, ast.Try))
        start = next(index for index, node in enumerate(body) if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'environment' for target in node.targets))
        calls = []
        def command(arguments):
            calls.append(arguments)
            return 'load=fixture' if arguments == ['uptime'] else 'machine=fixture'
        namespace = {'args': {'first_picture_idle': True}, 'command': command}
        exec(compile(ast.Module(body=body[start:start+2], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertIn(['uptime'], calls)
        self.assertIn('load=fixture', namespace['environment'])

    def test_ten_window_cohorts_use_the_real_overview_and_require_every_card_in_view(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next((node for node in ast.parse(source.read_text()).body
                         if isinstance(node, ast.FunctionDef) and node.name == 'show_fixture_cohort'), None)
        self.assertIsNotNone(function, 'cohort visibility setup is missing')
        calls = []
        def wait(script, **kwargs):
            calls.append(('visible', kwargs['arg']))
            for outside, expected in [(False, 'true'), (True, 'false')]:
                program = "const outside=" + str(outside).lower() + ";const document={querySelector:()=>({getBoundingClientRect:()=>({left:0,top:0,right:832,bottom:720})}),querySelectorAll:()=>Array.from({length:10},(_,i)=>({getBoundingClientRect:()=>({left:outside&&i===0?900:10,top:10,right:outside&&i===0?950:60,bottom:70,width:50,height:60})}))};console.log((" + script + ")(10));"
                result = subprocess.check_output(['bun', '-e', program], text=True).strip()
                self.assertEqual(result, expected)
        page = SimpleNamespace(evaluate=lambda script: calls.append(('overview', script)), wait_for_function=wait)
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['show_fixture_cohort'](page, 1)
        self.assertEqual(calls, [])
        namespace['show_fixture_cohort'](page, 10)
        self.assertEqual(calls, [('overview', 'window.__appwinCx.nav.showOverview(true)'), ('visible', 10)])

    def test_window_picker_does_not_confuse_numeric_title_suffixes(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        selector = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute) and node.func.attr == 'get_by_role'
                        and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'option'
                        and any(keyword.arg == 'name' and ast.unparse(keyword.value) == 'picker_title_pattern(title)'
                                for keyword in node.keywords))
        self.assertIsNotNone(selector)
        pattern_node = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                            and node.name == 'picker_title_pattern')
        namespace = {'re': re}
        exec(compile(ast.Module(body=[pattern_node], type_ignores=[]), str(source), 'exec'), namespace)
        pattern = namespace['picker_title_pattern']('App window measurement 1')
        self.assertIsNotNone(pattern.search('latency-window, App window measurement 1, on MacBook'))
        self.assertIsNone(pattern.search('latency-window, App window measurement 10, on MacBook'))


class FixtureSourceIdentityTests(unittest.TestCase):
    """The Mac cohort must bind each canvas card to its fixture window identity."""

    def test_canvas_targets_match_the_native_fixture_ids_in_card_order(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        target_rows = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                           and node.name == 'fixture_target_rows')
        namespace = {}
        exec(compile(ast.Module(body=[target_rows], type_ignores=[]), str(source), 'exec'), namespace)
        reports = [
            {'id': 'canvas-a', 'target': {'type': 'window', 'windowId': 502, 'ownerPid': 900}},
            {'id': 'canvas-b', 'target': {'type': 'window', 'windowId': 501, 'ownerPid': 900}},
        ]
        mapped = namespace['fixture_target_rows'](reports, ['canvas-a', 'canvas-b'], [502, 501], 900)
        self.assertEqual([row['target']['windowId'] for row in mapped], [502, 501])
        with self.assertRaisesRegex(RuntimeError, 'canvas target mismatch'):
            namespace['fixture_target_rows'](reports, ['canvas-a', 'canvas-b'], [501, 502], 900)


class InputCohortTests(unittest.TestCase):
    """The larger input cohort exits through cleanup before the independent demo."""

    def test_sample_count_is_bounded_to_the_two_supported_cohorts(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'INPUT_SAMPLE_COUNT' for target in node.targets))
        for enabled, count in ((False, 40), (True, 80)):
            namespace = {'args': {'input_only': enabled}}
            exec(compile(ast.Module(body=[assignment], type_ignores=[]), str(source), 'exec'), namespace)
            self.assertEqual(namespace['INPUT_SAMPLE_COUNT'], count)

    def test_input_only_completion_preserves_clock_receipts_and_cleanup(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "args.get('input_only')")
        class PhaseComplete(Exception):
            """Reach the real driver's finally block without entering another phase."""
        rows = []
        namespace = {'args': {'input_only': True}, 'INPUT_SAMPLE_COUNT': 80,
                     'source_round_trips': lambda phase: rows.append(phase),
                     'resource_sample': rows.append,
                     'native_clock': lambda: 'native', 'browser_clock': lambda: 'browser',
                     'battery': lambda: None, 'emit': rows.append, 'PhaseComplete': PhaseComplete}
        with self.assertRaises(PhaseComplete):
            exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertEqual(rows, ['after', 'input_idle', {'kind': 'clocks_after', 'native': 'native', 'browser': 'browser'},
                                {'kind': 'result', 'status': 'input_measured', 'count': 80}])

    def test_initial_control_admission_uses_the_measured_focus_mode(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'focus_input')
        actions = []
        def wait_for(**_kwargs):
            if 'emulated' not in actions:
                raise TimeoutError('native activation removed viewer admission')
        namespace = dict(args={}, cdp=SimpleNamespace(send=lambda *_: actions.append('emulated')),
                         consent_guard=lambda: None,
                         page=SimpleNamespace(locator=lambda _: SimpleNamespace(wait_for=wait_for)),
                         emit=lambda _: None)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['focus_input'](SimpleNamespace(click=lambda: actions.append('click'), evaluate=lambda _: True))
        self.assertEqual(actions, ['emulated', 'click', 'click'])

    def test_human_preview_and_resource_modes_keep_real_focus(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'focus_input')
        for mode in ('resources_only', 'demo_only', 'owner_preview'):
            actions = []
            namespace = dict(args={mode: True}, cdp=SimpleNamespace(send=lambda *_: actions.append('emulated')),
                             consent_guard=lambda: None,
                             page=SimpleNamespace(locator=lambda _: SimpleNamespace(wait_for=lambda **_: None)),
                             emit=lambda _: None)
            exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
            namespace['focus_input'](SimpleNamespace(click=lambda: actions.append('click'), evaluate=lambda _: True))
            self.assertEqual(actions, ['click', 'click'])

    def test_each_key_keeps_native_activation_outside_the_input_interval(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        loop = next(node for node in ast.walk(tree) if isinstance(node, ast.For)
                    and ast.unparse(node.iter) == 'range(INPUT_SAMPLE_COUNT)')
        admission = loop.body[:next(index for index, node in enumerate(loop.body)
                                    if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) == 'sequence')]
        for focused in (False, True):
            with self.subTest(focused=focused):
                actions = []
                def ready(*_args, **_kwargs):
                    actions.append('ready')
                def activate():
                    raise AssertionError('quiet input must not switch native apps')
                namespace = {'page': SimpleNamespace(bring_to_front=activate,
                                                      wait_for_function=ready),
                             'surface': SimpleNamespace(evaluate=lambda _: focused),
                             'focus_input': lambda _: actions.append('control_focus')}
                exec(compile(ast.Module(body=admission, type_ignores=[]), str(source), 'exec'), namespace)
                self.assertEqual(actions, ['ready'] if focused else ['control_focus', 'ready'])


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


class HelperRestorationTests(unittest.TestCase):
    """The signed capture bundle returns to its archived build before lock release."""

    def restore(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        functions = [node for node in ast.parse(source.read_text()).body
                     if isinstance(node, ast.FunctionDef)
                     and node.name in ('replace_signed_helper_bundle', 'restore_helper_bundle', 'validate_helper_archive_descriptor')]
        namespace = {'pathlib': pathlib, 'subprocess': subprocess}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), namespace)
        return namespace['restore_helper_bundle']

    def fixture(self, root):
        bundle = root / 'native-diagnostic' / 'InfraternalCaptureHelper.app'
        executable = bundle / 'Contents' / 'MacOS' / 'InfraternalCaptureHelper'
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'variant')
        archive = root / 'infraternal-bench' / 'shipped-helper.zip'
        archive.parent.mkdir()
        archive.write_bytes(b'known archive bytes')
        return bundle, executable, archive

    def test_archive_hash_mismatch_preserves_the_running_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle, executable, archive = self.fixture(root)
            with mock.patch('pathlib.Path.home', return_value=root):
                with mock.patch('subprocess.run') as run:
                    with self.assertRaisesRegex(RuntimeError, 'archive hash'):
                        self.restore()(bundle, archive, '0' * 64, '1' * 64, '2' * 40)
            run.assert_not_called()
            self.assertEqual(executable.read_bytes(), b'variant')

    def test_restore_verifies_archive_executable_and_designated_leaf(self):
        import hashlib
        leaf = '3e6ae7c6ba4cfe1e6280535eb93cf7a7959a7ba6'
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle, executable, archive = self.fixture(root)
            def run(argv, **_kwargs):
                if argv[0] == '/usr/bin/ditto':
                    self.assertFalse(bundle.exists())
                    restored = bundle / 'Contents' / 'MacOS' / 'InfraternalCaptureHelper'
                    restored.parent.mkdir(parents=True)
                    restored.write_bytes(b'shipped')
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                if argv[0] == '/usr/bin/codesign' and argv[1] == '--verify':
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                if argv[0] == '/usr/bin/codesign' and argv[1] == '-d':
                    requirement = f'designated => identifier "com.infraternal.desktop.helper" and certificate leaf = H"{leaf}"'
                    return SimpleNamespace(returncode=0, stdout='', stderr=requirement)
                raise AssertionError(argv)
            with mock.patch('pathlib.Path.home', return_value=root):
                with mock.patch('subprocess.run', side_effect=run):
                    result = self.restore()(bundle, archive, hashlib.sha256(archive.read_bytes()).hexdigest(),
                                            hashlib.sha256(b'shipped').hexdigest(), leaf)
            self.assertEqual(executable.read_bytes(), b'shipped')
            self.assertEqual(result['executable_sha256'], hashlib.sha256(b'shipped').hexdigest())
            self.assertEqual(result['leaf_sha1'], leaf)

    def test_restore_runs_before_the_macbook_lock_is_removed(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        restore = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Name) and node.func.id == 'restore_helper_bundle'
                       and node.lineno > 1000)
        release = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Attribute) and node.func.attr == 'rmdir'
                       and node.lineno > restore.lineno)
        self.assertLess(restore.lineno, release.lineno)
        self.assertEqual(ast.unparse(release.func.value), 'lock')

    def test_archive_descriptor_rejects_incomplete_or_relative_paths(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'validate_helper_archive_descriptor')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        valid = {'archive': '/Users/kayg/infraternal-bench/job/variant.zip',
                 'archive_sha256': 'A' * 64, 'executable_sha256': 'B' * 64, 'leaf_sha1': 'C' * 40}
        self.assertEqual(namespace['validate_helper_archive_descriptor'](valid)['leaf_sha1'], 'c' * 40)
        with self.assertRaises(ValueError):
            namespace['validate_helper_archive_descriptor']({**valid, 'archive': 'variant.zip'})

    def test_wrong_leaf_fails_even_when_the_restored_executable_hash_matches(self):
        import hashlib
        leaf = '3e6ae7c6ba4cfe1e6280535eb93cf7a7959a7ba6'
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle, executable, archive = self.fixture(root)
            def run(argv, **_kwargs):
                if argv[0] == '/usr/bin/ditto':
                    restored = bundle / 'Contents' / 'MacOS' / 'InfraternalCaptureHelper'
                    restored.parent.mkdir(parents=True)
                    restored.write_bytes(b'shipped')
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                if argv[0] == '/usr/bin/codesign' and argv[1] == '--verify':
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                if argv[0] == '/usr/bin/codesign' and argv[1] == '-d':
                    requirement = 'designated => identifier "com.infraternal.desktop.helper" and certificate leaf = H"' + 'a' * 40 + '"'
                    return SimpleNamespace(returncode=0, stdout='', stderr=requirement)
                raise AssertionError(argv)
            with mock.patch('pathlib.Path.home', return_value=root):
                with mock.patch('subprocess.run', side_effect=run):
                    with self.assertRaisesRegex(RuntimeError, 'leaf hash'):
                        self.restore()(bundle, archive, hashlib.sha256(archive.read_bytes()).hexdigest(),
                                       hashlib.sha256(b'shipped').hexdigest(), leaf)


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
        self.assertIsInstance(timeout, ast.IfExp)
        self.assertEqual(ast.literal_eval(timeout.body), 1800)
        self.assertEqual(ast.literal_eval(timeout.orelse), 900)
        self.assertIn('TEN_WINDOW_IDLE', ast.unparse(timeout.test))
        self.assertIn('FLOOD', ast.unparse(timeout.test))
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


class FirstPictureIdleTests(unittest.TestCase):
    """The short ten-window check records frame activity without resource timings."""

    def test_short_check_helper_binary_must_be_inside_the_job_bench(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'validate_helper_binary')
        namespace = {'pathlib': pathlib}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            bench = root / 'infraternal-bench'
            bench.mkdir()
            helper = bench / 'helper'
            helper.write_bytes(b'fixture')
            outside = root / 'outside-helper'
            outside.write_bytes(b'fixture')
            default = root / 'default-helper'
            validate = namespace['validate_helper_binary']
            self.assertEqual(validate(None, default, bench), default)
            self.assertEqual(validate(str(helper), default, bench), helper.resolve())
            with self.assertRaisesRegex(ValueError, 'helper binary outside Mac bench directory'):
                validate(str(outside), default, bench)
            with self.assertRaisesRegex(ValueError, 'invalid helper binary path'):
                validate('relative/helper', default, bench)

    def test_decode_timeout_is_recorded_and_stops_capture_immediately(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'wait_for_first_picture')
        class PictureTimeout(Exception):
            """Stand in for the browser driver's bounded picture wait."""
        class Card:
            def locator(self, selector):
                if selector == '.aw-stage[data-picture="live"]':
                    return SimpleNamespace(wait_for=lambda **_: (_ for _ in ()).throw(PictureTimeout()))
                if selector == '.aw-card':
                    return SimpleNamespace(get_attribute=lambda _: 'failed:decode')
                return SimpleNamespace(get_attribute=lambda _: 'error', bounding_box=lambda: {'x': 10, 'y': 20, 'width': 300, 'height': 200})
            def get_attribute(self, _):
                return 'fixture-window-3'
            def bounding_box(self):
                return {'x': 10, 'y': 20, 'width': 300, 'height': 200}
            def evaluate(self, _):
                return {'hidden': False, 'innerWidth': 848, 'innerHeight': 820}
        rows, checks, failures = [], [], []
        namespace = {'PlaywrightTimeoutError': PictureTimeout,
                     'args': {'first_picture_idle': True}, 'emit': rows.append,
                     'consent_check': lambda: checks.append(True),
                     'stop_capture': lambda: checks.append('stopped')}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        with self.assertRaisesRegex(RuntimeError, 'native first picture unavailable'):
            namespace['wait_for_first_picture'](Card(), 2, failures)
        self.assertEqual(failures, [{'fixture_index': 3, 'window_id': 'fixture-window-3',
                                     'card_state': 'failed:decode', 'picture': 'error',
                                     'card_rect': {'x': 10, 'y': 20, 'width': 300, 'height': 200},
                                     'stage_rect': {'x': 10, 'y': 20, 'width': 300, 'height': 200},
                                     'page_state': {'hidden': False, 'innerWidth': 848, 'innerHeight': 820}}])
        self.assertEqual(rows, [{'kind': 'first_picture_failure', **failures[0]}])
        self.assertEqual(checks, ['stopped'])

    def test_first_picture_idle_branch_checks_ten_live_windows_for_sixty_seconds(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "args.get('first_picture_idle')"
                      and any(isinstance(child, ast.Constant) and child.value == 'first_picture_idle_plan'
                              for child in ast.walk(node)))
        class PhaseComplete(Exception):
            """Stop after this functional phase, before other measurements."""
        now = [0.0]
        rows = []
        evidence = tempfile.TemporaryDirectory()
        metric_path = pathlib.Path(evidence.name) / 'companion-metrics.log'
        try:
            metric_path.write_text('')
            stats = {'received': 0, 'decoded': 0, 'painted': 0, 'dropped': 0, 'superseded': 0, 'repairs': 0}
            namespace = {
                'args': {'first_picture_idle': True}, 'fixture_window_count': 10,
                'first_picture_failures': [],
                'capture_helpers': set(range(1, 11)), 'helper_births': {pid: pid for pid in range(1, 11)},
                'process_identity': lambda pid: pid, 'native_command': rows.append,
                'battery': lambda: rows.append('battery'), 'consent_guard': lambda: None,
                'time': SimpleNamespace(monotonic=lambda: now[0]),
                'E': pathlib.Path(evidence.name),
                'page': SimpleNamespace(
                    locator=lambda _: SimpleNamespace(all=lambda: list(range(10))),
                    evaluate=lambda _: stats,
                    wait_for_timeout=lambda ms: now.__setitem__(0, now[0] + ms / 1000),
                ),
                'source': SimpleNamespace(poll=lambda: None), 'window': SimpleNamespace(poll=lambda: None),
                'browser': SimpleNamespace(is_connected=lambda: True),
                'drain': lambda: {'probe': {'videos': []}, 'frames': []},
                'metric_path': metric_path,
                'companion_metric_summary': lambda *_: {'source_callbacks': 0, 'fresh_deliveries': 0},
                'all_draws': [], 'emit': rows.append, 'PhaseComplete': PhaseComplete,
            }
            with self.assertRaises(PhaseComplete):
                exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), namespace)
            result = next(row for row in rows if isinstance(row, dict) and row.get('kind') == 'first_picture_idle_result')
            self.assertGreaterEqual(result['seconds'], 60)
            self.assertEqual(result['fixture_windows'], 10)
            self.assertEqual(result['capture_helpers'], 10)
            self.assertEqual(result['worker_delta'], {key: 0 for key in stats})
            self.assertTrue(result['worker_counters_available'])
            self.assertEqual(result['source_draws'], 0)
            self.assertEqual(result['browser_frames'], 0)
            self.assertEqual(result['worker_frames'], 0)
            self.assertNotIn('cpu_cores', result)
            self.assertIn({'kind': 'result', 'status': 'first_picture_idle_measured'}, rows)
        finally:
            evidence.cleanup()

    def test_first_picture_idle_branch_runs_without_a_decoder_worker_after_failure(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "args.get('first_picture_idle')"
                      and any(isinstance(child, ast.Constant) and child.value == 'first_picture_idle_plan'
                              for child in ast.walk(node)))
        now = [0.0]
        rows = []
        evidence = tempfile.TemporaryDirectory()
        metric_path = pathlib.Path(evidence.name) / 'companion-metrics.log'
        metric_path.write_text('')
        failure = {'fixture_index': 1, 'window_id': 'fixture-window-1',
                   'card_state': 'failed:decode', 'picture': 'error'}

        def evaluate(expression):
            if expression == 'window.__appWindowBench.stats()':
                raise RuntimeError('worker counters unavailable')
            raise AssertionError(f'unexpected page evaluation: {expression}')

        namespace = {
            'args': {'first_picture_idle': True}, 'fixture_window_count': 10,
            'first_picture_failures': [failure],
            'capture_helpers': set(range(1, 11)), 'helper_births': {pid: pid for pid in range(1, 11)},
            'process_identity': lambda pid: pid, 'native_command': rows.append,
            'battery': lambda: rows.append('battery'), 'consent_guard': lambda: None,
            'time': SimpleNamespace(monotonic=lambda: now[0]),
            'E': pathlib.Path(evidence.name),
            'page': SimpleNamespace(
                locator=lambda _: SimpleNamespace(all=lambda: []),
                evaluate=evaluate,
                wait_for_timeout=lambda ms: now.__setitem__(0, now[0] + ms / 1000),
            ),
            'source': SimpleNamespace(poll=lambda: None), 'window': SimpleNamespace(poll=lambda: None),
            'browser': SimpleNamespace(is_connected=lambda: True),
            'drain': lambda: {'probe': {'videos': []}, 'frames': []},
            'metric_path': metric_path,
            'companion_metric_summary': lambda *_: {'source_callbacks': 0, 'fresh_deliveries': 0},
            'all_draws': [], 'emit': rows.append,
        }
        try:
            with self.assertRaisesRegex(RuntimeError, 'did not meet the 60-second no-work bound'):
                exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), namespace)
            result = next(row for row in rows if isinstance(row, dict) and row.get('kind') == 'first_picture_idle_result')
            self.assertGreaterEqual(result['seconds'], 60)
            self.assertEqual(result['fixture_windows'], 10)
            self.assertEqual(result['live_pictures'], 0)
            self.assertEqual(result['first_picture_failures'], [failure])
            self.assertFalse(result['worker_counters_available'])
            self.assertIsNone(result['worker_delta'])
            self.assertIn({'kind': 'first_picture_idle_plan', 'seconds': 60,
                           'fixture_windows': 10, 'capture_helpers': 10}, rows)
        finally:
            evidence.cleanup()

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


class HelperResourceTests(unittest.TestCase):
    """Compute aggregate helper CPU, wakeups and resident memory from Mac samples."""

    def test_interval_delta_uses_only_matching_helpers_and_actual_elapsed_time(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'helper_resource_delta')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        before = {10: {'cpu_ns': 1_000_000_000, 'wakeups': 10, 'rss_kb': 100},
                  11: {'cpu_ns': 5_000_000_000, 'wakeups': 20, 'rss_kb': 200}}
        after = {10: {'cpu_ns': 2_000_000_000, 'wakeups': 15, 'rss_kb': 130},
                 11: {'cpu_ns': 7_000_000_000, 'wakeups': 35, 'rss_kb': 190},
                 12: {'cpu_ns': 0, 'wakeups': 0, 'rss_kb': 50}}
        self.assertEqual(namespace['helper_resource_delta'](before, after, 10), {
            'matched_helpers': 2, 'helper_count': 3, 'cpu_cores': 0.3,
            'wakeups_per_second': 2.0, 'rss_kb': 370,
            'rss_by_pid_kb': {'10': 130, '11': 190, '12': 50},
        })

    def test_companion_receipts_expose_queue_bound_and_latest_delivery_gap(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'companion_metric_summary')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            path = pathlib.Path(directory) / 'metrics.log'
            path.write_text('METRIC source_capture_config fps=120 queue_depth=3 interval_value=0\n'
                            'METRIC source_frame capture_ns=1 damaged=true\n'
                            'METRIC source_frame capture_ns=2 damaged=true\n'
                            'METRIC source_frame capture_ns=3 damaged=false\n'
                            'METRIC surface_delivery capture_ns=1 fresh=true\n'
                            'METRIC encoder_drop=1 drop_ns=3\n')
            self.assertEqual(namespace['companion_metric_summary'](path), {
                'queue_depth_max': 3, 'source_callbacks': 3, 'damaged_callbacks': 2, 'fresh_deliveries': 1,
                'latest_only_callback_gap': 1, 'encoder_drops': 1,
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


class RecoveryAccountingTests(unittest.TestCase):
    """A requested recovery must not bless extra socket or helper failures."""

    def test_recovery_counts_every_socket_reconnect(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and isinstance(node.test, ast.BoolOp)
                      and any(isinstance(value, ast.Name) and value.id == 'RECOVERY_ENABLED' for value in node.test.values)
                      and any(isinstance(value, ast.Compare) and ast.unparse(value) == 'iteration == RECONNECT_ITERATION' for value in node.test.values))
        before = {'opened': 1, 'closed': 1, 'history': []}
        after = {'opened': 4, 'closed': 4, 'history': []}
        snapshots = iter((before, after))
        counts = {'reconnects': 0, 'requested_drops': 0, 'stuck_frames': 0}
        namespace = {
            'RECOVERY_ENABLED': True, 'iteration': 3, 'RECONNECT_ITERATION': 3,
            'counts': counts,
            'page': SimpleNamespace(evaluate=lambda _script: next(snapshots),
                                    wait_for_function=lambda *_args, **_kwargs: None),
            'emit': lambda _row: None,
            'sys': SimpleNamespace(stdin=io.StringIO('{"kind":"network_restored"}\n')),
            'json': json, 'first_picture': lambda *_args: None,
        }
        exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertEqual(counts['reconnects'], after['opened'] - before['opened'])

    def test_requested_drop_does_not_excuse_control_owner_retirement(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        names = {'native_resize', 'initiated_retirement', 'expected_retirement'}
        statements = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id in names for target in node.targets)]
        statements.sort(key=lambda node: next(i for i, name in enumerate(('native_resize', 'initiated_retirement', 'expected_retirement'))
                                               if any(isinstance(target, ast.Name) and target.id == name for target in node.targets)))
        helpers = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'expected_capture_retirement':
                exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), helpers)
        namespace = {
            'RECOVERY_ENABLED': True, 'iteration': 3, 'RECONNECT_ITERATION': 3, 'REOPEN_ITERATION': 6,
            'previous_expected_retirement': False,
            'retired': {99}, 'capture_helpers': {101}, 'previous_helpers': {99, 101}, 'current_helpers': {101},
            'last_dimensions': (1512, 1020), 'current_dimensions': (1512, 1208), 'recent_resize_acks': [],
            'expected_capture_retirement': helpers['expected_capture_retirement'],
        }
        exec(compile(ast.Module(body=statements, type_ignores=[]), str(source), 'exec'), namespace)
        self.assertFalse(namespace['expected_retirement'])


class CaptureReconfigurationTests(unittest.TestCase):
    """A capture replacement requires causal resize evidence and the same live control owner."""

    def functions(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        names = {'expected_capture_retirement', 'read_resize_acks'}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        namespace = {}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
        return namespace

    def test_acknowledged_new_geometry_preserves_the_live_control_owner(self):
        classify = self.functions()['expected_capture_retirement']
        self.assertTrue(classify({101}, {101}, {99}, {99}, (1512, 1020), (1512, 1208), True))

    def test_a_crashed_control_owner_or_unexplained_exit_still_fails(self):
        classify = self.functions()['expected_capture_retirement']
        self.assertFalse(classify({99, 101}, {101}, {99}, set(), (1512, 1020), (1512, 1208), True))
        self.assertFalse(classify({101}, {101}, {99}, {99}, (1512, 1020), (1512, 1208), False))
        self.assertFalse(classify({101}, {101}, {99}, {99}, (1512, 1020), (1512, 1020), True))
        self.assertFalse(classify({101}, {101}, set(), set(), (1512, 1020), (1512, 1208), True))
        self.assertFalse(classify({101}, {101}, {99}, {100}, (1512, 1020), (1512, 1208), True))
        self.assertFalse(classify({102}, {101}, {99}, {99}, (1512, 1020), (1512, 1208), True))

    def test_partial_and_other_control_receipts_never_authorize_retirement(self):
        read = self.functions()['read_resize_acks']
        import tempfile
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            path = pathlib.Path(directory) / 'metrics.log'
            before = 'METRIC app_window_control pid=1 stage=helper_native_begin at_ns=2 kind=3\n'
            after = 'METRIC app_window_control pid=1 stage=helper_native_end at_ns=3 kind=3'
            path.write_text(before + after)
            cursor, rows = read(path, 0)
            self.assertEqual(rows, [])
            with path.open('a') as stream: stream.write('\n')
            cursor, rows = read(path, cursor)
            self.assertEqual(rows, [{'pid': '1', 'stage': 'helper_native_end', 'at_ns': '3', 'kind': '3'}])
            self.assertEqual(read(path, cursor), (cursor, []))


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

    def test_capture_projection_accounts_for_letterbox_and_auxiliary_bounds(self):
        state = {'width': 640, 'height': 400,
                 'actual': {'x': 100, 'y': 200, 'width': 640, 'height': 280},
                 'capture_rect': {'x': 100, 'y': 200, 'width': 640, 'height': 280},
                 'content_rect': {'x': 0, 'y': 60, 'width': 640, 'height': 280}}
        project = self.target('capture_projection')
        projection = project(state)
        self.assertAlmostEqual(projection['markerY'], .636)
        self.assertAlmostEqual(projection['colourY'], .675)
        state['capture_rect']['x'] = 90
        state['capture_rect']['width'] = 660
        state['content_rect']['width'] = 660
        state['width'] = 660
        self.assertAlmostEqual(project(state)['markerX'], (10 + 512) / 660)
        state['actual']['x'] = -1000
        with self.assertRaises(RuntimeError): project(state)

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
