"""Role: verify Mac measurement consent ownership and compositor coordinates without launching the browser (#146)."""
import ast
import io
import json
import pathlib
import sys
import unittest
import signal
from types import SimpleNamespace


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
            'helper_births': {101: 'current', 202: 'previous', 303: 'current'},
            'capture_helpers': {101, 202},
            'subprocess': SimpleNamespace(run=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='current')),
            'os': SimpleNamespace(kill=lambda pid, value: actions.append((pid, value))),
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['stop_capture']()
        namespace['stop_capture']()
        self.assertEqual(actions, ['sealed', ('source', signal.SIGINT), (101, signal.SIGTERM)])

    def test_resource_collection_includes_independent_helpers_by_identity(self):
        source = pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'live_helpers')
        namespace = {
            'helper_births': {101: 'current', 202: 'previous'},
            'subprocess': SimpleNamespace(run=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='current')),
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertEqual(namespace['live_helpers'](), {101})


class ConsentTests(unittest.TestCase):
    """Execute only the consent guard, without importing or launching the browser driver."""

    def check_prompt(self, controls, *, own_helper=True, title=None):
        source = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'consent_check')
        calls = []

        def cua(name, params):
            calls.append(name)
            if name == 'list_windows':
                return {'windows': [{'title': title or ('InfraternalCaptureHelper' if own_helper else 'Unrelated application'), 'pid': 101, 'window_id': 202}]}
            if name == 'get_window_state':
                return {'text': 'requesting to bypass', 'controls': controls}
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
        self.assertEqual(before['x'], 200 / 832)
        self.assertEqual(after['x'], 350 / 832)
        self.assertEqual(after['y'], 250 / 720)

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
