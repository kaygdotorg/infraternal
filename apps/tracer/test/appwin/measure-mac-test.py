"""Role: verify the Mac measurement refuses changed helper consent without clicking system controls (#146)."""
import ast
import json
import pathlib
import sys
import unittest


class ConsentTests(unittest.TestCase):
    """Execute only the consent guard, without importing or launching the browser driver."""

    def check_prompt(self, controls, *, own_helper=True):
        source = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name('measure-mac.py')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'consent_check')
        calls = []

        def cua(name, params):
            calls.append(name)
            if name == 'list_windows':
                return {'windows': [{'title': 'InfraternalCaptureHelper' if own_helper else 'Unrelated application', 'pid': 101, 'window_id': 202}]}
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

    def test_another_application_prompt_is_ignored(self):
        refused, calls = self.check_prompt([{'role': 'button', 'title': 'Allow', 'element_token': 'allow'}], own_helper=False)
        self.assertFalse(refused)
        self.assertEqual(calls, ['list_windows'])


if __name__ == '__main__':
    # The optional first argument is the baseline source used for the red run.
    unittest.main(argv=[sys.argv[0]])
