#!/usr/bin/env python3
"""Keep invalid measurement inputs from touching a disposable target (#189)."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("measure", Path(__file__).with_name("measure.py"))
MEASURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MEASURE)


class InputAdmission(unittest.TestCase):
    def test_missing_session_image_refuses_before_docker_mutation(self):
        # The fixture listing is valid; any subprocess mutation fails the test.
        arguments = ["measure.py", "--fresh", "--test-binary", "fixture-controller",
                     "--payload", "fixture-full", "--session-payload",
                     "/home/kayg/.cache/codex-scratch/addhost-instant/absent-session-fixture"]
        with mock.patch.object(sys, "argv", arguments), \
             mock.patch.dict(os.environ, {"ADDHOST_INSTANT": "1"}), \
             mock.patch.object(MEASURE.subprocess, "check_output", return_value=
                               "fixture::breakit2_live_ssh_install_join_and_terminal: test\n"), \
             mock.patch.object(MEASURE.subprocess, "run", side_effect=
                               AssertionError("Docker mutation before input refusal")):
            with self.assertRaises(SystemExit) as refusal:
                MEASURE.main()
            self.assertEqual(refusal.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
