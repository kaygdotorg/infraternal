#!/usr/bin/env python3
"""Keep invalid measurement inputs from touching a disposable target (#189)."""
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
from contextlib import redirect_stderr

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

    def test_retry_requires_the_published_session_image_before_docker_mutation(self):
        arguments = ["measure.py", "--retry", "--test-binary", "fixture-controller",
                     "--payload", "fixture-full"]
        errors = io.StringIO()
        with mock.patch.object(sys, "argv", arguments), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(MEASURE.subprocess, "run", side_effect=
                               AssertionError("Docker mutation before input refusal")), \
             redirect_stderr(errors):
            with self.assertRaises(SystemExit) as refusal:
                MEASURE.main()
        self.assertEqual(refusal.exception.code, 2)
        self.assertIn("--retry requires --session-payload", errors.getvalue())

    def test_retry_mode_selects_the_instant_failure_fixture(self):
        arguments = type("RetryArguments", (), {
            "retry": True,
            "session_payload": Path("/fixture/session"),
            "test_binary": Path("/fixture/test"),
            "payload": Path("/fixture/full"),
            "mode": "rootless",
            "user": "target",
            "controller_ip": MEASURE.ipaddress.IPv4Address("192.0.2.1"),
            "expect_failure": False,
        })()
        environment = MEASURE.live_test_environment(
            arguments, Path("/fixture/scratch"), "192.0.2.10"
        )
        self.assertEqual(environment["ADDHOST_INSTANT"], "1")
        self.assertEqual(environment["BREAKIT2_RETRY"], "1")
        self.assertEqual(environment["INFRATERNAL_REMOTE_TEST_SESSION_BINARY"], "/fixture/session")


if __name__ == "__main__":
    unittest.main()
