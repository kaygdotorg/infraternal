#!/usr/bin/env python3
"""Check the nightly `infraternal up` join proof's decisions: skip without root, verdicts, and the root script's invariants [#580, J1257].

Nothing here reaches a host. A fake `netbird` on PATH answers the root probe and the remote run, so
the coordinator's skip, pass and fail paths run end to end, and the root script is checked for the
rules that keep root's side safe: its own process group, the shared build slot, no host resolver, no
name-based kills, and the full non-root check.
"""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("nightly_up_approval", HERE / "nightly-up-approval.py")
nightly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nightly)

SHA = "1" * 40

# A stand-in for `netbird ssh <host> <command>`: the probe (`true`) exits with $FAKE_PROBE_RC; any other
# command records its stdin and its argument in $FAKE_LOG_DIR, prints $FAKE_OUTPUT and exits $FAKE_RUN_RC.
FAKE_NETBIRD = """#!/bin/sh
case "$3" in
  true) exit "${FAKE_PROBE_RC:-0}" ;;
  *) printf '%s\\n' "$3" > "$FAKE_LOG_DIR/command"; cat > "$FAKE_LOG_DIR/stdin"
     printf '%b' "${FAKE_OUTPUT:-}"; exit "${FAKE_RUN_RC:-0}" ;;
esac
"""


def fake_netbird(case, **env):
    """Put a fake `netbird` first on PATH for `case`'s test, configured by `env`; return its log folder.

    The environment is restored when the test ends, so the fake never leaks into another test.
    """
    folder = Path(tempfile.mkdtemp(prefix="nightly-up-test."))
    script = folder / "netbird"
    script.write_text(FAKE_NETBIRD, encoding="utf-8")
    script.chmod(0o700)
    logs = folder / "logs"
    logs.mkdir(mode=0o700)
    saved = dict(os.environ)
    os.environ["PATH"] = f"{folder}{os.pathsep}{saved['PATH']}"
    os.environ["FAKE_LOG_DIR"] = str(logs)
    os.environ.update({key: str(value) for key, value in env.items()})

    def restore():
        os.environ.clear()
        os.environ.update(saved)
    case.addCleanup(restore)
    return logs


class RootProbeTests(unittest.TestCase):
    """The root probe decides between a proof and a clean skip; a missing netbird is an error, not a skip."""

    def test_refused_probe_is_a_skip_with_the_reason(self):
        fake_netbird(self, FAKE_PROBE_RC=255)
        reachable, reason = nightly.probe_root()
        self.assertFalse(reachable)
        self.assertIn("refused the probe (exit 255)", reason)

    def test_answering_probe_is_reachable(self):
        fake_netbird(self, FAKE_PROBE_RC=0)
        self.assertEqual(nightly.probe_root(), (True, ""))

    def test_missing_netbird_is_an_error_not_a_skip(self):
        empty = Path(tempfile.mkdtemp(prefix="empty-path."))
        saved = os.environ["PATH"]
        self.addCleanup(os.environ.__setitem__, "PATH", saved)
        os.environ["PATH"] = str(empty)
        with self.assertRaises(RuntimeError):
            nightly.probe_root()


class MainTests(unittest.TestCase):
    """`main` runs the whole decision and records one folder per run."""

    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="nightly-up-out."))

    def run_main(self):
        """Call `main` with `--sha` and this test's output folder; return its exit status."""
        return nightly.main(["nightly-up-approval.py", "run", "--sha", SHA, "--out", str(self.out)])

    def recorded(self):
        """The `result.json` text of the one run folder this test wrote."""
        folders = list(self.out.iterdir())
        self.assertEqual(len(folders), 1)
        return (folders[0] / "result.json").read_text(encoding="utf-8")

    def test_no_root_skips_with_exit_77_and_never_runs_the_proof(self):
        logs = fake_netbird(self, FAKE_PROBE_RC=255)
        self.assertEqual(self.run_main(), nightly.EXIT_SKIP)
        self.assertFalse((logs / "command").exists())
        self.assertIn('"status": "skip"', self.recorded())

    def test_marker_zero_is_a_pass_and_the_script_goes_on_stdin(self):
        logs = fake_netbird(self, FAKE_PROBE_RC=0, FAKE_RUN_RC=0,
                            FAKE_OUTPUT=f"building\nUP_APPROVAL_NIGHTLY_EXIT=0 commit={SHA}\n")
        self.assertEqual(self.run_main(), nightly.EXIT_PASS)
        self.assertEqual((logs / "command").read_text(encoding="utf-8").strip(),
                         f"{nightly.REMOTE_ENV} bash -s -- {SHA}")
        self.assertEqual((logs / "stdin").read_text(encoding="utf-8"), nightly.ROOT_SCRIPT)
        self.assertIn('"status": "pass"', self.recorded())

    def test_nonzero_proof_is_a_fail(self):
        fake_netbird(self, FAKE_PROBE_RC=0, FAKE_RUN_RC=1,
                     FAKE_OUTPUT=f"proof\nUP_APPROVAL_NIGHTLY_EXIT=1 commit={SHA}\n")
        self.assertEqual(self.run_main(), nightly.EXIT_FAIL)
        self.assertIn("the proof exited 1", self.recorded())

    def test_missing_marker_is_a_fail_even_when_ssh_succeeds(self):
        fake_netbird(self, FAKE_PROBE_RC=0, FAKE_RUN_RC=0, FAKE_OUTPUT="clone failed before the proof\n")
        self.assertEqual(self.run_main(), nightly.EXIT_FAIL)
        self.assertIn("did not reach the proof", self.recorded())

    def test_bad_sha_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            nightly.main(["nightly-up-approval.py", "run", "--sha", "abc", "--out", str(self.out)])
        self.assertEqual(caught.exception.code, 2)


class RootScriptTests(unittest.TestCase):
    """The root script keeps its trust boundary: its own process group, the build slot, no resolver, no name kills."""

    def test_namespace_run_is_its_own_group_and_group_killed(self):
        script = nightly.ROOT_SCRIPT
        self.assertIn("setsid nix develop", script)
        self.assertIn('kill -TERM -- "-$group"', script)
        self.assertIn('kill -KILL -- "-$group"', script)
        self.assertIn('ps -o pgid= -p "$group"', script)

    def test_cleanup_also_sweeps_processes_started_from_the_run_folder(self):
        # Terminal shims set their own process groups, so the group kill alone leaves them running.
        self.assertIn('readlink -- "$proc/exe"', nightly.ROOT_SCRIPT)
        self.assertIn('case $exe in "$work"/*)', nightly.ROOT_SCRIPT)

    def test_build_is_held_through_the_shared_slot_as_root(self):
        self.assertIn("scripts/root-slot-hold --reserved nightly --keep-fd 9 nix develop", nightly.ROOT_SCRIPT)

    def test_full_non_root_check_is_never_skipped_on_root(self):
        # The script may name the variable in comments; what must never happen is setting it.
        self.assertNotIn("UP_E2E_SKIP_NONROOT=", nightly.ROOT_SCRIPT)
        self.assertNotIn("UP_E2E_SKIP_NONROOT=", nightly.REMOTE_ENV)

    def test_no_host_resolver_or_name_based_kill(self):
        for banned in ("resolvectl", "systemd-resolve", "pkill", "killall"):
            self.assertNotIn(banned, nightly.ROOT_SCRIPT, banned)

    def test_remote_environment_is_the_clean_allowlist(self):
        self.assertTrue(nightly.REMOTE_ENV.startswith("env -i PATH="))
        self.assertIn("HOME=/root", nightly.REMOTE_ENV)


if __name__ == "__main__":
    unittest.main(verbosity=2)
