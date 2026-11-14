#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the pinned R4b command-line parser without running a benchmark."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PerfAllCliTest(unittest.TestCase):
    """Keep validation mode reachable when optional row maps are empty."""

    def fake_restore_environment(
        self,
        root: Path,
        effective: str,
        cpuset: str = "0-5",
        dropins: str = "",
    ) -> dict[str, str]:
        """Provide a controlled systemd and cgroup view for restoration tests."""
        bin_dir = root / "bin"
        state_dir = root / "systemd-state"
        cgroup = root / "perf.slice"
        bin_dir.mkdir(exist_ok=True)
        state_dir.mkdir(exist_ok=True)
        cgroup.mkdir(exist_ok=True)
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "case \" $* \" in\n"
            "  *ControlGroup*) printf '/perf.slice\\n' ;;\n"
            "  *AllowedCPUs*) cat \"$J88I_TEST_SYSTEMD_STATE/allowed\" ;;\n"
            "  *EffectiveCPUs*) cat \"$J88I_TEST_SYSTEMD_STATE/effective\" ;;\n"
            "  *DropInPaths*) cat \"$J88I_TEST_SYSTEMD_STATE/dropins\" ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n"
        )
        systemctl.chmod(0o755)
        identity = bin_dir / "id"
        identity.write_text(
            "#!/usr/bin/env bash\n"
            "[[ ${1:-} == -un ]] && { printf 'claude\\n'; exit 0; }\n"
            "exec /usr/bin/id \"$@\"\n"
        )
        identity.chmod(0o755)
        taskset = bin_dir / "taskset"
        taskset.write_text(
            "#!/usr/bin/env bash\n"
            "[[ ${1:-} == -pc ]] && exit 0\n"
            "[[ ${1:-} == -c && $# -ge 3 ]] || exit 2\n"
            "shift 2\n"
            "exec \"$@\"\n"
        )
        taskset.chmod(0o755)
        awk = bin_dir / "awk"
        awk.write_text(
            "#!/usr/bin/env bash\n"
            "for arg in \"$@\"; do\n"
            "  [[ $arg == /proc/self/status ]] && { printf '0,5\\n'; exit 0; }\n"
            "done\n"
            "exec /usr/bin/awk \"$@\"\n"
        )
        awk.chmod(0o755)
        # Tests must not depend on the host's live process list: another job's
        # outgoing ssh starts a user-owned `netbird`, which the runner's guard refuses.
        process_list = bin_dir / "ps"
        process_list.write_text("#!/usr/bin/env bash\nexit 0\n")
        process_list.chmod(0o755)
        (state_dir / "allowed").write_text("0-5\n")
        (state_dir / "effective").write_text(f"{effective}\n")
        (state_dir / "dropins").write_text(dropins)
        (cgroup / "cpuset.cpus").write_text(f"{cpuset}\n")
        (cgroup / "cpuset.cpus.effective").write_text(f"{effective}\n")
        environment = os.environ.copy()
        environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
        environment["J88I_PERF_SLICE_CGROUP"] = str(cgroup)
        environment["J88I_EXPECTED_PERF_CPUS"] = "0-5"
        environment["J88I_TEST_SYSTEMD_STATE"] = str(state_dir)
        return environment

    def run_restore_check(
        self,
        root: Path,
        effective: str,
        *,
        cpuset: str = "0-5",
        allowed: str = "0-5",
        systemd_effective: str | None = None,
        workqueue_manifest: Path | None = None,
        perf_slice_baseline: Path | None = None,
        dropins: str = "",
        expected_cpus: str = "0-5",
        expected_effective: str = "0-5",
        expected_dropins: str = "",
    ) -> subprocess.CompletedProcess[str]:
        """Run the post-scope verifier against a temporary cgroup and systemd view."""
        script = Path(__file__).parent / "runner-overlays/J88i-verify-restored.sh"
        output = root / "restoration.txt"
        environment = self.fake_restore_environment(root, effective, cpuset, dropins)
        state_dir = root / "systemd-state"
        (state_dir / "allowed").write_text(f"{allowed}\n")
        (state_dir / "effective").write_text(
            f"{effective if systemd_effective is None else systemd_effective}\n"
        )
        cgroup_manifest = root / "cgroup-masks-before.tsv"
        cgroup_manifest.write_text(
            f"perf.slice\t/perf.slice\t{expected_cpus}\t{expected_effective}\t{expected_dropins}\n"
        )
        environment["J88I_CGROUP_ROOT"] = str(root)
        command = ["bash", str(script), str(output), str(cgroup_manifest)]
        if workqueue_manifest is not None:
            command.append(str(workqueue_manifest))
        if perf_slice_baseline is not None:
            while len(command) < 6:
                command.append("")
            command.append(str(perf_slice_baseline))
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def capture_perf_slice_baseline(
        self,
        root: Path,
        dropin_paths: list[Path],
        allowed_cpus: str,
    ) -> Path:
        """Capture a perf.slice fixture through the same helper the runner uses."""
        helper = Path(__file__).parent / "lib/perf_slice_dropins.py"
        baseline = root / "perf-slice-dropins-before.json"
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(helper),
                "snapshot",
                "--drop-in-paths",
                " ".join(map(str, dropin_paths)),
                "--allowed-cpus",
                allowed_cpus,
                "--output",
                str(baseline),
                "--raw-dir",
                str(root / "perf-slice-dropins-before"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return baseline

    def test_restore_check_accepts_baseline_cgroup_after_scope_exit(self) -> None:
        """The second locked run must see every captured cgroup mask restored."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-ok-") as temporary:
            root = Path(temporary)
            result = self.run_restore_check(root, "0-5")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cpuset.cpus.effective=0-5", (root / "restoration.txt").read_text())

    def test_restore_check_rejects_a_still_widened_cgroup(self) -> None:
        """The post-scope check must reject an effective mask that differs from its baseline."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-widened-") as temporary:
            result = self.run_restore_check(Path(temporary), "0-3")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("cpuset.cpus.effective=0-3", result.stderr)

    def test_restore_check_uses_cgroup_masks_when_systemd_lists_differ(self) -> None:
        """The final CPU mask comes from cgroups, even when systemd prints a different form."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-cgroup-authority-") as temporary:
            root = Path(temporary)
            result = self.run_restore_check(
                root,
                "0-5",
                allowed="",
                systemd_effective="1-3",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cpuset.cpus.effective=0-5", (root / "restoration.txt").read_text())

    def test_restore_check_rejects_wrong_cgroup_even_when_systemd_claims_baseline(self) -> None:
        """A correct property string cannot hide a cgroup that still has extra CPUs."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-cgroup-widened-") as temporary:
            result = self.run_restore_check(
                Path(temporary),
                "0-5",
                cpuset="0-4",
                allowed="0-5",
                systemd_effective="0-5",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("cpuset.cpus=0-4", result.stderr)

    def test_restore_check_accepts_exact_perf_slice_runtime_dropin(self) -> None:
        """The second locked audit accepts the original runtime bytes and property."""
        with tempfile.TemporaryDirectory(prefix="j317-restore-perf-slice-ok-") as temporary:
            root = Path(temporary)
            dropin = root / "system.control/perf.slice.d/50-AllowedCPUs.conf"
            dropin.parent.mkdir(parents=True)
            dropin.write_bytes(b"[Slice]\nAllowedCPUs=1-3\n")
            baseline = self.capture_perf_slice_baseline(root, [dropin], "1-3")
            result = self.run_restore_check(
                root,
                "1-3",
                cpuset="1-3",
                allowed="1-3",
                dropins=str(dropin),
                perf_slice_baseline=baseline,
                expected_cpus="1-3",
                expected_effective="1-3",
                expected_dropins=str(dropin),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("perf.slice baseline exact", result.stdout)

    def test_restore_check_rejects_changed_perf_slice_runtime_bytes(self) -> None:
        """The second locked audit catches a runtime file changed after the baseline."""
        with tempfile.TemporaryDirectory(prefix="j317-restore-perf-slice-bad-") as temporary:
            root = Path(temporary)
            dropin = root / "system.control/perf.slice.d/50-AllowedCPUs.conf"
            dropin.parent.mkdir(parents=True)
            dropin.write_bytes(b"[Slice]\nAllowedCPUs=1-3\n")
            baseline = self.capture_perf_slice_baseline(root, [dropin], "1-3")
            dropin.write_bytes(b"[Slice]\nAllowedCPUs=0-5\n")
            result = self.run_restore_check(
                root,
                "1-3",
                cpuset="1-3",
                allowed="1-3",
                dropins=str(dropin),
                perf_slice_baseline=baseline,
                expected_cpus="1-3",
                expected_effective="1-3",
                expected_dropins=str(dropin),
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("content differs", result.stderr)

    def test_validate_reaches_perf_runner_without_rows(self) -> None:
        """Empty validation options must not trip nounset before perf-run."""
        script = Path(__file__).parent / "perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-perf-all-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            capture = root / "runner-args.txt"
            count_file = root / "runner-count.txt"
            output = root / "validation"
            baseline = output / "perf-slice-dropins-before.json"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 1)); then\n"
                "  printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"\n"
                "  for arg in \"$@\"; do [[ $arg == H2H_RESULTS=* ]] && results=${arg#*=}; done\n"
                "  mkdir -p \"$results\"\n"
                "  printf '%s\\n' '{\"schema_version\":1,\"unit\":\"perf.slice\",\"drop_in_paths_raw\":\"\",\"drop_in_paths\":[],\"allowed_cpus\":\"0-5\",\"files\":[]}' > \"$results/perf-slice-dropins-before.json\"\n"
                "  printf 'perf.slice\\t/perf.slice\\t0-5\\t0-5\\t__EMPTY__\\n' > \"$results/cgroup-masks-before.tsv\"\n"
                "  exit 23\n"
                "fi\n"
                "printf '%s\\n' \"$@\" >> \"$PERF_RUN_CAPTURE\"\n"
                "printf 'verify-call\\n' >> \"$PERF_RUN_CAPTURE\"\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(count_file)
            environment["J88I_CGROUP_ROOT"] = str(root)

            result = subprocess.run(
                ["bash", str(script), "--validate", "--out", str(output)],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("D348 pinned validate", result.stdout)
            self.assertEqual(count_file.read_text().strip(), "2")
            self.assertIn("verify-call", capture.read_text())
            self.assertIn(str(baseline), capture.read_text())
            self.assertEqual(
                capture.read_text().splitlines()[:3],
                ["--root", "--out", str(output / "receipts")],
            )
            self.assertIn("H2H_LAN_TPUT_SECONDS=10", capture.read_text().splitlines())
            self.assertIn("cpuset.cpus.effective=0-5", (output / "cpuset-restoration.txt").read_text())

    def test_validation_resolves_smoke_helper_from_installed_kit_root(self) -> None:
        """D348 validation must find the helper copied beside the installed harness kit."""
        overlay = Path(__file__).parent
        runner = overlay / "runner-overlays/J88i-pinned-run.sh"
        helper = overlay / "cpuset-harness-smoke.sh"

        self.assertTrue(helper.is_file())
        self.assertIn('bash "$kit/cpuset-harness-smoke.sh"', runner.read_text())

    def test_calibration_forwards_lan_probe_count_to_measured_scope(self) -> None:
        """The 3,600-probe override must cross perf-run's sudo boundary explicitly."""
        script = Path(__file__).parent / "perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-calibration-count-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            capture = root / "runner-args.txt"
            count_file = root / "runner-count.txt"
            output = root / "calibration"
            binary = root / "gotatun"
            binary.write_text("#!/usr/bin/env bash\nexit 0\n")
            binary.chmod(0o755)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 1)); then printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"; exit 23; fi\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(count_file)
            environment["H2H_LAN_PING_COUNT"] = "3600"

            result = subprocess.run(
                [
                    "bash",
                    str(script),
                    "--calibration",
                    "--row",
                    "control-a=gotatun",
                    "--row",
                    "control-b=gotatun",
                    "--row",
                    "control-c=gotatun",
                    "--binary",
                    f"control-a={binary}",
                    "--binary",
                    f"control-b={binary}",
                    "--binary",
                    f"control-c={binary}",
                    "--source",
                    "control-a=84b7bb28e385d57dfb80493e78202898fad24d1e",
                    "--source",
                    "control-b=84b7bb28e385d57dfb80493e78202898fad24d1e",
                    "--source",
                    "control-c=84b7bb28e385d57dfb80493e78202898fad24d1e",
                    "--out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("H2H_LAN_PING_COUNT=3600", capture.read_text().splitlines())

    def run_calibration_plan(self, tags: list[str]) -> subprocess.CompletedProcess[str]:
        """Run `perf-all.sh --calibration` with `tags` as rows and a runner that stops at once.

        Returns the finished process. Exit 23 means the plan was accepted and the
        fake runner was reached; exit 2 means perf-all.sh rejected the plan.
        """
        script = Path(__file__).with_name("perf-all.sh")
        sha = "84b7bb28e385d57dfb80493e78202898fad24d1e"
        with tempfile.TemporaryDirectory(prefix="j317c-plan-") as temporary:
            root = Path(temporary)
            binary = root / "gotatun"
            binary.write_text("#!/usr/bin/env bash\nexit 0\n")
            binary.chmod(0o755)
            runner = root / "perf-run"
            # First call is the measured scope: fail it. Later calls (the restore
            # check) run their command, so exit 23 is what the script reports.
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "printf '%s\\n' $((count + 1)) > \"$PERF_RUN_COUNT_FILE\"\n"
                "((count > 0)) || exit 23\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_COUNT_FILE"] = str(root / "count")
            arguments = ["bash", str(script), "--calibration", "--out", str(root / "out")]
            for tag in tags:
                arguments += ["--row", f"{tag}=gotatun", "--binary", f"{tag}={binary}", "--source", f"{tag}={sha}"]
            return subprocess.run(arguments, capture_output=True, text=True, env=environment, check=False)

    def run_calibration_capture(self, *, environment_overrides: dict[str, str], path_prefix: Path | None = None
                                ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        """Run a three-control `--calibration` with a runner that records its arguments.

        Returns the finished process and the arguments the runner received for the
        measured scope. `path_prefix` is put first on PATH so a test can fake `ps`.
        """
        script = Path(__file__).with_name("perf-all.sh")
        sha = "84b7bb28e385d57dfb80493e78202898fad24d1e"
        with tempfile.TemporaryDirectory(prefix="j317c-capture-") as temporary:
            root = Path(temporary)
            binary = root / "gotatun"
            binary.write_text("#!/usr/bin/env bash\nexit 0\n")
            binary.chmod(0o755)
            capture = root / "capture"
            runner = root / "perf-run"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "printf '%s\\n' $((count + 1)) > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 0)); then printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"; exit 23; fi\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment.update(environment_overrides)
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(root / "count")
            if path_prefix is not None:
                environment["PATH"] = f"{path_prefix}:{environment.get('PATH', os.environ['PATH'])}"
            arguments = ["bash", str(script), "--calibration", "--out", str(root / "out")]
            for tag in ("control-a", "control-b", "control-c"):
                arguments += ["--row", f"{tag}=gotatun", "--binary", f"{tag}={binary}", "--source", f"{tag}={sha}"]
            result = subprocess.run(arguments, capture_output=True, text=True, env=environment, check=False)
            return result, capture.read_text().splitlines() if capture.exists() else []

    def run_ab_capture(self, *, rows: list[str] | None = None, environment_overrides: dict[str, str] | None = None
                       ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        """Run `--ab` with a runner that records the arguments of the measured scope."""
        script = Path(__file__).with_name("perf-all.sh")
        sha = "84b7bb28e385d57dfb80493e78202898fad24d1e"
        other = "7654321"
        rows = rows or ["control-a", "candidate-a", "candidate-b", "control-b"]
        with tempfile.TemporaryDirectory(prefix="j580-ab-") as temporary:
            root = Path(temporary)
            binaries = {}
            for name in ("control", "candidate"):
                binaries[name] = root / name
                binaries[name].write_text("#!/usr/bin/env bash\nexit 0\n")
                binaries[name].chmod(0o755)
            capture = root / "capture"
            runner = root / "perf-run"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "printf '%s\\n' $((count + 1)) > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 0)); then printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"; exit 23; fi\n"
                "exit 0\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment.update(environment_overrides or {})
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(root / "count")
            arguments = ["bash", str(script), "--ab", "--label", "j580", "--out", str(root / "out")]
            for tag in rows:
                kind = "control" if tag.startswith("control") else "candidate"
                arguments += ["--row", f"{tag}=gotatun", "--binary", f"{tag}={binaries[kind]}",
                              "--source", f"{tag}={sha if kind == 'control' else other}"]
            result = subprocess.run(arguments, capture_output=True, text=True, env=environment, check=False)
            return result, capture.read_text().splitlines() if capture.exists() else []

    def test_ab_runs_one_abba_round_in_a_single_hold(self) -> None:
        """`--ab` is a four-row control, candidate, candidate, control hold with calibration-shaped windows."""
        result, received = self.run_ab_capture()
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertIn("H2H_CALIBRATION_ONLY=1", received)
        self.assertIn("H2H_LAN_PING_COUNT=8000", received)
        self.assertEqual(received.count("--root"), 1)
        overlay = (Path(__file__).parent / "runner-overlays/J88i-pinned-run.sh").read_text()
        self.assertRegex(overlay, r"calibration\|hold\|matrix\|ab\)")

    def test_ab_rejects_other_row_orders_and_shapes(self) -> None:
        """The ABBA order is the experiment; any other order or count is refused before the lock."""
        result, _ = self.run_ab_capture(rows=["candidate-a", "control-a", "candidate-b", "control-b"])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("row 1 must be control-a=gotatun", result.stderr)
        result, _ = self.run_ab_capture(rows=["control-a", "candidate-a", "control-b"])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--ab takes exactly four rows", result.stderr)

    def test_ab_forwards_a_load_window_override(self) -> None:
        """An explicit load window crosses perf-run's sudo boundary in `--ab` like in calibration."""
        result, received = self.run_ab_capture(environment_overrides={"H2H_LAN_TPUT_SECONDS": "90"})
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertIn("H2H_LAN_TPUT_SECONDS=90", received)

    def test_calibration_forwards_the_longer_sampling_only_when_asked(self) -> None:
        """15,000 probes and an 85 s load are opt-in; the default is 8,000 probes (72 s load, set in lib/common.sh)."""
        result, received = self.run_calibration_capture(environment_overrides={})
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertIn("H2H_LAN_PING_COUNT=8000", received)
        self.assertFalse([item for item in received if item.startswith("H2H_LAN_TPUT_SECONDS=")])
        result, received = self.run_calibration_capture(
            environment_overrides={"H2H_LAN_PING_COUNT": "15000", "H2H_LAN_TPUT_SECONDS": "85"}
        )
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertIn("H2H_LAN_PING_COUNT=15000", received)
        self.assertIn("H2H_LAN_TPUT_SECONDS=85", received)

    def test_calibration_refuses_to_start_beside_a_non_root_netbird_process(self) -> None:
        """Another job's outgoing ssh (a user-owned `netbird` process) stops the run before it takes the lock."""
        with tempfile.TemporaryDirectory(prefix="j317c-fake-ps-") as temporary:
            fake = Path(temporary)
            ps = fake / "ps"
            ps.write_text("#!/usr/bin/env bash\nprintf '%s\\n' 'root 757 netbird' 'claude 4242 netbird'\n")
            ps.chmod(0o755)
            result, received = self.run_calibration_capture(environment_overrides={}, path_prefix=fake)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("non-root netbird process running (claude/4242)", result.stderr)
        self.assertEqual(received, [], "the perf runner must not be reached")

    def test_calibration_ignores_the_root_netbird_service(self) -> None:
        """The root daemon is expected and never blocks a run."""
        with tempfile.TemporaryDirectory(prefix="j317c-fake-ps-") as temporary:
            fake = Path(temporary)
            ps = fake / "ps"
            ps.write_text("#!/usr/bin/env bash\nprintf '%s\\n' 'root 757 netbird'\n")
            ps.chmod(0o755)
            result, _ = self.run_calibration_capture(environment_overrides={}, path_prefix=fake)
        self.assertEqual(result.returncode, 23, result.stderr)

    def test_calibration_accepts_a_leading_warmup_and_rotated_controls(self) -> None:
        """A discarded warmup row and any control order are valid calibration plans."""
        for tags in (
            ["control-a", "control-b", "control-c"],
            ["warmup", "control-a", "control-b", "control-c"],
            ["warmup", "control-b", "control-c", "control-a"],
            ["control-c", "control-a", "control-b"],
        ):
            with self.subTest(tags=tags):
                result = self.run_calibration_plan(tags)
                self.assertEqual(result.returncode, 23, result.stderr)

    def test_calibration_rejects_plans_without_each_control_once(self) -> None:
        """Missing controls, a misplaced warmup, or extra rows are refused before any run."""
        for tags in (
            ["control-a", "control-b"],
            ["control-a", "warmup", "control-b", "control-c"],
            ["warmup", "control-a", "control-b", "control-b2"],
        ):
            with self.subTest(tags=tags):
                result = self.run_calibration_plan(tags)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_restore_check_rejects_a_changed_workqueue_cpumask(self) -> None:
        """A mask left on housekeeping CPUs must fail the second locked restore check."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-workqueue-") as temporary:
            root = Path(temporary)
            mask = root / "workqueue" / "writeback" / "cpumask"
            mask.parent.mkdir(parents=True)
            mask.write_text("21\n")
            manifest = root / "workqueue-masks-before.tsv"
            manifest.write_text(f"{mask}\t3f\n")
            result = self.run_restore_check(
                root,
                "0-5",
                workqueue_manifest=manifest,
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("workqueue cpumask restore failed", result.stderr)

    def test_smoke_plan_accepts_wireguard_go_reference_engine(self) -> None:
        """The baseline comparison can schedule the existing wireguard-go harness case."""
        script = Path(__file__).parent / "perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-wireguard-go-row-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            capture = root / "runner-args.txt"
            count_file = root / "runner-count.txt"
            output = root / "wireguard-go"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 1)); then printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"; exit 23; fi\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(count_file)

            result = subprocess.run(
                [
                    "bash",
                    str(script),
                    "--smoke",
                    "--row",
                    "wireguard-go=wireguard-go",
                    "--out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("wireguard-go\twireguard-go", (output / "rows.tsv").read_text())

    def test_hold_plan_uses_plain_kernel_wireguard_as_the_matched_mtu_baseline(self) -> None:
        """A counted cut hold must use the direct kernel row at the userspace MTU."""
        script = Path(__file__).parent / "perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-kernel-mtu1420-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "for arg in \"$@\"; do\n"
                "  [[ $arg == */J88i-pinned-run.sh ]] && exit 23\n"
                "done\n"
                "exit 0\n"
            )
            runner.chmod(0o755)
            control = root / "control"
            candidate = root / "candidate"
            for binary in (control, candidate):
                binary.write_text("#!/usr/bin/env sh\\nexit 0\\n")
                binary.chmod(0o755)
            output = root / "hold"
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)

            result = subprocess.run(
                [
                    "bash",
                    str(script),
                    "--hold",
                    "--label",
                    "batch64-idle-lane",
                    "--row",
                    "kernel-before=kernel-plain",
                    "--row",
                    "wireguard-go-before=wireguard-go",
                    "--row",
                    "control-a=gotatun",
                    "--row",
                    "candidate-a=gotatun",
                    "--row",
                    "candidate-b=gotatun",
                    "--row",
                    "control-b=gotatun",
                    "--row",
                    "wireguard-go-after=wireguard-go",
                    "--row",
                    "kernel-after=kernel-plain",
                    "--binary",
                    f"control-a={control}",
                    "--binary",
                    f"control-b={control}",
                    "--binary",
                    f"candidate-a={candidate}",
                    "--binary",
                    f"candidate-b={candidate}",
                    "--source",
                    "control-a=1234567",
                    "--source",
                    "control-b=1234567",
                    "--source",
                    "candidate-a=7654321",
                    "--source",
                    "candidate-b=7654321",
                    "--out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            rows = (output / "rows.tsv").read_text()
            self.assertIn("kernel-before\tkernel-plain\t", rows)
            self.assertIn("kernel-after\tkernel-plain\t", rows)
            self.assertNotIn("mesh-netbird", rows)
            runner_overlay = Path(__file__).parent / "runner-overlays/J88i-pinned-run.sh"
            mesh_case = Path(__file__).parent / "cases/mesh.sh"
            self.assertIn("kernel-plain) case_name=mesh-kernel-plain", runner_overlay.read_text())
            kernel_setup = mesh_case.read_text().split("start_kernel_plain() {", 1)[1].split("\n}\n", 1)[0]
            self.assertIn("ip -n h2h-a link add wgA type wireguard", kernel_setup)
            self.assertIn('"$WG_BIN" set wgA', kernel_setup)
            self.assertIn("mtu 1420", kernel_setup)
            self.assertNotIn("start_netbird", kernel_setup)

    def test_kernel_peer_scale_keeps_remote_traffic_peers(self) -> None:
        """Peer-count replacement must retain each interface's opposite endpoint key."""
        mesh_case = Path(__file__).parent / "cases/mesh.sh"
        peer_scale = mesh_case.read_text().split("matrix_set_peer_count() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(
            '--active-public "$(cat "$D/keys/b.public")" --active-ip 10.66.0.2/32',
            peer_scale,
        )
        self.assertIn(
            '--active-public "$(cat "$D/keys/a.public")" --active-ip 10.66.0.1/32',
            peer_scale,
        )

    def test_matrix_plan_continues_after_one_row_fails(self) -> None:
        """One failed engine row must not prevent later engines from being measured."""
        runner = Path(__file__).parent / "runner-overlays/J88i-pinned-run.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-matrix-continue-") as temporary:
            root = Path(temporary)
            plan = root / "rows.tsv"
            visited = root / "visited.txt"
            plan.write_text(
                "kernel-a\tkernel-plain\t/fake/wg\tdeadbeef\n"
                "wireguard-go-a\twireguard-go\t/fake/wireguard-go\tdeadbeef\n"
                "gotatun-a\tgotatun\t/fake/gotatun\tdeadbeef\n",
                encoding="utf-8",
            )
            command = r"""
set -euo pipefail
runner=$1
plan=$2
visited=$3
run_plan_source=$(sed -n '/^run_plan() {/,/^}/p' "$runner")
[[ -n $run_plan_source ]]
eval "$run_plan_source"
run_row() {
    printf '%s\n' "$1" >> "$visited"
    [[ $1 != wireguard-go-a ]] || return 17
}
set +e
(
    set -e
    run_plan 0
)
rc=$?
set -e
printf 'RUN_PLAN_EXIT=%s\n' "$rc"
"""
            result = subprocess.run(
                ["bash", "-c", command, "matrix-plan-test", str(runner), str(plan), str(visited)],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(visited.read_text().splitlines(), ["kernel-a", "wireguard-go-a", "gotatun-a"])
            self.assertIn("RUN_PLAN_EXIT=1", result.stdout)
            self.assertIn("D348 row failed: wireguard-go-a", result.stderr)

    def test_matrix_accepts_shipped_and_candidate_gotatun_rows_in_one_window(self) -> None:
        """A shared-lock window can compare multiple SHA-labeled GotaTun variants."""
        script = Path(__file__).parent / "perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j317-matrix-window-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$@\" >> \"$PERF_RUN_ARGUMENTS\"\n"
                "for arg in \"$@\"; do\n"
                "  [[ $arg == */J88i-pinned-run.sh ]] && exit 23\n"
                "done\n"
                "exit 0\n"
            )
            runner.chmod(0o755)
            binaries = {}
            for name in ("gotatun-shipped", "gotatun-j88i", "wg", "wireguard-go"):
                path = root / name
                path.write_text("#!/usr/bin/env bash\nexit 0\n")
                path.chmod(0o755)
                binaries[name] = path
            output = root / "window-01"
            runner_arguments = root / "perf-run-arguments.txt"
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_ARGUMENTS"] = str(runner_arguments)

            result = subprocess.run(
                [
                    "bash", str(script), "--matrix", "--scenario", "wan-20ms-loss-1",
                    "--calibration-status", "uncalibrated, owner-directed",
                    "--label", "shipped and J88i baseline",
                    "--row", "kernel-plain-1=kernel-plain",
                    "--row", "wireguard-go-1=wireguard-go",
                    "--row", "gotatun-shipped-1=gotatun",
                    "--row", "gotatun-j88i-1=gotatun",
                    "--binary", f"gotatun-shipped-1={binaries['gotatun-shipped']}",
                    "--source", "gotatun-shipped-1=84b7bb28e385d57dfb80493e78202898fad24d1e",
                    "--binary", f"gotatun-j88i-1={binaries['gotatun-j88i']}",
                    "--source", "gotatun-j88i-1=f322a383faf2135c5b8cb9d4e4994a25479c22a1",
                    "--wg-bin", str(binaries["wg"]),
                    "--wireguard-go-bin", str(binaries["wireguard-go"]),
                    "--tcp-flow", "8",
                    "--out", str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertEqual(
                json.loads((output / "scenario.json").read_text())["tcp_flows"], [8]
            )
            self.assertIn(
                "H2H_MATRIX_CALIBRATION_STATUS=uncalibrated, owner-directed",
                runner_arguments.read_text(),
            )
            self.assertEqual(
                (output / "rows.tsv").read_text().splitlines(),
                [
                    f"kernel-plain-1\tkernel-plain\t\t",
                    f"wireguard-go-1\twireguard-go\t\t",
                    f"gotatun-shipped-1\tgotatun\t{binaries['gotatun-shipped']}\t84b7bb28e385d57dfb80493e78202898fad24d1e",
                    f"gotatun-j88i-1\tgotatun\t{binaries['gotatun-j88i']}\tf322a383faf2135c5b8cb9d4e4994a25479c22a1",
                ],
            )

    def run_matrix_window(self, rows: list[tuple[str, str]], partial: bool) -> subprocess.CompletedProcess[str]:
        """Run `perf-all.sh --matrix` over `rows` ((tag, engine) pairs) with a runner that stops at once."""
        script = Path(__file__).parent / "perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j317c-matrix-part-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            # Fail only the measured scope; the restore pass must succeed so 23 is reported.
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "for arg in \"$@\"; do\n"
                "  [[ $arg == */J88i-pinned-run.sh ]] && exit 23\n"
                "done\n"
                "exit 0\n"
            )
            runner.chmod(0o755)
            tools = {}
            for name in ("gotatun", "wg", "wireguard-go"):
                path = root / name
                path.write_text("#!/usr/bin/env bash\nexit 0\n")
                path.chmod(0o755)
                tools[name] = path
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            arguments = ["bash", str(script), "--matrix", "--scenario", "best-lan-15k",
                         "--label", "half window", "--wg-bin", str(tools["wg"]),
                         "--wireguard-go-bin", str(tools["wireguard-go"]), "--out", str(root / "w")]
            if partial:
                arguments.append("--partial")
            for tag, engine in rows:
                arguments += ["--row", f"{tag}={engine}"]
                if engine == "gotatun":
                    arguments += ["--binary", f"{tag}={tools['gotatun']}",
                                  "--source", f"{tag}=84b7bb28e385d57dfb80493e78202898fad24d1e"]
            return subprocess.run(arguments, capture_output=True, text=True, env=environment, check=False)

    def test_matrix_half_window_needs_partial(self) -> None:
        """Half of a window is refused unless it is marked --partial."""
        half = [("wireguard-go-2", "wireguard-go"), ("shipped-2", "gotatun")]
        self.assertEqual(self.run_matrix_window(half, partial=False).returncode, 2)
        self.assertEqual(self.run_matrix_window(half, partial=True).returncode, 23)

    def test_matrix_partial_still_refuses_a_repeated_control(self) -> None:
        """A partial window keeps one row per control engine at most."""
        rows = [("kernel-plain-1", "kernel-plain"), ("kernel-plain-2", "kernel-plain")]
        result = self.run_matrix_window(rows, partial=True)
        self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
