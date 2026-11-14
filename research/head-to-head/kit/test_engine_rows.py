#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Pinned rows for every rival engine (#260, J638): Tailscale and NetBird userspace."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import test_perf_all

KIT = Path(__file__).resolve().parent

CAPTURING_RUNNER = (
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


class PerfAllRun(unittest.TestCase):
    """Run perf-all.sh up to the measured perf-run call, which exits 23 and keeps its argv."""

    fake_restore_environment = test_perf_all.PerfAllCliTest.fake_restore_environment

    def perf_all(self, root: Path, arguments: list[str], extra_env: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        runner = root / "perf-run"
        capture = root / "runner-args.txt"
        runner.write_text(CAPTURING_RUNNER)
        runner.chmod(0o755)
        environment = self.fake_restore_environment(root, "0-5")
        environment.update(extra_env or {})
        environment["PERF_RUN"] = str(runner)
        environment["PERF_RUN_CAPTURE"] = str(capture)
        environment["PERF_RUN_COUNT_FILE"] = str(root / "count")
        result = subprocess.run(["bash", str(KIT / "perf-all.sh"), *arguments], capture_output=True,
                                text=True, env=environment, check=False)
        return result, capture.read_text().splitlines() if capture.exists() else []


class EngineRowsTest(PerfAllRun):
    def test_smoke_accepts_tailscale_and_netbird_userspace_rows(self) -> None:
        for engine in ("tailscale", "netbird-userspace"):
            with tempfile.TemporaryDirectory(prefix="j638-row-") as temporary:
                root = Path(temporary)
                result, _ = self.perf_all(root, ["--smoke", "--row", f"r={engine}", "--out", str(root / "out")])
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertIn(f"r\t{engine}", (root / "out/rows.tsv").read_text())

    def test_overlay_runs_each_rival_engine_in_its_own_case(self) -> None:
        overlay = (KIT / "runner-overlays/J88i-pinned-run.sh").read_text()
        self.assertIn("tailscale) case_name=mesh-tailscale", overlay)
        self.assertIn("netbird-userspace) case_name=mesh-netbird-userspace", overlay)

    def test_userspace_rivals_size_their_load_from_the_probe_count(self) -> None:
        """Userspace daemons slow ping under load like the in-app row; the guard must not trip by design."""
        mesh = (KIT / "cases/mesh.sh").read_text()
        self.assertIn("infraternal | tailscale | netbird-userspace)", mesh)


if __name__ == "__main__":
    unittest.main()
