#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Hold driver: hold.sh logs the real exit status of the hold and of each row (#260, J676)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parent


class HoldDriverTest(unittest.TestCase):
    """`hold.sh` runs perf-all.sh, so these tests give it a fake one that exits with a chosen status."""

    def run_driver(self, root: Path, exit_code: int, rows: dict[str, int]) -> tuple[subprocess.CompletedProcess[str], str]:
        perf_all = root / "perf-all.sh"
        status = "".join(
            f"mkdir -p \"$out/{name}\"; "
            f"printf '{{\"case\":\"{name}\",\"exit\":{code},\"seconds\":1}}\\n' > \"$out/{name}/status.json\"\n"
            for name, code in rows.items()
        )
        perf_all.write_text(
            "#!/usr/bin/env bash\n"
            "while (($#)); do [[ $1 == --out ]] && out=$2; shift; done\n"
            f"{status}"
            f"echo \"PERF_RUN=$PERF_RUN\"\n"
            f"exit {exit_code}\n"
        )
        perf_all.chmod(0o755)
        log = root / "holds.log"
        result = subprocess.run(
            ["bash", str(KIT / "hold.sh"), "--log", str(log), "--cap", "17m", "t1", "--", "--mixed",
             "--out", str(root / "out")],
            capture_output=True, text=True, check=False,
            env=dict(os.environ, H2H_PERF_ALL=str(perf_all), H2H_HOLD_NO_PAUSE="1"),
        )
        return result, log.read_text() if log.exists() else ""

    def test_logs_the_real_exit_status_of_the_hold_and_each_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j676-hold-") as temporary:
            result, log = self.run_driver(Path(temporary), 124, {"mesh-gotatun": 0, "mesh-kernel-plain": 3})
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertRegex(log, r"t1 exit 124\n")
            self.assertIn("t1 row mesh-gotatun exit 0", log)
            self.assertIn("t1 row mesh-kernel-plain exit 3", log)

    def test_success_logs_exit_zero_and_runs_perf_all_through_the_cap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j676-hold-") as temporary:
            result, log = self.run_driver(Path(temporary), 0, {"mesh-gotatun": 0})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(log, r"t1 exit 0\n")
            self.assertIn("perf-run-cap.sh", result.stdout)


if __name__ == "__main__":
    unittest.main()
