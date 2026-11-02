"""Role: keep phase-tagged pixel-damage receipts available to measurement reports."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("measure-app-window.py")


class MeasurementSummaryTests(unittest.TestCase):
    def test_summary_preserves_pixel_damage_bounds_and_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir()
            (run / "frames.tsv").write_text("recv_ns\tcapture_ns\tkey\tbytes\n")
            (run / "events.json").write_text(
                json.dumps(
                    {
                        "window": {"app_name": "TextEdit", "window_id": 4, "owner_pid": 5, "frame": {}},
                        "start": {"size": {"width": 320, "height": 200}},
                        "start_sent_ns": 10,
                        "start_reply_ns": 11,
                        "phases": [{"name": "idle", "begin_ns": 100, "end_ns": 300}],
                        "cpu_snapshots": [
                            {"at_ns": 100, "tree": {}},
                            {"at_ns": 300, "tree": {}},
                        ],
                    }
                )
            )
            helper_stderr = root / "helper.stderr"
            helper_stderr.write_text("METRIC launch_services pid=77 launch_ms=12.5\n")
            companion_stderr = root / "companion.stderr"
            companion_stderr.write_text(
                "METRIC pixel_damage capture_ns=200 kind=caret "
                "bounds=41,72,8,17 pixels=83 complete=true\n"
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "summarize",
                    str(run),
                    str(helper_stderr),
                    "--companion-stderr",
                    str(companion_stderr),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)

        self.assertIn("launch_services pid=77 launch_ms=12.5", summary["lifecycle"])
        self.assertEqual(
            summary["pixel_damage"],
            [
                {
                    "capture_ns": 200,
                    "phase": "idle",
                    "kind": "caret",
                    "bounds": "41,72,8,17",
                    "pixels": 83,
                    "complete": True,
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
