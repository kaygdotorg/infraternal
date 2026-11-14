#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Static checks on the Mac window scripts (#260, J674): they cannot run without the Mac VM."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

MAC = Path(__file__).parent / "mac"
LAN_COMMAND = re.compile(r"\$BIN/j421net (probe|sink|source|echo)\b|(?<![\w$])ping -c")


class WindowScriptTest(unittest.TestCase):
    """The scripts parse, and keep the privileges macOS Local Network privacy needs."""

    def test_scripts_parse(self) -> None:
        """Every shell script passes `bash -n`."""
        for script in MAC.glob("*.sh"):
            with self.subTest(script=script.name):
                self.assertEqual(subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode, 0)

    def test_lan_traffic_runs_under_sudo(self) -> None:
        """Every ping, probe, sink, source and echo started by the window script uses sudo.

        macOS refuses LAN traffic from a non-root, ssh-launched process, so a missing sudo
        fails a whole window instead of one command.
        """
        for number, line in enumerate((MAC / "mac-window.sh").read_text().splitlines(), 1):
            code = line.split("#", 1)[0] if line.lstrip().startswith("#") else line
            if LAN_COMMAND.search(code) and not line.lstrip().startswith("#"):
                with self.subTest(line=number):
                    self.assertRegex(code, r"sudo [^|;&]*(\$BIN/j421net|ping)", line)

    def test_engines_are_the_four_the_matrix_names(self) -> None:
        """The window runs pin, cand, tailscale and netbird, and both directions at 1 and 8 flows."""
        text = (MAC / "mac-window.sh").read_text()
        for engine in ("start_pin()", "start_cand()", "start_tailscale()", "start_netbird()"):
            self.assertIn(engine, text)
        self.assertIn('DIRS=${DIRS:-mac-tx mac-rx}', text)
        self.assertIn("for flows in 1 8", text)

    def test_secrets_stay_out_of_argv(self) -> None:
        """Keys go through root-only files: the harness gets an env file, not key arguments."""
        text = (MAC / "mac-window.sh").read_text()
        self.assertIn("chmod 600 $d/env", text)
        self.assertNotIn("--private-key", text)


if __name__ == "__main__":
    unittest.main()
