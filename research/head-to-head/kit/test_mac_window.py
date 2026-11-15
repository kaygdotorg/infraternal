#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Static checks on the Mac window scripts (#260, J674): they cannot run without the Mac VM."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
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


class LinuxSideSecretsTest(unittest.TestCase):
    """`lnx-side.sh coord-up` keeps the throwaway NetBird password and PAT out of argv."""

    def test_no_secret_reaches_any_argv(self) -> None:
        """Run the NetBird setup block with logging `python3`/`curl` shims and read their argv log."""
        lines = (MAC / "lnx-side.sh").read_text().splitlines()
        start = next(i for i, l in enumerate(lines) if l.strip() == "umask 077")
        end = next(i for i, l in enumerate(lines) if "> $S/nbs/setupkey" in l)
        block = "\n".join(lines[start : end + 1])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state" / "nbs").mkdir(parents=True)
            shims = root / "shims"
            shims.mkdir()
            argv_log = root / "argv.log"
            # curl shim: records argv, reads a `-H @file` header file, answers by URL.
            (shims / "curl").write_text(
                "#!/bin/bash\n"
                f'echo "curl $*" >> {argv_log}\n'
                'case "$*" in *api/setup-keys*) echo \'{"key":"SETUPKEY"}\' ;;'
                " *) echo '{\"personal_access_token\":\"PATSECRET123\"}' ;; esac\n"
            )
            (shims / "python3").write_text(
                f'#!/bin/bash\necho "python3 $*" >> {argv_log}\nexec {sys.executable} "$@"\n'
            )
            for shim in shims.iterdir():
                shim.chmod(0o755)
            script = root / "block.sh"
            script.write_text(f"set -u\nS={root}/state\nIP=127.0.0.1\n{block}\n")
            env = {"PATH": f"{shims}:{os.environ['PATH']}"}
            run = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            argv = argv_log.read_text()
            nbs = root / "state" / "nbs"
            password = json.loads((nbs / "setup.json").read_text())["password"]
            self.assertTrue(password.startswith("J461-"))
            self.assertNotIn(password, argv)
            self.assertNotIn("PATSECRET123", argv)
            self.assertIn("-H @", argv)
            self.assertEqual((nbs / "auth.hdr").read_text(), "Authorization: Token PATSECRET123\n")
            self.assertEqual((nbs / "setupkey").read_text().strip(), "SETUPKEY")
            for name in ("setup.json", "pat", "auth.hdr", "setupkey"):
                self.assertEqual((nbs / name).stat().st_mode & 0o777, 0o600, name)


class PinCheckTest(unittest.TestCase):
    """`check-pins.sh` refuses a Mac window whose clients are not the pinned versions."""

    PINS = Path(__file__).resolve().parents[1] / "pins.txt"

    def run_check(self, tailscale: str, netbird: str, *engines: str, pins: Path | None = None):
        """Run check-pins.sh against fake client binaries that print the given first lines."""
        with tempfile.TemporaryDirectory() as tmp:
            bindir = Path(tmp)
            for name, out in (("tailscale", tailscale), ("netbird", netbird)):
                if out:
                    (bindir / name).write_text(f"#!/bin/sh\necho '{out}'\n")
                    (bindir / name).chmod(0o755)
            return subprocess.run(
                ["bash", str(MAC / "check-pins.sh"), str(pins or self.PINS), str(bindir), *engines],
                capture_output=True,
                text=True,
            )

    def test_pins_file_has_both_darwin_entries(self) -> None:
        """Tailscale and NetBird each have a darwin-arm64 source pin with a sha256."""
        text = self.PINS.read_text()
        for name in ("tailscale-src", "netbird-src"):
            self.assertRegex(text, rf"(?m)^{name}\s+darwin-arm64\s+https://\S+/v[0-9.]+\.tar\.gz\s+[0-9a-f]{{64}}$")

    def test_matching_versions_pass(self) -> None:
        """Pinned versions (with a build suffix on Tailscale) pass."""
        run = self.run_check("1.104.4-ERR-BuildInfo", "0.82.0", "tailscale", "netbird", "pin", "cand")
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn("PIN_OK tailscale 1.104.4", run.stdout)

    def test_mismatch_is_refused(self) -> None:
        """A newer Tailscale, a longer number and a missing binary are all refused."""
        for ts, nb, engine in (("1.104.5-ERR-BuildInfo", "0.82.0", "tailscale"), ("1.104.40", "0.82.0", "tailscale"),
                               ("1.104.4", "0.82.1", "netbird"), ("1.104.4", "", "netbird")):
            with self.subTest(ts=ts, nb=nb):
                run = self.run_check(ts, nb, engine)
                self.assertEqual(run.returncode, 1)
                self.assertIn("PIN_MISMATCH " + engine, run.stdout)

    def test_missing_pin_is_refused(self) -> None:
        """An engine with no darwin pin in the file is refused, not waved through."""
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "pins.txt"
            empty.write_text("zellij any https://x/v1.tar.gz 00\n")
            run = self.run_check("1.104.4", "0.82.0", "tailscale", pins=empty)
        self.assertEqual(run.returncode, 1)
        self.assertIn("no darwin-arm64 pin", run.stdout)

    def test_window_runs_the_check_before_any_side_effect(self) -> None:
        """mac-window.sh exits 4 on a mismatch, before it asks for PEER or touches the Linux side."""
        with tempfile.TemporaryDirectory() as tmp:
            kit = Path(tmp) / "kit"
            (kit / "bin").mkdir(parents=True)
            for name in ("tailscale", "netbird"):
                (kit / "bin" / name).write_text("#!/bin/sh\necho 9.9.9\n")
                (kit / "bin" / name).chmod(0o755)
            env = {**os.environ, "KIT_HOME": str(kit), "ME": "127.0.0.1", "PEER": "127.0.0.1", "PSSH": "x"}
            run = subprocess.run(["bash", str(MAC / "mac-window.sh"), "w1", "tailscale"], env=env,
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 4, run.stderr)
            self.assertIn("REFUSED", run.stderr)
            self.assertIn("PIN_MISMATCH tailscale", (kit / "ev" / "w1" / "window.log").read_text())


class BuildHarnessTest(unittest.TestCase):
    """`build-harness.sh` builds pin and candidate from the checkout, never from hand-built files."""

    ROOT = Path(__file__).resolve().parents[3]
    SCRIPT = MAC / "build-harness.sh"

    def test_candidate_rev_edit_hits_exactly_the_gotatun_line(self) -> None:
        """The script's `sed` swaps the rev on the one `gotatun = ` line and nothing else."""
        toml = (self.ROOT / "crates/plugins/mesh/Cargo.toml").read_text()
        match = re.search(r"^gotatun = .*$", toml, re.M)
        self.assertIsNotNone(match, "mesh Cargo.toml has no gotatun dependency line")
        self.assertEqual(len(re.findall(r'^gotatun = .*\brev = "[0-9a-f]+"', toml, re.M)), 1)
        sed = re.search(r"sed -E -i '' \"(/\^gotatun = /s/[^\"]*)\"", self.SCRIPT.read_text())
        self.assertIsNotNone(sed, "the rev edit moved: update this test")
        sample = re.sub(r'rev = "[0-9a-f]+"', 'rev = "abcdef1"', match.group(0))
        self.assertIn('rev = "abcdef1"', sample)

    def test_harness_test_is_in_the_checkout(self) -> None:
        """The ignored `mac_bench_device` test the windows run is on this branch, not elsewhere."""
        source = (self.ROOT / "crates/plugins/mesh/src/macos_node.rs").read_text()
        self.assertIn("fn mac_bench_device()", source)

    def test_builds_only_from_the_checkout(self) -> None:
        """No git worktree of another commit, and the pin build uses the lock file as committed."""
        text = self.SCRIPT.read_text()
        self.assertNotIn("worktree add", text)
        self.assertIn("LOCKED=--locked", text)


if __name__ == "__main__":
    unittest.main()
