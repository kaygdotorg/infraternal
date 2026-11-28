#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Static checks on the Mac window scripts (#260, J674): they cannot run without the Mac VM."""

from __future__ import annotations

import json
import os
import re
import shutil
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


class ExtraEnvTest(unittest.TestCase):
    """PIN_ENV / CAND_ENV reach the root harness shell as data, never as shell syntax."""

    def render(self, entries: str):
        """Run extra-env.sh on `entries`."""
        return subprocess.run(["bash", str(MAC / "extra-env.sh"), entries], capture_output=True, text=True)

    def test_values_are_data_when_sourced(self) -> None:
        """Sourcing the output sets the variables literally and runs nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "pwned"
            run = self.render(f"J614_CREDITS=32 EVIL=$(>{marker});>{marker} Q=a'b\"c`d`")
            self.assertEqual(run.returncode, 0, run.stderr)
            probe = subprocess.run(
                ["bash", "-c", 'set -a; eval "$1"; set +a; printf "%s|%s|%s" "$J614_CREDITS" "$EVIL" "$Q"', "_", run.stdout],
                capture_output=True,
                text=True,
            )
            self.assertFalse(marker.exists(), "an env value executed")
            self.assertEqual(probe.stdout, f"32|$(>{marker});>{marker}|a'b\"c`d`")

    def test_malformed_entries_fail_closed(self) -> None:
        """A token that is not NAME=value, or has a bad name, prints nothing and exits 1."""
        for bad in ("rm -rf x", "A=1 ;ls", "1A=2", "A-B=1"):
            with self.subTest(bad=bad):
                run = self.render(bad)
                self.assertEqual(run.returncode, 1)
                self.assertEqual(run.stdout, "")

    def test_window_does_not_interpolate_env_into_the_root_shell(self) -> None:
        """The root `bash -c` takes paths as arguments and no longer carries `$2` in its command."""
        text = (MAC / "mac-window.sh").read_text()
        self.assertIn("extra-env.sh", text)
        self.assertNotRegex(text, r"bash -c \"[^\n]*\$2 exec")


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

    def fixture(self, tmp: Path, lock_edit: str, *, split: bool = True,
                fork_url: str | None = None) -> tuple[Path, Path]:
        """A copy of the workspace Cargo.toml and Cargo.lock plus a `cargo` shim.

        The shim stands in for `cargo metadata`: it rewrites the lock the way a real
        re-resolution would, with `lock_edit` as the python body deciding what moves.
        """
        src = tmp / "src"
        (src / "crates/plugins/mesh").mkdir(parents=True)
        shutil.copy(self.ROOT / "Cargo.toml", src / "Cargo.toml")
        shutil.copy(self.ROOT / "Cargo.lock", src / "Cargo.lock")
        lock = src / "Cargo.lock"
        parts = lock.read_text().split("\n[[package]]\n")
        main = next(b for b in parts[1:] if b.startswith('name = "gotatun"\n'))
        source = re.search(r'^source = "([^"]+)"', main, re.M).group(1)
        for name in ("gotatun-crypto", "gotatun-packet"):
            matching = [b for b in parts[1:] if b.startswith(f'name = "{name}"\n')]
            if split and not matching:
                parts.append(f'name = "{name}"\nversion = "0.1.0"\nsource = "{source}"\n')
            elif not split:
                parts = [b for b in parts if not b.startswith(f'name = "{name}"\n')]
        lock.write_text("\n[[package]]\n".join(parts))
        if fork_url is not None:
            original = source.removeprefix("git+").split("?", 1)[0]
            for path in (lock, src / "Cargo.toml"):
                path.write_text(path.read_text().replace(original, fork_url))
        shim = tmp / "cargo"
        shim.write_text(
            f"#!{sys.executable}\nimport re\nt = open('Cargo.lock').read()\n{lock_edit}\n"
            "open('Cargo.lock', 'w').write(t)\n"
        )
        shim.chmod(0o755)
        return src, shim

    def swap(self, src: Path, shim: Path, rev: str = "abcdef1234567"):
        """Run swap-gotatun-rev.sh on the fixture."""
        return subprocess.run(
            ["bash", str(MAC / "swap-gotatun-rev.sh"), str(src), rev],
            env={**os.environ, "CARGO": str(shim)},
            capture_output=True,
            text=True,
        )

    GOOD_LOCK = (
        "t = re.sub(r'((?:gotatun|gotatun-fork)\\?rev=)[0-9a-f]+#[0-9a-f]+', r'\\g<1>abcdef1234567#abcdef1234567', t)"
    )

    def test_split_crates_move_together_on_either_mirror(self) -> None:
        """All three fork packages may move, with the pinned repository identity preserved."""
        for url in ("https://github.com/kaygdotorg/gotatun", "https://git.kayg.org/kayg/gotatun-fork"):
            with self.subTest(url=url), tempfile.TemporaryDirectory() as tmp:
                src, shim = self.fixture(Path(tmp), self.GOOD_LOCK, fork_url=url)
                run = self.swap(src, shim)
                self.assertEqual(run.returncode, 0, run.stderr)
                blocks = (src / "Cargo.lock").read_text().split("\n[[package]]\n")
                for name in ("gotatun", "gotatun-crypto", "gotatun-packet"):
                    block = next(b for b in blocks if b.startswith(f'name = "{name}"\n'))
                    self.assertIn(f'{url}?rev=abcdef1234567#abcdef1234567', block)

    def test_legacy_single_crate_swap_still_passes(self) -> None:
        """The guard also accepts a fork revision from before the upstream crate extraction."""
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), self.GOOD_LOCK, split=False)
            (src / "Cargo.toml").rename(src / "crates/plugins/mesh/Cargo.toml")
            run = self.swap(src, shim)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_an_unchanged_lock_is_not_a_successful_swap(self) -> None:
        """A resolver that leaves the old fork revision behind must fail the build preflight."""
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), "t = t")
            self.assertEqual(self.swap(src, shim).returncode, 2)

    def test_a_stale_split_crate_is_refused(self) -> None:
        """Updating only the main crate cannot leave either extracted crate at the old SHA."""
        only_main = self.GOOD_LOCK.removesuffix(", t)") + ", t, count=1)"
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), only_main)
            run = self.swap(src, shim)
            self.assertEqual(run.returncode, 2, run.stderr)

    def test_a_same_named_registry_package_is_not_exempt(self) -> None:
        """Only entries from the pinned fork source may bypass the unrelated-drift check."""
        extra = self.GOOD_LOCK + '\nt += \'\\n[[package]]\\nname = "gotatun-packet"\\nversion = "9.9.9"\\nsource = "registry+https://example.invalid/index"\\n\''
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), extra)
            run = self.swap(src, shim)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertIn("gotatun-packet", run.stderr)

    def test_changing_the_fork_repository_is_refused(self) -> None:
        """A new repository is more than a revision swap even if all crate names match."""
        edit = self.GOOD_LOCK + '\nt = re.sub(r\'git\\+https://[^"?]+(?=\\?rev=)\', "git+https://example.invalid/fork", t)'
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), edit)
            run = self.swap(src, shim)
            self.assertEqual(run.returncode, 2, run.stderr)

    def test_candidate_rev_edit_hits_exactly_the_gotatun_line(self) -> None:
        """The script's own `sed` swaps the rev on the one `gotatun = ` line and nothing else."""
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), self.GOOD_LOCK)
            toml = src / "Cargo.toml"
            before = toml.read_text().splitlines()
            run = self.swap(src, shim)
            self.assertEqual(run.returncode, 0, run.stderr)
            after = toml.read_text().splitlines()
            self.assertEqual(len(before), len(after))
            changed = [(b, a) for b, a in zip(before, after) if b != a]
            self.assertEqual(len(changed), 1)
            self.assertTrue(changed[0][0].startswith("gotatun = "))
            self.assertIn('rev = "abcdef1234567"', changed[0][1])
            self.assertEqual(re.sub(r'rev = "[0-9a-f]+"', "", changed[0][0]), re.sub(r'rev = "[0-9a-f]+"', "", changed[0][1]))

    def test_lock_change_limited_to_gotatun_passes(self) -> None:
        """A re-resolution that only moves the gotatun entry is accepted."""
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), self.GOOD_LOCK)
            run = self.swap(src, shim)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("abcdef1234567", (src / "Cargo.lock").read_text())

    def test_lock_drift_outside_gotatun_fails(self) -> None:
        """A dependency version that moved too (here `serde`) makes the swap fail and names it."""
        drift = self.GOOD_LOCK + (
            "\nt = re.sub(r'(name = \"serde\"\\nversion = \")[0-9.]+', r'\\g<1>0.0.1', t, count=1)"
        )
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), drift)
            run = self.swap(src, shim)
            self.assertEqual(run.returncode, 2)
            self.assertIn("LOCK_DRIFT", run.stderr)
            self.assertIn("serde", run.stderr)

    def test_bad_rev_and_missing_gotatun_line_fail(self) -> None:
        """A non-hex rev, or a Cargo.toml with no matching line, never reaches cargo."""
        with tempfile.TemporaryDirectory() as tmp:
            src, shim = self.fixture(Path(tmp), self.GOOD_LOCK)
            self.assertEqual(self.swap(src, shim, "main; rm -rf /").returncode, 2)
            toml = src / "Cargo.toml"
            toml.write_text(re.sub(r"^gotatun = ", "gotatun_x = ", toml.read_text(), flags=re.M))
            self.assertEqual(self.swap(src, shim).returncode, 2)

    def test_build_script_uses_the_swap_and_stays_locked(self) -> None:
        """build-harness.sh delegates the candidate edit to the verified swap and always builds --locked."""
        text = self.SCRIPT.read_text()
        self.assertIn("swap-gotatun-rev.sh", text)
        self.assertNotRegex(text, r"LOCKED=\s*$")

    def test_harness_test_is_in_the_checkout(self) -> None:
        """The ignored `mac_bench_device` test the windows run is on this branch, not elsewhere."""
        source = (self.ROOT / "crates/plugins/mesh/src/macos_node/tests.rs").read_text()
        self.assertIn("fn mac_bench_device()", source)

    def test_builds_only_from_the_checkout(self) -> None:
        """No git worktree of another commit, and the pin build uses the lock file as committed."""
        text = self.SCRIPT.read_text()
        self.assertNotIn("worktree add", text)
        self.assertIn("LOCKED=--locked", text)


if __name__ == "__main__":
    unittest.main()
