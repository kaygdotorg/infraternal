#!/usr/bin/env python3
"""Replay existing sealed-recovery tests with a literal kernel-label suffix in a private install filename (#188)."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="current infraternal unit-test executable")
    parser.add_argument("--scratch", type=Path, required=True, help="private HOME-cache fixture root")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=options.scratch) as temporary:
        root = Path(temporary)
        cases = (
            ("linked", "restart::tests::path_review::late_recovery_from_path_invocation_keeps_install_target"),
            ("unlinked", "restart::tests::deleted_path_review::relative_recovery_after_atomic_install_keeps_live_install_path"),
        )
        for case, name in cases:
            state = root / case
            state.mkdir(mode=0o700)
            installed = state / "infraternal (deleted)"
            shutil.copy2(options.binary, installed)
            subprocess.run(["strip", "--strip-all", str(installed)], check=True)
            installed.chmod(0o700)
            environment = dict(os.environ)
            if case == "linked":
                environment["REVIEW_RECOVERY_PATH_STATE"] = str(state)
            else:
                environment["REVIEW_REPLACED_INSTALL_PATH"] = str(installed)
            # Exec preserves this child's PID, so the subprocess deadline also
            # bounds sealed recovery. Only the copied fixture can be replaced.
            result = subprocess.run(
                ["./infraternal (deleted)", "--exact", name, "--nocapture"],
                executable=str(installed), cwd=state, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=30,
            )
            print(f"LITERAL_SUFFIX inode={case} exit={result.returncode}", flush=True)
            print(result.stdout, end="", flush=True)
            if result.returncode:
                raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
