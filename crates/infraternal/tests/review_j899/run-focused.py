#!/usr/bin/env python3
"""Run the D395 round-two regressions and remove selected recovery guards.

Run from the repository root, inside the job's build slot and dev shell.
The driver restores its two modified source files on exit.
"""

from pathlib import Path
import subprocess
import sys

src = Path("crates/infraternal/src")
move = src / "install_move.rs"
disk = src / "install_move_fs.rs"
tests = src / "install_move_tests.rs"
additional = Path(__file__).with_name("relocation.rs")
mutations = [
    (
        "pre-switch keeps old authority",
        move,
        "if !switched && !journal.legacy_target {",
        "if journal.target.is_none() && !switched && !journal.legacy_target {",
        "pre_switch_retry_snapshots_data_written_after_old_unit_booted",
    ),
    (
        "post-switch keeps new authority",
        move,
        "if !switched && !journal.legacy_target {",
        "if !journal.legacy_target {",
        "retries_after_switch_keep_writes_to_the_new_database",
    ),
    (
        "healthy database required before cleanup",
        move,
        ".and_then(|()| service.ready(&target))",
        "",
        "retries_after_switch_keep_writes_to_the_new_database",
    ),
    (
        "backup inode bound to journal",
        disk,
        "if Identity::of(&folder)? != identity {",
        "if Identity::of(&folder)? != identity && name.is_empty() {",
        "refuses_a_replaced_backup_without_deleting_either_tree",
    ),
    (
        "shared base refused",
        move,
        "if disk::names(folder)?.iter().any(|name| is_shared(name)) {",
        "if false {",
        "legacy_shared_base_is_refused",
    ),
    (
        "changed listen address refused",
        move,
        "if command.is_none() || command != requested {",
        "if command.is_none() || requested.is_none() {",
        "move_refuses_a_different_listen_address",
    ),
]


def test(name, exact=True):
    """Run one focused target and save its exit code and test output."""
    args = [
        "cargo", "test", "--locked", "-j3", "-p", "infraternal", "--bin",
        "infraternal", "install_move::tests::" + name,
    ]
    if exact:
        args += ["--", "--exact"]
    result = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False,
    )
    print(result.stdout, end="", flush=True)
    return result


def main():
    """Check fixtures before and after each temporary mutation."""
    plain_tests = tests.read_bytes()
    regression = "\n".join(additional.read_text().splitlines()[3:])
    try:
        tests.write_bytes(plain_tests + ("\n" + regression + "\n").encode())
        result = test("review_j899_", exact=False)
        failed = result.stdout.count(" ... FAILED")
        print(f"REGRESSION_EXIT={result.returncode} FAILED={failed}", flush=True)
        if result.returncode != 0 and (result.returncode != 101 or failed != 3):
            raise RuntimeError("regressions returned an unexpected result")
        for label, path, original, changed, name in mutations:
            print(f"MUTATION {label}", flush=True)
            passing = test(name)
            if passing.returncode or "1 passed; 0 failed" not in passing.stdout:
                raise RuntimeError(f"{label}: baseline test failed")
            plain = path.read_text()
            if plain.count(original) != 1:
                raise RuntimeError(f"{label}: mutation anchor changed")
            try:
                path.write_text(plain.replace(original, changed, 1))
                caught = test(name)
                if caught.returncode != 101 or "0 passed; 1 failed" not in caught.stdout:
                    raise RuntimeError(f"{label}: expected a test assertion failure")
            finally:
                path.write_text(plain)
        print("MUTATION_EXIT=0", flush=True)
    finally:
        tests.write_bytes(plain_tests)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        sys.exit(str(error))
