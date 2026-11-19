#!/usr/bin/env python3
"""Prove a new SQL migration rebuilds the server list with a reused Cargo target (#542)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def ignore_source_copy(directory: str, names: list[str]) -> set[str]:
    """Skip generated and checkout metadata when copying a source tree."""
    ignored = {".git", "target", "node_modules", "dist", ".svelte-kit"}
    return ignored.intersection(names)


def run_migration_metadata_test(source: Path, target: Path) -> None:
    """Build and run the parity test with the target shared by both source paths."""
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "infraternal-server",
        "--lib",
        "original_migration_metadata_and_checksums_are_unchanged",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target)
    print(f"SOURCE={source}", flush=True)
    print(f"CARGO_TARGET_DIR={target}", flush=True)
    print(f"COMMAND={' '.join(command)}", flush=True)
    subprocess.run(command, cwd=source, env=environment, check=True)


def generated_migration_list(target: Path) -> Path:
    """Return the newest generated server migration list under the shared target."""
    generated = list(
        (target / "debug" / "build").glob(
            "infraternal-server-*/out/compact_migrations.rs"
        )
    )
    if not generated:
        raise RuntimeError(f"no generated migration list found under {target}")
    return max(generated, key=lambda path: path.stat().st_mtime_ns)


def main() -> None:
    """Build once, add one migration in a scratch copy, and prove the list changes."""
    source = Path(__file__).resolve().parents[1]
    target_value = os.environ.get("CARGO_TARGET_DIR")
    if not target_value:
        raise RuntimeError("set CARGO_TARGET_DIR to a fresh job-specific target")
    target = Path(target_value).resolve()
    if source == target or source in target.parents:
        raise RuntimeError("the proof target must be outside the source worktree")
    target.parent.mkdir(parents=True, exist_ok=True)

    version = "20991231235959"
    migration_name = f"{version}_target_invalidation_proof.sql"
    generated_description = '"target invalidation proof"'
    print(f"MIGRATION_INVALIDATION_BEGIN version={version}", flush=True)
    run_migration_metadata_test(source, target)
    before = generated_migration_list(target).read_text(encoding="utf-8")
    if generated_description in before:
        raise RuntimeError("proof migration unexpectedly exists in the base source")
    print("BASE_LIST=PASS migration_absent=true", flush=True)

    with tempfile.TemporaryDirectory(
        prefix="migration-invalidation-", dir=target.parent
    ) as scratch_name:
        scratch = Path(scratch_name) / "source"
        shutil.copytree(source, scratch, ignore=ignore_source_copy)
        migration = scratch / "crates/infraternal-server/migrations" / migration_name
        migration.write_text(
            "-- Added only to prove Cargo notices a new migration file.\n"
            "CREATE TABLE target_invalidation_proof (id INTEGER PRIMARY KEY);\n",
            encoding="utf-8",
        )
        print(f"ADDED_MIGRATION={migration}", flush=True)
        run_migration_metadata_test(scratch, target)
        after = generated_migration_list(target).read_text(encoding="utf-8")
        if generated_description not in after:
            raise RuntimeError(
                "the generated migration list did not include the newly added file"
            )

    print(
        f"MIGRATION_INVALIDATION_RESULT=PASS same_target=true version={version}",
        flush=True,
    )


if __name__ == "__main__":
    main()
