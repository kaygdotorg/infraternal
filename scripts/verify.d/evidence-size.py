"""Reject newly added or grown repository receipts and oversized source files."""

from pathlib import PurePosixPath
import os
import subprocess
import sys


REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAX_FILE_BYTES = 200_000
EVIDENCE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".mp4", ".gz", ".log", ".trace"}
VERIFICATION_RECEIPT_SUFFIXES = {".json", ".jsonl", ".txt"}
GENERATED_DIRECTORIES = {"target", "node_modules", ".svelte-kit", "build", "dist", ".wrangler"}


def git_bytes(*arguments: str) -> bytes:
    """Run a small, repository-local Git query without decoding file paths early."""
    return subprocess.check_output(["git", *arguments], cwd=REPOSITORY_ROOT)


def baseline_sizes(base: str) -> dict[str, int]:
    """Read the base tree once so changed files can be checked by byte growth."""
    result: dict[str, int] = {}
    for record in git_bytes("ls-tree", "-r", "-l", "-z", base).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        size = metadata.split()[-1]
        result[os.fsdecode(raw_path)] = int(size)
    return result


def changed_paths(base: str) -> set[str]:
    """Find tracked changes plus ordinary untracked files relative to the base."""
    tracked_changes = git_bytes("diff", "--name-only", "--diff-filter=ACMRT", "-z", base, "--")
    paths = {os.fsdecode(path) for path in tracked_changes.split(b"\0") if path}
    untracked = git_bytes("ls-files", "--others", "--exclude-standard", "-z")
    paths.update(os.fsdecode(path) for path in untracked.split(b"\0") if path)

    # Evidence and captures directories are intentionally ignored. Inspect only
    # those ignored trees so the ignore rule cannot hide a new receipt from this gate.
    ignored_artifacts = git_bytes(
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "-z",
        "--",
        ":(glob)**/evidence/**",
        ":(glob)**/captures/**",
    )
    for path in map(os.fsdecode, ignored_artifacts.split(b"\0")):
        if path and not (set(PurePosixPath(path).parts) & GENERATED_DIRECTORIES):
            paths.add(path)
    return paths


def is_allowlisted(path: str) -> bool:
    """Keep intentional source assets and decisions out of artifact sizing."""
    # The append-only owner ledger already predates this generic receipt cap.
    if path == "DECISIONS.md":
        return True
    parts = set(PurePosixPath(path).parts)
    suffix = PurePosixPath(path).suffix.lower()
    allowed_directories = {
        "fonts", "vendor", "vendored", "third_party", "third-party",
        "fixtures", "__fixtures__", "testdata",
    }
    font_suffixes = {".woff", ".woff2", ".ttf", ".otf", ".ttc", ".eot", ".sfnt"}
    return bool(parts & allowed_directories) or suffix in font_suffixes


def is_forbidden_receipt(path: str) -> bool:
    """Identify generated artifact locations and verification receipt formats."""
    parts = PurePosixPath(path).parts
    suffix = PurePosixPath(path).suffix.lower()
    if {"evidence", "captures"} & set(parts):
        return True
    if len(parts) >= 2 and parts[:2] == ("docs", "verification"):
        if suffix in EVIDENCE_SUFFIXES | VERIFICATION_RECEIPT_SUFFIXES:
            return True
        if path.endswith("-observed.nft"):
            return True
    return suffix in EVIDENCE_SUFFIXES


def main() -> int:
    try:
        base = git_bytes("merge-base", "HEAD", "origin/dev").decode().strip()
        sizes_at_base = baseline_sizes(base)
        paths = changed_paths(base)
    except (subprocess.CalledProcessError, IndexError, ValueError) as error:
        print(f"repository artifact gate: could not inspect merge base with origin/dev: {error}", file=sys.stderr)
        return 1

    offenders: list[tuple[str, int]] = []
    for relative_path in sorted(paths):
        absolute_path = os.path.join(REPOSITORY_ROOT, relative_path)
        try:
            size = os.path.getsize(absolute_path)
        except OSError:
            continue
        if is_allowlisted(relative_path):
            continue
        previous_size = sizes_at_base.get(relative_path)
        if previous_size is not None and size <= previous_size:
            continue
        if size > MAX_FILE_BYTES or is_forbidden_receipt(relative_path):
            offenders.append((relative_path, size))

    if offenders:
        for path, size in offenders:
            print(f"repository artifact gate: {path} {size} bytes", file=sys.stderr)
        print(
            f"repository artifact gate: FAIL ({len(offenders)} file(s)); "
            f"limit is {MAX_FILE_BYTES} bytes",
            file=sys.stderr,
        )
        return 1

    print(f"repository artifact gate: PASS ({len(paths)} changed path(s), merge base {base[:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
