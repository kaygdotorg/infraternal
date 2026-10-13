"""Resolve verification evidence output to a job-owned directory outside the checkout."""

import os
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def evidence_directory(job: str) -> Path:
    """Return an external issue-evidence directory, honoring an explicit job override."""
    configured = os.environ.get("INFRATERNAL_EVIDENCE_DIR")
    directory = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".cache" / "codex-scratch" / job / "evidence"
    ).resolve()
    if directory == REPOSITORY_ROOT or REPOSITORY_ROOT in directory.parents:
        raise ValueError("evidence output must stay outside the repository checkout")
    return directory
