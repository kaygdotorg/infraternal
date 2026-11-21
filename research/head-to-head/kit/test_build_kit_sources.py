"""Check that the head-to-head build script only uses available repository sources."""

from pathlib import Path
import re
import unittest


# Resolve sources from the repository root so the test works from any directory.
REPO_ROOT = Path(__file__).resolve().parents[3]
# Match paths in build-kit that are rooted at its repository and kit directories.
SOURCE_REFERENCE = re.compile(r"\$(here|repo)/([A-Za-z0-9_./*?+-]+)")


class BuildKitSourcesTest(unittest.TestCase):
    """Keep every build-kit source path present in the checkout."""

    def test_build_kit_source_references_exist(self):
        """Fail when build-kit calls or copies a missing source script or file."""
        build_kit = REPO_ROOT / "research/head-to-head/build-kit"
        missing = []

        for line_number, line in enumerate(
            build_kit.read_text().splitlines(), start=1
        ):
            unquoted = line.replace('"', "").replace("'", "")
            for anchor, relative in SOURCE_REFERENCE.findall(unquoted):
                base = (
                    REPO_ROOT / "research/head-to-head"
                    if anchor == "here"
                    else REPO_ROOT
                )
                source = base / relative
                matches = (
                    list(source.parent.glob(source.name))
                    if "*" in relative or "?" in relative
                    else [source]
                )
                if not matches or any(not match.exists() for match in matches):
                    missing.append(f"build-kit:{line_number}: ${anchor}/{relative}")
                elif source.suffix == ".sh" and any(not match.is_file() for match in matches):
                    missing.append(f"build-kit:{line_number}: ${anchor}/{relative}")

        self.assertFalse(missing, "missing build-kit source references:\n" + "\n".join(missing))
