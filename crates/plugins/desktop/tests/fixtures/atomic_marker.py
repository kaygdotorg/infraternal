# SPDX-License-Identifier: AGPL-3.0-only
"""Shared atomic marker publisher embedded in desktop test fixtures."""

import os
import tempfile


def publish_marker(path, body):
    """Publish complete marker bytes through a flushed same-directory rename."""
    parent = os.path.dirname(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".marker-", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as marker:
            marker.write(body)
            marker.flush()
            os.fsync(marker.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
