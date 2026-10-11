#!/usr/bin/env python3
"""Validates bounded release JSON responses without exposing provider diagnostics [224]."""
import json
import sys

class DuplicateField(ValueError):
    """Ambiguous objects must never grant publication permission."""


def unique_fields(pairs):
    """Reject repeated names at every object depth, before schema validation."""
    result = {}
    for name, value in pairs:
        if name in result:
            raise DuplicateField()
        result[name] = value
    return result


try:
    body = sys.stdin.buffer.read(1_048_577)
    if len(body) > 1_048_576:
        raise ValueError()
    response = json.loads(body, object_pairs_hook=unique_fields)
    if not isinstance(response, dict):
        raise ValueError()
    mode = sys.argv[1]
    if mode != "signed" and response.get("success") is not True:
        raise ValueError()
    if mode == "empty-prefix":
        if response.get("result") != [] or response.get("result_info", {}).get("is_truncated", False):
            raise ValueError()
    elif mode == "uploaded":
        if not isinstance(response.get("result"), dict):
            raise ValueError()
    elif mode != "signed":
        raise ValueError()
except DuplicateField:
    print("duplicate JSON fields in the release response", file=sys.stderr)
    sys.exit(1)
except (ValueError, KeyError, AttributeError, IndexError, RecursionError):
    print("release exists or the release response cannot be verified", file=sys.stderr)
    sys.exit(1)
