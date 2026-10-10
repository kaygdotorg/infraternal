#!/usr/bin/env python3
"""Validates bounded, public R2 API responses without exposing provider diagnostics [224]."""
import json
import sys

try:
    body = sys.stdin.buffer.read(1_048_577)
    if len(body) > 1_048_576:
        raise ValueError()
    response = json.loads(body)
    if not isinstance(response, dict) or response.get("success") is not True:
        raise ValueError()
    if sys.argv[1] == "empty-prefix":
        if response.get("result") != [] or response.get("result_info", {}).get("is_truncated", False):
            raise ValueError()
    elif sys.argv[1] == "uploaded":
        if not isinstance(response.get("result"), dict):
            raise ValueError()
    else:
        raise ValueError()
except (ValueError, KeyError, AttributeError, IndexError):
    print("release exists or the storage response cannot be verified", file=sys.stderr)
    sys.exit(1)
