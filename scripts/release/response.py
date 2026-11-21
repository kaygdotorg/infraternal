#!/usr/bin/env python3
"""Validates bounded release responses without exposing provider diagnostics [224, #211].

Modes (the response body arrives on stdin, at most 1 MiB):

* ``signed``: the Worker's JSON reply; objects may not repeat a field at any depth.
* ``uploaded``: the answer to an S3 PutObject. Success is the HTTP status that
  curl already checked; the body is only bounded and discarded.
* ``s3-empty-prefix BUCKET PREFIX``: one ListObjectsV2 page (XML) that must
  prove the prefix holds no object. Exit 0 and print nothing when the listing
  is complete and empty. Exit 0 and print a continuation token when the page is
  empty but truncated (the caller asks for the next page, a bounded number of
  times). Anything else, an object included, exits 1.
"""
import json
import re
import sys
import xml.etree.ElementTree as ET

LIMIT = 1_048_576


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


def read_body():
    """Read at most LIMIT bytes; a longer body is ambiguous, so it is refused."""
    body = sys.stdin.buffer.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ValueError()
    return body


def local_name(tag):
    """Drop the XML namespace: the S3 schema namespace carries no meaning here."""
    return tag.rsplit("}", 1)[-1]


def empty_prefix(body, bucket, prefix):
    """Strictly decode one ListObjectsV2 page; return a continuation token or None.

    The parser refuses DTDs and entities (no expansion tricks), a wrong root, a
    repeated singleton field, an unknown top-level element, any object entry and
    any inconsistency between KeyCount, IsTruncated and the token.
    """
    if b"<!" in body:
        raise ValueError()
    root = ET.fromstring(body)
    if local_name(root.tag) != "ListBucketResult":
        raise ValueError()
    fields = {}
    for child in root:
        name = local_name(child.tag)
        if name in ("Contents", "CommonPrefixes", "Versions"):
            raise ValueError()  # an object (or a folder of objects) exists
        if name not in ("Name", "Prefix", "KeyCount", "MaxKeys", "IsTruncated",
                        "NextContinuationToken", "ContinuationToken", "Delimiter",
                        "EncodingType", "StartAfter") or name in fields or len(child):
            raise ValueError()
        fields[name] = child.text or ""
    if fields.get("Name") != bucket or fields.get("Prefix") != prefix:
        raise ValueError()
    if fields.get("KeyCount") != "0" or fields.get("IsTruncated") not in ("true", "false"):
        raise ValueError()
    if fields["IsTruncated"] == "false":
        if "NextContinuationToken" in fields:
            raise ValueError()
        return None
    token = fields.get("NextContinuationToken", "")
    if not re.fullmatch(r"[A-Za-z0-9_.~+/=-]{1,2048}", token):
        raise ValueError()
    return token


try:
    mode = sys.argv[1]
    body = read_body()
    if mode == "s3-empty-prefix":
        token = empty_prefix(body, sys.argv[2], sys.argv[3])
        if token is not None:
            print(token)
    elif mode == "uploaded":
        pass
    elif mode == "signed":
        response = json.loads(body, object_pairs_hook=unique_fields)
        if not isinstance(response, dict):
            raise ValueError()
    else:
        raise ValueError()
except DuplicateField:
    print("duplicate JSON fields in the release response", file=sys.stderr)
    sys.exit(1)
except (ValueError, KeyError, AttributeError, IndexError, RecursionError, ET.ParseError):
    print("release exists or the release response cannot be verified", file=sys.stderr)
    sys.exit(1)
