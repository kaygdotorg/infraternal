#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Copy one file out of an official Docker Hub image, without a container engine.

NetBird publishes its management/signal/relay server only as container images,
so the head-to-head kit takes the `netbird-server` binary from the official
image. The platform manifest is fetched by digest (content-addressed), every
layer blob is checked against its digest, and the extracted file must match
the pinned SHA-256 (pins.txt).

    pull-image-file.py <repo> <platform-manifest-digest> <path-in-image> <out> <sha256>
"""
import hashlib
import io
import json
import sys
import tarfile
import urllib.request

repo, digest, member, out, expected = sys.argv[1:6]
token = json.load(urllib.request.urlopen(
    f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"))["token"]


def get(path, accept=None):
    headers = {"Authorization": "Bearer " + token}
    if accept:
        headers["Accept"] = accept
    return urllib.request.urlopen(urllib.request.Request(f"https://registry-1.docker.io/v2/{repo}/{path}", headers=headers))


raw = get(f"manifests/{digest}", "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json").read()
if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
    sys.exit("manifest digest mismatch")
manifest = json.loads(raw)
for layer in reversed(manifest["layers"]):
    blob = get(f"blobs/{layer['digest']}").read()
    if "sha256:" + hashlib.sha256(blob).hexdigest() != layer["digest"]:
        sys.exit("layer digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
        if member in archive.getnames():
            data = archive.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != expected:
                sys.exit("file SHA-256 mismatch")
            with open(out, "wb") as handle:
                handle.write(data)
            break
else:
    sys.exit(f"{member} not in image")
