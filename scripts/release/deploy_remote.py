#!/usr/bin/env python3
"""Apply a prebuilt release with online backup and verified warm rollback [217,244,250]."""
import fcntl
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import time
import urllib.error
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep the administrator session on the requested local endpoint only."""
    def redirect_request(self, request, file, code, message, headers, url):
        return None


def local_http(request):
    # Ambient proxy settings must never carry a local administrator cookie.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        return opener.open(request, timeout=2)
    except urllib.error.HTTPError as error:
        error.close()
        raise


def verify_signed(directory, trust, image, complete=False):
    manifest_path = directory / "MANIFEST"
    signature = directory / "MANIFEST.sig"
    if (manifest_path.stat().st_size > 65536 or signature.stat().st_size > 1024
            or (directory / "VERSION").stat().st_size > 128):
        raise ValueError("release metadata exceeds bound")
    manifest = manifest_path.read_bytes()
    subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(trust),
                    "-I", "release@infraternal.com", "-n", "infraternal-release",
                    "-s", str(signature)], input=manifest, capture_output=True, check=True)
    lines = manifest.decode().splitlines()
    version = (directory / "VERSION").read_text()
    channel = "edge" if re.fullmatch(r"edge-[0-9]{8}T[0-9]{6}Z\n", version) else "stable"
    if channel == "stable" and not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\n", version):
        raise ValueError("invalid signed version")
    if lines[:3] != ["infraternal-release-manifest-v1", "version " + version.strip(), "channel " + channel]:
        raise ValueError("signed release identity mismatch")
    entries = {}
    for line in lines[3:]:
        value, name = line.split("  ", 1)
        if (name in entries or name not in {"VERSION", "infraternal", "infraternal-x86_64-musl", "infraternal-aarch64-musl"}
                or not re.fullmatch(r"[0-9a-f]{64}", value)):
            raise ValueError("invalid signed artifact list")
        entries[name] = value
    required = {"VERSION", "infraternal-x86_64-musl"}
    if complete:
        required.add("infraternal-aarch64-musl")
    if not required <= entries.keys():
        raise ValueError("incomplete signed bundle")
    # The executable alias and the distributed x86 payload are separate files.
    # Authenticate both on admission; retained rollback needs only its executable.
    with image.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != entries["infraternal-x86_64-musl"]:
            raise ValueError("signed server image mismatch")
    for name in required:
        if name == "infraternal-x86_64-musl" and not complete:
            continue  # The retained executable was already authenticated above.
        artifact = directory / name
        with artifact.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != entries[name]:
                raise ValueError("signed artifact mismatch")
    if "infraternal" in entries and entries["infraternal"] != entries["infraternal-x86_64-musl"]:
        raise ValueError("server and x86 payload identity mismatch")


def checksums(directory):
    if directory.is_symlink() or any(p.is_symlink() for p in directory.rglob("*")):
        raise ValueError("release refuses symlinks")
    seen = set()
    if (directory / "SHA256SUMS").stat().st_size > 4 * 1024 * 1024:
        raise ValueError("release checksum list exceeds bound")
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        value, name = line.split("  ", 1)
        path = directory / name
        if (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                or name in seen or str(Path(name)) != name or Path(name).is_absolute() or ".." in Path(name).parts
                or any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file()):
            raise ValueError("invalid release checksums")
        seen.add(name)
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != value:
                raise ValueError("release checksum mismatch")
    expected = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file()
                and str(p.relative_to(directory)) not in {"SHA256SUMS", "MANIFEST", "MANIFEST.sig"}}
    if seen != expected:
        raise ValueError("release checksums must cover every artifact")


def unlocked(config):
    request = urllib.request.Request(config["health"] + "/remote/ca/status", data=b"", headers={
        "Origin": config["origin"], "Cookie": "__Host-infraternal=" + config["session"],
        "User-Agent": "infraternal-deploy"})
    with local_http(request) as response:
        status = json.loads(response.read(4096))
    return status.get("locked") is False and status.get("initialized") is True


def healthy(config):
    try:
        with local_http(config["health"] + "/healthz") as response:
            return response.status == 200 and unlocked(config)
    except (OSError, ValueError):
        return False


def same_image(pid, binary):
    with Path(f"/proc/{pid}/exe").open("rb") as running, binary.open("rb") as installed:
        return hashlib.file_digest(running, "sha256").digest() == hashlib.file_digest(installed, "sha256").digest()


def restart(data, binary):
    payload = os.fsencode(binary)
    if len(payload) > 4096:
        raise ValueError("replacement path exceeds control bound")
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(5)
        peer.connect(str(data / "restart/control.sock"))
        peer.sendall(struct.pack("!H", len(payload)) + payload)
        reply = bytearray()
        while b"\n" not in reply and len(reply) < 128:
            part = peer.recv(128 - len(reply))
            if not part:
                break
            reply.extend(part)
    if reply != b"RESTARTING\n":
        raise ValueError("warm verified replacement refused")


def wait_for_success(config, old_endpoint, binary):
    with binary.open("rb") as stream:
        expected = hashlib.file_digest(stream, "sha256").hexdigest()
    last_image = None
    actual = None
    until = time.monotonic() + 30
    while time.monotonic() < until:
        try:
            current = (Path(config["data"]) / "restart/control.sock").stat()
            changed = (current.st_ino, current.st_ctime_ns) != old_endpoint
            # Exec keeps the PID. Health alone could observe the old server or late recovery.
            running = Path(f"/proc/{config['pid']}/exe")
            if changed and healthy(config):
                info = running.stat()
                image = (info.st_dev, info.st_ino)
                if image != last_image:
                    with running.open("rb") as stream:
                        actual = hashlib.file_digest(stream, "sha256").hexdigest()
                    last_image = image
                if actual == expected:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise ValueError("replacement did not become healthy with unlocked CA")


def endpoint(data):
    info = (data / "restart/control.sock").stat()
    return info.st_ino, info.st_ctime_ns


def swap_link(path, target):
    temporary = path.with_name(path.name + ".deploy-new")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    os.replace(temporary, path)


def backup(data, destination):
    destination.mkdir(mode=0o700)
    # The SQLite backup API includes committed WAL pages while serving continues.
    # Other persisted state is retained unchanged by binary handoff; save encrypted
    # state/public metadata too, excluding live sockets and mutable database sidecars.
    database = data / "infraternal.sqlite"
    with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as source:
        with closing(sqlite3.connect(destination / "infraternal.sqlite")) as target:
            source.backup(target)
    for path in data.iterdir():
        if path.name.startswith("infraternal.sqlite") or path.name == "restart":
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.copytree(path, destination / path.name,
                            ignore=lambda root, names: [n for n in names if
                                Path(root, n).is_symlink() or not
                                (Path(root, n).is_file() or Path(root, n).is_dir())])
        elif path.is_file() and not path.is_symlink():
            shutil.copy2(path, destination / path.name)


def apply(config):
    if os.geteuid() != 0:
        raise ValueError("CA-preserving deployment requires the root service account")
    root = Path(config["root"])
    release = root / "releases" / config["sha"]
    data = Path(config["data"])
    binary = release / "infraternal"
    installed_binary = Path(config["binary"])
    previous = installed_binary.resolve(strict=True)
    web = Path(config["web"])
    previous_web = web.with_name(web.name + ".prev")
    with (root / ".deploy.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        checksums(release)
        verify_signed(release, root / "allowed_signers", binary, complete=True)
        if not config["web_only"]:
            verify_signed(previous.parent, root / "allowed_signers", previous)
        if not healthy(config):
            raise ValueError("preflight requires healthy server and unlocked CA")
        if not config["web_only"] and not same_image(config["pid"], previous):
            raise ValueError("installed and running binary mismatch")
        # Persist the original executable as a recovery artifact. Warm rollback
        # uses its existing signed release metadata, never an unsigned copy.
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        # Rapid retry/redeploy of the same release must retain both snapshots.
        saved = root / "backups" / (stamp + "-" + uuid.uuid4().hex + "-" + config["sha"])
        saved.parent.mkdir(mode=0o700, exist_ok=True)
        backup(data, saved)
        previous_directory = saved / "previous"
        previous_directory.mkdir(mode=0o700)
        shutil.copy2(previous, previous_directory / "infraternal")
        for name in ("MANIFEST", "MANIFEST.sig", "VERSION"):
            source = previous.parent / name
            if source.is_file():
                shutil.copy2(source, previous_directory / name)
        previous = previous_directory / "infraternal"
        old_payloads = {}
        for name in ("infraternal-x86_64-musl", "infraternal-aarch64-musl"):
            source = installed_binary.parent / name
            if source.is_file():
                shutil.copy2(source, previous_directory / name)
                old_payloads[name] = previous_directory / name
        old = endpoint(data)
        if not config["web_only"] and not all((previous.parent / name).is_file()
                for name in ("MANIFEST", "MANIFEST.sig", "VERSION")):
            raise ValueError("previous release requires signed metadata for warm rollback")
        new_web = web.with_name(web.name + ".new")
        if new_web.exists():
            shutil.rmtree(new_web)
        shutil.copytree(release / "web", new_web)
        replaced_web = False
        requested = False
        changed_aliases = []
        try:
            if not config["web_only"]:
                # Refusal keeps the old process alive. Late exec refusal is recovered
                # by round4; the identity check above distinguishes that from success.
                requested = True
                restart(data, binary)
                wait_for_success(config, old, binary)
            if previous_web.exists():
                shutil.rmtree(previous_web)
            if web.exists():
                web.rename(previous_web)
            try:
                new_web.rename(web)
            except BaseException:
                if previous_web.exists():
                    previous_web.rename(web)
                raise
            replaced_web = True
            if not healthy(config):
                raise ValueError("web health or CA check failed")
            if not config["web_only"]:
                for name in ("infraternal", "infraternal-x86_64-musl", "infraternal-aarch64-musl"):
                    alias = installed_binary.parent / name
                    swap_link(alias, release / name)
                    changed_aliases.append(alias)
            return {"state": "deployed", "sha": config["sha"], "backup": str(saved), "ca_unlocked": True}
        except BaseException:
            restoration_failed = False
            for alias in reversed(changed_aliases):
                try:
                    if alias.name == "infraternal":
                        swap_link(alias, previous)
                    elif alias.name in old_payloads:
                        swap_link(alias, old_payloads[alias.name])
                    else:
                        alias.unlink()
                except (OSError, ValueError):
                    restoration_failed = True
            if replaced_web:
                try:
                    shutil.rmtree(web)
                    previous_web.rename(web)
                except (OSError, ValueError):
                    restoration_failed = True
            # Allocation failures restoring aliases/web must not skip process
            # recovery: its signed image already exists in the retained backup.
            if requested:
                before_rollback = endpoint(data)
                restart(data, previous)
                wait_for_success(config, before_rollback, previous)
            # Never overwrite a running SQLite database. Restoring a database is
            # a separate cold recovery operation; automatic rollback keeps its data.
            if restoration_failed or not healthy(config):
                raise ValueError("rollback requires operator recovery") from None
            raise ValueError("deployment refused; previous release healthy and CA unlocked") from None


if __name__ == "__main__":
    os.umask(0o077)
    try:
        import sys
        config = json.loads(sys.stdin.buffer.read(16385))
        result = apply(config)
        print(json.dumps(result))
    except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.CalledProcessError):
        # No session, URL response, exception detail or journal output reaches logs.
        print('{"state":"failed","next":"Check deployment state and retained backup"}')
        raise SystemExit(1) from None
