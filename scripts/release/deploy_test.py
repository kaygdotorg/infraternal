#!/usr/bin/env python3
"""Exercise deployment refusal/rollback, real WAL backup and private control framing [250], #188."""
import hashlib
import fcntl
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.machinery
import importlib.util
import json
import io
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import tarfile
import threading
import unittest
from unittest.mock import patch

import deploy_remote as remote
import dev_builder as builder

loader = importlib.machinery.SourceFileLoader("deploy", str(Path(__file__).with_name("deploy")))
spec = importlib.util.spec_from_loader(loader.name, loader)
deploy = importlib.util.module_from_spec(spec)
loader.exec_module(deploy)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get("INFRATERNAL_RELEASE_TEST_SCRATCH",
                       str(Path.home() / ".cache/codex-scratch/deploy-pipeline/tests")))
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def bundle(self):
        directory = self.root / "release"
        directory.mkdir()
        (directory / "VERSION").write_text("edge-20261012T000000Z\n")
        (directory / "web").mkdir()
        (directory / "web/index.html").write_text("new web")
        self.sums(directory)
        return directory

    def sums(self, directory):
        (directory / "BUILDSUMS").write_text("".join(
            hashlib.sha256(file.read_bytes()).hexdigest() + "  " + str(file.relative_to(directory)) + "\n"
            for file in sorted(directory.rglob("*")) if file.is_file() and file.name != "BUILDSUMS"))

    def test_checksums_reject_unlisted_changed_traversal_and_symlink_files(self):
        directory = self.bundle()
        remote.checksums(directory)
        (directory / "extra").write_text("unlisted")
        with self.assertRaises(ValueError):
            remote.checksums(directory)
        (directory / "extra").unlink()
        (directory / "web/index.html").write_text("tampered")
        with self.assertRaises(ValueError):
            remote.checksums(directory)
        (directory / "BUILDSUMS").write_text("0" * 64 + "  ../outside\n")
        with self.assertRaises(ValueError):
            remote.checksums(directory)
        (directory / "link").symlink_to(directory / "VERSION")
        with self.assertRaises(ValueError):
            deploy.archive(directory)

    def test_streamed_archive_retains_exact_artifacts(self):
        directory = self.bundle()
        output = io.BytesIO()
        self.assertIsNone(deploy.archive(directory, output))
        output.seek(0)
        with tarfile.open(fileobj=output) as bundle:
            self.assertEqual(set(bundle.getnames()), {"VERSION", "BUILDSUMS", "web/index.html"})
            self.assertEqual(bundle.extractfile("web/index.html").read(), b"new web")

    def test_signed_metadata_bounds_fail_before_verification(self):
        directory = self.bundle()
        (directory / "SHA256SUMS").write_bytes(b"checksums")
        (directory / "SHA256SUMS.sig").write_bytes(b"signature")
        for name, limit in (("SHA256SUMS", 65536), ("SHA256SUMS.sig", 1024), ("VERSION", 128)):
            original = (directory / name).read_bytes()
            (directory / name).write_bytes(b"x" * (limit + 1))
            with patch.object(remote.subprocess, "run") as verify:
                with self.assertRaisesRegex(ValueError, "metadata exceeds bound"):
                    remote.verify_signed(directory, self.root / "trust", directory / "infraternal")
                verify.assert_not_called()
            (directory / name).write_bytes(original)

    def test_real_online_backup_includes_committed_wal_pages(self):
        data = self.root / "data"
        data.mkdir()
        with closing(sqlite3.connect(data / "infraternal.sqlite")) as live:
            live.execute("PRAGMA journal_mode=WAL")
            live.execute("CREATE TABLE state(value TEXT)")
            live.execute("INSERT INTO state VALUES ('retained')")
            live.commit()
            remote.backup(data, self.root / "backup")
            with closing(sqlite3.connect(self.root / "backup/infraternal.sqlite")) as saved:
                self.assertEqual(saved.execute("SELECT value FROM state").fetchall(), [("retained",)])
            self.assertEqual(live.execute("PRAGMA integrity_check").fetchone(), ("ok",))

    def test_pre_upgrade_snapshot_never_copies_embedded_mesh_private_key(self):
        """Keep the server's Mesh identity outside pre-upgrade snapshots."""
        data = self.root / "data"
        mesh = data / "mesh"
        mesh.mkdir(parents=True, mode=0o700)
        with closing(sqlite3.connect(data / "infraternal.sqlite")) as database:
            database.execute("CREATE TABLE state(value TEXT)")
            database.commit()
        private_key = mesh / "mesh-private-key"
        private_key.write_bytes(b"synthetic-private-key")
        private_key.chmod(0o600)
        os.link(private_key, data / "backup-selected-config")

        destination = self.root / "backup"
        remote.backup(data, destination)

        saved_files = [
            path.read_bytes()
            for path in destination.rglob("*")
            if path.is_file() and not path.is_symlink()
        ]
        self.assertFalse(
            any(b"synthetic-private-key" in saved for saved in saved_files),
            "pre-upgrade snapshots must not contain Mesh private-key bytes",
        )

    def test_pre_upgrade_snapshot_excludes_mesh_rotation_journal_and_aliases(self):
        """Keep the private rotation journal out of snapshots, even through a hard link."""
        data = self.root / "data"
        mesh = data / "mesh"
        mesh.mkdir(parents=True, mode=0o700)
        with closing(sqlite3.connect(data / "infraternal.sqlite")) as database:
            database.execute("CREATE TABLE state(value TEXT)")
            database.commit()

        journal = mesh / "mesh-key-rotation.bin"
        journal.write_bytes(b"synthetic-rotation-secret")
        journal.chmod(0o600)
        os.link(journal, data / "backup-selected-journal")

        destination = self.root / "backup"
        remote.backup(data, destination)

        saved_files = [
            path.read_bytes()
            for path in destination.rglob("*")
            if path.is_file() and not path.is_symlink()
        ]
        self.assertFalse(
            any(b"synthetic-rotation-secret" in saved for saved in saved_files),
            "pre-upgrade snapshots must not contain Mesh rotation secrets",
        )

    def test_d295_rollback_restores_latest_mesh_state_before_old_binary_starts(self):
        """Make the old binary's legacy Mesh path ready before a warm rollback."""
        root = self.root / "deployment"
        release = root / "releases" / "candidate"
        release.mkdir(parents=True)
        (release / "infraternal").write_bytes(b"candidate")
        (release / "web").mkdir()
        (release / "web/index.html").write_text("new web")

        old_release = self.root / "old-release"
        old_release.mkdir()
        old_binary = old_release / "infraternal"
        old_binary.write_bytes(b"c4")
        for name, value in (("MANIFEST", b"manifest"),
                            ("MANIFEST.sig", b"signature"),
                            ("VERSION", b"edge-20261012T000000Z\n")):
            (old_release / name).write_bytes(value)

        data = self.root / "data"
        data.mkdir()
        with closing(sqlite3.connect(data / "infraternal.sqlite")):
            pass
        (data / "restart").mkdir()
        web = self.root / "web"
        web.mkdir()
        (web / "index.html").write_text("old web")
        legacy = self.root / "run/infraternal"
        legacy.mkdir(parents=True, mode=0o700)
        legacy_key = legacy / "mesh-private-key"
        legacy_public = legacy / "mesh-public.json"
        legacy_key.write_bytes(b"old-key")
        legacy_key.chmod(0o600)

        observed_by_old_binary = []

        def restart_for_test(_data, binary):
            if binary == release / "infraternal":
                mesh = data / "mesh"
                mesh.mkdir(mode=0o700)
                legacy_key.rename(mesh / "mesh-private-key")
                (mesh / "mesh-private-key").write_bytes(b"latest-candidate-key")
                (mesh / "mesh-public.json").write_bytes(b'{"enabled":true}')
            else:
                observed_by_old_binary.append(
                    (
                        legacy_key.read_bytes() if legacy_key.exists() else None,
                        legacy_public.read_bytes() if legacy_public.exists() else None,
                    )
                )

        config = {
            "root": root,
            "sha": "candidate",
            "data": data,
            "binary": old_binary,
            "web": web,
            "pid": 1234,
            "web_only": False,
        }
        with (patch.object(remote.os, "geteuid", return_value=0),
              patch.object(remote, "checksums"),
              patch.object(remote, "verify_signed"),
              patch.object(remote, "healthy", side_effect=[True, False, True]),
              patch.object(remote, "same_image", return_value=True),
              patch.object(remote, "endpoint", return_value=(1, 1)),
              patch.object(remote, "restart", side_effect=restart_for_test),
              patch.object(remote, "wait_for_success")):
            with self.assertRaisesRegex(ValueError, "deployment refused"):
                remote.apply(config)

        self.assertEqual(
            observed_by_old_binary,
            [(b"latest-candidate-key", b'{"enabled":true}')],
            "the previous binary must see latest Mesh identity and public state at the legacy path",
        )

    def test_ca_status_refuses_redirect_without_forwarding_session(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()
            def do_GET(self):
                seen.append(self.headers.get("Cookie"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"locked":false,"initialized":true}')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            config = {"health": f"http://127.0.0.1:{server.server_port}",
                      "origin": "https://localhost", "session": "synthetic-in-memory-fixture"}
            with self.assertRaises(OSError):
                remote.unlocked(config)
            self.assertEqual(seen, [])
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_control_refuses_cold_reply_and_accepts_fragmented_warm_reply(self):
        # Linux socket names have a strict bound; use the fixture root directly.
        data = self.root
        (data / "restart").mkdir()
        for reply in (b"RESTARTING\n", b"RESTARTING COLD (CA locked)\n", b"REFUSED\n"):
            path = data / "restart/control.sock"
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(path))
                server.listen()
                def respond():
                    with server.accept()[0] as peer:
                        request = peer.recv(4098)
                        self.assertEqual(request[:2], len(b"/binary").to_bytes(2, "big"))
                        for byte in reply:
                            peer.sendall(bytes([byte]))
                worker = threading.Thread(target=respond)
                worker.start()
                if reply == b"RESTARTING\n":
                    remote.restart(data, Path("/binary"))
                else:
                    with self.assertRaises(ValueError):
                        remote.restart(data, Path("/binary"))
                worker.join()
            path.unlink()

    def setup_apply(self):
        release = self.bundle()
        sha = "a" * 40
        (self.root / "releases").mkdir()
        release.rename(self.root / "releases" / sha)
        old = self.root / "old"
        old.mkdir()
        (old / "infraternal").write_bytes(b"old binary")
        for name in ("SHA256SUMS", "SHA256SUMS.sig", "VERSION"):
            (old / name).write_text("fixture metadata")
        web = self.root / "web"
        web.mkdir()
        (web / "index.html").write_text("old web")
        data = self.root / "data"
        data.mkdir()
        return {"root": str(self.root), "sha": sha, "data": str(data),
                "binary": str(old / "infraternal"), "web": str(web), "web_only": False, "pid": os.getpid()}, old

    def test_bad_replacement_rolls_back_and_keeps_database(self):
        config, old = self.setup_apply()
        with patch.object(remote.os, "geteuid", return_value=0), patch.object(remote, "healthy", return_value=True), \
                patch.object(remote, "same_image", return_value=True), \
                patch.object(remote, "verify_signed"), \
                patch.object(remote, "endpoint", return_value=(1, 2)), patch.object(remote, "backup", side_effect=lambda data, saved: saved.mkdir()), \
                patch.object(remote, "restart") as restart, patch.object(remote, "wait_for_success", side_effect=[ValueError("failed"), None]):
            with self.assertRaisesRegex(ValueError, "previous release healthy"):
                remote.apply(config)
            rollback = restart.call_args_list[1].args[1]
            self.assertEqual(rollback.read_bytes(), (old / "infraternal").read_bytes())
            self.assertTrue((rollback.parent / "SHA256SUMS.sig").is_file())
        self.assertEqual((self.root / "web/index.html").read_text(), "old web")

    def test_web_only_failure_restores_web_without_restart(self):
        config, _ = self.setup_apply()
        config["web_only"] = True
        with patch.object(remote.os, "geteuid", return_value=0), patch.object(remote, "healthy", side_effect=[True, False, True]), \
                patch.object(remote, "verify_signed"), \
                patch.object(remote, "endpoint", return_value=(1, 2)), patch.object(remote, "backup", side_effect=lambda data, saved: saved.mkdir()), \
                patch.object(remote, "restart") as restart:
            with self.assertRaises(ValueError):
                remote.apply(config)
            restart.assert_not_called()
        self.assertEqual((self.root / "web/index.html").read_text(), "old web")

    def test_two_deployments_in_one_second_retain_distinct_backups(self):
        config, _ = self.setup_apply()
        config["web_only"] = True
        with patch.object(remote.os, "geteuid", return_value=0), patch.object(remote, "healthy", return_value=True), \
                patch.object(remote, "verify_signed"), patch.object(remote, "endpoint", return_value=(1, 2)), \
                patch.object(remote, "backup", side_effect=lambda data, saved: saved.mkdir()), \
                patch.object(remote.time, "strftime", return_value="20261012T000000Z"):
            first = remote.apply(config)
            second = remote.apply(config)
        self.assertNotEqual(first["backup"], second["backup"])
        self.assertTrue(Path(first["backup"]).is_dir())
        self.assertTrue(Path(second["backup"]).is_dir())

    def test_load_backoff_starts_no_fetch_or_build(self):
        with patch.object(builder.os, "getloadavg", return_value=(9, 8, 7)), patch.object(builder, "run") as run:
            builder.cycle(self.root, self.root, self.root, "required-gate", 8, "a" * 40)
            run.assert_not_called()

    def test_build_children_retain_the_same_lifetime_lock(self):
        with (self.root / "build.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(lock.fileno())
            with patch.object(builder, "BUILD_LOCK_FD", lock.fileno(), create=True):
                builder.run(sys.executable, "-c",
                            "import os,sys; s=os.fstat(int(sys.argv[1])); "
                            "assert (s.st_dev,s.st_ino)==(int(sys.argv[2]),int(sys.argv[3]))",
                            str(lock.fileno()), str(info.st_dev), str(info.st_ino),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_pruning_keeps_ten_complete_releases(self):
        for number in range(12):
            (self.root / f"{number:040x}").mkdir()
        (self.root / ".building").mkdir()
        builder.prune(self.root)
        self.assertEqual(len([p for p in self.root.iterdir() if len(p.name) == 40]), 10)
        self.assertTrue((self.root / ".building").exists())

    def test_failed_head_does_not_block_newer_heads(self):
        first, second = "a" * 40, "b" * 40
        listing = subprocess.CompletedProcess([], 0, stdout=first + "\n" + second + "\n")
        with patch.object(builder.os, "getloadavg", return_value=(0, 0, 0)), \
                patch.object(builder, "run", side_effect=[None, None, listing]), \
                patch.object(builder, "build", side_effect=[subprocess.CalledProcessError(1, "gate"), None]) as build:
            builder.cycle(self.root, self.root, self.root, "", 8, "0" * 40)
            self.assertEqual([call.args[1] for call in build.call_args_list], [first, second])
        self.assertTrue((self.root / "failed" / first).exists())

    def test_pruned_completed_head_is_not_rebuilt(self):
        sha = "a" * 40
        (self.root / "completed").mkdir()
        (self.root / "completed" / sha).touch()
        listing = subprocess.CompletedProcess([], 0, stdout=sha + "\n")
        with patch.object(builder.os, "getloadavg", return_value=(0, 0, 0)), \
                patch.object(builder, "run", side_effect=[None, None, listing]), \
                patch.object(builder, "build") as build:
            builder.cycle(self.root, self.root, self.root, "", 8, "0" * 40)
            build.assert_not_called()

    def test_newer_pending_gate_overrides_older_success(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return json.dumps([{"context": "gate", "status": "pending"},
                                   {"context": "gate", "status": "success"}]).encode()
        with patch.object(builder.urllib.request, "urlopen", return_value=Response()):
            self.assertFalse(builder.gate_passed("a" * 40, "gate"))


if __name__ == "__main__":
    unittest.main()
