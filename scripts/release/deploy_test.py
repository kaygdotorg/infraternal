#!/usr/bin/env python3
"""Exercise deployment refusal/rollback, real WAL backup and private control framing [250], #188."""
import hashlib
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
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
        scratch = Path.home() / ".cache/codex-scratch/deploy-pipeline/tests"
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
        (directory / "SHA256SUMS").write_text("".join(
            hashlib.sha256(file.read_bytes()).hexdigest() + "  " + str(file.relative_to(directory)) + "\n"
            for file in sorted(directory.rglob("*")) if file.is_file() and file.name != "SHA256SUMS"))

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
        (directory / "SHA256SUMS").write_text("0" * 64 + "  ../outside\n")
        with self.assertRaises(ValueError):
            remote.checksums(directory)
        (directory / "link").symlink_to(directory / "VERSION")
        with self.assertRaises(ValueError):
            deploy.archive(directory)

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
        for name in ("MANIFEST", "MANIFEST.sig", "VERSION"):
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
            self.assertTrue((rollback.parent / "MANIFEST.sig").is_file())
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

    def test_load_backoff_starts_no_fetch_or_build(self):
        with patch.object(builder.os, "getloadavg", return_value=(9, 8, 7)), patch.object(builder, "run") as run:
            builder.cycle(self.root, self.root, self.root, "required-gate", 8, "a" * 40)
            run.assert_not_called()

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
