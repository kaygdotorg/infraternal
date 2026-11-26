#!/usr/bin/env python3
"""Full infraternal agent adapter for the isolated Mesh proof's inherited authenticated channel [9,169]."""
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
from pathlib import Path
from agent_fixture import exact, integer, varint


class BinaryNode:
    """Own one daemon, its private runtime directory and a trusted inherited leg-B socket."""
    def __init__(self, binary, scratch, namespace_pid=None, state_path=None):
        self.state = Path(state_path) if state_path else Path(tempfile.mkdtemp(prefix="node-", dir=scratch))
        self.sock, peer = socket.socketpair()
        self.sock.settimeout(60)
        env = os.environ.copy()
        prefix = [] if namespace_pid is None else [shutil.which("nsenter"), "-t", str(namespace_pid), "-n"]
        command = prefix + [shutil.which("bash"), "-c", 'leg_b_fd=$1; if [ "$leg_b_fd" != 3 ]; then exec 3<&"$leg_b_fd"; exec {leg_b_fd}<&-; fi; shift; exec "$@"',
                            "leg-b", str(peer.fileno()), str(binary), "agent", "--fd", "3", "--state", str(self.state)]
        self.log = (Path(scratch) / (self.state.name + ".stderr")).open("ab")
        self.child = subprocess.Popen(command, pass_fds=(peer.fileno(),), env=env,
                                      stdout=subprocess.DEVNULL, stderr=self.log)
        peer.close()
        self.pid = self.child.pid
        self.call_id = 0
        stream, kind, _ = self.read()
        assert (stream, kind) == (0, 0)
        self.send(0, struct.pack("<HQ", 1, 0) + varint(10) + b"mesh-proof")
        self.send(0x08, struct.pack("<QQ", 0, 0))
        while True:
            stream, kind, _ = self.read()
            if (stream, kind) == (0, 0x09):
                break
        # Mesh is a node component: enable it explicitly before joining.
        self.call("mesh.up", {})
        identity = self.call("mesh.identity", {})
        assert identity is not None
        self.stdout = io.StringIO(json.dumps(identity) + "\n")

    def send(self, kind, body):
        self.sock.sendall(varint(0) + varint(1 + len(body)) + bytes([kind]) + body)

    def read(self):
        stream = integer(self.sock)
        body = exact(self.sock, integer(self.sock))
        return stream, body[0], body[1:]

    def call(self, action, value):
        self.call_id += 1
        encoded = action.encode()
        self.send(0x30, struct.pack("<I", self.call_id) + varint(len(encoded)) + encoded + json.dumps(value, separators=(",", ":")).encode())
        while True:
            stream, kind, body = self.read()
            if (stream, kind) == (0, 0x31):
                assert struct.unpack("<I", body[:4])[0] == self.call_id
                if body[4] != 1:
                    raise RuntimeError("Mesh node action refused")
                return json.loads(body[5:])

    def request(self, value):
        if value == "quit":
            self.call("mesh.down", {})
            status = self.call("mesh.status", {})
            assert status["state"] == "Off"
            self.terminate()
            return {"off": True}
        import time
        started = time.monotonic_ns()
        result = self.call("mesh.configure", value)
        result["apply_us"] = (time.monotonic_ns() - started) // 1000
        return result

    def poll(self):
        return self.child.poll()

    def terminate(self):
        self.child.terminate()

    def crash(self):
        """Stop the process without deleting the state or its retained kernel interface."""
        if self.poll() is None:
            self.child.kill()
            self.child.wait(timeout=5)
        self.sock.close()
        self.log.close()

    def wait(self, timeout):
        result = self.child.wait(timeout=timeout)
        self.sock.close()
        self.log.close()
        shutil.rmtree(self.state, ignore_errors=True)
        return result

    def close(self):
        self.sock.close()
        if self.poll() is None:
            self.terminate()
            try:
                self.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.wait(timeout=5)
        self.log.close()
        shutil.rmtree(self.state, ignore_errors=True)


class CoordinatorFixture:
    """Run the production-schema coordinator compiler without writing private material."""
    def __init__(self, executable, extra_members=0):
        self.child = subprocess.Popen([str(executable), str(extra_members)], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True)

    def configuration(self, mode, identities=None):
        return self.request({"mode": mode, "identities": identities})

    def request(self, value):
        self.child.stdin.write(json.dumps(value) + "\n")
        self.child.stdin.flush()
        line = self.child.stdout.readline()
        if not line:
            raise RuntimeError("coordinator fixture process stopped")
        return json.loads(line)

    def rotate_key(self, node, public_key):
        return self.request({"mode": "rotation-start", "node": node, "public_key": public_key})

    def acknowledge(self, node, version):
        return self.request({"mode": "rotation-ack", "node": node, "version": version})

    def finish_rotation(self, now, reachable):
        return self.request({"mode": "rotation-finish", "now": now, "reachable": reachable})

    def compromise_key(self, node, public_key):
        return self.request({"mode": "rotation-compromise", "node": node, "public_key": public_key})

    def close(self):
        self.child.stdin.close()
        if self.child.wait(timeout=5) != 0:
            raise RuntimeError("coordinator fixture was refused")
