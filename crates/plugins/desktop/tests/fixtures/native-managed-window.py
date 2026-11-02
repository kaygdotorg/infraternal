"""Verify managed-window geometry on an owned document under the Mac hardware lock [D290].

The first assertion precedes all differently sized requests, so the installed
pre-fix helper fails safely without triggering a resize fight. The window
manager must already be running; this test never configures or controls it.
"""
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import time

helper_path, scratch = sys.argv[1:]
assert sys.platform == "darwin"
root = Path(scratch)
root.mkdir(parents=True, exist_ok=True)
document = root / ("native-managed-window-" + str(os.getpid()) + ".txt")
child = None
owned = None


def pids():
    return set(subprocess.run(["pgrep", "-x", "TextEdit"], capture_output=True, text=True).stdout.split())


def packet(kind, value):
    body = json.dumps(value).encode()
    child.stdin.write(struct.pack(">IBB", len(body) + 2, 1, kind) + body)
    child.stdin.flush()


def exact(count):
    data = b""
    deadline = time.monotonic() + 10
    while len(data) < count:
        assert time.monotonic() < deadline, "native reply timed out"
        if select.select([child.stdout], [], [], 0.1)[0]:
            part = os.read(child.stdout.fileno(), count - len(data))
            assert part, "native EOF"
            data += part
    return data


def receive(expected):
    size, version, kind = struct.unpack(">IBB", exact(6))
    assert version == 1 and 2 <= size <= 4 * 1024 * 1024
    body = json.loads(exact(size - 2))
    assert kind == expected, "unexpected native reply kind " + str(kind)
    return body


try:
    assert subprocess.run(["pgrep", "-x", "OmniWM"], stdout=subprocess.DEVNULL).returncode == 0, "required managing process is absent"
    permissions = json.loads(subprocess.check_output([helper_path, "--check-permissions"]))
    assert permissions == {"device_control": True, "screen_recording": True}
    document.write_text("")
    before = pids()
    opened = subprocess.Popen(["open", "-n", "-F", "-a", "TextEdit", str(document)])
    print("OPEN_PID=" + str(opened.pid), flush=True)
    assert opened.wait() == 0
    time.sleep(3)
    created = pids() - before
    assert len(created) == 1, "owned document PID is ambiguous"
    owned = int(created.pop())
    child = subprocess.Popen([helper_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    print("OWNED_PIDS text=" + str(owned) + " helper=" + str(child.pid), flush=True)
    packet(1, {})
    inventory = receive(65)
    target = next(w for w in inventory["windows"] if w["owner_pid"] == owned and document.name in w["title"])
    frame = target["frame"]
    cx, cy = frame["x"] + frame["width"] / 2, frame["y"] + frame["height"] / 2
    display = next(d for d in inventory["displays"] if d["frame"]["x"] <= cx < d["frame"]["x"] + d["frame"]["width"] and d["frame"]["y"] <= cy < d["frame"]["y"] + d["frame"]["height"])
    scale = display["backing_scale"]
    size = {"width": frame["width"] * scale, "height": frame["height"] * scale,
            "canvas_width": frame["width"], "canvas_height": frame["height"], "backing_scale": scale}
    packet(2, {"target": {"type": "window", "window_id": target["window_id"], "owner_pid": owned}, "size": size})
    initial = receive(66)
    print("INITIAL_GEOMETRY=" + json.dumps(initial), flush=True)
    assert initial.get("managed") is True and initial.get("reason") == "managed", "managing process must be detected before any resize"
    baseline = initial["actual"]
    samples = []
    started = time.monotonic()
    while time.monotonic() - started < 30:
        if len(samples) in [0, 20, 40]:
            width = 800 + len(samples) * 4
            packet(3, {"width": width, "height": 600, "canvas_width": width, "canvas_height": 600, "backing_scale": 1})
            geometry = receive(66)
        else:
            packet(6, {})
            geometry = receive(68)
        assert geometry["managed"] and geometry["resize_requests"] == 0, "managed session issued a real resize"
        assert geometry["actual"]["width"] == baseline["width"] and geometry["actual"]["height"] == baseline["height"], "managed source frame size flipped"
        samples.append(geometry)
        time.sleep(0.5)
    print("MANAGED_WINDOW seconds=30 samples=" + str(len(samples)) + " resize_requests=0 frame_size_flips=0 canvas_resizes=3", flush=True)
finally:
    if child:
        try:
            packet(5, {})
            receive(68)
        finally:
            child.stdin.close()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=10)
    if owned:
        os.kill(owned, signal.SIGTERM)
        time.sleep(1)
    for pid in [owned, child.pid if child else None, opened.pid if "opened" in globals() else None]:
        if pid:
            result = subprocess.run(["ps", "-p", str(pid), "-o", "pid=,stat=,comm="], capture_output=True, text=True)
            print("CLEANUP_PID=" + str(pid) + " PS_EXIT=" + str(result.returncode) + " REMAINS=" + result.stdout.strip(), flush=True)
            assert not result.stdout.strip(), "owned process remains"
    document.unlink(missing_ok=True)
