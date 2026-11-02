#!/usr/bin/env python3
# Role: deterministic same-user helper fixture and opt-in recorded-native IDR scale replay; native capture is excluded from replay measurements.
import base64
import json
import os
import select
import socket
import struct
import sys
import time

runtime = sys.argv[1]
assert "--once" in sys.argv
companion = sys.argv[sys.argv.index("--companion-runtime") + 1]
os.umask(0o077)
listener = socket.socket(socket.AF_UNIX)
listener.bind(os.path.join(runtime, "desktop.sock"))
listener.listen(1)
connection, _ = listener.accept()
listener.close()
source = connection.makefile("rb", buffering=0)
capture_ns = 123456789
clip_path = os.environ.get("INFRATERNAL_BENCH_REPLAY_CLIP")
clip = None
units = []
next_unit = 0
replay_fps = int(os.environ.get("INFRATERNAL_BENCH_REPLAY_FPS", "30"))
assert 1 <= replay_fps <= 120
if clip_path:
    with open(clip_path, "rb") as recording:
        document = json.loads(recording.read(8 * 1024 * 1024))
    assert document["width"] == 960 and document["height"] == 600
    clip = base64.b64decode(document["bytes_base64"], validate=True)
    assert 0 < len(clip) < 4 * 1024 * 1024
    if "units" not in document:
        units.append((True, clip))
    else:
        for unit in document["units"]:
            assert type(unit["keyframe"]) is bool
            payload = base64.b64decode(unit["bytes_base64"], validate=True)
            assert 0 < len(payload) < 4 * 1024 * 1024
            units.append((unit["keyframe"], payload))
    assert 1 <= len(units) <= 300 and units[0][0]
    assert sum(len(payload) for _, payload in units) <= 4 * 1024 * 1024
qos_result = None
timer_name = os.environ.get("INFRATERNAL_BENCH_REPLAY_TIMER", "select")
assert timer_name in ("select", "mach")
mach = None
if clip is not None and timer_name == "mach":
    assert sys.platform == "darwin"
    import ctypes
    class Timebase(ctypes.Structure):
        _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
    mach = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    mach.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
    mach.mach_timebase_info.restype = ctypes.c_int
    mach.mach_absolute_time.argtypes = []
    mach.mach_absolute_time.restype = ctypes.c_uint64
    mach.mach_wait_until.argtypes = [ctypes.c_uint64]
    mach.mach_wait_until.restype = ctypes.c_int
    timebase = Timebase()
    assert mach.mach_timebase_info(ctypes.byref(timebase)) == 0
    assert timebase.numer > 0 and timebase.denom > 0
if clip is not None and os.environ.get("INFRATERNAL_BENCH_REPLAY_QOS") == "1":
    assert sys.platform == "darwin"
    import ctypes
    # This scheduling experiment affects only the active replay fixture thread,
    # not capture engines or production processes. Never hide a failed request.
    qos = ctypes.CDLL("/usr/lib/libSystem.B.dylib").pthread_set_qos_class_self_np
    qos.argtypes = [ctypes.c_uint, ctypes.c_int]
    qos.restype = ctypes.c_int
    qos_result = qos(0x21, 0)
    assert qos_result == 0
frames_sent = 0
active = False
next_frame = 0.0
# Recorded replay measures its own waits separately from native capture. Numeric
# aggregates are included in the fixture's Status reply, never in video bytes.
stage_totals = {name: {"count": 0, "total_ns": 0, "max_ns": 0} for name in ("timer", "timer_requested", "write")}

def stage(name, duration_ns):
    row = stage_totals[name]
    row["count"] += 1
    row["total_ns"] += duration_ns
    row["max_ns"] = max(row["max_ns"], duration_ns)

def readable(timeout):
    if mach is None:
        return select.select([connection], [], [], timeout)[0]
    ready = select.select([connection], [], [], 0)[0]
    if ready:
        return ready
    # A sleeping absolute-clock experiment avoids a CPU load generator. Control
    # remains bounded by one replay interval; the idle fixture does not call it.
    deadline = mach.mach_absolute_time() + int(timeout * 1e9 * timebase.denom / timebase.numer)
    assert mach.mach_wait_until(deadline) == 0
    return select.select([connection], [], [], 0)[0]

def record(kind, body):
    if clip is not None:
        return
    with open(os.path.join(companion, "events.jsonl"), "a", encoding="utf-8") as output:
        output.write(json.dumps({"kind": kind, "body": body, "pid": os.getpid(), "companion": companion}) + "\n")

def send(kind, body):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    connection.sendall(struct.pack(">IBB", len(body) + 2, 1, kind) + body)

def video():
    global frames_sent, next_unit
    stamp = time.monotonic_ns() if clip is not None else capture_ns
    keyframe, payload = units[next_unit] if clip is not None else (True, b"\x00\x00\x00\x01\x65" + bytes(2048))
    started = time.monotonic_ns()
    send(70, struct.pack(">Q", stamp) + bytes([int(keyframe)]) + payload)
    if clip is not None:
        stage("write", time.monotonic_ns() - started)
    frames_sent += 1
    if clip is not None:
        next_unit = (next_unit + 1) % len(units)

try:
    while True:
        if clip is not None and active:
            timeout = max(0.0, next_frame - time.monotonic())
            started = time.monotonic_ns()
            ready = readable(timeout)
            stage("timer", time.monotonic_ns() - started)
            stage("timer_requested", int(timeout * 1e9))
            if not ready:
                video()
                next_frame = time.monotonic() + 1.0 / replay_fps
                continue
        header = source.read(6)
        if not header:
            break
        assert len(header) == 6
        length, version, kind = struct.unpack(">IBB", header)
        assert version == 1 and 2 <= length <= 65536
        body = source.read(length - 2)
        assert len(body) == length - 2
        body = json.loads(body)
        record(kind, body)
        if kind == 1:
            windows = [] if clip is not None else [{"window_id": index + 1, "owner_pid": 123, "title": "window " + str(index) + "x" * 200} for index in range(100)]
            send(65, {"windows": windows, "displays": [{"display_id": 1, "pixel_width": 1920, "pixel_height": 1080}], "permission_state": {"screen_recording": clip is None, "accessibility": clip is None}, "source": "recorded-native" if clip is not None else "fixture"})
        elif kind == 2:
            if clip is not None:
                assert body["size"]["width"] == 960 and body["size"]["height"] == 600
            send(66, {"capture_rect": {"x": 0, "y": 0, "width": body["size"]["canvas_width"], "height": body["size"]["canvas_height"]}})
            video()
            active = True
            next_frame = time.monotonic() + 1.0 / replay_fps
        elif kind == 3:
            send(66, {"capture_rect": {"x": 0, "y": 0, "width": body["canvas_width"], "height": body["canvas_height"]}})
            video()
        elif kind == 4:
            send(67, {"injected": clip is None})
        elif kind == 5:
            send(68, {"restored": True})
            break
        elif kind == 6:
            stamp = time.monotonic_ns() if clip is not None else capture_ns
            send(68, {"capture_ns": stamp, "capture_ticks": stamp, "state": "on", "replay_fps": replay_fps if clip is not None else None, "frames_sent": frames_sent, "replay_waits": stage_totals if clip is not None else None, "qos_result": qos_result, "timer": timer_name})
        elif kind == 7:
            send(68, {"keyframe_requested": True})
            next_unit = 0
            # Real capture coalesces repair into its worker's next frame. A
            # replay must not multiply its cadence by the number of viewers.
            if clip is None:
                video()
        elif kind == 8:
            send(68, {"released": True})
        elif kind == 10:
            send(68, {"state": "on", "control": body["active"]})
        elif kind == 9:
            # This is a routing fixture, not a hardware/quality measurement.
            send(68, {"state": "on"})
        else:
            raise AssertionError("unsupported helper command")
finally:
    record(5, {"restored": True, "eof": True})
    connection.close()
