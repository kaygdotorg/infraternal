"""Exercise the signed native input path at typing cadence on an owned document (#146).

Run only on an authorized Mac under its hardware lock. The helper's existing
three-second control-reply budget applies to every queued scalar; text is never
replayed after failure. Every GUI process and document here belongs to this test.
"""
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import threading
import time

helper_path, scratch = sys.argv[1:]
assert sys.platform == "darwin"
root = Path(scratch)
root.mkdir(parents=True, exist_ok=True)
document = root / ("native-input-pipeline-" + str(os.getpid()) + ".txt")
child = None
owned = None
writer = None
sent = []
errors = []


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
    permissions = json.loads(subprocess.check_output([helper_path, "--check-permissions"]))
    assert permissions == {"device_control": True, "screen_recording": True}
    document.write_text("")
    before = pids()
    subprocess.run(["open", "-n", "-F", "-a", "TextEdit", str(document)], check=True)
    time.sleep(2)
    created = pids() - before
    assert len(created) == 1, "owned document PID is ambiguous"
    owned = int(created.pop())
    child = subprocess.Popen([helper_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    print("OWNED_PIDS text=" + str(owned) + " helper=" + str(child.pid), flush=True)
    packet(1, {})
    inventory = receive(65)
    target = next(w for w in inventory["windows"] if w["owner_pid"] == owned and document.name in w["title"])
    packet(2, {"target": {"type": "window", "window_id": target["window_id"], "owner_pid": owned},
               "size": {"width": 1440, "height": 900, "canvas_width": 1440, "canvas_height": 900, "backing_scale": 1}})
    receive(66)
    packet(10, {"active": True})
    receive(68)
    time.sleep(2.5)
    text = "This sentence was typed from the infraternal browser into TextEdit on the MacBook."

    def type_text():
        try:
            for letter in text:
                sent.append(time.monotonic())
                packet(4, {"type": "text", "scalar": ord(letter)})
                time.sleep(0.09)
        except Exception as error:
            errors.append(error)

    writer = threading.Thread(target=type_text)
    writer.start()
    ages = []
    for _ in text:
        reply = receive(67)
        ages.append(time.monotonic() - sent[len(ages)])
        assert reply.get("accepted") is True, "native input was refused"
    writer.join()
    assert not errors, "native writer failed"
    packet(5, {})
    receive(68)
    print("INPUT_PIPELINE count=" + str(len(ages)) + " maximum_reply_ms=" + str(max(ages) * 1000), flush=True)
    assert max(ages) < 3, "typing exceeded the existing three-second source control-reply budget"
finally:
    if writer:
        writer.join(timeout=10)
    if child:
        child.stdin.close()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.terminate()
            child.wait(timeout=10)
    if owned:
        os.kill(owned, signal.SIGTERM)
        time.sleep(1)
    for pid in [owned, child.pid if child else None]:
        if pid:
            result = subprocess.run(["ps", "-p", str(pid), "-o", "pid=,stat=,comm="], capture_output=True, text=True)
            print("CLEANUP_PID=" + str(pid) + " REMAINS=" + result.stdout.strip(), flush=True)
            assert not result.stdout.strip(), "owned GUI process remains"
    document.unlink(missing_ok=True)
