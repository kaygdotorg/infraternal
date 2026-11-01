#!/usr/bin/env python3
# Role: drive one real app-window stream through the desktop helper socket and summarize its native receipts [D200,D204,D208,#146].
"""Measure a real app-window stream end to end on a logged-in Mac.

`capture --app` launches the signed companion bundle through LaunchServices and
speaks its private stdio framing (native/main.swift); `capture --socket` speaks
the bounded local helper protocol (contracts/desktop-helper.md) to a running
`infraternal-desktop-helper`. Either way it starts one window stream at the
window's own size x backing scale (so nothing is resized), keeps
it idle, then types into it through the helper's own tagged input injection, and
stops. `--focus` clicks the window center before warmup, for measurements where
the idle caret must already be visible. It saves the Annex-B stream and one
receipt per received video frame.

`summarize` joins those receipts with the helper and companion's opt-in METRIC
lines by capture timestamp. Pass the companion's separate stderr log with
`--companion-stderr` for a socket capture; direct `--app` captures read their
`companion.stderr` file automatically. It prints per-phase latency percentiles,
bytes and bitrate, CPU and raw SCFrameStatus callback receipts. It also
preserves each pixel-damage class, changed bound and phase so the receipt shows
what the caret classifier saw.
All native stamps and the receipts use the same clock (mach_absolute_time in
ns == CLOCK_UPTIME_RAW), so differences are exact on one host. Standard
library only; runs with the system python3.

No permission is requested here: Screen Recording and Accessibility must already
be granted to the signed companion. Observed on macOS 26.5 (#146): a companion
spawned by the Rust helper under `sudo` passed TCC as its own bundle, yet macOS
asked the person at the Mac whether "sudo" may bypass the private window picker.
Launching the bundle itself through LaunchServices avoids naming a parent. Cleanup
of a socket helper and of the target app is the caller's job.
"""
import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

VIDEO, ERROR, STATE, GEOMETRY, WINDOWS, INPUT_RESULT = 70, 69, 68, 66, 65, 67
TEXT = "the quick brown fox jumps over the lazy dog 0123456789 "
METRIC = re.compile(r"^METRIC (.*)$")


def fields(line):
    return dict(item.split("=", 1) for item in line.split() if "=" in item)


def now():
    return time.clock_gettime_ns(time.CLOCK_UPTIME_RAW)


def packet(kind, body):
    payload = json.dumps(body, separators=(",", ":")).encode()
    return struct.pack(">IBB", len(payload) + 2, 1, kind) + payload


def parse_header(header):
    length, version, kind = struct.unpack(">IBB", header)
    if version != 1 or not 2 <= length <= 4 * 1024 * 1024 + 1024:
        raise ValueError("bad frame header")
    return length - 2, kind


class HelperLink:
    """Public helper socket (contracts/desktop-helper.md)."""

    def __init__(self, path, helper_pid, metrics_log):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.lock = threading.Lock()
        self.root = helper_pid
        self.metrics_log = metrics_log
        self.private = False

    def send(self, kind, body):
        with self.lock:
            self.sock.sendall(packet(kind, body))

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            part = self.sock.recv(count - len(data))
            if not part:
                raise EOFError
            data.extend(part)
        return bytes(data)

    def read(self):
        length, kind = parse_header(self.exact(6))
        return kind, self.exact(length)

    def close(self):
        self.sock.close()


class CompanionLink:
    """The signed companion bundle itself, started by LaunchServices.

    macOS attributes Screen Recording to the process that LaunchServices
    launched, so the bundle runs from `open` rather than as a child of a shell,
    sudo or the Rust helper. Its private stdio framing (native/main.swift) is
    carried over a FIFO (stdin) and an append-only file (stdout). The FIFO is
    held open read-write here so the companion never sees an early EOF; closing
    it is the companion's normal EOF cleanup.
    """

    def __init__(self, app, workdir):
        self.private = True
        fifo = os.path.join(workdir, "companion.stdin")
        os.mkfifo(fifo, 0o600)
        self.fifo = os.open(fifo, os.O_RDWR)
        self.output = os.path.join(workdir, "companion.stdout")
        open(self.output, "wb").close()
        self.errors = os.path.join(workdir, "companion.stderr")
        pidfile = os.path.join(workdir, "companion.pid")
        self.lock = threading.Lock()
        self.launcher = subprocess.Popen(
            ["/usr/bin/open", "-n", "-W", "-g", "--stdin", fifo, "--stdout", self.output, "--stderr", self.errors,
             "--env", "INFRATERNAL_DESKTOP_MEASURE=1", app, "--args", "--surface-capture", "--launch-pid-file", pidfile])
        deadline = time.monotonic() + 10
        while not (os.path.exists(pidfile) and open(pidfile).read().endswith("\n")):
            if time.monotonic() > deadline or self.launcher.poll() is not None:
                raise SystemExit("companion did not start")
            time.sleep(0.01)
        self.root = int(open(pidfile).read())
        self.launch_ms = (time.monotonic() - deadline + 10) * 1000
        self.reader = open(self.output, "rb")

    def send(self, kind, body):
        data = packet(kind, body)
        with self.lock:
            while data:
                data = data[os.write(self.fifo, data):]

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            part = self.reader.read(count - len(data))
            if part:
                data.extend(part)
                continue
            if self.launcher.poll() is not None:
                raise EOFError
            # Receipt stamps carry this poll granularity; native stamps do not.
            time.sleep(0.0002)
        return bytes(data)

    def read(self):
        length, kind = parse_header(self.exact(6))
        return kind, self.exact(length)

    def close(self):
        os.close(self.fifo)
        try:
            self.launcher.wait(15)
        except subprocess.TimeoutExpired:
            os.kill(self.root, 15)
            self.launcher.wait(5)


# Out-of-process work the stream causes: the VideoToolbox encoder service, the
# capture daemon and the compositor. Sampled whole (they also serve others).
SYSTEM = ("VTEncoderXPCService", "replayd", "WindowServer")


def helper_companion_pids(path):
    """Read LaunchServices companion PIDs reported by the helper, if still live."""
    if not path:
        return set()
    pids = set()
    with open(path, errors="replace") as metrics:
        for line in metrics:
            match = METRIC.match(line.strip())
            if not match or not match.group(1).startswith("launch_services"):
                continue
            pid = fields(match.group(1)).get("pid")
            if pid and pid.isdecimal() and int(pid) > 1:
                pids.add(int(pid))
    return pids


def process_snapshot(link, metrics_log=None):
    """Sample the helper, its detached LaunchServices companion and system work."""
    companion_pids = {link.root} if link.private else helper_companion_pids(metrics_log)
    roots = {link.root} | companion_pids
    return {"at_ns": now(), "companion_pids": sorted(companion_pids), "tree": process_tree(roots)}


def process_tree(roots):
    """CPU seconds and RSS KiB of explicit roots, descendants and SYSTEM processes."""
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,time=,rss=,comm="], capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        pid, ppid, cpu, rss, command = line.split(None, 4)
        rows[int(pid)] = (int(ppid), cpu_seconds(cpu), int(rss))
        if os.path.basename(command) in SYSTEM:
            rows[os.path.basename(command) + ":" + pid] = rows[int(pid)]
    roots = set(roots)
    members = roots | {key for key in rows if isinstance(key, str)}
    frontier = list(roots)
    while frontier:
        parent = frontier.pop()
        for pid, (ppid, _, _) in rows.items():
            if ppid == parent and pid not in members and not isinstance(pid, str):
                members.add(pid)
                frontier.append(pid)
    return {str(pid): {"cpu_s": rows[pid][1], "rss_kib": rows[pid][2]} for pid in members if pid in rows}


def cpu_seconds(text):
    days, _, rest = text.rpartition("-")
    parts = [float(p) for p in rest.split(":")]
    seconds = 0.0
    for part in parts:
        seconds = seconds * 60 + part
    return seconds + (int(days) * 86400 if days else 0)


def capture(args):
    if args.socket and args.helper_pid is None:
        raise SystemExit("--helper-pid is required with --socket so helper CPU and RSS are sampled")
    if args.socket and not args.metrics_log:
        raise SystemExit("--metrics-log is required with --socket so detached companion CPU and RSS are sampled")
    if args.socket and not os.path.isfile(args.metrics_log):
        raise SystemExit("--metrics-log must name the running helper's stderr file")
    os.makedirs(args.out, exist_ok=False)
    link = CompanionLink(args.app, args.out) if args.app else HelperLink(args.socket, args.helper_pid, args.metrics_log)
    link.send(1, {})
    kind, body = link.read()
    assert kind == WINDOWS, kind
    inventory = json.loads(body)
    if args.window_id:
        window = next(w for w in inventory["windows"] if w["window_id"] == args.window_id and w["owner_pid"] == args.owner_pid)
    else:
        window = next(w for w in inventory["windows"] if w["app_name"] == args.app_name and w["on_screen"] and w["layer"] == 0
                      and (args.title is None or w["title"] == args.title))
        args.window_id, args.owner_pid = window["window_id"], window["owner_pid"]
    frame = window["frame"]
    display = next(d for d in inventory["displays"]
                   if d["frame"]["x"] <= frame["x"] + frame["width"] / 2 < d["frame"]["x"] + d["frame"]["width"])
    scale = float(display["backing_scale"])
    # Even pixel sizes at exactly the window's point size keep follow a no-op.
    width = int(frame["width"] * scale) // 2 * 2
    height = int(frame["height"] * scale) // 2 * 2
    start = {"target": {"type": "window", "window_id": args.window_id, "owner_pid": args.owner_pid},
             "size": {"width": width, "height": height, "canvas_width": width / scale,
                      "canvas_height": height / scale, "backing_scale": scale}}
    if link.private:
        # The private companion captures this point rectangle; the public
        # helper derives it from its own control child instead.
        start["capture_rect"] = frame
    launch = getattr(link, "launch_ms", None)
    events = {"launch_ms": launch, "window": window, "display": display, "start": start,
              "focused_before_measurement": args.focus, "phases": []}
    receipts = []
    replies = []
    stream = open(os.path.join(args.out, "stream.h264"), "wb")
    stopped = threading.Event()

    def reader():
        try:
            while True:
                kind, body = link.read()
                at = now()
                if kind == VIDEO:
                    capture_ns, keyframe = struct.unpack(">QB", body[:9])
                    receipts.append((at, capture_ns, keyframe, len(body) - 9))
                    stream.write(body[9:])
                else:
                    replies.append((at, kind, body[:512].decode("utf-8", "replace")))
                    if kind == STATE and b'"restored"' in body:
                        break
        except (EOFError, OSError):
            pass
        finally:
            stopped.set()

    events["start_sent_ns"] = now()
    link.send(2, start)
    kind, body = link.read()
    events["start_reply_ns"] = now()
    events["start_reply"] = json.loads(body)
    if kind != GEOMETRY:
        raise SystemExit("Start refused: %s" % body.decode("utf-8", "replace"))
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    if args.focus:
        # A frontmost application alone does not guarantee that its insertion caret is active.
        click = {"type": "mouse", "x": width / 2, "y": height / 2, "button": 0, "modifiers": 0}
        link.send(4, {**click, "state": 1})
        link.send(4, {**click, "state": 2})
        time.sleep(0.1)
        link.send(10, {"active": False})
    # Warmup absorbs process start, first IDR and encoder warm-up so idle is steady state.
    phases = [("warmup", args.warmup, None), ("idle", args.idle, None), ("typing", args.motion, "type")]
    if args.scroll:
        phases.append(("scroll", args.scroll, "scroll"))
    if args.after_idle:
        phases.append(("settled", args.after_idle, None))
    snapshots = [process_snapshot(link, args.metrics_log)]
    for name, seconds, action in phases:
        began = now()
        if action == "scroll":
            # Whole-content motion: a long document scrolled by the helper's
            # tagged wheel events at the window centre, reversing every 20 steps.
            link.send(10, {"active": True})
            deadline = time.monotonic() + seconds
            index = 0
            next_at = time.monotonic()
            while time.monotonic() < deadline and not stopped.is_set():
                dy = -args.scroll_step if (index // 20) % 2 == 0 else args.scroll_step
                link.send(4, {"type": "scroll", "x": width / 2, "y": height / 2, "dx": 0, "dy": dy, "modifiers": 0})
                index += 1
                next_at += 1.0 / args.scroll_rate
                time.sleep(max(0.0, next_at - time.monotonic()))
            link.send(10, {"active": False})
            events["scrolled"] = index
        elif action == "type":
            link.send(10, {"active": True})
            interval = 1.0 / args.rate
            deadline = time.monotonic() + seconds
            index = 0
            next_at = time.monotonic()
            while time.monotonic() < deadline and not stopped.is_set():
                if index and index % 48 == 0:
                    for down in (True, False):
                        link.send(4, {"type": "key", "keycode": 36, "down": down, "modifiers": 0})
                else:
                    link.send(4, {"type": "text", "scalar": ord(TEXT[index % len(TEXT)])})
                index += 1
                next_at += interval
                time.sleep(max(0.0, next_at - time.monotonic()))
            link.send(10, {"active": False})
            events["typed"] = index
        else:
            time.sleep(seconds)
        snapshots.append(process_snapshot(link, args.metrics_log))
        events["phases"].append({"name": name, "begin_ns": began, "end_ns": now()})
    link.send(5, {})
    stopped.wait(10)
    stream.close()
    link.close()
    events["cpu_snapshots"] = snapshots
    events["companion_pids"] = sorted({pid for snapshot in snapshots for pid in snapshot["companion_pids"]})
    events["replies"] = replies
    with open(os.path.join(args.out, "events.json"), "w") as handle:
        json.dump(events, handle, indent=1)
    with open(os.path.join(args.out, "frames.tsv"), "w") as handle:
        handle.write("recv_ns\tcapture_ns\tkeyframe\tbytes\n")
        for row in receipts:
            handle.write("\t".join(str(v) for v in row) + "\n")
    first = receipts[0][0] - events["start_sent_ns"] if receipts else None
    print(json.dumps({"frames": len(receipts), "first_frame_ms": first and first / 1e6, "out": args.out}))


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    # Nearest rank, as in earlier #146 receipts.
    return ordered[max(0, min(len(ordered) - 1, int(-(-q * len(ordered) // 100)) - 1))]


def summarize(args):
    events = json.load(open(os.path.join(args.run, "events.json")))
    receipts = []
    for line in open(os.path.join(args.run, "frames.tsv")).read().splitlines()[1:]:
        recv, cap, key, size = (int(v) for v in line.split("\t"))
        receipts.append({"recv": recv, "capture": cap, "key": key, "bytes": size})
    encodes, deliveries, callbacks, lifecycle, pixel_damage = {}, {}, [], [], []
    companion_pids = set()
    metric_logs = [args.stderr]
    if args.companion_stderr:
        metric_logs.append(args.companion_stderr)
    else:
        private_companion_stderr = os.path.join(args.run, "companion.stderr")
        if os.path.isfile(private_companion_stderr):
            metric_logs.append(private_companion_stderr)
    for metric_log in dict.fromkeys(metric_logs):
        for line in open(metric_log, errors="replace"):
            match = METRIC.match(line.strip())
            if not match:
                continue
            values = fields(match.group(1))
            if "encode_ns" in values:
                # A settled refresh re-encodes the retained picture with its original
                # capture stamp; keep encodes per stamp in order and pair them FIFO.
                encodes.setdefault(int(values["capture_ns"]), []).append(values)
            elif match.group(1).startswith("surface_delivery"):
                deliveries.setdefault(int(values["capture_ns"]), []).append(values["fresh"] == "true")
            elif match.group(1).startswith("capture_callback"):
                callbacks.append(values)
            elif match.group(1).startswith("pixel_damage"):
                capture_ns = int(values["capture_ns"])
                phase = next(
                    (
                        phase["name"]
                        for phase in events["phases"]
                        if phase["begin_ns"] <= capture_ns < phase["end_ns"]
                    ),
                    None,
                )
                pixel_damage.append(
                    {
                        "capture_ns": capture_ns,
                        "phase": phase,
                        "kind": values["kind"],
                        "bounds": values["bounds"],
                        "pixels": int(values["pixels"]),
                        "complete": values["complete"] == "true",
                    }
                )
            elif match.group(1).startswith("launch_services"):
                lifecycle.append(match.group(1))
            elif match.group(1).startswith(("capture_lifecycle", "capture_window", "source_capture_config", "capture_start_failed", "capture_stopped", "hardware=")):
                lifecycle.append(match.group(1))
            if "pid" in values and match.group(1).startswith(("source_capture_config", "capture_window")):
                companion_pids.add(int(values["pid"]))
    companion_pids.update(events.get("companion_pids", []))
    result = {"window": {k: events["window"].get(k) for k in ("app_name", "window_id", "owner_pid", "frame")},
              "output": [events["start"]["size"]["width"], events["start"]["size"]["height"]],
              "first_frame_ms": (receipts[0]["recv"] - events["start_sent_ns"]) / 1e6 if receipts else None,
              "launch_ms": events.get("launch_ms"),
              "companion_pids": sorted(companion_pids),
              "start_reply_ms": (events["start_reply_ns"] - events["start_sent_ns"]) / 1e6,
              "typed": events.get("typed"), "scrolled": events.get("scrolled"), "phases": [], "callbacks": callbacks, "lifecycle": lifecycle,
              "pixel_damage": pixel_damage}
    launches = [fields(entry) for entry in lifecycle if entry.startswith("launch_services")]
    if launches and "launch_ms" in launches[-1]:
        result["launch_ms"] = float(launches[-1]["launch_ms"])
    sent = events["start_sent_ns"]
    stamps = {}
    for entry in lifecycle:
        values = fields(entry)
        if entry.startswith("capture_lifecycle") and "at_ns" in values:
            stamps.setdefault(values["stage"], int(values["at_ns"]))
    if callbacks:
        stamps["first_callback"] = int(callbacks[0]["at_ns"])
    if receipts:
        first = receipts[0]
        stamps["first_capture"] = first["capture"]
        if first["capture"] in encodes:
            stamps["first_encoded"] = int(encodes[first["capture"]][0]["encode_finished_ns"])
        stamps["first_client_receipt"] = first["recv"]
    result["first_frame_breakdown_ms"] = {k: round((v - sent) / 1e6, 3) for k, v in sorted(stamps.items(), key=lambda kv: kv[1])}
    snapshots = events["cpu_snapshots"]
    pending = {stamp: list(values) for stamp, values in encodes.items()}
    fresh_flags = {stamp: list(values) for stamp, values in deliveries.items()}
    for index, phase in enumerate(events["phases"]):
        frames = [r for r in receipts if phase["begin_ns"] <= r["recv"] < phase["end_ns"]]
        joined, refreshes = [], 0
        for r in frames:
            entry = pending[r["capture"]].pop(0) if pending.get(r["capture"]) else None
            fresh = fresh_flags[r["capture"]].pop(0) if fresh_flags.get(r["capture"]) else True
            # Encodes of the retained picture (settled sharp refresh, repair) are
            # not new captures; their capture-stamp age is not latency.
            if not fresh:
                refreshes += 1
                continue
            joined.append((r, entry))
        encode_latency = [(int(e["encode_finished_ns"]) - r["capture"]) / 1e6 for r, e in joined if e]
        encode_only = [int(e["encode_ns"]) / 1e6 for _, e in joined if e]
        receive_latency = [(r["recv"] - r["capture"]) / 1e6 for r, _ in joined]
        seconds = (phase["end_ns"] - phase["begin_ns"]) / 1e9
        total = sum(r["bytes"] for r in frames)
        before, after = snapshots[index]["tree"], snapshots[index + 1]["tree"]
        wall = (snapshots[index + 1]["at_ns"] - snapshots[index]["at_ns"]) / 1e9
        cpu = {pid: round(100 * (after[pid]["cpu_s"] - before.get(pid, {"cpu_s": 0})["cpu_s"]) / wall, 1) for pid in after}
        result["phases"].append({
            "name": phase["name"], "seconds": round(seconds, 2), "frames": len(frames),
            "keyframes": sum(r["key"] for r in frames), "fps": round(len(frames) / seconds, 2),
            "capture_to_encoded_ms": {q: percentile(encode_latency, q) for q in (50, 95, 99)},
            "encode_call_ms": {q: percentile(encode_only, q) for q in (50, 95, 99)},
            "capture_to_client_ms": {q: percentile(receive_latency, q) for q in (50, 95, 99)},
            "joined": len(encode_latency), "refreshes": refreshes,
            "bytes_per_frame_mean": round(total / len(frames)) if frames else 0,
            "bytes_per_frame_p95": percentile([r["bytes"] for r in frames], 95),
            "kbit_per_s": round(total * 8 / seconds / 1000, 1),
            "cpu_percent_of_one_core": cpu,
            "rss_kib": {pid: after[pid]["rss_kib"] for pid in after},
        })
    print(json.dumps(result, indent=1))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("capture")
    run.add_argument("--socket", help="public helper socket")
    run.add_argument("--app", help="signed companion .app, launched with open (preferred: TCC attributes it to the bundle)")
    run.add_argument("--window-id", type=int)
    run.add_argument("--owner-pid", type=int)
    run.add_argument("--app-name", help="first on-screen normal window of this app, instead of an ID")
    run.add_argument("--title", help="with --app-name: the window with exactly this title")
    run.add_argument("--helper-pid", type=int, help="helper PID for CPU sampling (with --socket)")
    run.add_argument("--metrics-log", help="helper stderr path (required with --socket; supplies detached companion PIDs)")
    run.add_argument("--focus", action="store_true", help="click the target window center before warmup; use when that point is an editor")
    run.add_argument("--out", required=True)
    run.add_argument("--warmup", type=float, default=3)
    run.add_argument("--idle", type=float, default=10)
    run.add_argument("--scroll", type=float, default=0)
    run.add_argument("--scroll-rate", type=float, default=30, help="wheel events per second")
    run.add_argument("--scroll-step", type=int, default=40, help="pixels per wheel event")
    run.add_argument("--motion", type=float, default=10)
    run.add_argument("--after-idle", type=float, default=0)
    run.add_argument("--rate", type=float, default=15, help="typed characters per second")
    report = commands.add_parser("summarize")
    report.add_argument("run")
    report.add_argument("stderr")
    report.add_argument("--companion-stderr", help="separate stderr log from the LaunchServices-launched companion")
    args = parser.parse_args()
    capture(args) if args.command == "capture" else summarize(args)


if __name__ == "__main__":
    main()
