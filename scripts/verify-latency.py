"""Measure the native D375 rows on the real infraternal agent and PTY [#55, D375, D296, D259, D122, D130].

This probe drives the real agent binary over its fixture socket, through the
same latency relay the browser suite uses, and prints the D375 rows the browser
cannot see:

- `real_echo` as a component line (`keystroke_pty_echo_*`): key in, PTY echo out,
  through the configured round trip. The D375 row itself is the browser's
  key-to-paint number; the agent's share is gated here against the same bound;
- `flood_effect`: how much a flooding terminal (another session, then the same
  one) grows echo p99;
- `own_overhead`: echo p99 with no network at all (relay delay 0), the measure
  D296 set the ~25 ms baseline on;
- `reconnect_resumed_link`: re-attaching a terminal over a link that stays up,
  from Attach sent to the agent's acknowledgement (the terminal is current and
  accepts keys), then one key's echo as proof it is typable;
- `idle_agent_rss`: the agent's resident memory when idle, with no session and
  with one quiet session; the larger is the row.

Each row is a `METRIC name=d375_<key>` line from `latency_targets.row_line()`.
The process exits non-zero when a gated row or component fails;
`latency_targets.py report` then prints the whole table for the run.
"""
import argparse
import os
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state, rss
from latency_proxy import LatencyConfig
import latency_targets as targets


#: D375: a flooding terminal may grow typing echo p99 by at most one 120 Hz frame.
FLOOD_DELTA_BUDGET_MS = targets.FRAME_MS
#: D375: the real echo may take the round trip plus two 120 Hz frames.
REAL_ECHO_FRAMES_MS = 2 * targets.FRAME_MS
PROBE_SAMPLES = 100
#: Re-attaches measured for the resumed-link row; p99 of 20 samples is their maximum.
REATTACH_SAMPLES = 20
ECHO_KEY = b"x"


def percentile(samples, fraction):
    ordered = sorted(samples)
    rank = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[rank]


def metric(name, samples, budget_ms):
    """Print one supporting (non-D375-row) latency line and return its p50 and p99."""
    p50 = percentile(samples, 0.50)
    p99 = percentile(samples, 0.99)
    result = "PASS" if p99 <= budget_ms else "FAIL"
    print(
        f"METRIC name={name} source=real-agent-pty n={len(samples)} "
        f"p50_ms={p50:.2f} p99_ms={p99:.2f} budget_ms={budget_ms:.2f} result={result}",
        flush=True,
    )
    return p50, p99


def update_state_output(client, streams, stream, body):
    """Maintain the current output cursor and a bounded ready-marker tail."""
    state = streams[stream]
    sequence = struct.unpack("<Q", body[:8])[0]
    if sequence != state["out"]:
        raise AssertionError(f"stream {stream} output gap: expected={state['out']} actual={sequence}")
    data = body[8:]
    state["out"] += len(data)
    state["output_bytes"] += len(data)
    state["echoes"] += data.count(ECHO_KEY)
    state["recent_output"].extend(data)
    if len(state["recent_output"]) > 4096:
        del state["recent_output"][:-4096]
    state["credit_pending"] += len(data)
    if state["credit_pending"] >= 64 * 1024:
        client.send(stream, 0x14, struct.pack("<I", state["credit_pending"]))
        state["credit_pending"] = 0
    if state.get("pending_echo") and state["echoes"] >= state["pending_echo"][0]:
        state["pending_echo"][2] = time.perf_counter()


def frame(client, streams):
    """Read one mux frame and update its stream's Ack/Output state.

    Returns `(stream, kind)` so a caller waiting for a connection-level reply
    (stream 0, such as a Pong fence) can see it; other stream-0 frames are ignored.
    """
    stream, kind, body = client.read()
    if stream == 0:
        return stream, kind
    state = streams.get(stream)
    if state is None:
        raise AssertionError(f"unexpected stream {stream}")
    if kind == 0x13:
        ack = struct.unpack("<Q", body)[0]
        if ack < state["acked"]:
            raise AssertionError("PTY Ack moved backwards")
        state["acked"] = ack
        if state.get("pending_ack") and ack >= state["pending_ack"][0]:
            state["pending_ack"][2] = time.perf_counter()
    elif kind == 0x11:
        update_state_output(client, streams, stream, body)
    elif kind == 0x15:
        sequence = struct.unpack("<Q", body[:8])[0]
        state["out"] = sequence
    elif kind == 0x33:
        pass
    else:
        raise AssertionError(f"unexpected stream frame {(stream, kind)}")
    return stream, kind


def new_stream_state(session_id):
    """Fresh per-stream bookkeeping: cursors, echo counter, credit and pending probes."""
    return {
        "id": session_id,
        "out": 0,
        "entered": 0,
        "acked": 0,
        "echoes": 0,
        "output_bytes": 0,
        "credit_pending": 0,
        "recent_output": bytearray(),
        "pending_ack": None,
        "pending_echo": None,
    }


def attach_streams(client, streams):
    """Attach every stream from cursor zero with a 1 MiB credit window and wait for the agent's Acks."""
    for stream, state in streams.items():
        client.send(stream, 0x16, state["id"].bytes + struct.pack("<QQ", 0, 0))
        client.send(stream, 0x14, struct.pack("<I", 1024 * 1024))
    wait_for(client, streams, lambda: all(state["acked"] == 0 for state in streams.values()))
    # Keep only a small rolling marker tail while still crediting every PTY Output byte.
    for state in streams.values():
        state["recent_output"] = bytearray()


def wait_for(client, streams, predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError("PTY latency fixture did not reach its expected marker")
        frame(client, streams)


def send_input(client, streams, stream, payload):
    state = streams[stream]
    start = state["entered"]
    state["entered"] += len(payload)
    client.send(stream, 0x10, struct.pack("<Q", start) + payload)
    return start, state["entered"]


def prepare_cat(client, streams, stream, marker):
    state = streams[stream]
    marker_bytes = marker.encode()
    send_input(client, streams, stream, b"stty raw -echo; printf '" + marker_bytes + b"'; cat\n")
    wait_for(client, streams, lambda: marker_bytes in state["recent_output"])
    state["recent_output"] = bytearray()
    state["echoes"] = 0


def start_flood(client, streams, stream, command):
    state = streams[stream]
    marker = f"__FLOOD_{stream}__".encode()
    send_input(client, streams, stream, b"stty -echo -opost; printf '" + marker + b"'; " + command.encode() + b"\n")
    wait_for(client, streams, lambda: marker in state["recent_output"])
    output_at_start = state["output_bytes"]
    wait_for(client, streams, lambda: state["output_bytes"] >= output_at_start + 64 * 1024)


def stop_background_flood(client, streams, stream):
    state = streams[stream]
    marker = b"__FLOOD_STOPPED__"
    send_input(client, streams, stream, b"kill %1; printf '" + marker + b"'\n")
    wait_for(client, streams, lambda: marker in state["recent_output"])


def sample_echoes(client, streams, stream, count):
    """Type `count` single keys one at a time; return per-key times to the agent's Ack and to the PTY echo (ms)."""
    state = streams[stream]
    ack_ms = []
    echo_ms = []
    for _ in range(count):
        target_ack = state["entered"] + len(ECHO_KEY)
        target_echo = state["echoes"] + len(ECHO_KEY)
        started = time.perf_counter()
        state["pending_ack"] = [target_ack, started, None]
        state["pending_echo"] = [target_echo, started, None]
        send_input(client, streams, stream, ECHO_KEY)
        while state["pending_ack"][2] is None or state["pending_echo"][2] is None:
            frame(client, streams)
        ack_ms.append((state["pending_ack"][2] - started) * 1000)
        echo_ms.append((state["pending_echo"][2] - started) * 1000)
        state["pending_ack"] = None
        state["pending_echo"] = None
    return ack_ms, echo_ms


def fence(client, streams, nonce):
    """Send a Ping and read frames until its Pong: everything the agent queued before it has arrived."""
    client.send(0, 0x08, struct.pack("<QQ", nonce, 0))
    while frame(client, streams) != (0, 0x09):
        pass


def sample_reattach(client, streams, stream, count):
    """Re-attach one terminal over the same live link `count` times (the D375 resumed-link row).

    Each round releases the window (Close), fences with a Ping so no old frame
    is in flight, then sends Attach with the current cursors and a fresh credit
    window. The clock stops at the agent's Ack: the agent has confirmed the
    attachment and recovered the shim's input state, so the terminal is up to
    date and accepts keys. One key is then typed and its echo awaited, to prove
    the terminal is typable; that echo time is reported, not gated.
    Returns (attach-to-Ack ms, attach-to-echo ms) per round.
    """
    state = streams[stream]
    ready_ms = []
    echo_ms = []
    for nonce in range(1, count + 1):
        client.send(stream, 0x0f, struct.pack("<H", 0) + b"window released")
        fence(client, streams, nonce)
        state["credit_pending"] = 0
        started = time.perf_counter()
        state["pending_ack"] = [state["acked"], started, None]
        client.send(stream, 0x16, state["id"].bytes + struct.pack("<QQ", state["out"], state["acked"]))
        client.send(stream, 0x14, struct.pack("<I", 1024 * 1024))
        while state["pending_ack"][2] is None:
            frame(client, streams)
        ready_ms.append((state["pending_ack"][2] - started) * 1000)
        state["pending_ack"] = None
        state["pending_echo"] = [state["echoes"] + len(ECHO_KEY), started, None]
        send_input(client, streams, stream, ECHO_KEY)
        while state["pending_echo"][2] is None:
            frame(client, streams)
        echo_ms.append((state["pending_echo"][2] - started) * 1000)
        state["pending_echo"] = None
    return ready_ms, echo_ms


def measure_without_network(binary, state_dir, samples):
    """Run a second agent with the relay delay at 0 and measure own overhead and idle memory.

    Returns (echo samples in ms, idle RSS with no session in kB, idle RSS with one
    quiet session in kB). The relay still forwards bytes, but adds no delay or
    jitter, so the echo time is the agent, PTY and fixture's own work: the D296
    measure behind the ~25 ms baseline.
    """
    previous = os.environ.get("INFRATERNAL_TEST_RTT")
    os.environ["INFRATERNAL_TEST_RTT"] = "0"
    try:
        client = Binary(binary.resolve(), state_dir)
    finally:
        if previous is None:
            del os.environ["INFRATERNAL_TEST_RTT"]
        else:
            os.environ["INFRATERNAL_TEST_RTT"] = previous
    try:
        # sleep: no protocol event says "the agent is idle"; give startup allocations a second to settle before reading RSS.
        time.sleep(1.0)
        idle_kb = rss(client.child.pid)
        streams = {1: new_stream_state(client.open())}
        attach_streams(client, streams)
        prepare_cat(client, streams, 1, "__OVERHEAD_READY__")
        _, echo = sample_echoes(client, streams, 1, samples)
        # sleep: same settle window as above, now with one quiet session attached.
        time.sleep(1.0)
        session_kb = rss(client.child.pid)
        return echo, idle_kb, session_kb
    finally:
        client.kill()
        cleanup(state_dir)


def run(binary, state_dir, overhead_state, samples):
    """Measure every native D375 row, print them, and raise when a gated row or component failed."""
    config = LatencyConfig.from_environment()
    round_trip_ms = targets.round_trip_bound_ms(config.rtt_ms, config.jitter_ms)
    rtt_echo_budget_ms = round_trip_ms + REAL_ECHO_FRAMES_MS
    failed_metrics = []

    overhead_echo, idle_kb, session_kb = measure_without_network(binary, overhead_state, samples)
    overhead_p99 = percentile(overhead_echo, 0.99)
    overhead_line = targets.row_line(
        "own_overhead", source="real-agent-pty", n=len(overhead_echo), value=overhead_p99, unit="ms",
        target=targets.FRAME_MS, gate=targets.OWN_OVERHEAD_BASELINE_MS,
        extra=f"p50_ms={percentile(overhead_echo, 0.50):.2f} rtt_ms=0 stretch_ms=5.00")
    print(overhead_line, flush=True)
    rss_mb = max(idle_kb, session_kb) * 1024 / 1_000_000
    rss_line = targets.row_line(
        "idle_agent_rss", source="real-agent", n=2, value=rss_mb, unit="MB", target=targets.IDLE_AGENT_RSS_MB,
        extra=f"no_session_kb={idle_kb} one_quiet_session_kb={session_kb}")
    print(rss_line, flush=True)
    failed_metrics += [name for name, line in (("own_overhead", overhead_line), ("idle_agent_rss", rss_line))
                       if "result=FAIL" in line]

    client = Binary(binary.resolve(), state_dir)
    try:
        ids = [client.open(), client.open(), client.open()]
        streams = {stream: new_stream_state(session_id) for stream, session_id in zip((1, 3, 5), ids, strict=True)}
        attach_streams(client, streams)
        prepare_cat(client, streams, 1, "__BASELINE_READY__")
        baseline_ack, baseline_echo = sample_echoes(client, streams, 1, samples)
        _, baseline_ack_p99 = metric("keystroke_echo_confirmed_baseline", baseline_ack, rtt_echo_budget_ms)
        _, baseline_echo_p99 = metric("keystroke_pty_echo_baseline", baseline_echo, rtt_echo_budget_ms)
        if baseline_ack_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_echo_confirmed_baseline")
        if baseline_echo_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_pty_echo_baseline")

        # Session 5 runs `yes` while stream 1 receives input and echoes it through a separate PTY.
        start_flood(client, streams, 5, "yes &")
        other_ack, other_echo = sample_echoes(client, streams, 1, samples)
        _, other_ack_p99 = metric("keystroke_echo_confirmed_flood_other_session", other_ack, rtt_echo_budget_ms)
        _, other_echo_p99 = metric("keystroke_pty_echo_flood_other_session", other_echo, rtt_echo_budget_ms)
        other_growth = other_echo_p99 - baseline_echo_p99
        print(
            f"METRIC name=flood_isolation_other_session source=real-agent-pty n={samples} "
            f"baseline_p99_ms={baseline_echo_p99:.2f} flood_p99_ms={other_echo_p99:.2f} "
            f"growth_ms={other_growth:.2f} budget_ms={FLOOD_DELTA_BUDGET_MS:.2f} "
            f"result={'PASS' if other_growth <= FLOOD_DELTA_BUDGET_MS else 'FAIL'}",
            flush=True,
        )
        if other_ack_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_echo_confirmed_flood_other_session")
        if other_echo_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_pty_echo_flood_other_session")
        if other_growth > FLOOD_DELTA_BUDGET_MS:
            failed_metrics.append("flood_isolation_other_session")

        stop_background_flood(client, streams, 5)

        # The terminal on stream 1 is quiet again: re-attach it over the same link.
        ready_ms, reattach_echo_ms = sample_reattach(client, streams, 1, REATTACH_SAMPLES)
        resumed_line = targets.row_line(
            "reconnect_resumed_link", source="real-agent-pty", n=len(ready_ms), value=percentile(ready_ms, 0.99),
            unit="ms", target=round_trip_ms + targets.RECONNECT_ALLOWANCE_MS,
            extra=(f"p50_ms={percentile(ready_ms, 0.50):.2f} first_key_echo_p99_ms={percentile(reattach_echo_ms, 0.99):.2f} "
                   f"rtt_ms={config.rtt_ms} jitter_ms={config.jitter_ms}"))
        print(resumed_line, flush=True)
        if "result=FAIL" in resumed_line:
            failed_metrics.append("reconnect_resumed_link")

        # Session 3 runs a PTY writer and `cat` concurrently; x is distinguishable from `yes`'s y\n.
        same_flood_start = streams[3]["output_bytes"]
        same_command = b"stty raw -echo; yes & cat\n"
        send_input(client, streams, 3, same_command)
        wait_for(client, streams, lambda: streams[3]["output_bytes"] >= same_flood_start + 64 * 1024)
        streams[3]["echoes"] = 0
        same_ack, same_echo = sample_echoes(client, streams, 3, samples)
        _, same_ack_p99 = metric("keystroke_echo_confirmed_flood_same_session", same_ack, rtt_echo_budget_ms)
        _, same_echo_p99 = metric("keystroke_pty_echo_flood_same_session", same_echo, rtt_echo_budget_ms)
        same_growth = same_echo_p99 - baseline_echo_p99
        print(
            f"METRIC name=flood_isolation_same_session source=real-agent-pty n={samples} "
            f"baseline_p99_ms={baseline_echo_p99:.2f} flood_p99_ms={same_echo_p99:.2f} "
            f"growth_ms={same_growth:.2f} budget_ms={FLOOD_DELTA_BUDGET_MS:.2f} "
            f"result={'PASS' if same_growth <= FLOOD_DELTA_BUDGET_MS else 'FAIL'}",
            flush=True,
        )
        if same_ack_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_echo_confirmed_flood_same_session")
        if same_echo_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_pty_echo_flood_same_session")
        if same_growth > FLOOD_DELTA_BUDGET_MS:
            failed_metrics.append("flood_isolation_same_session")
        worst = max(other_growth, same_growth)
        flood_line = targets.row_line(
            "flood_effect", source="real-agent-pty", n=samples, value=worst, unit="ms", target=FLOOD_DELTA_BUDGET_MS,
            extra=f"other_session_ms={other_growth:.2f} same_session_ms={same_growth:.2f} baseline_p99_ms={baseline_echo_p99:.2f}")
        print(flood_line, flush=True)
        if failed_metrics:
            raise AssertionError("latency budget failures: " + ", ".join(failed_metrics))
    finally:
        client.kill()
        cleanup(state_dir)


def parser_args():
    """Command line: the agent binary to measure, the samples per probe, and a private state path."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=PROBE_SAMPLES)
    parser.add_argument("--state", type=Path, default=fixture_state("l"))
    parser.add_argument("--overhead-state", type=Path, default=fixture_state("o"))
    return parser.parse_args()


if __name__ == "__main__":
    args = parser_args()
    if args.samples < 20:
        raise SystemExit("--samples must be at least 20 for p99")
    args.state.mkdir(mode=0o700, parents=True, exist_ok=False)
    args.overhead_state.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        run(args.binary, args.state, args.overhead_state, args.samples)
    finally:
        # Idempotent: a failure before the profile client starts still leaves no state behind.
        cleanup(args.state)
        cleanup(args.overhead_state)
