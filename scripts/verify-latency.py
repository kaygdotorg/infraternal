"""Measure the native D375 rows on the real infraternal agent and PTY [#55, D375, D296, D259, D122, D130].

This probe drives the real agent binary over its fixture socket, through the
same latency relay the browser suite uses, and prints the D375 rows the browser
cannot see:

- `real_echo` as a component line (`keystroke_pty_echo_*`): key in, PTY echo out,
  through the configured round trip. The D375 row itself is the browser's
  key-to-paint number; the agent's share is gated here against the same bound;
- `flood_effect`: how much a flooding terminal (another session, then the same
  one) grows echo p99;
- the agent's share of `own_overhead`: echo p99 with no network at all (relay
  delay 0), printed as `own_overhead_agent`; the report adds the browser's
  share to form the row;
- `reconnect_resumed_link`: re-attaching a terminal over a link that stays up,
  from Attach sent to the agent's acknowledgement (the terminal is current and
  accepts keys), then one key's echo as proof it is typable;
- `idle_agent_rss`: the agent's resident memory when idle, with no session and
  with one quiet session; the larger is the row.

Each row is a `METRIC name=d375_<key>` line from `latency_targets.row_line()`
(own overhead is composed by the report from the two shares).
The process exits non-zero when a gated row or component fails;
`latency_targets.py report` then prints the whole table for the run.

The fixture plays the browser's part of the output flow control: it returns
credit for every Output and Snapshot byte it receives, as the tracer does
(#477). A Snapshot is a repaint that replaces raw output the agent skipped
after a key or its credit starvation deadline, so raw echo bytes inside a
flooding session can legitimately never arrive. The initial credit includes
the relay's 64 KiB repaint reserve. The same-session phase therefore measures
each key's visible effect: a numbered token drawn on row 1, read from raw
output or from a repaint, whichever comes first.

Repaint bytes are terminal-control programs, so marker and token checks strip
those controls before searching. Credit is still refunded by the wire byte
length after a simulated 120 Hz paint frame. The fixture batches all frames
already waiting before that boundary; the browser profile separately uses the
real Ghostty paint callback.
"""
import argparse
import os
from pathlib import Path
import re
import select
import signal
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
# Keep the 1 MiB bulk window while also funding the relay's 64 KiB key repaint reserve.
INITIAL_CREDIT = 1024 * 1024 + 64 * 1024
ECHO_KEY = b"x"
#: The longest one key's Ack and echo (or one re-attach) may take before the probe fails instead of waiting on. Echo
#: under a same-session flood has measured up to ~0.5 s at 300 ms RTT, so 30 s only trips on a stalled stream (a key that never shows is a typing
#: freeze: fail with the stream's flow state instead of hanging the gate).
SAMPLE_TIMEOUT_S = 30
# The fixture returns queued wire bytes at its next simulated terminal paint.
PAINT_INTERVAL_S = targets.FRAME_MS / 1000
# The same-session program draws `<K000001>`, `<K000002>`, ... on row 1 for
# successive keys and starts `yes` when it reads FLOOD_KEY. One write(2) per
# token keeps it whole between `yes` writes; the scroll region `ESC [2r` keeps
# `yes` off row 1, so the newest token is on screen, and thus in a repaint.
TOKEN = re.compile(rb"<K(\d{6})>")
TOKEN_TAIL = 16
FLOOD_KEY = b"F"
TOKEN_PROGRAM = (
    b"stty raw -echo; printf '\\033[2J\\033[2r'; n=0; "
    b"while IFS= read -rsn1 c; do "
    b"if [ \"$c\" = F ]; then yes & "
    b"else n=$((n+1)); printf '\\0337\\033[1;1H<K%06d>\\0338' \"$n\"; fi; "
    b"done\n"
)


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


def visible_snapshot_text(data):
    """Return screen characters from an ANSI repaint without changing wire accounting.

    Snapshot frames position and style cells with terminal controls, often
    between every visible character. The fixture searches the flattened screen
    text for markers and key tokens; callers must still refund the original
    snapshot byte length because those controls were sent to the client.
    """
    visible = bytearray()
    offset = 0
    while offset < len(data):
        current = data[offset]
        if current == 0x1B:
            offset += 1
            if offset >= len(data):
                break
            kind = data[offset]
            offset += 1
            if kind == ord("["):
                while offset < len(data) and not 0x40 <= data[offset] <= 0x7E:
                    offset += 1
                if offset < len(data):
                    offset += 1
            elif kind in (ord("]"), ord("P"), ord("X"), ord("^"), ord("_")):
                while offset < len(data):
                    if kind == ord("]") and data[offset] == 0x07:
                        offset += 1
                        break
                    if data[offset] == 0x1B and offset + 1 < len(data) and data[offset + 1] == ord("\\"):
                        offset += 2
                        break
                    offset += 1
            elif kind in (ord("("), ord(")"), ord("*"), ord("+"), ord("-"), ord("."), ord("/"), ord("#")):
                if offset < len(data):
                    offset += 1
        elif current < 0x20 or current == 0x7F:
            offset += 1
        else:
            visible.append(current)
            offset += 1
    return bytes(visible)


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
    observe_tokens(state, state["token_tail"] + data)
    state["token_tail"] = (state["token_tail"] + data)[-TOKEN_TAIL:]
    queue_paint_credit(client, stream, state, len(data))


def observe_tokens(state, data):
    """Record the newest row-1 token found in raw output or a repaint."""
    for match in TOKEN.finditer(data):
        state["token"] = max(state["token"], int(match.group(1)))


def settle_echo(state):
    """Stamp and report a pending key once its echo is visible after paint."""
    pending = state.get("pending_echo")
    if not pending or pending[2] is not None:
        return False
    seen = state["token"] if state["echo_by_token"] else state["echoes"]
    if seen >= pending[0]:
        pending[2] = time.perf_counter()
        return True
    return False


def queue_paint_credit(client, stream, state, length):
    """Hold received wire bytes until the next paint callback returns their credit."""
    if length > 0:
        state["paint_credit_pending"] = state.get("paint_credit_pending", 0) + length
        if getattr(client, "paint_frame_due", None) is None:
            client.paint_frame_due = time.monotonic() + PAINT_INTERVAL_S


def paint_frame(client, streams):
    """Paint queued updates, return exact wire credit, and report completed echoes."""
    settled_echo = False
    for stream, state in streams.items():
        pending = state.get("paint_credit_pending", 0)
        if pending > 0:
            state["paint_credit_pending"] = 0
            client.send(stream, 0x14, struct.pack("<I", pending))
        settled_echo = settle_echo(state) or settled_echo
    client.paint_frame_due = None
    return settled_echo


def paint_if_due(client, streams):
    """Paint due output and report whether that paint completed a pending echo."""
    if not any(state.get("paint_credit_pending", 0) for state in streams.values()):
        return False
    sock = getattr(client, "sock", None)
    if sock is None:
        return False
    remaining = getattr(client, "paint_frame_due", time.monotonic()) - time.monotonic()
    if remaining > 0:
        readable, _, _ = select.select([sock], [], [], remaining)
        if readable:
            return False
    return paint_frame(client, streams)


def frame(client, streams):
    """Read one mux frame and update its stream's Ack/Output state.

    Returns `(stream, kind)` so a caller waiting for a connection-level reply
    (stream 0, such as a Pong fence) can see it; other stream-0 frames are ignored.
    """
    if paint_if_due(client, streams):
        return
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
        # A repaint replaces skipped raw output. It costs credit like Output,
        # and the tracer returns that credit once painted; a fixture that kept
        # it would shrink the window by one repaint per starvation cycle.
        sequence = struct.unpack("<Q", body[:8])[0]
        data = body[8:]
        state["out"] = sequence
        state["repaints"] += 1
        state["token_tail"] = b""
        # Screen matching uses visible cells; flow control still uses wire bytes.
        visible = visible_snapshot_text(data)
        state["recent_output"] = bytearray(visible[-4096:])
        observe_tokens(state, visible)
        queue_paint_credit(client, stream, state, len(data))
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
        "repaints": 0,
        "echo_by_token": False,
        "token": 0,
        "token_keys": 0,
        "token_tail": b"",
        "paint_credit_pending": 0,
        "recent_output": bytearray(),
        "pending_ack": None,
        "pending_echo": None,
    }


def attach_streams(client, streams):
    """Attach every stream from cursor zero with the initial credit window (1 MiB plus the repaint reserve) and wait for the agent's Acks."""
    for stream, state in streams.items():
        client.send(stream, 0x16, state["id"].bytes + struct.pack("<QQ", 0, 0))
        client.send(stream, 0x14, struct.pack("<I", INITIAL_CREDIT))
    wait_for(client, streams, lambda: all(state["acked"] == 0 for state in streams.values()))
    # Keep only a small rolling marker tail while still crediting every PTY Output byte.
    for state in streams.values():
        state["recent_output"] = bytearray()


def wait_for(client, streams, predicate, timeout=20, what="its expected marker"):
    """Read frames until `predicate()` holds; raise TimeoutError after `timeout` seconds.

    The deadline is checked between frames, so a link that keeps delivering
    unrelated frames (connection-level traffic on stream 0) can never keep a
    probe waiting forever: a stalled stream fails the run instead of holding
    its build slot.
    """
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"PTY latency fixture did not reach {what} within {timeout} s")
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
    """Type `count` keys one at a time; return each key's Ack and echo latency in ms.

    The echo is the raw `x` from `cat`, or the key's row-1 token when the
    stream runs TOKEN_PROGRAM (`echo_by_token`). A key that shows nothing
    within SAMPLE_TIMEOUT_S fails with the stream's flow state.
    """
    state = streams[stream]
    ack_ms = []
    echo_ms = []
    for _ in range(count):
        target_ack = state["entered"] + len(ECHO_KEY)
        if state["echo_by_token"]:
            state["token_keys"] += 1
            target_echo = state["token_keys"]
        else:
            target_echo = state["echoes"] + len(ECHO_KEY)
        started = time.perf_counter()
        state["pending_ack"] = [target_ack, started, None]
        state["pending_echo"] = [target_echo, started, None]
        send_input(client, streams, stream, ECHO_KEY)
        deadline = time.monotonic() + SAMPLE_TIMEOUT_S
        while state["pending_ack"][2] is None or state["pending_echo"][2] is None:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"stream {stream} key {len(echo_ms) + 1} showed no "
                    f"{'Ack' if state['pending_ack'][2] is None else 'echo'} within {SAMPLE_TIMEOUT_S} s "
                    f"(output_bytes={state['output_bytes']} repaints={state['repaints']} "
                    f"token={state['token']})"
                )
            frame(client, streams)
        ack_ms.append((state["pending_ack"][2] - started) * 1000)
        echo_ms.append((state["pending_echo"][2] - started) * 1000)
        state["pending_ack"] = None
        state["pending_echo"] = None
    return ack_ms, echo_ms


def fence(client, streams, nonce):
    """Send a Ping and read frames until its Pong: everything the agent queued before it has arrived."""
    client.send(0, 0x08, struct.pack("<QQ", nonce, 0))
    deadline = time.monotonic() + SAMPLE_TIMEOUT_S
    while frame(client, streams) != (0, 0x09):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"no Pong for fence {nonce} within {SAMPLE_TIMEOUT_S} s")


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
        state["paint_credit_pending"] = 0
        started = time.perf_counter()
        state["pending_ack"] = [state["acked"], started, None]
        client.send(stream, 0x16, state["id"].bytes + struct.pack("<QQ", state["out"], state["acked"]))
        client.send(stream, 0x14, struct.pack("<I", INITIAL_CREDIT))
        wait_for(client, streams, lambda: state["pending_ack"][2] is not None, timeout=SAMPLE_TIMEOUT_S,
                 what=f"the Ack of a re-attach on stream {stream}")
        ready_ms.append((state["pending_ack"][2] - started) * 1000)
        state["pending_ack"] = None
        state["pending_echo"] = [state["echoes"] + len(ECHO_KEY), started, None]
        send_input(client, streams, stream, ECHO_KEY)
        wait_for(client, streams, lambda: state["pending_echo"][2] is not None, timeout=SAMPLE_TIMEOUT_S,
                 what=f"the first key's echo after a re-attach on stream {stream}")
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
    # The agent's share of the own-overhead row; the report adds the browser's share (latency_targets.compose_own_overhead).
    print(f"METRIC name=own_overhead_agent source=real-agent-pty n={len(overhead_echo)} "
          f"p50_ms={percentile(overhead_echo, 0.50):.2f} p99_ms={percentile(overhead_echo, 0.99):.2f} rtt_ms=0 result=REPORT",
          flush=True)
    rss_mb = max(idle_kb, session_kb) * 1024 / 1_000_000
    rss_line = targets.row_line(
        "idle_agent_rss", source="real-agent", n=2, value=rss_mb, unit="MB", target=targets.IDLE_AGENT_RSS_MB,
        extra=f"no_session_kb={idle_kb} one_quiet_session_kb={session_kb}")
    print(rss_line, flush=True)
    if "result=FAIL" in rss_line:
        failed_metrics.append("idle_agent_rss")

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

        # Session 3 types into TOKEN_PROGRAM: first quiet, as this phase's own
        # baseline, then with `yes` writing into the same PTY. Under the flood the
        # agent may skip raw output for a repaint (#477), and `yes` would scroll
        # a raw `x` away at once; the row-1 token stays visible in either form.
        same = streams[3]
        same["echo_by_token"] = True
        send_input(client, streams, 3, TOKEN_PROGRAM)
        sample_echoes(client, streams, 3, 1)  # the loop is reading keys
        _, same_quiet_echo = sample_echoes(client, streams, 3, samples)
        _, same_quiet_p99 = metric("keystroke_token_echo_quiet_same_session", same_quiet_echo, rtt_echo_budget_ms)
        send_input(client, streams, 3, FLOOD_KEY)
        same_flood_start = same["output_bytes"]
        wait_for(client, streams, lambda: same["output_bytes"] >= same_flood_start + 64 * 1024)
        cursor_start, delivered_start, repaints_start = same["out"], same["output_bytes"], same["repaints"]
        flood_started = time.perf_counter()
        same_ack, same_echo = sample_echoes(client, streams, 3, samples)
        flood_seconds = time.perf_counter() - flood_started
        # `produced` follows the agent's output cursor, which a repaint moves past
        # skipped bytes: it is how fast the flooding program ran. `delivered` is
        # the raw output that reached this client.
        print(
            f"METRIC name=flood_throughput_same_session source=real-agent-pty seconds={flood_seconds:.2f} "
            f"produced_mb_s={(same['out'] - cursor_start) / flood_seconds / 1e6:.2f} "
            f"delivered_mb_s={(same['output_bytes'] - delivered_start) / flood_seconds / 1e6:.2f} "
            f"repaints={same['repaints'] - repaints_start} result=REPORT",
            flush=True,
        )
        _, same_ack_p99 = metric("keystroke_echo_confirmed_flood_same_session", same_ack, rtt_echo_budget_ms)
        _, same_echo_p99 = metric("keystroke_pty_echo_flood_same_session", same_echo, rtt_echo_budget_ms)
        same_growth = same_echo_p99 - same_quiet_p99
        print(
            f"METRIC name=flood_isolation_same_session source=real-agent-pty n={samples} "
            f"baseline_p99_ms={same_quiet_p99:.2f} flood_p99_ms={same_echo_p99:.2f} "
            f"growth_ms={same_growth:.2f} budget_ms={FLOOD_DELTA_BUDGET_MS:.2f} "
            f"d375_target_ms={FLOOD_DELTA_BUDGET_MS:.2f} "
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
    # A stopped run (SIGTERM from a slot timeout or an operator) still reaches the cleanup below, so the agent, its
    # shims and their `yes`/`cat` children are not left running (a J407 run on dev-02 left nine such processes).
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
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
