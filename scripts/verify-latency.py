"""Gate real PTY echo and flood isolation through the configured high-latency agent link [#55, D41, D122, D130].

The fixture plays the browser's part of the output flow control: it returns
credit for every Output and Snapshot byte it receives, as the tracer does
(#477). A Snapshot is a repaint that replaces raw output the agent skipped
after a key or its credit starvation deadline, so raw echo bytes inside a
flooding session can legitimately never arrive. The initial credit includes
the relay's 64 KiB repaint reserve. The same-session phase therefore measures
each key's visible effect: a numbered token drawn on row 1, read from raw
output or from a repaint, whichever comes first.
"""
import argparse
import os
from pathlib import Path
import re
import struct
import sys
import time
sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state
from latency_proxy import LatencyConfig


FRAME_MS = 1000 / 60
FLOOD_DELTA_BUDGET_MS = FRAME_MS
PROBE_SAMPLES = 100
# Keep the 1 MiB bulk window while also funding the relay's 64 KiB key repaint reserve.
INITIAL_CREDIT = 1024 * 1024 + 64 * 1024
ECHO_KEY = b"x"
# Longest wait for one key's Ack and echo. A key that never shows is a typing
# freeze: fail with the stream's flow state instead of hanging the gate.
SAMPLE_TIMEOUT_S = 30
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
    observe_tokens(state, state["token_tail"] + data)
    state["token_tail"] = (state["token_tail"] + data)[-TOKEN_TAIL:]
    return_credit(client, stream, state, len(data))
    settle_echo(state)


def observe_tokens(state, data):
    """Record the newest row-1 token found in raw output or a repaint."""
    for match in TOKEN.finditer(data):
        state["token"] = max(state["token"], int(match.group(1)))


def settle_echo(state):
    """Stamp the pending key once its echo (raw `x` or row-1 token) is visible."""
    pending = state.get("pending_echo")
    if not pending or pending[2] is not None:
        return
    seen = state["token"] if state["echo_by_token"] else state["echoes"]
    if seen >= pending[0]:
        pending[2] = time.perf_counter()


def return_credit(client, stream, state, length):
    """Return the credit of each received frame at once, as the tracer does after painting each write.

    Holding credit back until 64 KiB had built up made the fixture slower to
    refill the window than any browser, and that alone added ~100 ms to the
    same-session echo tail (#477).
    """
    if length > 0:
        client.send(stream, 0x14, struct.pack("<I", length))


def frame(client, streams):
    """Read one mux frame and update its stream's Ack/Output state."""
    stream, kind, body = client.read()
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
        state["out"] = sequence
        state["repaints"] += 1
        state["token_tail"] = b""
        observe_tokens(state, body[8:])
        return_credit(client, stream, state, len(body) - 8)
        settle_echo(state)
    elif kind == 0x33:
        pass
    else:
        raise AssertionError(f"unexpected stream frame {(stream, kind)}")
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


def run(binary, state_dir, samples):
    config = LatencyConfig.from_environment()
    rtt_echo_budget_ms = config.rtt_ms + 2 * 17
    failed_metrics = []
    client = Binary(binary.resolve(), state_dir)
    try:
        ids = [client.open(), client.open(), client.open()]
        streams = {
            stream: {
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
                "recent_output": bytearray(),
                "pending_ack": None,
                "pending_echo": None,
            }
            for stream, session_id in zip((1, 3, 5), ids, strict=True)
        }
        for stream, state in streams.items():
            client.send(stream, 0x16, state["id"].bytes + struct.pack("<QQ", 0, 0))
            client.send(stream, 0x14, struct.pack("<I", INITIAL_CREDIT))
        wait_for(client, streams, lambda: all(state["acked"] == 0 for state in streams.values()))

        # Keep only a small rolling marker tail while still crediting every PTY Output byte.
        for state in streams.values():
            state["recent_output"] = bytearray()
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
            f"d375_target_ms={1000 / 120:.2f} "
            f"result={'PASS' if same_growth <= FLOOD_DELTA_BUDGET_MS else 'FAIL'}",
            flush=True,
        )
        if same_ack_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_echo_confirmed_flood_same_session")
        if same_echo_p99 > rtt_echo_budget_ms:
            failed_metrics.append("keystroke_pty_echo_flood_same_session")
        if same_growth > FLOOD_DELTA_BUDGET_MS:
            failed_metrics.append("flood_isolation_same_session")
        if failed_metrics:
            raise AssertionError("latency budget failures: " + ", ".join(failed_metrics))
    finally:
        client.kill()
        cleanup(state_dir)


def parser_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=PROBE_SAMPLES)
    parser.add_argument("--state", type=Path, default=fixture_state("l"))
    return parser.parse_args()


if __name__ == "__main__":
    args = parser_args()
    if args.samples < 20:
        raise SystemExit("--samples must be at least 20 for p99")
    args.state.mkdir(mode=0o700, parents=True, exist_ok=False)
    run(args.binary, args.state, args.samples)
