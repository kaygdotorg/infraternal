"""Gate real PTY echo and flood isolation through the configured high-latency agent link [#55, D41, D122, D130]."""
import argparse
import os
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state
from latency_proxy import LatencyConfig


FRAME_MS = 1000 / 60
FLOOD_DELTA_BUDGET_MS = FRAME_MS
PROBE_SAMPLES = 100
ECHO_KEY = b"x"


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
    state["credit_pending"] += len(data)
    if state["credit_pending"] >= 64 * 1024:
        client.send(stream, 0x14, struct.pack("<I", state["credit_pending"]))
        state["credit_pending"] = 0
    if state.get("pending_echo") and state["echoes"] >= state["pending_echo"][0]:
        state["pending_echo"][2] = time.perf_counter()


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
        sequence = struct.unpack("<Q", body[:8])[0]
        state["out"] = sequence
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
                "credit_pending": 0,
                "recent_output": bytearray(),
                "pending_ack": None,
                "pending_echo": None,
            }
            for stream, session_id in zip((1, 3, 5), ids, strict=True)
        }
        for stream, state in streams.items():
            client.send(stream, 0x16, state["id"].bytes + struct.pack("<QQ", 0, 0))
            client.send(stream, 0x14, struct.pack("<I", 1024 * 1024))
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
