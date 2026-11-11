"""Run the J88c app mesh fixture and sample its live GotaTun counters."""

from __future__ import annotations

import argparse
import json
import os
import re
import select
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def flatten_node_counters(status: dict[str, Any], peer_page: dict[str, Any]) -> dict[str, int]:
    """Keep GotaTun health and byte totals while dropping peer identity fields."""
    engine = status.get("engine")
    engine = engine if isinstance(engine, dict) else {}
    peers = peer_page.get("peers")
    peers = peers if isinstance(peers, list) else []
    counters = [
        row.get("counters", {})
        for row in peers
        if isinstance(row, dict) and isinstance(row.get("counters"), dict)
    ]
    output = {
        "gotatun_stopped": int(bool(engine.get("stopped", False))),
        "gotatun_restarts": int(engine.get("restarts", 0) or 0),
        "gotatun_refused_frames": int(engine.get("refused_frames", 0) or 0),
        "gotatun_tx_bytes": sum(int(row.get("sent_bytes", 0) or 0) for row in counters),
        "gotatun_rx_bytes": sum(int(row.get("received_bytes", 0) or 0) for row in counters),
        "gotatun_handshakes": sum(int(row.get("handshake_secs", 0) or 0) > 0 for row in counters),
    }
    queue_length = engine.get("tx_queue_len")
    if queue_length is not None:
        output["tun_tx_queue_len"] = int(queue_length)
    return output


def process_counters(pid: int) -> dict[str, int]:
    """Read RSS, descriptors, threads, CPU ticks and context switches from procfs."""
    process = Path("/proc") / str(pid)
    status = _status_fields((process / "status").read_text(encoding="ascii"))
    stat = (process / "stat").read_text(encoding="ascii")
    rest = stat[stat.rfind(")") + 1 :].split()
    return {
        "rss_bytes": status.get("VmRSS", 0) * 1024,
        "fd_count": len(list((process / "fd").iterdir())),
        "thread_count": status.get("Threads", 0),
        "cpu_ticks": int(rest[11]) + int(rest[12]),
        "voluntary_context_switches": status.get("voluntary_ctxt_switches", 0),
        "involuntary_context_switches": status.get("nonvoluntary_ctxt_switches", 0),
    }


def _status_fields(contents: str) -> dict[str, int]:
    """Read the integer fields needed from one `/proc/<pid>/status` snapshot."""
    fields: dict[str, int] = {}
    wanted = {
        "VmRSS",
        "Threads",
        "voluntary_ctxt_switches",
        "nonvoluntary_ctxt_switches",
    }
    for line in contents.splitlines():
        name, separator, value = line.partition(":")
        if name in wanted and separator:
            fields[name] = int(value.split()[0])
    return fields


def qdisc_counters(interface: str, namespace_pid: int | None = None) -> dict[str, int]:
    """Read queue backlog and drops for one TUN qdisc without changing it."""
    tc = shutil.which("tc")
    if tc is None:
        return {"qdisc_available": 0}
    command = [tc, "-j", "-s", "qdisc", "show", "dev", interface]
    if namespace_pid is not None:
        nsenter = shutil.which("nsenter")
        if nsenter is None:
            return {"qdisc_available": 0}
        command = [nsenter, "-t", str(namespace_pid), "-n", "--", *command]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return {"qdisc_available": 0}
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"qdisc_available": 0}
    backlog_bytes = 0
    backlog_packets = 0
    drops = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        backlog = row.get("backlog", 0)
        if isinstance(backlog, dict):
            backlog_bytes += int(backlog.get("bytes", 0) or 0)
            backlog_packets += int(backlog.get("packets", 0) or 0)
        else:
            backlog_bytes += int(backlog or 0)
        backlog_packets += int(row.get("qlen", 0) or 0)
        drops += int(row.get("drops", 0) or 0)
    return {
        "qdisc_available": 1,
        "qdisc_backlog_bytes": backlog_bytes,
        "qdisc_backlog_packets": backlog_packets,
        "qdisc_drops": drops,
    }


def _sample_node(node: Any, pid: int) -> dict[str, int]:
    """Read one agent's mesh counters and its process resource snapshot."""
    status = node.call("mesh.status", {})
    peers = node.call("mesh.peers", {})
    return {
        **flatten_node_counters(status, peers),
        **{f"process_{name}": value for name, value in process_counters(pid).items()},
    }


def _write_counter_sample(
    output: Any, left: Any, right: Any, left_pid: int, right_pid: int, right_namespace_pid: int
) -> None:
    """Append one monotonic sample from both agent nodes and their TUN qdiscs."""
    started_ns = time.monotonic_ns()
    left_counters = _sample_node(left, left_pid)
    right_counters = _sample_node(right, right_pid)
    counters = {f"a_{name}": value for name, value in left_counters.items()}
    counters.update({f"b_{name}": value for name, value in right_counters.items()})
    counters.update({f"a_{name}": value for name, value in qdisc_counters("infraternal0").items()})
    counters.update(
        {f"a_underlay_{name}": value for name, value in qdisc_counters("underlay0").items()}
    )
    counters.update(
        {
            f"b_{name}": value
            for name, value in qdisc_counters("infraternal0", right_namespace_pid).items()
        }
    )
    counters.update(
        {
            f"b_underlay_{name}": value
            for name, value in qdisc_counters("underlay1", right_namespace_pid).items()
        }
    )
    ended_ns = time.monotonic_ns()
    row = {
        "timestamp_ns": (started_ns + ended_ns) // 2,
        "sample_duration_ns": ended_ns - started_ns,
        "counters": counters,
    }
    output.write(json.dumps(row, separators=(",", ":")) + "\n")
    output.flush()


def counter_poll_timeout_ns(*, now_ns: int, next_sample_ns: int, sampling_active: bool) -> int:
    """Wait up to one second for the start marker instead of spinning on its absence."""
    if not sampling_active:
        return 1_000_000_000
    return max(0, next_sample_ns - now_ns)


@dataclass(frozen=True, slots=True)
class PipelineQueueSample:
    """One process-relative GotaTun crypto-queue depth mapped to host monotonic time."""

    timestamp_ns: int
    side: str
    queue_jobs: int


class PipelineQueueClock:
    """Map one GotaTun process's relative queue timestamps to the host monotonic clock."""

    _PATTERN = re.compile(
        r"pipeline mono_ns=(?P<elapsed>\d+) "
        r"stage=crypto_queue_(?:push|pop) queued_jobs=(?P<queued>\d+)"
    )

    def __init__(self, side: str):
        """Create a clock for the app node labelled `a` or `b`."""
        if side not in {"a", "b"}:
            raise ValueError("pipeline side must be 'a' or 'b'")
        self.side = side
        self.offset_ns: int | None = None

    def observe(self, line: str, *, observed_ns: int) -> PipelineQueueSample | None:
        """Convert a queue log line using its first observed host-monotonic timestamp."""
        if observed_ns < 0:
            raise ValueError("observed monotonic timestamp must be non-negative")
        match = self._PATTERN.search(line)
        if match is None:
            return None
        elapsed_ns = int(match.group("elapsed"))
        if self.offset_ns is None:
            self.offset_ns = observed_ns - elapsed_ns
        timestamp_ns = self.offset_ns + elapsed_ns
        if timestamp_ns < 0:
            raise ValueError("mapped pipeline timestamp must be non-negative")
        return PipelineQueueSample(
            timestamp_ns=timestamp_ns,
            side=self.side,
            queue_jobs=int(match.group("queued")),
        )


class PipelineQueueAggregator:
    """Keep queue peaks in short host-monotonic buckets instead of one row per packet."""

    def __init__(self, *, bucket_ns: int = 100_000_000):
        """Collect per-node queue maxima and last values in buckets of `bucket_ns`."""
        if bucket_ns < 1:
            raise ValueError("pipeline queue bucket must be positive")
        self.bucket_ns = bucket_ns
        self._buckets: dict[int, dict[str, int]] = {}

    def record(self, sample: PipelineQueueSample) -> None:
        """Add one queue-depth event to its host-monotonic bucket."""
        if sample.side not in {"a", "b"} or sample.timestamp_ns < 0 or sample.queue_jobs < 0:
            raise ValueError("pipeline queue sample has invalid side, timestamp, or depth")
        started_ns = sample.timestamp_ns // self.bucket_ns * self.bucket_ns
        counters = self._buckets.setdefault(started_ns, {})
        prefix = f"{sample.side}_crypto_queue_jobs"
        counters[prefix] = sample.queue_jobs
        counters[f"{prefix}_max"] = max(
            counters.get(f"{prefix}_max", sample.queue_jobs), sample.queue_jobs
        )
        event_name = f"{sample.side}_crypto_queue_events"
        counters[event_name] = counters.get(event_name, 0) + 1

    def drain_before(self, before_ns: int) -> list[dict[str, Any]]:
        """Return complete buckets whose end is at or before `before_ns`."""
        ready = [
            started_ns
            for started_ns in sorted(self._buckets)
            if started_ns + self.bucket_ns <= before_ns
        ]
        return [self._take_bucket(started_ns) for started_ns in ready]

    def finish(self) -> list[dict[str, Any]]:
        """Return the remaining partial bucket rows when log capture ends."""
        return [self._take_bucket(started_ns) for started_ns in sorted(self._buckets)]

    def _take_bucket(self, started_ns: int) -> dict[str, Any]:
        """Remove one bucket and return the JSON row consumed by the trace reporter."""
        return {
            "timestamp_ns": started_ns,
            "counters": self._buckets.pop(started_ns),
        }


def main() -> None:
    """Start two production app nodes, publish readiness and sample until `quit`."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit-lib", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--coordinator", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--pid-b", required=True, type=int)
    parser.add_argument("--counter-output", required=True, type=Path)
    parser.add_argument("--pipeline-counters", required=True, type=Path)
    parser.add_argument("--pipeline-diagnostics", action="store_true")
    parser.add_argument("--counter-start-marker", required=True, type=Path)
    parser.add_argument("--counter-stop-marker", required=True, type=Path)
    parser.add_argument("--counter-interval-ms", type=int, default=1_000)
    arguments = parser.parse_args()
    if arguments.counter_interval_ms < 100:
        parser.error("counter interval must be at least 100 ms")
    sys.path.insert(0, str(arguments.kit_lib))
    from mesh_agent_fixture import BinaryNode, CoordinatorFixture

    arguments.counter_output.parent.mkdir(parents=True, exist_ok=True)
    arguments.pipeline_counters.parent.mkdir(parents=True, exist_ok=True)
    pipeline_output = arguments.pipeline_counters.open("w", encoding="utf-8")
    pipeline_readers: dict[str, Any] = {}
    pipeline_clocks: dict[str, PipelineQueueClock] = {}
    pipeline_bucket_ns = 100_000_000
    pipeline_aggregator = PipelineQueueAggregator(bucket_ns=pipeline_bucket_ns)
    coordinator: Any | None = None
    left: Any | None = None
    right: Any | None = None
    start_ns = time.monotonic_ns()
    interval_ns = arguments.counter_interval_ms * 1_000_000
    next_sample_ns = 0
    try:
        coordinator = CoordinatorFixture(
            str(arguments.coordinator), int(os.environ.get("H2H_IX_EXTRA_MEMBERS", "0"))
        )
        left = BinaryNode(str(arguments.binary), str(arguments.scratch))
        right = BinaryNode(str(arguments.binary), str(arguments.scratch), arguments.pid_b)
        if arguments.pipeline_diagnostics:
            for side, node in (("a", left), ("b", right)):
                log = getattr(node, "log", None)
                log_path = getattr(log, "name", None)
                if not isinstance(log_path, str):
                    raise RuntimeError("the mesh fixture does not expose its agent log path")
                pipeline_readers[side] = Path(log_path).open(
                    "r", encoding="utf-8", errors="replace"
                )
                pipeline_clocks[side] = PipelineQueueClock(side)
        identities = [json.loads(node.stdout.readline()) for node in (left, right)]
        compiled = coordinator.configuration("allow", identities)
        applied = []
        for index, node in enumerate((left, right)):
            for part in compiled["chunks"][index]:
                applied.append(node.request(part)["apply_us"])
        print(
            json.dumps(
                {
                    "start_ns": start_ns,
                    "peer_ipv4": compiled["addresses"][1]["ipv4"],
                    "self_ipv4": compiled["addresses"][0]["ipv4"],
                    "pids": [left.pid, right.pid],
                    "configure_apply_us": applied,
                }
            ),
            flush=True,
        )
        with arguments.counter_output.open("w", encoding="utf-8") as output:
            while True:
                now_ns = time.monotonic_ns()
                if arguments.pipeline_diagnostics:
                    for side, reader in pipeline_readers.items():
                        for line in reader:
                            sample = pipeline_clocks[side].observe(
                                line, observed_ns=time.monotonic_ns()
                            )
                            if sample is not None:
                                pipeline_aggregator.record(sample)
                    pipeline_rows = pipeline_aggregator.drain_before(
                        time.monotonic_ns() - pipeline_bucket_ns
                    )
                    for row in pipeline_rows:
                        pipeline_output.write(json.dumps(row, separators=(",", ":")) + "\n")
                    if pipeline_rows:
                        pipeline_output.flush()
                sampling_active = (
                    arguments.counter_start_marker.exists()
                    and not arguments.counter_stop_marker.exists()
                )
                if sampling_active:
                    if now_ns >= next_sample_ns:
                        _write_counter_sample(
                            output, left, right, left.pid, right.pid, arguments.pid_b
                        )
                        next_sample_ns = time.monotonic_ns() + interval_ns
                timeout_ns = counter_poll_timeout_ns(
                    now_ns=time.monotonic_ns(),
                    next_sample_ns=next_sample_ns,
                    sampling_active=sampling_active,
                )
                if arguments.pipeline_diagnostics:
                    timeout_ns = min(timeout_ns, 10_000_000)
                ready, _, _ = select.select(
                    [sys.stdin], [], [], min(timeout_ns, 1_000_000_000) / 1e9
                )
                if ready:
                    line = sys.stdin.readline()
                    if not line or line.strip() == "quit":
                        break
    finally:
        for node in (left, right):
            if node is not None:
                node.close()
        if arguments.pipeline_diagnostics:
            for side, reader in pipeline_readers.items():
                for line in reader:
                    sample = pipeline_clocks[side].observe(
                        line, observed_ns=time.monotonic_ns()
                    )
                    if sample is not None:
                        pipeline_aggregator.record(sample)
            for row in pipeline_aggregator.finish():
                pipeline_output.write(json.dumps(row, separators=(",", ":")) + "\n")
            for reader in pipeline_readers.values():
                reader.close()
        pipeline_output.close()
        if coordinator is not None:
            coordinator.close()


if __name__ == "__main__":
    main()
