"""Run one production-agent TCP flow beside monotonic tunnel probes and counters."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Mapping, TextIO


def net_tput_command(h2h: Path, destination: str, seconds: int) -> list[str]:
    """Build the J88c TCP load command with exactly one flow for this window."""
    try:
        ipaddress.IPv4Address(destination)
    except ipaddress.AddressValueError as error:
        raise ValueError("the tunnel destination must be an IPv4 address") from error
    if seconds < 1:
        raise ValueError("load duration must be positive")
    return [
        str(h2h),
        "net-tput",
        "--to",
        f"{destination}:5201",
        "--flows",
        "1",
        "--seconds",
        str(seconds),
    ]


def underlay_tbf_command(tc: Path, interface: str, rate_mbit: int) -> list[str]:
    """Build a small, bounded TBF queue for one side of the private underlay."""
    if interface not in {"underlay0", "underlay1"}:
        raise ValueError("the loaded soak can shape only its private underlay interfaces")
    if type(rate_mbit) is not int or not 100 <= rate_mbit <= 10_000:
        raise ValueError("the underlay rate must be between 100 and 10000 Mbit/s")
    return [
        str(tc),
        "qdisc",
        "replace",
        "dev",
        interface,
        "root",
        "tbf",
        "rate",
        f"{rate_mbit}mbit",
        "burst",
        "32kb",
        "latency",
        "10ms",
    ]


def soak_environment(
    source: Mapping[str, str],
    *,
    pipeline_diagnostics: bool,
    queue_depth_sampling: bool,
) -> dict[str, str]:
    """Select bounded queue sampling without inheriting verbose GotaTun diagnostics."""
    if pipeline_diagnostics and queue_depth_sampling:
        raise ValueError("full pipeline logging and sampled queue depth are mutually exclusive")
    environment = dict(source)
    environment["INFRATERNAL_MESH_ENGINE"] = "gotatun"
    for name in tuple(environment):
        if name.startswith("GOTATUN_DIAG_"):
            environment.pop(name)
    if pipeline_diagnostics:
        environment["GOTATUN_DIAG_PIPELINE"] = "1"
    if queue_depth_sampling:
        environment["GOTATUN_DIAG_CRYPTO_QUEUE_DEPTH"] = "1"
    return environment


def _tool(name: str) -> str:
    """Return an installed network tool or explain the missing suite dependency."""
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required Linux tool is not on PATH: {name}")
    return path


def _run(command: list[str], *, timeout: float = 15.0) -> None:
    """Run one fixture setup command and keep its error text for the run record."""
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{command[0]} exited {result.returncode}: {detail}")


def _in_namespace(pid: int, *command: str) -> list[str]:
    """Prefix a command with the namespace holder that owns the peer endpoint."""
    return [_tool("nsenter"), "-t", str(pid), "-n", "--", *command]


def _check_disposable_user_namespace() -> None:
    """Require the isolated one-ID user namespace used by the Linux mesh proof."""
    fields = Path("/proc/self/uid_map").read_text(encoding="ascii").split()
    if fields[2:] != ["1"]:
        raise RuntimeError("run inside a disposable user/network namespace: unshare -Urn")


def _start_peer_namespace(duration_seconds: int, underlay_mtu: int) -> subprocess.Popen[bytes]:
    """Create the second network namespace and connect it with one private veth pair."""
    child = subprocess.Popen(
        [_tool("unshare"), "-n", _tool("sleep"), str(duration_seconds + 120)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _run([_tool("ip"), "link", "set", "lo", "up"])
        _run(_in_namespace(child.pid, _tool("ip"), "link", "set", "lo", "up"))
        _run(
            [
                _tool("ip"),
                "link",
                "add",
                "underlay0",
                "type",
                "veth",
                "peer",
                "name",
                "underlay1",
            ]
        )
        _run([_tool("ip"), "link", "set", "underlay1", "netns", str(child.pid)])
        _run([_tool("ip"), "link", "set", "underlay0", "mtu", str(underlay_mtu)])
        _run(_in_namespace(child.pid, _tool("ip"), "link", "set", "underlay1", "mtu", str(underlay_mtu)))
        _run([_tool("ip"), "addr", "add", "10.220.0.1/24", "dev", "underlay0"])
        _run([_tool("ip"), "link", "set", "underlay0", "up"])
        _run(_in_namespace(child.pid, _tool("ip"), "addr", "add", "10.220.0.2/24", "dev", "underlay1"))
        _run(_in_namespace(child.pid, _tool("ip"), "link", "set", "underlay1", "up"))
    except Exception:
        _stop_process(child)
        raise
    return child


def _read_ready_json(stream: TextIO | None, name: str, timeout_seconds: float = 10.0) -> dict[str, Any]:
    """Read one readiness object without waiting forever on a failed helper."""
    if stream is None:
        raise RuntimeError(f"{name} did not provide its readiness stream")
    readable, _, _ = select.select([stream], [], [], timeout_seconds)
    if not readable:
        raise TimeoutError(f"{name} did not become ready within {timeout_seconds:g} seconds")
    line = stream.readline()
    if not line:
        raise RuntimeError(f"{name} exited before publishing readiness")
    row = json.loads(line)
    if not isinstance(row, dict):
        raise RuntimeError(f"{name} readiness must be a JSON object")
    return row


def _agent_thread_ids(pids: object) -> list[int]:
    """Read all live kernel thread IDs for the configured product process pair."""
    if (
        not isinstance(pids, list)
        or len(pids) != 2
        or any(type(pid) is not int or pid < 1 for pid in pids)
        or pids[0] == pids[1]
    ):
        raise RuntimeError("the product fixture did not report two distinct agent process IDs")
    tids: set[int] = set()
    for pid in pids:
        task_directory = Path("/proc") / str(pid) / "task"
        try:
            tids.update(int(task.name) for task in task_directory.iterdir())
        except (OSError, ValueError) as error:
            raise RuntimeError(f"cannot enumerate GotaTun threads for process {pid}") from error
    if len(tids) < 2 or not set(pids).issubset(tids):
        raise RuntimeError("the configured GotaTun processes have no complete thread listing")
    return sorted(tids)


def _publish_agent_pids(
    path: Path, pids: object, tids: object, tids_after: object | None = None
) -> None:
    """Publish the process pair with thread snapshots bracketing the trace window."""
    if (
        not isinstance(pids, list)
        or len(pids) != 2
        or any(type(pid) is not int or pid < 1 for pid in pids)
        or pids[0] == pids[1]
    ):
        raise RuntimeError("the product fixture did not report two distinct agent process IDs")
    if (
        not isinstance(tids, list)
        or len(tids) < 2
        or any(type(tid) is not int or tid < 1 for tid in tids)
        or len(set(tids)) != len(tids)
        or not set(pids).issubset(tids)
    ):
        raise RuntimeError("the product fixture did not expose a complete GotaTun thread listing")
    if tids_after is not None and (
        not isinstance(tids_after, list)
        or len(tids_after) < 2
        or any(type(tid) is not int or tid < 1 for tid in tids_after)
        or len(set(tids_after)) != len(tids_after)
        or not set(pids).issubset(tids_after)
    ):
        raise RuntimeError("the product fixture did not expose a complete final thread listing")
    manifest = {"pids": pids, "tids": tids}
    if tids_after is not None:
        manifest["tids_after"] = tids_after
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    temporary.replace(path)


def _wait_for_capture_start(marker: Path, timeout_seconds: float = 60.0) -> None:
    """Keep traffic idle until the parent confirms that filtered tracing is active."""
    deadline = time.monotonic() + timeout_seconds
    while not marker.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("TID-filtered scheduler capture did not become ready")
        # sleep: poll the parent-created marker while the already-configured peers remain idle.
        time.sleep(0.01)


def _wait_for_tunnel_server(h2h: Path, destination: str, server: subprocess.Popen[bytes]) -> None:
    """Wait for the real tunnel TCP endpoint while keeping its helper failure visible."""
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError(f"J88c net-server exited early with status {server.returncode}")
        result = subprocess.run(
            [str(h2h), "net-wait", "--to", f"{destination}:5201", "--timeout-s", "1"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        if result.returncode == 0:
            return
    raise TimeoutError("the one-flow TCP server was not reachable through the mesh tunnel")


def _stop_process(process: subprocess.Popen[Any] | None, *, process_group: bool = False) -> None:
    """Stop one process owned by this run, escalating only against its recorded PID/group."""
    if process is None or process.poll() is not None:
        return
    if process_group:
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if process_group:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)


def main() -> None:
    """Capture one bounded loaded-latency window for the product's real mesh nodes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--coordinator", required=True, type=Path)
    parser.add_argument("--kit-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--duration-seconds", type=int, default=780)
    parser.add_argument("--probe-interval-ms", type=int, default=10)
    parser.add_argument("--counter-interval-ms", type=int, default=1_000)
    parser.add_argument("--underlay-mtu", type=int, default=1500)
    parser.add_argument("--underlay-rate-mbit", type=int)
    parser.add_argument("--pipeline-diagnostics", action="store_true")
    parser.add_argument("--queue-depth-sampling", action="store_true")
    parser.add_argument("--agent-pids", type=Path)
    parser.add_argument("--capture-start-marker", type=Path)
    arguments = parser.parse_args()
    if (arguments.agent_pids is None) != (arguments.capture_start_marker is None):
        parser.error("agent PID output and capture-start marker must be supplied together")
    if arguments.pipeline_diagnostics and arguments.queue_depth_sampling:
        parser.error("full pipeline logging and sampled queue depth are mutually exclusive")
    if not 60 <= arguments.duration_seconds <= 7_200:
        parser.error("the loaded-latency run must last between 60 and 7200 seconds")
    if arguments.probe_interval_ms < 1 or arguments.counter_interval_ms < 100:
        parser.error("probe interval must be positive and counter interval at least 100 ms")
    if not 576 <= arguments.underlay_mtu <= 65_535:
        parser.error("underlay MTU must be between 576 and 65535")
    if arguments.underlay_rate_mbit is not None and not 100 <= arguments.underlay_rate_mbit <= 10_000:
        parser.error("underlay rate must be between 100 and 10000 Mbit/s")
    for executable in (arguments.binary, arguments.coordinator, arguments.kit_dir / "bin/h2h"):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            parser.error(f"required executable is missing or not executable: {executable}")
    kit_lib = arguments.kit_dir / "lib"
    if not (kit_lib / "mesh_agent_fixture.py").is_file():
        parser.error(f"J88c mesh fixture is missing: {kit_lib / 'mesh_agent_fixture.py'}")

    arguments.output.mkdir(parents=True, exist_ok=True)
    counter_path = arguments.output / "counters.jsonl"
    pipeline_counter_path = arguments.output / "pipeline-counters.jsonl"
    probe_path = arguments.output / "probes.jsonl"
    outputs = [
        arguments.output / "counter-start",
        arguments.output / "counter-stop",
        counter_path,
        pipeline_counter_path,
        probe_path,
        arguments.output / "run.json",
        arguments.output / "agent-sampler.stderr",
        arguments.output / "tcp-server.log",
        arguments.output / "probe-server.stderr",
        arguments.output / "probe-client.stderr",
        arguments.output / "net-tput.log",
        arguments.output / "warmup-tput.log",
    ]
    outputs.extend(
        path
        for path in (arguments.agent_pids, arguments.capture_start_marker)
        if path is not None
    )
    if any(path.exists() for path in outputs):
        parser.error("output already contains window evidence; choose a fresh window directory")
    scratch = arguments.output / "scratch"
    scratch.mkdir(exist_ok=True)
    counter_start = arguments.output / "counter-start"
    counter_stop = arguments.output / "counter-stop"
    run_record: dict[str, Any] = {
        "case": "single-flow-loaded-latency",
        "platform": "linux",
        "duration_seconds_requested": arguments.duration_seconds,
        "probe_interval_ms": arguments.probe_interval_ms,
        "counter_interval_ms": arguments.counter_interval_ms,
        "tcp_flows": 1,
        "underlay_mtu": arguments.underlay_mtu,
        "underlay_rate_mbit": arguments.underlay_rate_mbit,
        "pipeline_diagnostics_enabled": arguments.pipeline_diagnostics,
        "queue_depth_sampling_enabled": arguments.queue_depth_sampling,
        "pipeline_log_tail_poll_interval_ms": (
            10 if arguments.pipeline_diagnostics or arguments.queue_depth_sampling else None
        ),
        "pipeline_counter_path": str(pipeline_counter_path),
        "thread_snapshot_policy": "after one 1-second TCP warm-up and after measured transfer",
        "manual_fixes": [],
    }
    agent_pids: object | None = None
    agent_tids: list[int] | None = None
    right_namespace: subprocess.Popen[bytes] | None = None
    sampler: subprocess.Popen[str] | None = None
    tcp_server: subprocess.Popen[bytes] | None = None
    probe_server: subprocess.Popen[str] | None = None
    probe_client: subprocess.Popen[bytes] | None = None
    load_client: subprocess.Popen[bytes] | None = None
    sampler_stderr = (arguments.output / "agent-sampler.stderr").open("wb")
    tcp_server_log = (arguments.output / "tcp-server.log").open("wb")
    probe_server_log = (arguments.output / "probe-server.stderr").open("wb")
    probe_client_log = (arguments.output / "probe-client.stderr").open("wb")
    load_client_log = (arguments.output / "net-tput.log").open("wb")
    try:
        _check_disposable_user_namespace()
        right_namespace = _start_peer_namespace(arguments.duration_seconds, arguments.underlay_mtu)
        if arguments.underlay_rate_mbit is not None:
            tc = Path(_tool("tc"))
            _run(underlay_tbf_command(tc, "underlay0", arguments.underlay_rate_mbit))
            _run(
                _in_namespace(
                    right_namespace.pid,
                    *underlay_tbf_command(tc, "underlay1", arguments.underlay_rate_mbit),
                )
            )
        environment = soak_environment(
            os.environ,
            pipeline_diagnostics=arguments.pipeline_diagnostics,
            queue_depth_sampling=arguments.queue_depth_sampling,
        )
        sampler_command = [
                sys.executable,
                "-I",
                str(Path(__file__).with_name("mesh_ix_soak.py")),
                "--kit-lib",
                str(kit_lib),
                "--binary",
                str(arguments.binary),
                "--coordinator",
                str(arguments.coordinator),
                "--scratch",
                str(scratch),
                "--pid-b",
                str(right_namespace.pid),
                "--counter-output",
                str(counter_path),
                "--pipeline-counters",
                str(pipeline_counter_path),
                "--counter-start-marker",
                str(counter_start),
                "--counter-stop-marker",
                str(counter_stop),
                "--counter-interval-ms",
                str(arguments.counter_interval_ms),
            ]
        if arguments.pipeline_diagnostics or arguments.queue_depth_sampling:
            sampler_command.append("--pipeline-diagnostics")
        sampler = subprocess.Popen(
            sampler_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sampler_stderr,
            text=True,
            env=environment,
            start_new_session=True,
        )
        ready = _read_ready_json(sampler.stdout, "product agent pair")
        destination = str(ready["peer_ipv4"])
        run_record.update(
            {
                "self_ipv4": ready["self_ipv4"],
                "peer_ipv4": destination,
                "agent_pids": ready["pids"],
                "configure_apply_us": ready["configure_apply_us"],
            }
        )
        if arguments.agent_pids is not None:
            agent_pids = ready.get("pids")

        h2h = arguments.kit_dir / "bin/h2h"
        tcp_server = subprocess.Popen(
            _in_namespace(
                right_namespace.pid,
                str(h2h),
                "net-server",
                "--bind",
                "0.0.0.0:5201",
            ),
            stdin=subprocess.DEVNULL,
            stdout=tcp_server_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        _wait_for_tunnel_server(h2h, destination, tcp_server)

        probe_server = subprocess.Popen(
            _in_namespace(
                right_namespace.pid,
                sys.executable,
                "-I",
                str(Path(__file__).with_name("udp_probe.py")),
                "serve",
                "--bind",
                "0.0.0.0",
                "--port",
                "5202",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=probe_server_log,
            text=True,
            start_new_session=True,
        )
        probe_ready = _read_ready_json(probe_server.stdout, "probe echo server")
        if probe_ready != {"ready": True, "bind": "0.0.0.0", "port": 5202}:
            raise RuntimeError("probe echo server published an unexpected endpoint")

        # Warm up thread pools before taking the TID snapshot; this keeps lazy workers inside the trace.
        warmup_log = (arguments.output / "warmup-tput.log").open("wb")
        try:
            warmup = subprocess.run(
                net_tput_command(h2h, destination, 1),
                stdin=subprocess.DEVNULL,
                stdout=warmup_log,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=15,
            )
        finally:
            warmup_log.close()
        run_record["thread_warmup_exit_status"] = warmup.returncode
        if warmup.returncode != 0:
            raise RuntimeError("the one-flow thread warm-up failed")
        if arguments.agent_pids is not None:
            agent_tids = _agent_thread_ids(agent_pids)
            _publish_agent_pids(arguments.agent_pids, agent_pids, agent_tids)
        if arguments.capture_start_marker is not None:
            _wait_for_capture_start(arguments.capture_start_marker)

        run_started_ns = time.monotonic_ns()
        counter_start.touch()
        probe_client = subprocess.Popen(
            [
                sys.executable,
                "-I",
                str(Path(__file__).with_name("udp_probe.py")),
                "probe",
                "--target",
                destination,
                "--port",
                "5202",
                "--seconds",
                str(arguments.duration_seconds),
                "--interval-ms",
                str(arguments.probe_interval_ms),
                "--output",
                str(probe_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=probe_client_log,
            start_new_session=True,
        )
        load_started_ns = time.monotonic_ns()
        load_client = subprocess.Popen(
            net_tput_command(h2h, destination, arguments.duration_seconds),
            stdin=subprocess.DEVNULL,
            stdout=load_client_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        load_status = load_client.wait(timeout=arguments.duration_seconds + 30)
        probe_status = probe_client.wait(timeout=arguments.duration_seconds + 30)
        run_ended_ns = time.monotonic_ns()
        if arguments.agent_pids is not None:
            if agent_tids is None:
                raise RuntimeError("the initial GotaTun thread snapshot was not recorded")
            agent_tids_after = _agent_thread_ids(agent_pids)
            _publish_agent_pids(arguments.agent_pids, agent_pids, agent_tids, agent_tids_after)
            run_record.update(
                {
                    "agent_tids_start": agent_tids,
                    "agent_tids_end": agent_tids_after,
                    "agent_tids_stable": agent_tids_after == agent_tids,
                }
            )
        counter_stop.touch()
        if sampler.stdin is not None:
            sampler.stdin.write("quit\n")
            sampler.stdin.flush()
        sampler_status = sampler.wait(timeout=15)
        run_record.update(
            {
                "start_ns": run_started_ns,
                "load_start_ns": load_started_ns,
                "end_ns": run_ended_ns,
                "load_exit_status": load_status,
                "probe_exit_status": probe_status,
                "sampler_exit_status": sampler_status,
                "probe_path": str(probe_path),
                "counter_path": str(counter_path),
                "load_log_path": str(arguments.output / "net-tput.log"),
                "integrity_ok": load_status == 0 and probe_status == 0 and sampler_status == 0,
            }
        )
        if not run_record["integrity_ok"]:
            raise RuntimeError("one-flow load, probe client, or app counter sampler failed")
    except Exception as error:
        run_record["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        counter_stop.touch(exist_ok=True)
        if sampler is not None and sampler.poll() is None:
            try:
                if sampler.stdin is not None:
                    sampler.stdin.write("quit\n")
                    sampler.stdin.flush()
                sampler.wait(timeout=10)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                _stop_process(sampler, process_group=True)
        for process in (load_client, probe_client, probe_server, tcp_server, right_namespace):
            _stop_process(process)
        for stream in (
            None if sampler is None else sampler.stdout,
            None if probe_server is None else probe_server.stdout,
            sampler_stderr,
            tcp_server_log,
            probe_server_log,
            probe_client_log,
            load_client_log,
        ):
            if stream is not None:
                stream.close()
        run_record.setdefault("end_ns", time.monotonic_ns())
        (arguments.output / "run.json").write_text(
            json.dumps(run_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(run_record, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
