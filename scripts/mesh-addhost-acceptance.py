#!/usr/bin/env python3
"""Run fresh real-SSH mesh lifecycles on the pinned perf VM; never builds (#201).

The fixture and shipping payload are prebuilt on the build host. Each lifecycle
owns two Docker network namespaces and a fresh systemd target. Private SSH keys
exist only in memory and stdin pipes. Unrestricted route hints are diagnostics;
the separate post-fence marker establishes mesh byte delivery causally. The
fenced-canary profile blocks the enrolled ingress before creating its readiness
PTY, so its first authenticated Output supplies a separate causal mesh witness.
Unrestricted runs also timestamp the existing post-success fenced marker: this
bounds usability after natural unheld joining, including fixture overhead; it
never claims the earliest mesh Output of bootstrap itself.

`check-standing --receipts DIR` checks complete release VM receipts offline,
including the causal switch/fallback byte budgets and preserved writer proofs.
"""
import argparse
import base64
import hashlib
import json
import math
import os
import resource
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import uuid


def check_standing_receipts(root):
    """Check complete VM cohorts offline; no failed or unstarted case is omitted.

    This gate covers the causal byte boundary and session integrity only. It
    cannot waive scale health, static size or natural unheld-join acceptance.
    All firewall, input and echo overhead remains in the recorded durations.
    """
    provenance = json.loads((root / "provenance.json").read_text())
    samples = provenance["samples_per_venue"]
    assert type(samples) is int and samples >= 31, "31+ samples per venue required"
    assert provenance["machine"] == "infraternal-perf-test", "wrong measurement venue"
    assert provenance["profile"] == "release", "release receipts required"
    assert provenance["acceptance_mode"] == "standing-switch", "standing witnesses required"
    assert not provenance.get("packet_diagnostic_observer", False), "packet observer adds a separate cost"
    failures = []
    for venue in (0, 150):
        aggregate = json.loads((root / f"venue-{venue}.json").read_text())
        assert len(aggregate) == samples, f"incomplete {venue}ms aggregate"
        reports = []
        for index in range(samples):
            case = root / str(venue) / str(index)
            assert (case / "exit").read_text().strip() == "0", f"failed lifecycle {venue}/{index}"
            report = json.loads((case / "acceptance.json").read_text())
            assert report == aggregate[index], f"aggregate differs from raw case {venue}/{index}"
            assert int(report["rtt_ms"]) == venue
            for proof in (
                "terminal_byte_integrity", "connection_preservation_claimed",
                "tls_admission_counts_unchanged", "control_counts_unchanged",
                "standing_uses_same_writer_and_attachment", "standing_first_output_path_proven",
                "post_fence_fresh_marker_mesh_path_proven", "mesh_disable_checked",
            ):
                assert report[proof] is True, f"{venue}/{index}: missing {proof}"
            assert report["initial_control_callbacks"] == report["final_control_callbacks"] == 1
            writer = report["terminal_writer_id"]
            assert type(writer) is int and writer > 0 and writer % 2 == 0
            assert report["standing_first_output_writer_id"] == writer, "wrong first-byte writer"
            if "verified_terminal_bytes" in report:
                assert report["verified_terminal_bytes"] == report["expected_terminal_bytes"] > 0
                assert report["terminal_writer_id"] == 2
            reports.append(report)
        budget_us = (venue + 50) * 1000
        for metric, field in (
            ("switch", "node_handshake_to_standing_first_mesh_output_us"),
            ("fallback_echo", "cut_to_complete_fallback_echo_us"),
        ):
            values = [report[field] for report in reports]
            assert all(type(value) is int and value >= 0 for value in values), "invalid duration"
            values.sort()
            p50 = values[math.ceil(samples * 0.5) - 1]
            p99 = values[math.ceil(samples * 0.99) - 1]
            print(f"METRIC mesh_standing_{metric} rtt_ms={venue} n={samples} p50_us={p50} p99_us={p99} budget_us={budget_us}")
            if p99 > budget_us:
                failures.append(f"{venue}ms {metric} p99 {p99}us exceeds {budget_us}us")
    if failures:
        raise AssertionError("; ".join(failures))
    print("Standing-session byte budgets and integrity passed; scale, size and natural joining remain separate gates.")


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, **kwargs)


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def generated_key():
    private = subprocess.check_output(["openssl", "genpkey", "-algorithm", "ED25519"], stderr=subprocess.DEVNULL)
    public = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private, stderr=subprocess.DEVNULL)
    raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + public[12:]
    return private, "ssh-ed25519 " + base64.b64encode(raw).decode()


def inspect(name, field):
    return subprocess.check_output(["docker", "inspect", "-f", field, name], text=True).strip()


def stop(process):
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def lifecycle(args, venue, index):
    evidence = args.output / args.label / str(venue) / str(index)
    evidence.mkdir(parents=True, exist_ok=False)
    nonce = uuid.uuid4().hex[:12]
    target, controller = "macc-node-" + nonce, "macc-server-" + nonce
    scratch = Path("/root/infraternal-bench/mesh-autoswitch/s") / nonce
    scratch.mkdir(mode=0o700, parents=True)
    sshd = counter = None
    captures, capture_files = [], []
    try:
        docker("run", "-d", "--name", controller, "--privileged", "--ulimit", "memlock=8388608:8388608", "--entrypoint", "/bin/sleep", args.image, "600", stdout=subprocess.DEVNULL)
        docker("run", "-d", "--name", target, "--privileged", "--ulimit", "memlock=8388608:8388608", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", args.image, stdout=subprocess.DEVNULL)
        for _ in range(100):
            ready = subprocess.run(["docker", "exec", target, "loginctl", "enable-linger", "target"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("owned target systemd unavailable")
        docker("exec", target, "systemctl", "mask", "--now", "ssh.service", "ssh.socket", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        node_ip = inspect(target, "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
        server_ip = inspect(controller, "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
        node_pid = inspect(target, "{{.State.Pid}}")
        server_pid = inspect(controller, "{{.State.Pid}}")
        docker("exec", "-i", target, "sh", "-c", "cat >>/etc/hosts", input=(server_ip + " addhost-breakit2.test\n").encode())
        # Public fixture admission only: no explicit WireGuard-port exception.
        for pid, ports, filename in ((server_pid, "tcp dport {4929,4930} accept; udp dport 4930 accept;", "server-admission.nft"),
                                     (node_pid, "tcp dport {22,4931} accept;", "node-admission.nft")):
            admission_rules = "table inet acceptance_admission { chain input { type filter hook input priority 0; policy drop; iifname lo accept; ct state established,related accept; " + ports + " }\n}\n"
            run("nsenter", "-t", pid, "-n", "nft", "-f", "-", input=admission_rules.encode())
            (evidence / filename).write_text(admission_rules)
        # The SSH fixture image predates kernel mesh and lacks its supported
        # packet-filter frontend. Stage only existing public executables/libraries;
        # never build or fetch packages on the benchmark machine.
        frontend = Path(shutil.which("nft"))
        dependencies = subprocess.check_output(["ldd", str(frontend)], text=True)
        staged = [str(frontend)]
        docker("cp", str(frontend), target + ":/usr/sbin/nft", stdout=subprocess.DEVNULL)
        for line in dependencies.splitlines():
            fields = line.split()
            library = fields[2] if len(fields) > 2 and fields[1] == "=>" else fields[0] if fields else ""
            if not library.startswith("/"):
                continue
            exists = subprocess.run(["docker", "exec", target, "test", "-e", library], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exists.returncode:
                docker("exec", target, "mkdir", "-p", str(Path(library).parent), stdout=subprocess.DEVNULL)
                docker("cp", "-L", library, target + ":" + library, stdout=subprocess.DEVNULL)
                staged.append(library)
        version = subprocess.check_output(["docker", "exec", target, "/usr/sbin/nft", "--version"], text=True).strip()
        (evidence / "fixture-prerequisites.json").write_text(json.dumps({"packet_filter":version,"public_tool_paths_staged":staged}, indent=2))
        private, public = generated_key()
        sshd_source = args.sshd_source.read_text()
        sshd = subprocess.Popen(["docker", "exec", "-i", target, "python3", "-u", "-c", sshd_source], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        sshd.stdin.write((public + "\n").encode())
        sshd.stdin.close()
        pin = sshd.stdout.readline().decode().strip()
        assert pin.startswith("ssh-ed25519 "), "generated public host pin unavailable"
        known = scratch / "known_hosts"
        known.write_text(node_ip + " " + pin + "\n")
        known.chmod(0o600)
        config = scratch / "config"
        config.write_text(f"Host *\n UserKnownHostsFile {known}\n GlobalKnownHostsFile /dev/null\n StrictHostKeyChecking yes\n UpdateHostKeys no\n")
        wrapper = scratch / "ssh"
        wrapper.write_text(f"#!/bin/sh\nexec /usr/bin/ssh -F '{config}' \"$@\"\n")
        wrapper.chmod(0o700)
        if venue:
            docker("exec", target, "ip", "link", "add", "ifb0", "type", "ifb")
            docker("exec", target, "ip", "link", "set", "ifb0", "up")
            docker("exec", target, "tc", "qdisc", "add", "dev", "eth0", "handle", "ffff:", "ingress")
            docker("exec", target, "tc", "filter", "add", "dev", "eth0", "parent", "ffff:", "protocol", "all", "matchall", "action", "mirred", "egress", "redirect", "dev", "ifb0")
            for device in ("eth0", "ifb0"):
                docker("exec", target, "tc", "qdisc", "add", "dev", device, "root", "netem", "delay", "75ms")
        environment = dict(os.environ, ACCEPTANCE_COUNTER_ADDR=node_ip + ":4931")
        if args.packet_diagnostics:
            # Bracket only fixed public fixture barriers; retain no rule body.
            nft_observer = scratch / "nft"
            nft_observer.write_text(
                "#!/usr/bin/python3\n"
                '"""Record public fixture barrier clocks without recording rules."""\n'
                "import json, subprocess, sys, time\nfrom pathlib import Path\n"
                "body = sys.stdin.buffer.read() if sys.argv[1:] == ['-f', '-'] else None\n"
                "start = time.time_ns() // 1000\n"
                f"result = subprocess.run([{str(frontend)!r}, *sys.argv[1:]], input=body)\n"
                "finish = time.time_ns() // 1000\n"
                "if body is not None:\n"
                " for tag in ['acceptance_standing_fence', 'acceptance_cut']:\n"
                "  if ('table inet ' + tag).encode() in body:\n"
                f"   with Path({str(evidence / 'fixture-barriers.jsonl')!r}).open('a') as output:\n"
                "    output.write(json.dumps(dict(barrier=tag, removed=body.startswith(b'delete'), before_us=start, completed_us=finish, exit=result.returncode)) + '\\n')\n"
                "sys.exit(result.returncode)\n"
            )
            nft_observer.chmod(0o700)
            environment["PATH"] = str(scratch) + os.pathsep + environment["PATH"]
            # Header summaries only: never capture payloads, netlink messages
            # or identity material. Both processes belong to this lifecycle.
            for name, pid in (("node", node_pid), ("server", server_pid)):
                capture = (evidence / (name + "-udp-headers.log")).open("w")
                capture_files.append(capture)
                captures.append(subprocess.Popen([
                    "nsenter", "-t", pid, "-n", "tcpdump", "-i", "any", "-nn", "-tt", "-l", "-q",
                    "-c", "20000", "udp", "and", "port", "4930",
                ], stdout=capture, stderr=subprocess.DEVNULL))
        if args.acceptance_mode == "standing-switch":
            environment["ACCEPTANCE_COUNTER_PIPE"] = str(scratch / "counter.sock")
        counter = subprocess.Popen(["nsenter", "-t", node_pid, "-n", str(args.fixture), "mesh_acceptance_node_counters", "--ignored", "--nocapture", "--test-threads=1"], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        environment.update(INFRATERNAL_TEST_STATE_ROOT=str(scratch), INFRATERNAL_REMOTE_TEST_BINARY=str(args.payload),
                           INFRATERNAL_MESH_PROOF_SCRATCH=str(scratch), BREAKIT2_CONTROLLER_IP=server_ip,
                           ACCEPTANCE_NODE_IP=node_ip, BREAKIT2_TARGET="root@" + node_ip + ":22",
                           ACCEPTANCE_OWNED_CONTAINER="1", ACCEPTANCE_DIAGNOSTICS=args.diagnostics, ACCEPTANCE_MODE=args.acceptance_mode, ACCEPTANCE_TRANSPORT_EXPECTATION=args.transport_expectation, INFRATERNAL_TEST_RTT=str(venue),
                           ACCEPTANCE_HOST_NETNS=os.readlink("/proc/self/ns/net"), ACCEPTANCE_HOST_MNTNS=os.readlink("/proc/self/ns/mnt"))
        # Private mount propagation and passwd binding happen inside unshare;
        # only the owned controller network namespace is entered.
        with (evidence / "run.log").open("w") as output:
            result = subprocess.run(["unshare", "-m", "nsenter", "-t", server_pid, "-n", str(args.fixture), "mesh_acceptance_real_addhost", "--ignored", "--nocapture", "--test-threads=1"], input=private, env=environment, stdout=output, stderr=subprocess.STDOUT, timeout=360)
        for capture in captures:
            stop(capture)
            assert capture.returncode in (0, -15), "owned packet observer failed"
        for capture in capture_files:
            capture.flush()
            assert Path(capture.name).stat().st_size, "owned packet observer recorded no UDP headers"
        (evidence / "exit").write_text(str(result.returncode))
        if args.packet_diagnostics:
            # Only this disposable node's daemon unit, never host journals.
            with (evidence / "node-daemon.log").open("w") as output:
                subprocess.run([
                    "docker", "exec", target, "journalctl", "--no-pager", "-o", "short-precise",
                    "_SYSTEMD_UNIT=infraternal-agent.service", "+",
                    "_SYSTEMD_USER_UNIT=infraternal-agent.service",
                ], stdout=output, stderr=subprocess.DEVNULL, check=False)
        metadata_source = "import json; from pathlib import Path; paths=['/var/lib/infraternal/state','/var/lib/infraternal/sessions']; print(json.dumps({p:dict(uid=Path(p).stat().st_uid,mode=oct(Path(p).stat().st_mode & 0o777)) for p in paths if Path(p).exists()}))"
        metadata = subprocess.check_output(["docker", "exec", target, "python3", "-c", metadata_source])
        (evidence / "node-state-metadata.json").write_bytes(metadata)
        for name in ("acceptance.json", "exclusive-path-firewall.nft", "path-timeout-Mesh.json", "path-timeout-Fallback.json", "fenced-canary-stage.json", "fenced-canary-firewall.nft", "bootstrap-terminal-stage.json", "canary-return-diagnostic.json", "canary-internal-stages.json"):
            if (scratch / name).exists():
                shutil.copyfile(scratch / name, evidence / name)
        if result.returncode:
            raise RuntimeError("acceptance lifecycle failed; keep its receipt and stop")
        report = json.loads((evidence / "acceptance.json").read_text())
        if args.packet_diagnostics:
            report.update(packet_diagnostic_observer=True, ordinary_latency_acceptance=False)
            (evidence / "acceptance.json").write_text(json.dumps(report, indent=2))
        if args.diagnostics == "canary-return":
            assert report.get("diagnostic_profile") == "canary-return", "fixture does not implement requested diagnostics"
            assert not report["ordinary_latency_acceptance"]
        if report.get("recorded_operation_failure"):
            # Only an explicitly recorded production operation failure can
            # continue a baseline series. A panic, timeout, malformed report or
            # preserved-profile failure still stops after retaining evidence.
            assert args.transport_expectation == "baseline"
            assert report.get("transport_expectation") == "baseline"
            assert report.get("bootstrap_succeeded") is False
            failure = report["public_failure"]
            assert failure["kind"] in ("unreachable", "auth", "mesh-policy", "host-key", "unsupported", "install", "stale_previous_attempt", "setup_running")
            assert not report["connection_preservation_claimed"]
            assert report["node_handshake_to_first_fenced_canary_output_us"] is None
            print(json.dumps(dict(label=args.label, venue=venue, sample=index,
                                  receipt=str(evidence), recorded_operation_failure=True,
                                  failure_kind=failure["kind"], failed_step=failure["failed_step"],
                                  baseline_observation_only=True)), flush=True)
            return report
        assert report["post_fence_fresh_marker_mesh_path_proven"]
        if args.transport_expectation == "preserved":
            assert report["terminal_byte_integrity"]
            assert report["connection_preservation_claimed"]
        else:
            assert report.get("transport_expectation") == "baseline", "fixture does not implement requested baseline profile"
            assert not report["connection_preservation_claimed"]
        if args.acceptance_mode == "fenced-canary":
            assert report.get("acceptance_mode") == "fenced-canary", "fixture does not implement requested fenced profile"
            assert report["first_fenced_canary_output_path_proven"]
            assert report["node_handshake_to_first_fenced_canary_output_us"] >= 0
        if args.acceptance_mode == "unrestricted":
            assert report["natural_unheld_join_post_success_witness"]
            assert report["natural_first_post_fence_output_path_proven"]
            assert not report["natural_earliest_mesh_output_claimed"]
            for origin in ("start", "success", "node_handshake"):
                first = report[f"natural_{origin}_to_first_post_fence_output_us"]
                complete = report[f"natural_{origin}_to_complete_post_fence_marker_us"]
                assert 0 <= first <= complete
        if args.acceptance_mode == "standing-switch":
            assert report["controlled_standing_session_switch"]
            assert report["standing_first_output_path_proven"]
            assert not report["terminal_opened_after_initial_mesh_join"]
            assert not report["ordinary_latency_acceptance"]
            assert report["node_handshake_to_standing_first_mesh_output_us"] >= 0
        print(json.dumps(dict(label=args.label, venue=venue, sample=index, receipt=str(evidence), terminal_byte_integrity=report["terminal_byte_integrity"], baseline_observation_only=args.transport_expectation == "baseline")), flush=True)
        return report
    finally:
        for capture in captures:
            stop(capture)
        for capture in capture_files:
            capture.close()
        stop(counter)
        stop(sshd)
        for name in (target, controller):
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(scratch)


def main():
    if sys.argv[1:2] == ["check-standing"]:
        parser = argparse.ArgumentParser(description="Check complete standing-session VM receipts offline (#201).")
        parser.add_argument("--receipts", type=Path, required=True)
        args = parser.parse_args(sys.argv[2:])
        check_standing_receipts(args.receipts)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--sshd-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", required=True, help="unique before/after provenance label")
    parser.add_argument("--profile", choices=("debug", "release"), default="debug")
    parser.add_argument("--transport-expectation", choices=("preserved", "baseline"), default="preserved")
    parser.add_argument("--packet-diagnostics", action="store_true", help="Record bounded UDP header summaries; diagnostic runs are not ordinary latency acceptance")
    parser.add_argument("--acceptance-mode", choices=("unrestricted", "fenced-canary", "standing-switch"), default="unrestricted")
    parser.add_argument("--diagnostics", choices=("none", "canary-return"), default="none",
                        help="bounded post-canary public queries; diagnostic completion includes their overhead")
    parser.add_argument("--samples", type=int, default=31)
    parser.add_argument("--venues", type=int, nargs="+", choices=(0, 150), default=[0, 150])
    parser.add_argument("--image", default="infraternal-addhost-breakit2:debian")
    parser.add_argument("--locked", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--single-venue", type=int, choices=(0, 150), help=argparse.SUPPRESS)
    parser.add_argument("--single-index", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.uname().nodename != "infraternal-perf-test":
        parser.error("This measurement runner is pinned to infraternal-perf-test.")
    assert os.geteuid() == 0 and args.samples > 0
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (8388608, 8388608))
    args.fixture, args.payload = args.fixture.resolve(), args.payload.resolve()
    if args.locked:
        assert args.single_venue is not None and args.single_index is not None
        lifecycle(args, args.single_venue, args.single_index)
        return 0
    assert args.single_venue is None and args.single_index is None
    destination = args.output / args.label
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(Path(__file__).resolve(), destination / "runner.py")
    shutil.copyfile(args.sshd_source, destination / "sshd.py")
    provenance = {"fixture_sha256":hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
                  "payload_sha256":hashlib.sha256(args.payload.read_bytes()).hexdigest(),
                  "samples_per_venue":args.samples,"venues":args.venues,"machine":os.uname().nodename,
                  "cores":os.cpu_count(),"load_start":Path("/proc/loadavg").read_text().strip(),
                  "profile":args.profile,"acceptance_mode":args.acceptance_mode,"transport_expectation":args.transport_expectation,
                  "diagnostic_profile":args.diagnostics,"packet_diagnostic_observer":args.packet_diagnostics,
                  "ordinary_latency_acceptance":args.profile == "release" and args.diagnostics == "none" and args.acceptance_mode != "standing-switch" and not args.packet_diagnostics,"debug_numbers_are_acceptance":False,
                  "unrestricted_exact_first_mesh_byte_claimed":False,
                  "unrestricted_post_success_witness_scope":"upper bound including fixture overhead; initial join unheld; readiness and commit unblocked"}
    (destination / "provenance.json").write_text(json.dumps(provenance, indent=2))
    for venue in args.venues:
        reports = []
        for index in range(args.samples):
            # Release the shared measurement lock after each fresh lifecycle.
            # Its provisioning and teardown are included to avoid disturbing
            # another project's measurement, but no build holds the lock.
            run("flock", "-w", "3600", "/var/lock/perf-bench.lock", sys.executable,
                str(Path(__file__).resolve()), *sys.argv[1:], "--locked",
                "--single-venue", str(venue), "--single-index", str(index))
            reports.append(json.loads((destination / str(venue) / str(index) / "acceptance.json").read_text()))
            (destination / f"venue-{venue}.json").write_text(json.dumps(reports, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
