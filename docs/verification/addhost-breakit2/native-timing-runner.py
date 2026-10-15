#!/usr/bin/env python3
"""Run the unfiltered native gate, moving its physical QUIC path suite to the designated locked VM (#189)."""
import gzip
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

CASES = [
    "remote_client::server_path::tests::" + name
    for name in [
        'component_down_activates_the_warm_fallback_without_a_new_connection',
        'component_down_keeps_its_reason_when_mesh_closes_during_replacement',
        'component_down_proves_tcp_fallback_when_enrolled_udp_is_unavailable',
        'component_down_replaces_mesh_with_a_proven_fallback',
        'healthy_mesh_probes_do_not_inherit_the_previous_paths_rtt',
        'invalid_application_proof_keeps_the_live_fallback',
        'parked_fallback_recovers_mesh_and_keeps_control_actions_usable',
        'proven_mesh_destination_is_preferred_and_failure_returns_to_enrolled_port',
        'retained_mesh_proposal_connects_when_the_fallback_port_is_unavailable',
        'untrusted_candidate_never_retires_the_authenticated_fallback',
    ]
]


def direct(binary: Path, arguments: list[str]) -> None:
    os.execv(binary, [str(binary), *arguments])


def locked_measurement(program: str, lock="/var/lock/perf-bench.lock",
                       owner="/var/lock/perf-bench.owner") -> str:
    """Bound the entire held measurement, including stalled children, below thirty minutes."""
    owned = ("printf 'addhost-instant started=%s\\n' \"$(date -u +%FT%TZ)\" > "
             + shlex.quote(owner) + "; trap "
             + shlex.quote("rm -f -- " + shlex.quote(owner)) + " EXIT; " + program)
    return shlex.join(["flock", "-w", "3600", lock, "timeout", "--kill-after=10",
                       "1750", "sh", "-c", owned])


def main() -> int:
    binary = Path(sys.argv[1]).resolve()
    arguments = sys.argv[2:]
    if not re.fullmatch(r"infraternal_agent-[0-9a-f]+", binary.name) or "--list" in arguments:
        direct(binary, arguments)
    listing = subprocess.check_output([str(binary), "--list"], text=True)
    present = [f"{case}: test" in listing.splitlines() for case in CASES]
    if not any(present):
        direct(binary, arguments)
    if not all(present) or any(
        argument not in {"--nocapture", "--show-output"}
        and not argument.startswith("--test-threads=")
        for argument in arguments
    ):
        raise RuntimeError("Use this runner only for the unfiltered native gate with the complete temporal suite present")
    vm_root = os.environ["ADDHOST_NATIVE_VM_ROOT"]
    state_root = os.environ["ADDHOST_NATIVE_VM_STATE_ROOT"]
    if any(not path.startswith("/root/infraternal-bench/") or ".." in Path(path).parts for path in [vm_root, state_root]):
        raise RuntimeError("Native test artifacts and state must stay in the designated bench directory")
    content = binary.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    remote_binary = f"{vm_root}/native-tests-{digest}"
    temporary = f"{remote_binary}.upload-{os.getpid()}"
    stage = (
        shlex.join(["mkdir", "-p", vm_root, state_root])
        + " && " + shlex.join(["chmod", "700", state_root])
        + " && gzip -dc > " + shlex.quote(temporary)
        + " && " + shlex.join(["chmod", "755", temporary])
        + " && " + shlex.join(["mv", "--", temporary, remote_binary])
        + " && " + shlex.join(["sha256sum", remote_binary])
    )
    staged = subprocess.run(
        ["netbird", "ssh", "--no-browser", "root@10.69.69.208", stage],
        input=gzip.compress(content, compresslevel=1, mtime=0), capture_output=True,
    )
    digest_lines = staged.stdout.decode(errors="replace").splitlines()
    if staged.returncode or not any(line.split() == [digest, remote_binary] for line in digest_lines):
        raise RuntimeError("Designated VM artifact staging failed; no credentials or arbitrary SSH diagnostics emitted")
    print(f"NATIVE_TIMING artifact_sha256={digest} remote_cases={len(CASES)}", flush=True)
    commands = ["aggregate=0"]
    for case in CASES:
        command = shlex.join([
            "env", f"INFRATERNAL_TEST_STATE_ROOT={state_root}",
            os.environ["ADDHOST_NATIVE_VM_LOADER"], "--library-path",
            os.environ["ADDHOST_NATIVE_VM_LIB"], remote_binary,
            case, "--exact", "--nocapture", "--test-threads=1",
        ])
        # Run the short suite under one lock, retaining every exact case's exit.
        # A remote SSH success is insufficient evidence of a successful child.
        commands.append(command)
        commands.append('result=$?; printf "NATIVE_TIMING_EXIT %s=%s\\n" ' + shlex.quote(case) + ' "$result"; [ "$result" -eq 0 ] || aggregate=1')
    commands.append('exit "$aggregate"')
    remote = locked_measurement("; ".join(commands))
    result = subprocess.run(
        ["netbird", "ssh", "--no-browser", "root@10.69.69.208", remote],
        capture_output=True, text=True,
    )
    print(result.stdout, end="", flush=True)
    expected = [f"NATIVE_TIMING_EXIT {case}=0" for case in CASES]
    failed = (
        result.returncode != 0
        or any(line not in result.stdout.splitlines() for line in expected)
        or len(re.findall(r"^test result: ok\. 1 passed; 0 failed;", result.stdout, re.MULTILINE)) != len(CASES)
    )
    # These cases have run, not been waived. Every remaining native case still
    # runs on the build host; either side's failure fails the enclosing gate.
    skipped = [argument for case in CASES for argument in ["--skip", case]]
    print(f"NATIVE_TIMING VM cases {'failed' if failed else 'verified'}; running all remaining native cases locally", flush=True)
    local = subprocess.run([str(binary), *arguments, *skipped]).returncode
    return local or int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
