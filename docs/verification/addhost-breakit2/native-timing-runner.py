#!/usr/bin/env python3
"""Run the unfiltered native gate, moving its two physical QUIC timing cases to the designated locked VM (#189)."""
import gzip
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

CASES = [
    "remote_client::server_path::tests::healthy_mesh_probes_do_not_inherit_the_previous_paths_rtt",
    "remote_client::server_path::tests::component_down_activates_the_warm_fallback_without_a_new_connection",
]


def direct(binary: Path, arguments: list[str]) -> None:
    os.execv(binary, [str(binary), *arguments])


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
        raise RuntimeError("Use this runner only for the unfiltered native gate with both temporal cases present")
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
    failed = False
    for case in CASES:
        command = shlex.join([
            "env", f"INFRATERNAL_TEST_STATE_ROOT={state_root}",
            os.environ["ADDHOST_NATIVE_VM_LOADER"], "--library-path",
            os.environ["ADDHOST_NATIVE_VM_LIB"], remote_binary,
            case, "--exact", "--nocapture", "--test-threads=1",
        ])
        # The VM has occasionally returned SSH success for a failed child.
        # Require the exact nonzero-sensitive sentinel and one executed case.
        command += '; result=$?; printf "NATIVE_TIMING_EXIT=%s\\n" "$result"; exit "$result"'
        remote = shlex.join(["flock", "-w", "3600", "/var/lock/perf-bench.lock", "sh", "-c", command])
        result = subprocess.run(
            ["netbird", "ssh", "--no-browser", "root@10.69.69.208", remote],
            capture_output=True, text=True,
        )
        print(result.stdout, end="", flush=True)
        if result.returncode or "NATIVE_TIMING_EXIT=0" not in result.stdout.splitlines() or not re.search(r"^test result: ok\. 1 passed; 0 failed;", result.stdout, re.MULTILINE):
            failed = True
    # These cases have run, not been waived. Every remaining native case still
    # runs on the build host; either side's failure fails the enclosing gate.
    skipped = [argument for case in CASES for argument in ["--skip", case]]
    print(f"NATIVE_TIMING VM cases {'failed' if failed else 'verified'}; running all remaining native cases locally", flush=True)
    local = subprocess.run([str(binary), *arguments, *skipped]).returncode
    return local or int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
