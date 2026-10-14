#!/usr/bin/env python3
"""Collect public timing boundaries and TCP headers for the owned D255 fixture; no protocol bodies or credentials (#189)."""
import os
from contextlib import contextmanager
import json
from pathlib import Path
import runpy
import re
import signal
import subprocess
import time
import sys

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = Path(os.environ["ADDHOST_TIMELINE_EVIDENCE"])
EVIDENCE.mkdir(parents=True, exist_ok=True)
original = subprocess.run
original_popen = subprocess.Popen
prompt_ms = None


def target_ssh(command, *args, **kwargs):
    if isinstance(command, list) and command and isinstance(command[-1], str) and 'memory-only generated host key (#169)' in command[-1]:
        script = command[-1].replace('LogLevel ERROR', 'LogLevel DEBUG3')
        old = 'subprocess.run(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], check=True)'
        new = '''import json, re, time
child = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stderr=subprocess.PIPE)
with open("/run/addhost-fast-ssh-times", "a") as receipts:
    for line in child.stderr:
        text = line.decode(errors="replace")
        message = re.search(r"^debug3: (send|receive) packet: type (\\d+)", text)
        if message:
            receipts.write(json.dumps({"source":"target_ssh", "step":f"packet_{message[1]}_{message[2]}", "epoch_ms":time.time()*1000})+"\\n")
            receipts.flush()
raise SystemExit(child.wait())'''
        if old not in script:
            raise RuntimeError("The owned SSH fixture diagnostic boundary changed")
        command = [*command[:-1], script.replace(old, new)]
    return original_popen(command, *args, **kwargs)


@contextmanager
def captured_headers(name, arguments):
    """Retire only this capture, including partial startup or fixture refusal."""
    with (EVIDENCE / name).open("w") as output:
        capture = original_popen(arguments, stdout=output, stderr=subprocess.PIPE)
        try:
            yield
        finally:
            capture.send_signal(signal.SIGINT)
            try:
                _, diagnostics = capture.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.communicate(timeout=10)
                raise RuntimeError("Owned header capture did not stop") from None
            print(diagnostics.decode(), flush=True)
            if capture.returncode not in (0, -signal.SIGINT):
                raise RuntimeError(f"Owned header capture failed: {name}")


def measured(command, *args, **kwargs):
    global prompt_ms
    environment = kwargs.get("env", {})
    if isinstance(command, list) and any("cat > /usr/local/bin/sh" in argument for argument in command):
        kwargs["input"] = (ROOT / "docs/verification/addhost-breakit2/timeline-shell.sh").read_bytes()
    if isinstance(command, list) and "BREAKIT2_TARGET" in environment and "--nocapture" in command:
        target = environment["BREAKIT2_TARGET"].split("@", 1)[1].rsplit(":", 1)[0]
        wrapper = Path(environment["INFRATERNAL_TEST_STATE_ROOT"]) / "ssh"
        # Preserve the generated strict known-host configuration. Only the
        # owned master adds verbosity; reduce diagnostics before storing them.
        text = wrapper.read_text()
        text = text.replace("exec /usr/bin/ssh", f"exec /usr/bin/python3 '{ROOT}/docs/verification/addhost-breakit2/timeline_ssh.py'")
        wrapper.write_text(text)
        name = os.environ.get("ADDHOST_TIMELINE_TARGET", "addhost-instant-timeline")
        pid = original(["sudo", "-n", "docker", "inspect", "--format", "{{.State.Pid}}", name], capture_output=True, text=True, check=True).stdout.strip()
        if not pid.isdecimal() or int(pid) <= 0:
            raise RuntimeError("Owned target network namespace is unavailable")
        # eth0 ingress is observed before the fixture's incoming netem delay.
        # The redirected interface observes delivery after that queue. Stop
        # this observer at the first SYN, well before image transfer begins.
        delayed = original(["sudo", "-n", "docker", "exec", name, "ip", "link", "show", "dev", "ifb0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        delivery = "ifb0" if delayed else "eth0"
        with captured_headers("packet-headers.txt", ["tcpdump", "-i", "docker0", "-nn", "-tt", "-l", f"host {target} and tcp"]), captured_headers("browser-packet-headers.txt", ["tcpdump", "-i", "lo", "-nn", "-tt", "-l", "tcp port 4929"]), captured_headers("target-packet-headers.txt", ["nsenter", "--target", pid, "--net", "tcpdump", "-c", "3", "-i", "eth0", "-nn", "-tt", "-l", "tcp port 22"]), captured_headers("target-delivery-headers.txt", ["nsenter", "--target", pid, "--net", "tcpdump", "-c", "1", "-i", delivery, "-nn", "-tt", "-l", "tcp port 22 and tcp[tcpflags] & tcp-syn != 0"]):
            print(f"TIMELINE source=collector step=target_delivery_capture interface={delivery}", flush=True)
            print(f"TIMELINE source=collector step=begin epoch_ms={time.time()*1000:.3f}", flush=True)
            result = original(command, *args, **kwargs, stdout=subprocess.PIPE)
            transcript = result.stdout.decode()
            print(transcript, end="", flush=True)
            (EVIDENCE / "controller.log").write_text(transcript)
            signed_in = re.search(r"TIMELINE source=server step=key_sign_in state=end epoch_ms=([0-9.]+)", transcript)
            for line in transcript.splitlines():
                if not line.startswith('{'):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # Concurrent fixed server/browser records may share a
                    # line; missing required boundaries fail the budget.
                    continue
                if record.get("source") == "browser" and record.get("step") == "first_prompt_painted" and signed_in:
                    prompt_ms = record["epoch_ms"] - float(signed_in[1])
            name = os.environ.get("ADDHOST_TIMELINE_TARGET", "addhost-instant-timeline")
            receipts = original(["sudo", "-n", "docker", "exec", name, "cat", "/run/addhost-fast-step-times"], capture_output=True, text=True, check=True)
            (EVIDENCE / "target-boundaries.jsonl").write_text(receipts.stdout)
            packets = original(["sudo", "-n", "docker", "exec", name, "cat", "/run/addhost-fast-ssh-times"], capture_output=True, text=True, check=True)
            (EVIDENCE / "target-ssh-boundaries.jsonl").write_text(packets.stdout)
            return result
    return original(command, *args, **kwargs)


subprocess.run = measured
subprocess.Popen = target_ssh
try:
    runpy.run_path(str(ROOT / "docs/verification/addhost-breakit2/measure.py"), run_name="__main__")
except SystemExit as result:
    if result.code:
        raise
    if "ADDHOST_PROMPT_BUDGET_MS" in os.environ:
        if prompt_ms is None:
            print("BENCHMARK FAIL: painted prompt or SSH sign-in boundary missing", flush=True)
            sys.exit(1)
        budget = float(os.environ["ADDHOST_PROMPT_BUDGET_MS"])
        passed = prompt_ms <= budget
        print(f"METRIC addhost_browser signin_to_prompt_ms={prompt_ms:.3f} budget_ms={budget:.3f} result={'PASS' if passed else 'FAIL'}", flush=True)
        sys.exit(0 if passed else 1)
