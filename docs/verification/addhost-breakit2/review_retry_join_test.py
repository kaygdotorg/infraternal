#!/usr/bin/env python3
"""Review #230 with real SSH, delayed service startup and isolated link delay."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("measure", Path(__file__).with_name("measure.py"))
MEASURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MEASURE)


@unittest.skipUnless(os.environ.get("REVIEW_JOIN_LIVE") == "1", "disposable perf-VM fixture opt-in")
class JoinDeadlineReview(unittest.TestCase):
    """Require healthy delayed hosts to finish without a second manual Retry."""

    def run_case(self, *, retry=False, rtt=0, startup=0, instant=True, tcp_only=False, mode="rootless"):
        self.assertEqual(os.uname().nodename, "infraternal-perf-test")
        fixture = Path(os.environ["REVIEW_JOIN_ARTIFACTS"])
        target = os.environ.get("REVIEW_JOIN_CONTAINER", "retry-join-time-r2")
        original = MEASURE.docker

        def docker(*args, **kwargs):
            # Both directions stay inside this disposable container's netns.
            if "netem" in args and args[-1] == "75ms":
                args = (*args[:-1], f"{rtt // 2}ms")
            result = original(*args, **kwargs)
            if args[:4] == ("exec", target, "systemctl", "mask") and tcp_only:
                MEASURE.stage_packet_filter()
                # Refuse only the daemon's fixture UDP port in this target;
                # enrollment HTTPS and the real TCP fallback remain reachable.
                original("exec", "-i", target, "/usr/sbin/nft", "-f", "-",
                         input=b"table inet review_join { chain output { type filter hook output priority 0; policy accept; udp dport 4930 counter drop; } ; }\n")
            if args[:4] == ("exec", target, "systemctl", "mask") and startup:
                original("exec", target, "sh", "-c",
                         "mkdir -p /home/target/.config/systemd/user/infraternal-agent.service.d; "
                         "printf '[Service]\\nExecStart=\\n"
                         f"ExecStart=/bin/sh -c \"sleep {startup}; exec "
                         "/home/target/.local/share/infraternal/bin/current agent "
                         "--data /home/target/.local/share/infraternal/state "
                         "--state /home/target/.local/share/infraternal/sessions run\"\\n' > "
                         "/home/target/.config/systemd/user/infraternal-agent.service.d/review.conf; "
                         "chown -R target:target /home/target/.config")
            return result

        arguments = ["measure.py", "--fresh", "--container-name", target,
                     "--controller-ip", "172.17.0.1", "--test-binary",
                     os.environ.get("REVIEW_JOIN_CONTROLLER", str(fixture / "server-tests")),
                     "--payload", str(fixture / "payload"), "--rtt", "150" if rtt else "0",
                     "--mode", mode, "--user", "root" if mode == "root" else "target"]
        if instant:
            arguments += ["--session-payload", str(fixture / "session")]
        if retry:
            arguments += ["--retry"]
        environment = dict(BREAKIT2_SCRATCH=str(fixture / "s"), BREAKIT2_READD="1",
                           ADDHOST_RETRY_PHASE_TIMING="1", INFRATERNAL_TEST_RTT="0")
        if instant:
            environment["ADDHOST_INSTANT"] = "1"
        print(f"REVIEW rtt_ms={rtt} startup_seconds={startup} retry={retry} instant={instant} tcp_only={tcp_only} mode={mode}", flush=True)
        try:
            with mock.patch.object(MEASURE, "DOCKER", ["docker"]), \
                 mock.patch.object(MEASURE, "TARGET", "addhost-breakit2-target"), \
                 mock.patch.object(MEASURE, "SCRATCH", fixture / "s"), \
                 mock.patch.object(MEASURE, "docker", docker), \
                 mock.patch.object(sys, "argv", arguments), \
                 mock.patch.dict(os.environ, environment):
                with self.assertRaises(SystemExit) as outcome:
                    MEASURE.main()
                self.assertEqual(outcome.exception.code, 0,
                                 "healthy delayed host failed setup instead of completing join")
        finally:
            # Destroy only the exact disposable container this test created.
            MEASURE.subprocess.run(["docker", "rm", "-f", target], check=True)
            print("CLEANUP review_container_removed=true", flush=True)

    def test_clean_and_already_added_zero_rtt(self):
        self.run_case()

    def test_retry_and_already_added_zero_rtt(self):
        self.run_case(retry=True)

    def test_clean_and_already_added_600_ms_rtt(self):
        self.run_case(rtt=600)

    def test_retry_and_already_added_600_ms_rtt(self):
        self.run_case(retry=True, rtt=600)

    def test_clean_slow_service_start(self):
        self.run_case(startup=2)

    def test_retry_slow_service_start(self):
        self.run_case(retry=True, startup=2)

    def test_retry_600_ms_rtt_slow_service_start(self):
        self.run_case(retry=True, rtt=600, startup=2)

    def test_full_image_slow_service_start(self):
        self.run_case(startup=2, instant=False)

    def test_tcp_fallback_zero_rtt(self):
        self.run_case(tcp_only=True)

    def test_clean_tcp_fallback_600_ms_rtt(self):
        self.run_case(rtt=600, tcp_only=True)

    def test_retry_tcp_fallback_600_ms_rtt(self):
        self.run_case(retry=True, rtt=600, tcp_only=True)

    def test_retry_root_lan(self):
        self.run_case(retry=True, mode="root")

    def test_clean_150_ms_rtt(self):
        self.run_case(rtt=150)

    def test_retry_150_ms_rtt(self):
        self.run_case(retry=True, rtt=150)

    def test_clean_tcp_fallback_150_ms_rtt(self):
        self.run_case(rtt=150, tcp_only=True)

    def test_retry_tcp_fallback_150_ms_rtt(self):
        self.run_case(retry=True, rtt=150, tcp_only=True)


if __name__ == "__main__":
    unittest.main()
