#!/usr/bin/env python3
"""Probe disposable login-shell and privilege edges over strict real OpenSSH; no stored private fixture key (#169)."""
import os
import argparse
from pathlib import Path
import re
import subprocess
import time
from measure import DOCKER, ROOT, SCRATCH, TARGET, docker, generated_key


def main():
    global TARGET
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assert-startup-safe", action="store_true")
    parser.add_argument("--container", default=TARGET)
    parser.add_argument("--basic", action="store_true", help="probe only; no shell/privilege/systemd mutations")
    args = parser.parse_args()
    TARGET = args.container
    scratch = SCRATCH / "targets"
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    scratch.chmod(0o700)
    private, public = generated_key()
    ip = subprocess.check_output(DOCKER + ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", TARGET], text=True).strip()
    sshd = subprocess.Popen(DOCKER + ["exec", "-i", TARGET, "python3", "-u", "-c", (ROOT / "docs/verification/addhost-breakit2/sshd.py").read_text()], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    agent = subprocess.Popen(["ssh-agent", "-D", "-a", str(scratch / "agent.sock")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        sshd.stdin.write((public + "\n").encode())
        sshd.stdin.close()
        host_public = sshd.stdout.readline().decode().strip()
        assert host_public.startswith("ssh-ed25519 ")
        (scratch / "known_hosts").write_text(f"{ip} {host_public}\n")
        environment = dict(os.environ, SSH_AUTH_SOCK=str(scratch / "agent.sock"), SSH_ASKPASS_REQUIRE="never")
        for _ in range(100):
            if (scratch / "agent.sock").exists():
                break
            time.sleep(0.05)
        subprocess.run(["ssh-add", "-"], input=private, env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        source = (ROOT / "crates/plugins/ssh/src/probe.rs").read_text()
        check = re.search(r'pub const CHECK_SCRIPT: &str = r#"(.*?)"#;', source, re.S).group(1)
        base = ["ssh", "-F", "/dev/null", "-T", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={scratch / 'known_hosts'}", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentityFile=none", "-o", "BatchMode=yes"]
        print(f"ENVIRONMENT machine={os.uname().nodename} cores={os.cpu_count()} load={Path('/proc/loadavg').read_text().strip()}", flush=True)

        failed_startup = []

        def probe(name, user="target", timeout=4):
            started = time.monotonic()
            try:
                result = subprocess.run(base + [f"{user}@{ip}", "sh -c '" + check.replace("'", "'\\''") + "'"], env=environment, capture_output=True, timeout=timeout)
                lines = result.stdout.decode(errors="replace").splitlines()
                canonical = len(lines) == 9 and lines[0] == "INFRATERNAL_CHECK_V1"
                # Emit fixed observation fields, never arbitrary remote output.
                suffix = f" init={lines[3]} uid={lines[4]} sudo={lines[5]} user_manager={lines[6]} linger={lines[7]}" if canonical else ""
                print(f"TARGET case={name} status={result.returncode} canonical={canonical} output_bytes={len(result.stdout)} elapsed_ms={(time.monotonic()-started)*1000:.3f}{suffix}", flush=True)
                if ("-env-" in name or "-print" in name) and (not canonical or result.returncode != 0):
                    failed_startup.append(name)
            except subprocess.TimeoutExpired:
                print(f"TARGET case={name} status=timeout canonical=False elapsed_ms={(time.monotonic()-started)*1000:.3f}", flush=True)
                failed_startup.append(name)

        if args.basic:
            probe("basic-non-root")
            probe("basic-root", "root")
            return
        for shell in ["bash", "zsh", "fish", "sh"]:
            docker("exec", TARGET, "usermod", "-s", f"/bin/{shell}", "target", stdout=subprocess.DEVNULL)
            probe(f"{shell}-clean")
        docker("exec", TARGET, "usermod", "-s", "/bin/zsh", "target", stdout=subprocess.DEVNULL)
        startup = [
            ("print", "printf 'public startup greeting\\n'"),
            ("exit", "exit 0"),
            ("prompt", "read reply"),
            ("tmux", "exec tmux new-session"),
            ("screen", "exec screen"),
            ("hang", "sleep 10"),
        ]
        for name, body in startup:
            docker("exec", "-i", TARGET, "sh", "-c", "cat > /home/target/.zshenv; chown target:target /home/target/.zshenv", input=(body + "\n").encode(), stdout=subprocess.DEVNULL)
            probe(f"zsh-env-{name}")
        docker("exec", TARGET, "rm", "-f", "/home/target/.zshenv", stdout=subprocess.DEVNULL)
        docker("exec", TARGET, "usermod", "-s", "/bin/bash", "target", stdout=subprocess.DEVNULL)
        docker("exec", "-i", TARGET, "sh", "-c", "cat > /home/target/.bashrc; chown target:target /home/target/.bashrc", input=b"printf 'public bash startup greeting\\n'\n", stdout=subprocess.DEVNULL)
        probe("bash-rc-print")
        docker("exec", TARGET, "rm", "-f", "/home/target/.bashrc", stdout=subprocess.DEVNULL)
        docker("exec", "-i", TARGET, "sh", "-c", "mkdir -p /home/target/.config/fish; cat > /home/target/.config/fish/config.fish; chown -R target:target /home/target/.config/fish", input=b"printf 'public fish startup greeting\\n'\n", stdout=subprocess.DEVNULL)
        docker("exec", TARGET, "usermod", "-s", "/bin/fish", "target", stdout=subprocess.DEVNULL)
        probe("fish-config-print")
        docker("exec", TARGET, "rm", "-f", "/home/target/.config/fish/config.fish", stdout=subprocess.DEVNULL)
        docker("exec", TARGET, "usermod", "-s", "/bin/bash", "target", stdout=subprocess.DEVNULL)
        probe("root-passwordless", "root")
        docker("exec", TARGET, "sh", "-c", "printf 'target ALL=(ALL) ALL\\n' > /etc/sudoers.d/target", stdout=subprocess.DEVNULL)
        probe("password-sudo")
        docker("exec", TARGET, "mv", "/usr/bin/sudo", "/usr/bin/sudo.breakit2", stdout=subprocess.DEVNULL)
        probe("no-sudo")
        docker("exec", TARGET, "mv", "/usr/bin/sudo.breakit2", "/usr/bin/sudo", stdout=subprocess.DEVNULL)
        docker("exec", TARGET, "sh", "-c", "printf 'target ALL=(ALL) NOPASSWD: ALL\\n' > /etc/sudoers.d/target", stdout=subprocess.DEVNULL)
        docker("exec", TARGET, "loginctl", "disable-linger", "target", stdout=subprocess.DEVNULL)
        probe("linger-off")
        docker("exec", TARGET, "systemctl", "mask", "--now", "user@1101.service", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        probe("no-user-manager")
        docker("exec", TARGET, "systemctl", "unmask", "user@1101.service", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        docker("exec", TARGET, "loginctl", "enable-linger", "target", stdout=subprocess.DEVNULL)
        # Change only our disposable public pin; an unknown/replaced host key
        # must be rejected without publishing trust or installing anything.
        (scratch / "known_hosts").write_text(f"{ip} {public}\n")
        probe("changed-host-key")
        if args.assert_startup_safe:
            assert not failed_startup, "SSH check is blocked by startup profiles: " + ", ".join(failed_startup)
    finally:
        subprocess.run(DOCKER + ["exec", TARGET, "sh", "-c", "if [ -f /run/addhost-breakit2/sshd.pid ]; then kill $(cat /run/addhost-breakit2/sshd.pid); fi"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sshd.terminate()
        agent.terminate()
        for process in [sshd, agent]:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
