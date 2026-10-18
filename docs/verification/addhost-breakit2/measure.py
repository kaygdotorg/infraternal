#!/usr/bin/env python3
"""Time add-host against this lane's disposable Docker target; capabilities stay in pipes (#169)."""
import argparse
import base64
import hashlib
import ipaddress
import os
from pathlib import Path
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
# Each repair run owns its scratch storage; a short alias keeps Unix sockets valid.
SCRATCH = Path(os.environ.get("BREAKIT2_SCRATCH", str(Path.home() / ".cache/codex-scratch/addhost-breakit2")))
DOCKER = ["sudo", "-n", "docker"]
TARGET = "addhost-breakit2-target"


def docker(*args, **kwargs):
    return subprocess.run(DOCKER + list(args), check=True, **kwargs)


def generated_key():
    private = subprocess.check_output(["openssl", "genpkey", "-algorithm", "ED25519"], stderr=subprocess.DEVNULL)
    public = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private, stderr=subprocess.DEVNULL)
    raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + public[12:]
    return private, "ssh-ed25519 " + base64.b64encode(raw).decode()


def stage_packet_filter():
    """Copy this host's packet-filter frontend into the target; the image has none."""
    docker("cp", "/usr/sbin/nft", f"{TARGET}:/usr/sbin/nft", stdout=subprocess.DEVNULL)
    listing = subprocess.check_output(["/usr/bin/ldd", "/usr/sbin/nft"], text=True)
    for line in listing.splitlines():
        fields = line.split()
        library = fields[2] if len(fields) > 2 and fields[1] == "=>" else ""
        if library.startswith("/") and subprocess.run(DOCKER + ["exec", TARGET, "test", "-e", library]).returncode:
            docker("cp", "-L", library, f"{TARGET}:{library}", stdout=subprocess.DEVNULL)


def mesh_state():
    """Report the mesh kernel objects on the target by name only."""
    link = subprocess.run(DOCKER + ["exec", TARGET, "ip", "link", "show", "infraternal0"], capture_output=True).returncode == 0
    tables = subprocess.run(DOCKER + ["exec", TARGET, "sh", "-c", "[ -x /usr/sbin/nft ] && /usr/sbin/nft list tables || true"], capture_output=True, text=True).stdout
    return f"mesh_link_present={link} mesh_table_present={'inet infraternal_mesh' in tables}"


# Everything removal must take away, per mode, as one shell probe on the target.
REMOVAL_PROBE = """
set -u
if [ "$1" = root ]; then
  base=/var/lib/infraternal unit=/etc/systemd/system/infraternal-agent.service launcher=/usr/local/bin/infraternal
  active=$(systemctl is-active infraternal-agent.service || true)
  scopes=$(systemctl list-units --all --plain --no-legend 'infraternal-session-*' | wc -l)
else
  base=/home/target/.local/share/infraternal unit=/home/target/.config/systemd/user/infraternal-agent.service launcher=/home/target/.local/bin/infraternal
  user() { runuser -u target -- env XDG_RUNTIME_DIR=/run/user/1101 "$@"; }
  active=$(user systemctl --user is-active infraternal-agent.service || true)
  scopes=$(user systemctl --user list-units --all --plain --no-legend 'infraternal-session-*' | wc -l)
fi
processes=0
for comm in /proc/[0-9]*/comm; do
  [ "$(cat "$comm" 2>/dev/null)" = infraternal ] && processes=$((processes + 1))
done
present() { if [ -e "$1" ] || [ -L "$1" ]; then echo True; else echo False; fi; }
echo "unit_active=$active session_scopes=$scopes infraternal_processes=$processes data_present=$(present $base) unit_present=$(present $unit) launcher_present=$(present $launcher)"
"""


def prove_removed(mode):
    """Poll until the host-side uninstall finished (bounded by its 30 s limit), then require nothing of it left.

    The rootful seed is a marked interface and table this installation never
    recorded, as the server's own infraternal agent would own on its machine:
    uninstall must leave both (#235). The kernel tests in
    crates/plugins/mesh/tests/review_retire_ownership.rs prove that a
    recorded interface and filter are removed.
    """
    clean = "unit_active=inactive session_scopes=0 infraternal_processes=0 data_present=False unit_present=False launcher_present=False"
    seeded = mode == "root"
    kept = f"mesh_link_present={seeded} mesh_table_present={seeded}"
    deadline = time.monotonic() + 45
    while True:
        state = subprocess.run(DOCKER + ["exec", TARGET, "sh", "-c", REMOVAL_PROBE, "probe", mode], capture_output=True, text=True).stdout.strip()
        mesh = mesh_state()
        done = state == clean and mesh == kept
        if done or time.monotonic() > deadline:
            break
        time.sleep(0.25)
    print(f"REMOVED mode={mode} {state} {mesh}", flush=True)
    if seeded:
        # Leave the fixture as the seed found it for the re-add run.
        subprocess.run(DOCKER + ["exec", TARGET, "ip", "link", "delete", "infraternal0"], capture_output=True)
        subprocess.run(DOCKER + ["exec", TARGET, "/usr/sbin/nft", "delete table inet infraternal_mesh"], capture_output=True)
    assert done, "removal left infraternal on the host, or took a mesh object it did not create"


def main():
    global TARGET
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", choices=["addhost-breakit2-target", "addhost-breakit2-alpine"], default=TARGET)
    parser.add_argument("--container-name", help="unique owned Docker fixture name")
    parser.add_argument("--controller-ip", type=ipaddress.IPv4Address, default=ipaddress.IPv4Address("10.69.69.125"), help="local controller address reachable from the disposable target")
    parser.add_argument("--ssh-server", choices=["openssh", "netbird"], default="openssh")
    parser.add_argument("--netbird-binary", type=Path, help="owned standalone real server fixture")
    parser.add_argument("--expect-failure", action="store_true", help="assert refusal, retired authority and empty owned host state")
    parser.add_argument("--remove", action="store_true", help="after joining, remove the host as the canvas does and prove nothing is left on it (#235)")
    parser.add_argument("--fresh", action="store_true", help="recreate only this lane target before measuring")
    parser.add_argument("--test-binary", type=Path, required=True)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--session-payload", type=Path, help="explicit trusted initial-session fixture image")
    parser.add_argument("--rtt", type=int, choices=[0, 150], default=0)
    parser.add_argument("--mode", choices=["rootless", "root"], default="rootless")
    parser.add_argument("--user", choices=["target", "root"], default="target")
    parser.add_argument("--case", choices=["clean", "tiny-disk", "readonly-home", "noexec-tmp", "foreign-base", "linger-off", "no-manager", "password-sudo", "no-sudo"], default="clean")
    parser.add_argument("--shell", choices=["bash", "zsh", "fish", "sh"], default="bash")
    args = parser.parse_args()
    if "ADDHOST_INSTANT" in os.environ and args.session_payload is None:
        parser.error("Instant-shell measurements require --session-payload; a full-image fallback is a different case")
    if args.session_payload is not None:
        try:
            args.session_payload = args.session_payload.resolve(strict=True)
            if not args.session_payload.is_file():
                parser.error("The session fixture image must be a regular file")
        except OSError:
            parser.error("The session fixture image is unavailable")
    # Cargo feature removal can leave a valid test executable without this live
    # fixture. A zero-test success must never count as provisioning evidence.
    listing = subprocess.check_output([str(args.test_binary.resolve()), "--list"], text=True)
    live_tests = [line.removesuffix(": test") for line in listing.splitlines()
                  if line.endswith("breakit2_live_ssh_install_join_and_terminal: test")]
    if len(live_tests) != 1:
        raise RuntimeError("The controller must contain exactly one live host provisioning test; build with the remote feature")
    with args.payload.open("rb") as image:
        full_digest = hashlib.file_digest(image, "sha256").hexdigest()
    print(f"ARTIFACT full_bytes={args.payload.stat().st_size} full_sha256={full_digest}", flush=True)
    if args.session_payload is not None:
        with args.session_payload.open("rb") as image:
            session_digest = hashlib.file_digest(image, "sha256").hexdigest()
        print(f"ARTIFACT session_bytes={args.session_payload.stat().st_size} session_sha256={session_digest}", flush=True)
    TARGET = args.container_name or args.container
    if not TARGET or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in TARGET):
        parser.error("--container-name must be a Docker fixture identifier")
    if args.fresh and args.container != "addhost-breakit2-target":
        parser.error("--fresh recreates only the Debian systemd target")
    scratch = SCRATCH / "live"
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    scratch.chmod(0o700)
    if args.fresh:
        subprocess.run(DOCKER + ["rm", "-f", TARGET], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Static payloads need no build-host store on the performance machine.
        store_mount = ["--mount", "type=bind,src=/nix/store,dst=/nix/store,readonly"] if Path("/nix/store").is_dir() else []
        docker("run", "-d", "--name", TARGET, "--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", *store_mount, "infraternal-addhost-breakit2:debian", stdout=subprocess.DEVNULL)
        for _ in range(100):
            ready = subprocess.run(DOCKER + ["exec", TARGET, "loginctl", "enable-linger", "target"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Disposable target system bus did not start")
    if args.container == "addhost-breakit2-target":
        # The target image's service manager must never race the fixture sshd
        # for its listen port while systemd finishes initial activation.
        docker("exec", TARGET, "systemctl", "mask", "--now", "ssh.service", "ssh.socket", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    private, public = generated_key()
    ip = subprocess.check_output(DOCKER + ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", TARGET], text=True).strip()
    if args.container == "addhost-breakit2-target":
        docker("exec", TARGET, "usermod", "-s", f"/bin/{args.shell}", "target")
    docker("exec", TARGET, "sh", "-c", f"grep -q 'addhost-breakit2.test' /etc/hosts || printf '{args.controller_ip} addhost-breakit2.test\\n' >> /etc/hosts")
    # Cases mutate only the fresh disposable target. Recreate it between cases;
    # this intentionally does not pretend that a later case is a clean install.
    cases = {
        "tiny-disk": ["mount -t tmpfs -o size=1m,uid=1101,gid=1101 tmpfs /home/target"],
        "readonly-home": ["mount --bind /home/target /home/target", "mount -o remount,bind,ro /home/target"],
        "noexec-tmp": ["mount -o remount,noexec /tmp"],
        "foreign-base": ["install -d -o target -g target /home/target/.local/share/infraternal", "printf 'foreign fixture data\\n' > /home/target/.local/share/infraternal/foreign; chown target:target /home/target/.local/share/infraternal/foreign"],
        "linger-off": ["loginctl disable-linger target"],
        "no-manager": ["systemctl mask --now user@1101.service"],
        "password-sudo": ["printf 'target ALL=(ALL) ALL\\n' > /etc/sudoers.d/target"],
        "no-sudo": ["mv /usr/bin/sudo /usr/bin/sudo.breakit2"],
    }
    for command in cases.get(args.case, []):
        docker("exec", TARGET, "sh", "-c", command)
    if os.environ.get("ADDHOST_FAST_STEP_PROFILE") == "1":
        # Target-owned diagnostics contain fixed names/status/numbers only. The
        # wrapper delegates untouched stdin and output to the actual shell.
        wrapper_script = (ROOT / "docs/verification/addhost-breakit2/step-shell.sh").read_bytes()
        docker("exec", "-i", TARGET, "/bin/sh", "-c",
               "cat > /usr/local/bin/sh; chmod 755 /usr/local/bin/sh; : > /run/addhost-fast-step-times; chmod 666 /run/addhost-fast-step-times",
               input=wrapper_script)
    script = (ROOT / "docs/verification/addhost-breakit2/sshd.py").read_text()
    if args.ssh_server == "netbird":
        if args.netbird_binary is None:
            parser.error("--netbird-binary is required for the owned server fixture")
        gateway = subprocess.check_output(DOCKER + ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", TARGET], text=True).strip()
        docker("cp", str(args.netbird_binary.resolve()), f"{TARGET}:/usr/local/lib/netbird-ssh-fixture")
        server_command = ["exec", "-i", TARGET, "/usr/local/lib/netbird-ssh-fixture", ip, gateway]
    else:
        server_command = ["exec", "-i", TARGET, "python3", "-u", "-c", script]
    sshd = subprocess.Popen(DOCKER + server_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        sshd.stdin.write((public + "\n").encode())
        sshd.stdin.close()
        host_public = sshd.stdout.readline().decode().strip()
        assert host_public.startswith("ssh-ed25519 ")
        for _ in range(100):
            listening = subprocess.run(DOCKER + ["exec", TARGET, "python3", "-c", "import socket; s=socket.socket(); s.settimeout(.2); s.connect(('127.0.0.1',22)); s.close()"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if listening.returncode == 0 and sshd.poll() is None:
                break
            if sshd.poll() is not None:
                raise RuntimeError("Disposable fixture sshd failed to start")
            time.sleep(0.1)
        else:
            raise RuntimeError("Disposable fixture sshd did not listen")
        known = scratch / "known_hosts"
        known.write_text(f"{ip} {host_public}\n")
        known.chmod(0o600)
        config = scratch / "config"
        config.write_text(f"# Generated public fixture policy, strict host keys.\nHost *\n UserKnownHostsFile {known}\n GlobalKnownHostsFile /dev/null\n StrictHostKeyChecking yes\n UpdateHostKeys no\n")
        wrapper = scratch / "ssh"
        fdpass = ""
        if os.environ.get("BREAKIT2_FDPASS_CANDIDATE") == "1":
            # This experimental connector changes only the first owned master,
            # never config inspection, later mux commands or trust admission.
            candidate = ROOT / "docs/verification/addhost-breakit2/fdpass-candidate.py"
            fdpass = (
                'for argument; do\n'
                '    if [ "$argument" = -M ]; then\n'
                f"        exec /usr/bin/ssh -F '{config}' -o ProxyUseFdpass=yes "
                f"-o 'ProxyCommand=/usr/bin/python3 {candidate} %h %p' \"$@\"\n"
                '    fi\n'
                'done\n'
            )
        wrapper.write_text(f"#!/bin/sh\n{fdpass}exec /usr/bin/ssh -F '{config}' \"$@\"\n")
        wrapper.chmod(0o700)
        if args.rtt:
            # Both delays and redirect devices live solely in the target netns.
            docker("exec", TARGET, "ip", "link", "add", "ifb0", "type", "ifb")
            docker("exec", TARGET, "ip", "link", "set", "ifb0", "up")
            docker("exec", TARGET, "tc", "qdisc", "add", "dev", "eth0", "handle", "ffff:", "ingress")
            docker("exec", TARGET, "tc", "filter", "add", "dev", "eth0", "parent", "ffff:", "protocol", "all", "matchall", "action", "mirred", "egress", "redirect", "dev", "ifb0")
            for device in ["eth0", "ifb0"]:
                docker("exec", TARGET, "tc", "qdisc", "add", "dev", device, "root", "netem", "delay", "75ms")
        print(f"ENVIRONMENT machine={os.uname().nodename} cores={os.cpu_count()} load={Path('/proc/loadavg').read_text().strip()} ssh_server={args.ssh_server} case={args.case} user={args.user} rtt_ms={args.rtt} mode={args.mode} shell={args.shell} payload_bytes={args.payload.stat().st_size}", flush=True)
        environment = dict(os.environ, INFRATERNAL_TEST_STATE_ROOT=str(scratch), INFRATERNAL_REMOTE_TEST_BINARY=str(args.payload.resolve()), BREAKIT2_TARGET=f"{args.user}@{ip}:22", BREAKIT2_MODE=args.mode, BREAKIT2_CONTROLLER_IP=str(args.controller_ip))
        if args.session_payload is not None:
            environment["INFRATERNAL_REMOTE_TEST_SESSION_BINARY"] = str(args.session_payload)
        if args.expect_failure:
            environment["BREAKIT2_EXPECT_FAILURE"] = "1"
        seeder = None
        if args.remove:
            if args.expect_failure:
                parser.error("--remove needs a successful join")
            environment["BREAKIT2_REMOVE"] = "1"
            for name in ("removal-ready", "removal-go"):
                (scratch / name).unlink(missing_ok=True)
            if args.mode == "root":
                stage_packet_filter()
            import threading
            def seed():
                # Wait for the joined host, then place marked kernel objects
                # this installation never recorded, as another infraternal
                # agent on the machine would own them. Removal must leave both
                # and name them (#235).
                deadline = time.monotonic() + 300
                while not (scratch / "removal-ready").exists():
                    if time.monotonic() > deadline:
                        return
                    time.sleep(0.05)
                if args.mode == "root":
                    for command in (["ip", "link", "add", "infraternal0", "type", "wireguard"],
                                    ["ip", "link", "set", "infraternal0", "alias", "infraternal.mesh.v1"],
                                    ["/usr/sbin/nft", "add table inet infraternal_mesh { comment \"infraternal.mesh.v1\"; }"]):
                        docker("exec", TARGET, *command)
                    print("SEEDED " + mesh_state(), flush=True)
                (scratch / "removal-go").write_bytes(b"")
            seeder = threading.Thread(target=seed, daemon=True)
            seeder.start()
        time.sleep(0.3)
        command = [str(args.test_binary.resolve()), live_tests[0], "--exact", "--ignored", "--nocapture"]
        if os.environ.get("ADDHOST_FAST_TCP_PROFILE") == "1":
            import threading
            stop = threading.Event()
            def sample():
                started = time.monotonic()
                while not stop.wait(0.2):
                    snapshot = subprocess.run(["ss", "-tin", "dst", ip], capture_output=True, text=True, check=True)
                    print(f"TCP_PROFILE elapsed_ms={(time.monotonic()-started)*1000:.3f}\n{snapshot.stdout}", flush=True)
            sampler = threading.Thread(target=sample)
            sampler.start()
            try:
                result = subprocess.run(command, input=private, env=environment, cwd=ROOT)
            finally:
                stop.set()
                sampler.join()
        else:
            result = subprocess.run(command, input=private, env=environment, cwd=ROOT)
        if result.returncode == 0 and args.remove:
            prove_removed(args.mode)
            raise SystemExit(0)
        if result.returncode == 0 and not args.expect_failure:
            home = "/root" if args.user == "root" else "/home/target"
            base = "/var/lib/infraternal" if args.mode == "root" else f"{home}/.local/share/infraternal"
            installed = docker("exec", TARGET, "sha256sum", f"{base}/bin/live", capture_output=True, text=True)
            assert installed.stdout.split()[0] == full_digest, "Installed executable differs from the full fixture image"
            print(f"PROOF installed_full_sha256_matches=true full_sha256={full_digest}", flush=True)
        # Queue counters distinguish the requested delay from unintended fixture loss.
        if os.environ.get("ADDHOST_FAST_STEP_PROFILE") == "1":
            docker("exec", TARGET, "/bin/cat", "/run/addhost-fast-step-times")
        for device in ["eth0", "ifb0"] if args.rtt else ["eth0"]:
            print(f"QDISC device={device}", flush=True)
            docker("exec", TARGET, "tc", "-s", "qdisc", "show", "dev", device)
        docker("exec", TARGET, "python3", "-c", "from pathlib import Path; b=Path('/home/target/.local/share/infraternal'); print('CLEANUP base_present='+str(b.exists())+' launcher_present='+str(Path('/home/target/.local/bin/infraternal').exists())+' unit_present='+str(Path('/home/target/.config/systemd/user/infraternal-agent.service').exists())+' foreign_present='+str((b/'foreign').exists()))")
        if args.mode == "root":
            docker("exec", TARGET, "python3", "-c", "from pathlib import Path; print('ROOT_STATE base_present='+str(Path('/var/lib/infraternal').exists())+' launcher_present='+str(Path('/usr/local/bin/infraternal').exists())+' unit_present='+str(Path('/etc/systemd/system/infraternal-agent.service').exists()))")
        docker("exec", TARGET, "sh", "-c", "printf 'CLEANUP live_unit='; systemctl is-active infraternal-agent.service || true; printf 'CLEANUP user_unit='; runuser -u target -- env XDG_RUNTIME_DIR=/run/user/1101 systemctl --user is-active infraternal-agent.service || true")
        docker("exec", TARGET, "python3", "-c", "import subprocess; from pathlib import Path; scopes=subprocess.run(['runuser','-u','target','--','env','XDG_RUNTIME_DIR=/run/user/1101','systemctl','--user','list-units','--type=scope','--state=running','--no-legend','--plain'],capture_output=True,text=True) if Path('/usr/sbin/runuser').exists() else None; count=sum('infraternal-session-' in l for l in scopes.stdout.splitlines()) if scopes and scopes.returncode==0 else -1; processes=sum(p.read_text().strip()=='infraternal' for p in Path('/proc').glob('[0-9]*/comm') if p.exists()); print(f'PROCESS_STATE user_running_session_scopes={count} infraternal_processes={processes}')")
        if args.expect_failure and args.case != "foreign-base":
            clean = subprocess.run(DOCKER + ["exec", TARGET, "python3", "-c", "from pathlib import Path; assert not Path('/home/target/.local/share/infraternal').exists(), 'failed add-host left owned installation artifacts'"])
            assert clean.returncode == 0, "failure cleanup contract did not hold"
        raise SystemExit(result.returncode)
    finally:
        # Kill only our disposable sshd through its public pid receipt, then stop
        # the exec client. Destroy the container separately after evidence checks.
        subprocess.run(DOCKER + ["exec", TARGET, "sh", "-c", "if [ -f /run/addhost-breakit2/sshd.pid ]; then kill $(cat /run/addhost-breakit2/sshd.pid); fi"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sshd.terminate()
        try:
            sshd.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sshd.kill()
            sshd.wait()
        if args.rtt:
            for command in [["tc", "qdisc", "del", "dev", "eth0", "root"], ["tc", "qdisc", "del", "dev", "eth0", "ingress"], ["ip", "link", "del", "ifb0"]]:
                subprocess.run(DOCKER + ["exec", TARGET] + command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
