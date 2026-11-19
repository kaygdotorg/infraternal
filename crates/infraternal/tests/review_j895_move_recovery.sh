#!/usr/bin/env bash
# Replay J740's live-server relocation in private mount, network and PID
# namespaces. The narrow systemctl adapter runs the effective generated
# ExecStart and reports process state. J803/J771 separately check call order.
set -euo pipefail
P=${PROOF_ROOT:?}
BIN=${BIN:?}
method=${1:?choose a proof scenario}
trap 'printf "HARNESS_ERROR method=%s line=%s\n" "$method" "$LINENO" >&2' ERR
[[ $$ == 1 && $(id -u) == 0 ]]
for dir in /run/systemd /var/lib; do
    if [[ "$dir" == /var/lib && "$method" == full ]]; then
        mount -t tmpfs -o mode=0755,size=32m none "$dir"
    else
        mount -t tmpfs -o mode=0755 none "$dir"
    fi
done
if [[ -d /run/dbus ]]; then mount -t tmpfs none /run/dbus; fi
mkdir -m 755 "$P/units" "$P/localbin"
mount --bind "$P/units" /etc/systemd/system
mount --bind "$P/localbin" /usr/local/bin
ip link set lo up
export UNIT=/etc/systemd/system/infraternal-server.service
UNIT_NAME=${UNIT##*/}
cat > "$P/systemctl" <<'PY'
#!/usr/bin/python3
"""Run the generated service command in the proof's private namespaces."""
import os
import shlex
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

unit = Path(os.environ["UNIT"])
root = Path(os.environ["PROOF_ROOT"])
pid_path = root / "server.pid"
worker = unit.with_name("infraternal-d395-" + unit.name)
client = root / "cutover-client"
target = Path("/var/lib/infraternal")

def cut(point, data):
    """Write to the selected database, then kill only the installer client."""
    marker = root / (point + "-kill")
    if not marker.is_file() or not client.is_file():
        return
    marker.unlink()
    with sqlite3.connect(data / "infraternal.sqlite") as database:
        database.execute("CREATE TABLE IF NOT EXISTS d395_fixture (point TEXT)")
        database.execute("INSERT INTO d395_fixture VALUES (?)", (point,))
    (root / "cut-reached").write_text(point)
    os.killpg(int(client.read_text()), signal.SIGKILL)


def active():
    """Return the service process group while its leader can still run."""
    if pid_path.exists():
        pid = int(pid_path.read_text())
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            if state != "Z":
                return pid
        except FileNotFoundError:
            pass
    return None

def wait_for(ready):
    """Wait for the expected state under one deadline."""
    deadline = time.monotonic() + 60
    while not ready():
        if time.monotonic() >= deadline:
            raise RuntimeError("service state did not change before deadline")
        time.sleep(0.1)

args = sys.argv[1:]
with (root / "systemctl.log").open("a") as log:
    print(shlex.join(args), file=log)
if args in (["enable", worker.name], ["disable", worker.name]):
    pass
elif args == ["start", worker.name]:
    # Model a manager-owned process with a different process group and no
    # dependency on the waiting CLI or the CLI's output pipes.
    client.write_text(str(os.getppid()))
    os.setsid()
    line = next(line for line in worker.read_text().splitlines() if line.startswith("ExecStart=:"))
    command = shlex.split(line.removeprefix("ExecStart=:"))
    with (root / "worker.log").open("ab") as log:
        job = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            cwd=root, start_new_session=True,
        )
        status = job.wait()
    (root / "worker.exit").write_text(str(status))
    sys.exit(status)
elif args == ["show", "-p", "ActiveState", "--value", unit.name]:
    print("active" if active() else "inactive")
elif args == ["show", "-p", "MainPID", "--value", unit.name]:
    print(active() or 0)
elif args == ["stop", unit.name]:
    if pid := active():
        os.killpg(pid, signal.SIGTERM)
        wait_for(lambda: not active())
    cut("post-stop", Path("/var/lib/j895-old"))
elif args in (["start", unit.name], ["enable", "--now", unit.name]):
    if args[0] == "start":
        cut("before-start", target)
    if not active():
        snippets = sorted(Path(f"{unit}.d").glob("*.conf"))
        line = [line for file in [unit, *snippets] for line in file.read_text().splitlines()
                if line.startswith("ExecStart=")][-1]
        command = shlex.split(line.removeprefix("ExecStart="))
        if (root / "wrong-tree").exists():
            command[command.index("--data") + 1] = "/var/lib/j895-old"
        with (root / "server.log").open("ab") as log:
            child = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                cwd=root, start_new_session=True,
            )
        pid_path.write_text(str(child.pid))
        data = Path(command[command.index("--data") + 1])
        wait_for(lambda: child.poll() is not None or (data / "setup-token.sock").is_socket())
        if child.poll() is not None:
            raise RuntimeError(f"server exited {child.returncode} before socket readiness")
    if args[0] == "start":
        cut("after-start", target)
    else:
        cut("after-enable", target)
elif args == ["daemon-reload"]:
    cut("cutover", target)
elif args != ["daemon-reload"]:
    sys.exit(1)
PY
chmod 0755 "$P/systemctl"
mount --bind "$P/systemctl" /usr/bin/systemctl
case "$method" in
    rename|resume|shared|force|partial|cutover|wrong-tree|post-stop|before-start|after-start|after-enable|metadata) old=/var/lib/j895-old ;;
    copy|full|stale) old=$P/old ;;
    *) exit 2 ;;
esac
target=/var/lib/infraternal
common=(--system --listen 127.0.0.1:47941 --behind-proxy --trusted-proxy 127.0.0.1 --host-firewall-off)
init() { common[2]="${LISTEN:-127.0.0.1:47941}"; "$BIN" --json server init "${common[@]}" "$@"; }
check() { local name=$1; shift; "$@" || { echo "CASE $name BAD"; exit 1; }; echo "CASE $name ok"; }
fp() { stat -c '%d:%i %a %s %y' "$1"; sha256sum < "$1"; }
token_ready() { "$BIN" server setup-token --data "$1" >/dev/null 2>&1; }
wait_token_ready() {
    local deadline=$((SECONDS+15))
    until token_ready "$1"; do
        (( SECONDS < deadline )) || return 1
        sleep 0.1 # Wait for the restarted server to replace its old setup socket.
    done
}
cp /proc/self/uid_map "$P/uid-map"
init --data "$old" --yes > "$P/first.json" 2> "$P/first.err"
pid_before=$(cat "$P/server.pid")
check OLD_SERVER_ANSWERS token_ready "$old"
printf 'J895 %s proof\n' "$method" > "$old/probe"
unit_before=$(fp "$UNIT")
if [[ "$method" == partial ]]; then
    /usr/bin/systemctl stop infraternal-server.service
    printf '%s' "$old" > "$old/.infraternal-move"
    mv -- "$old" "$target"
    mkdir "$UNIT.d"
    {
        printf '[Service]\nExecStart=\n'
        awk -v from="$old" -v to="$target" '/^ExecStart=/ {gsub(from, to); print}' "$UNIT"
    } > "$UNIT.d/10-effective.conf"
    check PARTIAL_ORIGINAL_UNIT test "$unit_before" = "$(fp "$UNIT")"
    check PARTIAL_DATA_PRESENT test -f "$target/probe"
    chmod 0600 "$UNIT.d/10-effective.conf"
    if ! init --yes > "$P/partial.json" 2> "$P/partial.err"; then
        check RESUME_REPAIRS_UNIT_AND_STARTS false
    fi
    check RESUME_BASE_POINTS_TO_TARGET grep -Fq '"--data" "/var/lib/infraternal"' "$UNIT"
    check RESUME_DROPIN_MODE test "$(stat -c %a "$UNIT.d/10-effective.conf")" = 600
    check RESUME_REPAIRS_UNIT_AND_STARTS wait_token_ready "$target"
    check RESUME_PRESERVES_DATABASE test -f "$target/probe"
    /usr/bin/systemctl stop infraternal-server.service
    echo RESULT=0
    exit 0
fi
if [[ "$method" == cutover || "$method" == post-stop || "$method" == before-start ||
      "$method" == after-start || "$method" == after-enable ]]; then
    touch "$P/$method-kill"
    status=0
    setsid "$BIN" --json server init "${common[@]}" --yes         > "$P/interrupted.json" 2> "$P/interrupted.err" || status=$?
    check CUTOVER_KILLED_INSTALLER test "$status" = 137
    check CUTOVER_SELECTED_BOUNDARY test "$(cat "$P/cut-reached")" = "$method"
    check CUTOVER_REACHES_MOVED_SERVER wait_token_ready "$target"
    deadline=$((SECONDS+15))
    until [[ -e "$P/worker.exit" ]]; do
        (( SECONDS < deadline )) || { echo "CASE CUTOVER_WORKER_DEADLINE BAD"; exit 1; }
        # sleep: wait for the independent manager job to publish its exit status.
        sleep 0.1
    done
    check CUTOVER_WORKER_SUCCESS test "$(cat "$P/worker.exit")" = 0
    check CUTOVER_MOVED_SERVICE_ACTIVE test "$(/usr/bin/systemctl show -p ActiveState --value "$UNIT_NAME")" = active
    check CUTOVER_NEW_UNIT_DURABLE grep -Fq '"--data" "/var/lib/infraternal"' "$UNIT"
    check CUTOVER_WRITE_PRESERVED python3 - "$target/infraternal.sqlite" "$method" <<'PY_CUT'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as database:
    assert database.execute("SELECT point FROM d395_fixture").fetchall() == [(sys.argv[2],)]
PY_CUT
    check CUTOVER_OLD_REMOVED_AFTER_HEALTH test ! -e "$old"
    /usr/bin/systemctl stop "$UNIT_NAME"
    echo RESULT=0
    exit 0
fi
if [[ "$method" == metadata ]]; then
    chown 0:65534 "$old"
    chmod 2750 "$old"
    python3 - "$old" <<'PY_META'
import os
import struct
import sys

old = sys.argv[1]
os.setxattr(old, "user.infraternal.proof", b"root metadata")
# Linux POSIX ACL version 2, with a named user and an explicit group mask.
acl = struct.pack("<I", 2) + b"".join(
    struct.pack("<HHI", tag, perm, ident)
    for tag, perm, ident in [(1, 7, -1), (2, 5, 65534), (4, 5, -1), (16, 5, -1), (32, 0, -1)]
    for ident in [ident & 0xffffffff]
)
for name in ("system.posix_acl_access", "system.posix_acl_default"):
    os.setxattr(old, name, acl)
PY_META
    meta() {
        stat -c '%a %u:%g' "$1"
        python3 -c 'import os, sys; print(sorted((n, os.getxattr(sys.argv[1], n)) for n in os.listxattr(sys.argv[1])))' "$1"
    }
    before=$(meta "$old")
    init --yes > "$P/metadata.json" 2> "$P/metadata.err"
    check METADATA_SERVER_ANSWERS token_ready "$target"
    after=$(meta "$target")
    printf 'ROOT_DIRECTORY_METADATA before=%s
after=%s
' "$before" "$after"
    check ROOT_DIRECTORY_METADATA test "$before" = "$after"
    /usr/bin/systemctl stop "$UNIT_NAME"
    echo RESULT=0
    exit 0
fi
if [[ "$method" == wrong-tree ]]; then
    touch "$P/wrong-tree"
    if init --yes > "$P/wrong-tree.json" 2> "$P/wrong-tree.err"; then
        check WRONG_TREE_REFUSED false
    fi
    check WRONG_TREE_EXPLAINS grep -Fq 'has not opened the moved database' "$P/wrong-tree.json"
    check WRONG_TREE_KEEPS_SOURCE test -f "$old/probe"
    check WRONG_TREE_KEEPS_CANDIDATE test -f "$target/probe"
    check WRONG_TREE_SERVICE_STOPPED test "$(/usr/bin/systemctl show -p ActiveState --value infraternal-server.service)" = inactive
    printf 'write from wrong tree
' > "$old/outstanding-write"
    rm "$P/wrong-tree"
    init --yes > "$P/wrong-tree-retry.json" 2> "$P/wrong-tree-retry.err"
    check WRONG_TREE_RETRY_STARTS_TARGET wait_token_ready "$target"
    backups=("$old".moved-*)
    check WRONG_TREE_BACKUP_RETAINS_WRITE test -f "${backups[0]}/outstanding-write"
    /usr/bin/systemctl stop infraternal-server.service
    echo RESULT=0
    exit 0
fi
if [[ "$method" == stale ]]; then
    other=/var/lib/.infraternal.partial-not-migration-data
    install -d -m 0700 "$other"
    printf 'unrelated fixture\n' > "$other/probe"
    init --yes > "$P/stale.json" 2> "$P/stale.err"
    check STALE_CASE_SERVER_ANSWERS token_ready "$target"
    if [[ -f "$other/probe" ]]; then
        echo "CASE UNRELATED_DIRECTORY_RETAINED ok"
        echo RESULT=0
    else
        echo "CASE UNRELATED_DIRECTORY_RETAINED BAD"
        echo RESULT=1
    fi
    /usr/bin/systemctl stop infraternal-server.service
    exit 0
fi
if [[ "$method" == full ]]; then
    dd if=/dev/zero of="$old/fill-fixture" bs=1M count=40 status=none
    if init --yes > "$P/full.json" 2> "$P/full.err"; then
        echo "CASE ENOSPC_FAILS_MOVE BAD"
        exit 1
    fi
    check ENOSPC_REPORTED grep -qi 'No space left on device' "$P/full.json"
    check ENOSPC_OLD_UNIT test "$unit_before" = "$(fp "$UNIT")"
    check ENOSPC_OLD_DATA test "$(cat "$old/probe")" = "J895 full proof"
    check ENOSPC_OLD_SERVER_ANSWERS wait_token_ready "$old"
    check ENOSPC_TARGET_ABSENT test ! -e "$target"
    check ENOSPC_NO_STAGING test -z "$(find /var/lib -maxdepth 1 -name '.infraternal.partial-*' -print)"
    check ENOSPC_OLD_MARKER_ABSENT test ! -e "$old/.infraternal-move"
    /usr/bin/systemctl stop infraternal-server.service
    echo RESULT=0
    exit 0
fi
if [[ "$method" == resume ]]; then
    /usr/bin/systemctl stop infraternal-server.service
    printf '%s' "$old" > "$old/.infraternal-move"
    mv -- "$old" "$target"
    check INTERRUPTED_RENAME_HAS_DATA test -f "$target/probe"
    check INTERRUPTED_RENAME_HAS_OLD_UNIT test "$unit_before" = "$(fp "$UNIT")"
    /usr/bin/systemctl start infraternal-server.service
    check OLD_UNIT_RECREATES_DATABASE test -f "$old/infraternal.sqlite"
    check OLD_UNIT_RECREATES_EMPTY_TREE test ! -e "$old/probe"
    init --yes > "$P/resume.json" 2> "$P/resume.err"
    check RECOVERY_STARTS_NEW_SERVER token_ready "$target"
    check RECOVERY_KEEPS_ORIGINAL_DATA test "$(cat "$target/probe")" = "J895 resume proof"
    backups=("$old".moved-*)
    check RECOVERY_RETAINS_REPLACEMENT test -f "${backups[0]}/infraternal.sqlite"
    /usr/bin/systemctl stop infraternal-server.service
    echo RESULT=0
    exit 0
fi
install -m 0600 /dev/null "$old/secret-fixture"
install -d -m 0700 "$old/private-fixture"
chown 0:65534 "$old/secret-fixture" "$old/private-fixture"
secret_mode=$(stat -c '%u:%g %a' "$old/secret-fixture")
private_mode=$(stat -c '%u:%g %a' "$old/private-fixture")

if [[ "$method" == force ]]; then
    if LISTEN=127.0.0.1:47942 init --yes --force > "$P/force.json" 2> "$P/force.err"; then
        check FORCE_REFUSED false
    fi
    check FORCE_REFUSAL_EXPLAINS grep -Fq 'configuration differs' "$P/force.json"
    check FORCE_UNIT_STILL_OLD test "$unit_before" = "$(fp "$UNIT")"
    check FORCE_PROCESS_STILL_MATCHES_UNIT grep -azq '127.0.0.1:47941' "/proc/$(cat "$P/server.pid")/cmdline"
    check FORCE_OLD_SERVER_ANSWERS token_ready "$old"
    check FORCE_DESTINATION_ABSENT test ! -e "$target"
    echo RESULT=0
    /usr/bin/systemctl stop infraternal-server.service
    exit 0
fi
if [[ "$method" == shared ]]; then
    install -d -m 0711 "$target"
    install -d -m 0755 "$target/bin"
    install -m 0755 /dev/null "$target/bin/agent-fixture"
    check SHARED_AGENT_REACHABLE_BEFORE setpriv --reuid 65534 --regid 65534 --clear-groups test -x "$target/bin/agent-fixture"
    if init --yes > "$P/shared.json" 2> "$P/shared.err"; then
        check SHARED_MOVE_REFUSED false
    fi
    check SHARED_REFUSAL_EXPLAINS grep -Fq 'shared install base' "$P/shared.json"
    check SHARED_OLD_SERVER_ANSWERS token_ready "$old"
    check SHARED_MODE_PRESERVED test "$(stat -c %a "$target")" = 711
    check SHARED_AGENT_REACHABLE_AFTER setpriv --reuid 65534 --regid 65534 --clear-groups test -x "$target/bin/agent-fixture"
    # Start a server that was explicitly configured to use the existing shared base.
    /usr/bin/systemctl stop infraternal-server.service
    init --data "$target" --yes --force > "$P/shared-explicit.json" 2> "$P/shared-explicit.err"
    check SHARED_EXPLICIT_SERVER_ANSWERS wait_token_ready "$target"
    check SHARED_EXPLICIT_MODE_PRESERVED test "$(stat -c %a "$target")" = 711
    check SHARED_AGENT_REACHABLE_AFTER_EXPLICIT_START setpriv --reuid 65534 --regid 65534 --clear-groups test -x "$target/bin/agent-fixture"
    /usr/bin/systemctl stop infraternal-server.service
    echo RESULT=0
    exit 0
fi
init --dry-run > "$P/plan.json" 2> "$P/plan.err"
python3 - "$P/plan.json" "$old" "$target" "$method" <<'PY'
import json, sys
plan, old, target, method = sys.argv[1:]
move = json.load(open(plan))["data"]["data_move"]
assert (move["from"], move["to"], move["same_filesystem"], move["moved"]) == (
    old, target, method == "rename", False
)
print("CASE PLAN_REPORTS_MOVE ok")
PY
check PLAN_KEEPS_UNIT test "$unit_before" = "$(fp "$UNIT")"
check PLAN_KEEPS_DESTINATION_ABSENT test ! -e "$target"
init --yes > "$P/move.json" 2> "$P/move.err"
pid_after=$(cat "$P/server.pid")
echo "METHOD=$method SERVER_PID_BEFORE=$pid_before SERVER_PID_AFTER=$pid_after"
check NEW_PROCESS test "$pid_before" != "$pid_after"
check NEW_SERVER_ANSWERS token_ready "$target"
check NEW_UNIT_DATA grep -Fq '"--data" "/var/lib/infraternal"' "$UNIT"
check OLD_PATH_GONE test ! -e "$old"
check DATA_CARRIED test "$(cat "$target/probe")" = "J895 $method proof"
python3 - "$P/move.json" "$target" "$method" "$old" <<'PY'
import json, pathlib, sqlite3, stat, sys
output, target, method, old = sys.argv[1:]
target = pathlib.Path(target)
move = json.load(open(output))["data"]["data_move"]
assert move["moved"] is True
if method == "copy":
    left = pathlib.Path(move["leftover"])
    assert left.name.startswith(pathlib.Path(old).name + ".moved-")
    assert (left / "probe").read_bytes() == (target / "probe").read_bytes()
    assert all(not p.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
               for p in [left, *left.rglob("*")] if not p.is_symlink())
    print(f"CASE DATED_LEFTOVER_READ_ONLY ok ({left.name})")
else:
    assert move["leftover"] is None
    print("CASE RENAME_HAS_NO_LEFTOVER ok")
with sqlite3.connect(f"file:{target}/infraternal.sqlite?mode=ro", uri=True) as db:
    assert db.execute("PRAGMA quick_check").fetchone() == ("ok",)
print("CASE LIVE_DATABASE_INTEGRITY ok")
PY
check TARGET_PRIVATE test "$(stat -c '%u:%g %a' "$target")" = "0:0 700"
check SECRET_MODE_AND_OWNER test "$(stat -c '%u:%g %a' "$target/secret-fixture")" = "$secret_mode"
check DIRECTORY_MODE_AND_OWNER test "$(stat -c '%u:%g %a' "$target/private-fixture")" = "$private_mode"
data_after=$(fp "$target/probe")
unit_after=$(fp "$UNIT")
init --yes > "$P/rerun.json" 2> "$P/rerun.err"
check NOOP_UNIT test "$unit_after" = "$(fp "$UNIT")"
check NOOP_HAS_NO_RELOCATION python3 -c 'import json,sys; assert "data_move" not in json.load(open(sys.argv[1]))["data"]' "$P/rerun.json"
check NOOP_DATA test "$data_after" = "$(fp "$target/probe")"
check NOOP_SERVER_PID test "$pid_after" = "$(cat "$P/server.pid")"
check NOOP_SERVER_ANSWERS token_ready "$target"
/usr/bin/systemctl stop infraternal-server.service
echo RESULT=0
