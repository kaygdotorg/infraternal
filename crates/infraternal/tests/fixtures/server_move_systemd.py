#!/usr/bin/env python3
"""Replay the persistent D395 boundaries using the real manager and server."""
import contextlib
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
import tempfile
import struct
import subprocess
import sys
import time
import traceback
import urllib.request

BIN = Path(os.environ["BIN"]).resolve()
UNITS = Path(os.environ["XDG_RUNTIME_DIR"]) / "systemd/user"
UNITS.mkdir(mode=0o700, parents=True, exist_ok=True)
os.umask(0o077)
CTL = "/usr/bin/systemctl"
CASES = (
    "admitted-start", "hook-no-record", "initial-partial-record",
    "saved-before-stop", "unrecorded-stage", "partial-stage", "published-rename",
    "published-exchange", "published-recorded", "database-recorded",
    "mixed-unit", "switched", "switched-active", "ready", "source-renamed",
    "source-removed", "receipt-with-journal", "receipt-without-journal",
    "boot-target", "concurrent-start", "failed-recovery", "nested-metadata",
)
COMBINED_RETIREMENT = ("backup-created", "entry-renamed", "entry-removed")


def systemctl(*args, check=True, deadline=45):
    """Operate only on the proof's units, using the actual host manager."""
    return subprocess.run(
        [CTL, "--user", *args], check=check, timeout=deadline, capture_output=True, text=True,
    )


def wait_for(predicate, seconds=40):
    """Wait for an observable readiness or completion event."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def health(port):
    """Read health from the test's loopback server."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as response:
            return response.status == 200
    except OSError:
        return False


def port_number():
    """Pick a loopback port currently available to the test."""
    with socket.socket() as bound:
        bound.bind(("127.0.0.1", 0))
        return bound.getsockname()[1]


def identity(path):
    """Encode the kernel identity the production journal expects."""
    info = path.stat()
    return dict(dev=info.st_dev, ino=info.st_ino)


def record(path, data):
    """Write a private serialized journal, request, or receipt fixture."""
    path.write_text(json.dumps(data))
    path.chmod(0o600)


def sqlite_values(path, extra=None):
    """Read the carried row, optionally simulating an early candidate write."""
    with contextlib.closing(sqlite3.connect(path / "infraternal.sqlite")) as db:
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS j925_fixture (value TEXT)")
            if extra:
                db.execute("INSERT INTO j925_fixture VALUES (?)", (extra,))
            return db.execute("SELECT value FROM j925_fixture ORDER BY rowid").fetchall()


def migration_history(path):
    """Read the versions and original checksums without altering the live database."""
    uri = (path / "infraternal.sqlite").as_uri() + "?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as db:
        return dict(db.execute("SELECT version, checksum FROM _sqlx_migrations"))


def copy_snapshot(source, target, selected=None):
    """Copy the stopped fixture, excluding transient sockets."""
    def ignore(folder, names):
        """Ignore exactly socket entries."""
        return [name for name in names
                if stat.S_ISSOCK((Path(folder) / name).lstat().st_mode)
                or (selected is not None and Path(folder) == source and source / name not in selected)]

    shutil.copytree(source, target, symlinks=True, ignore=ignore)



def copied_database_values(source, *, retained=False):
    """Read a stopped SQLite snapshot without checkpointing its original WAL."""
    with tempfile.TemporaryDirectory(dir=source.parent) as scratch:
        copy = Path(scratch)
        for file in source.glob("infraternal.sqlite*"):
            if retained:
                assert not file.stat().st_mode & 0o222, file
            dest = copy / file.name
            shutil.copyfile(file, dest)
            dest.chmod(0o600)
        with contextlib.closing(sqlite3.connect(copy / "infraternal.sqlite")) as db:
            assert db.execute("PRAGMA quick_check").fetchone() == ("ok",)
            return db.execute("SELECT value FROM j925_fixture ORDER BY rowid").fetchall()

def leave_committed_wal(path):
    """Exit a fixture writer before SQLite closes and checkpoints its sidecars."""
    subprocess.run(
        [sys.executable, "-c", """
import os
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
db.execute("PRAGMA journal_mode=WAL")
db.execute("INSERT INTO j925_fixture VALUES ('wal-only')")
db.commit()
os._exit(0)
""", str(path / "infraternal.sqlite")],
        check=True,
    )
    assert (path / "infraternal.sqlite-wal").exists()
    assert (path / "infraternal.sqlite-shm").exists()

def release_fifo(path):
    """Signal a waiting pre-start without blocking if its reader has exited."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ENXIO:
            return False
        raise
    with os.fdopen(fd, "w") as gate:
        gate.write("continue\n")
    return True


def run_case(workspace, case, combined=False):
    """Construct one on-disk frontier, then recover through real systemctl."""
    label = f"combined-{case}" if combined else case
    root = workspace / label
    root.mkdir(mode=0o700)
    prefix = f"d395-{os.getpid()}-{label}"
    server = f"{prefix}.service"
    target = f"{prefix}.target"
    unit = UNITS / server
    boot_target = UNITS / target
    drop_dir = UNITS / f"{server}.d"
    drop = drop_dir / "10-effective.conf"
    hook = drop_dir / "zz-infraternal-d395.conf"
    old, new, backup = (root / p for p in ("old", "new", "old.moved-test"))
    control = root / ".new.cutover"
    work = root / ".infraternal-move-new"
    stage = work / "data"
    manager = root / "systemctl"
    port = port_number()
    listener = f"127.0.0.1:{port}"
    timer = time.monotonic()
    old.mkdir(mode=0o700)
    if combined:
        old.chmod(0o711)
        new, backup = old / "server", old / ".server.moved-test"
        control = old / ".server.cutover"
        work = old / ".infraternal-move-server"
        stage = work / "data"
        agent = old / "agent"
        agent.mkdir(mode=0o700)
        (agent / "state").write_text("agent state")
        base_id, agent_id = identity(old), identity(agent / "state")
    frontier = "ready" if case in COMBINED_RETIREMENT else case
    control.mkdir(mode=0o700)

    def originals():
        """List the stopped server entries, excluding the separate infraternal agent and cutover paths."""
        return [p for p in old.iterdir()
                if p.name not in ("agent", control.name, work.name, new.name) and not p.is_socket()]

    def snapshot():
        """Publish the fixture's stopped snapshot as the real staging code would."""
        copy_snapshot(old, new, originals() if combined else None)
        if combined:
            new.chmod(0o700)

    def command(path, binary=BIN):
        """Render the product command the real manager will run."""
        return f'ExecStart="{binary}" "server" "--listen" "{listener}" "--data" "{path}" "--behind-proxy" "--trusted-proxy" "127.0.0.1"\n'

    pre = root / "pre"
    pre.write_text(
        "#!/bin/bash\nset -eu\n"
        f'[[ ! -e "{root / "fail-start"}" ]] || exit 1\n'
        f'if [[ -p "{root / "start-pipe"}" ]]; then\n'
        f'  : > "{root / "start-entered"}"\n'
        f'  read -r ignored < "{root / "start-pipe"}"\nfi\n'
    )
    pre.chmod(0o700)

    restart = "no" if case in ("staging-refusal", "destination-drift") else "on-failure"
    template = (
        f"[Unit]\nDescription=D395 isolated server ({case})\nAfter=network.target\n"
        f"[Service]\nType=simple\nExecStartPre={pre}\n"
        "{command}" + f"Restart={restart}\nRestartSec=2\nKillMode=process\nDelegate=yes\n"
        f"[Install]\nWantedBy={target}\n"
    )
    before = template.format(command=command(old))
    after = template.format(command=command(new))
    hook_text = (
        f'[Service]\nExecStartPre=:"{BIN}" __server-cutover-pre "{control}"\n'
        f'ExecStartPost=:"{BIN}" __server-cutover-post "{control}"\n'
        "TimeoutStartSec=infinity\n"
    )
    manager.write_text(
        "#!/bin/bash\nset -eu\n[[ $1 == --user ]]\nshift\n"
        'case "$1" in enable|disable) exec /usr/bin/systemctl --user --runtime "$@";; esac\n'
        'exec /usr/bin/systemctl --user "$@"\n'
    )
    manager.chmod(0o700)

    for path in [unit, boot_target, drop_dir]:
        assert not path.exists(), f"fixture unit already exists: {path}"
    joined = None
    rows = [("source",)]
    history = None
    try:
        if case == "dev-upgrade":
            base_binary = Path(os.environ["D395_DEV_BIN"]).resolve(strict=True)
            assert base_binary != BIN
            unit.write_text(template.format(command=command(old, base_binary)))
        else:
            unit.write_text(before)
        boot_target.write_text(f"[Unit]\nDescription=D395 isolated target\nWants={server}\n")
        systemctl("daemon-reload")
        systemctl("start", server)
        assert wait_for(lambda: health(port)), "initial server health"
        assert sqlite_values(old, "source") == [("source",)]
        if case == "dev-upgrade":
            history = migration_history(old)
            assert history, "the dev binary recorded no migrations"
        systemctl("stop", server)
        if history is not None:
            unit.write_text(before)
        if combined:
            (old / "server-fixture").write_text("server state")
            if case == "failed-recovery":
                leave_committed_wal(old)
                rows.append(("wal-only",))
        metadata = {}
        if case == "nested-metadata":
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", tag, perm, ident & 0xffffffff)
                for tag, perm, ident in [(1, 7, -1), (2, 5, 65534), (4, 5, -1), (16, 5, -1), (32, 0, -1)]
            )
            (old / "nested").mkdir(mode=0o700)
            (old / "nested/file").write_text("nested fixture")
            for relative in ("nested", "nested/file"):
                os.setxattr(old / relative, "system.posix_acl_access", acl)
                os.setxattr(old / relative, "user.j925", b"nested metadata")
                if relative == "nested":
                    os.setxattr(old / relative, "system.posix_acl_default", acl)
                info = (old / relative).stat()
                metadata[relative] = (info.st_mode, info.st_uid, info.st_gid, {n: os.getxattr(old / relative, n) for n in os.listxattr(old / relative)})
        updates = [dict(path=str(unit), before=before, after=after)]
        effective = 0
        if case == "mixed-unit":
            drop_dir.mkdir()
            old_drop = "[Service]\nExecStart=\n" + command(old)
            new_drop = "[Service]\nExecStart=\n" + command(new)
            drop.write_text(old_drop)
            unit.write_text(after)
            updates.append(dict(path=str(drop), before=old_drop, after=new_drop))
            effective = 1
        plan = dict(
            from_=str(old), to=str(new), unit=str(unit), same_filesystem=True,
            resuming=False, units=updates, effective=effective, legacy_target=False,
        )
        plan["from"] = plan.pop("from_")
        request = dict(
            relocation=plan,
            service=dict(program=str(manager), user=True, service=server, listen=listener, tls=False),
            install=dict(systemctl=str(manager), firewall="Untouched"),
        )
        journals = CASES[3:]
        journal = None
        if case == "initial-partial-record":
            work.mkdir(mode=0o700)
            (work / "journal.next").touch(mode=0o600)
        elif frontier in journals or case == "destination-drift":
            work.mkdir(mode=0o700)
            journal = dict(
                **{name: plan[name] for name in ("from", "to", "unit", "units", "effective", "legacy_target")},
                source=identity(old), target=None, database=None, staging=str(stage), staged=None,
                backup=str(backup), backup_action="Remove", ready=False, was_running=True,
            )
            if combined:
                journal["original_entries"] = {p.name: identity(p) for p in originals()}
            if case in ("unrecorded-stage", "partial-stage", "destination-drift"):
                stage.mkdir(mode=0o700)
                if case != "unrecorded-stage":
                    journal["staged"] = identity(stage)
                    (stage / "partial").write_text("unfinished")
            if case == "destination-drift":
                # The journal owns the partial staging tree but never claimed this destination.
                new.mkdir(mode=0o700)
                (new / "unrelated").write_text("preserve this")
            if case in ("published-rename", "published-exchange"):
                snapshot()
                journal["staged"] = identity(new)
                if case == "published-exchange":
                    stage.mkdir(mode=0o700)
                    (stage / "host-firewall-server.json").write_text("{}")
                    (new / "host-firewall-server.json").write_text("{}")
                    journal["target"] = identity(stage)
            if frontier in CASES[8:]:
                snapshot()
                journal["target"] = identity(new)
                if case != "published-recorded":
                    journal["database"] = identity(new / "infraternal.sqlite")
            if frontier in CASES[11:18] or case == "failed-recovery":
                unit.write_text(after)
            if frontier in CASES[13:18]:
                journal["ready"] = True
            if case in COMBINED_RETIREMENT:
                backup.mkdir(mode=0o700)
                if case in ("entry-renamed", "entry-removed"):
                    journal["backup_identity"] = identity(backup)
                    names = ("server-fixture",) if case == "entry-renamed" else journal["original_entries"]
                    for name in names:
                        (old / name).rename(backup / name)
                if case == "entry-removed":
                    (backup / "server-fixture").unlink()
            if case in ("source-renamed", "source-removed", "receipt-with-journal", "receipt-without-journal"):
                if combined:
                    backup.mkdir(mode=0o700)
                    journal["backup_identity"] = identity(backup)
                    for name in journal["original_entries"]:
                        (old / name).rename(backup / name)
                else:
                    old.rename(backup)
                if case != "source-renamed":
                    shutil.rmtree(backup)
            if case in ("receipt-with-journal", "receipt-without-journal"):
                record(control / "receipt.json", {"Ready": dict(
                    outcome=dict(leftover=None), target=journal["target"], database=journal["database"],
                )})
            if case == "receipt-without-journal":
                work.rmdir()
            else:
                record(work / "journal.json", journal)
        if case == "switched-active":
            systemctl("daemon-reload")
            systemctl("start", server)
            assert wait_for(lambda: health(port)), "candidate server health"
            assert sqlite_values(new, "early candidate") == [("source",), ("early candidate",)]
            assert sqlite_values(old, "possible original") == [("source",), ("possible original",)]
            systemctl("stop", server)
        drop_dir.mkdir(exist_ok=True)
        hook.write_text(hook_text)
        systemctl("daemon-reload")
        if case == "admitted-start":
            # Startup with only the hook installed must still use the original.
            systemctl("start", server)
            assert wait_for(lambda: health(port))
            assert not new.exists()
            systemctl("stop", server)
        if case == "staging-refusal":
            nested = old / "nested"
            nested.mkdir(mode=0o700)
            # Copying makes the nested staging directory before rejecting the FIFO.
            fifo = nested / "unsupported"
            os.mkfifo(fifo, 0o600)
        if case in ("staging-refusal", "destination-drift"):
            source_db = old / "infraternal.sqlite"
            before_db = source_db.read_bytes(), identity(source_db)
        # Model a lost client just after publication. The next start joins recovery.
        record(control / "request.json", request)
        if case == "concurrent-start":
            pipe = root / "start-pipe"
            os.mkfifo(pipe, 0o600)
            joined = subprocess.Popen(
                [CTL, "--user", "start", server], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            assert wait_for(lambda: (root / "start-entered").is_file())
            # The second request must join the start already held in ExecStartPre.
            second = subprocess.Popen(
                [CTL, "--user", "start", server], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            assert wait_for(lambda: release_fifo(pipe)), "pre-start did not read its FIFO"
            pipe.unlink()
            stdout, stderr = second.communicate(timeout=45)
            result = subprocess.CompletedProcess(second.args, second.returncode, stdout, stderr)
            stdout, stderr = joined.communicate(timeout=45)
            assert joined.returncode == 0, stdout + stderr
        else:
            if case == "failed-recovery":
                (root / "fail-start").touch()
            kickoff = target if case == "boot-target" else server
            result = systemctl("start", kickoff, check=False)
        if case in ("staging-refusal", "destination-drift"):
            assert result.returncode != 0 and not health(port), result
            assert systemctl("is-failed", server, check=False).returncode == 0
            assert unit.read_text() == before
            assert (source_db.read_bytes(), identity(source_db)) == before_db
            receipt_path = control / "receipt.json"
            assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
            error = json.loads(receipt_path.read_text())["Error"]
            if case == "destination-drift":
                assert "destination identity changed" in error, error
                assert (new / "unrelated").read_text() == "preserve this"
                assert not stage.exists(), "the tracked partial snapshot was left behind"
                return
            assert "unsupported file type in data folder" in error, error
            assert not new.exists() and not work.exists()
            assert stat.S_ISFIFO(fifo.stat().st_mode)
            fifo.unlink()
            systemctl("start", server)
        elif case == "failed-recovery":
            assert result.returncode != 0 and not health(port), result
            assert copied_database_values(old) == copied_database_values(new) == rows
            if combined:
                assert {p.name: identity(p) for p in originals()} == journal["original_entries"]
            (root / "fail-start").unlink()
            systemctl("reset-failed", server)
            systemctl("start", server)
            assert copied_database_values(backup, retained=True) == rows
        else:
            assert result.returncode == 0, result
        if case in ("boot-target", "receipt-without-journal"):
            # A target can be active before its Wants or an already completed move starts.
            assert wait_for(lambda: health(port))
            systemctl("start", server)
        assert health(port), "start answered before its server was ready"
        if case == "switched-active":
            rows.append(("early candidate",))
        assert sqlite_values(new) == rows
        if history is not None:
            upgraded = migration_history(new)
            assert all(upgraded.get(version) == checksum for version, checksum in history.items())
            print(f"MIGRATIONS: carried {len(history)} recorded versions into {len(upgraded)} versions", flush=True)
        if case == "switched-active":
            assert copied_database_values(backup, retained=True) == [("source",), ("possible original",)]
        if combined:
            assert identity(old) == base_id and stat.S_IMODE(old.stat().st_mode) == 0o711
            assert identity(agent / "state") == agent_id
            assert (agent / "state").read_text() == "agent state"
            assert not (new / "agent").exists() and not (old / "infraternal.sqlite").exists()
            assert (new / "server-fixture").read_text() == "server state"
            assert not (old / "server-fixture").exists()
            assert stat.S_IMODE(new.stat().st_mode) == 0o700 and new.stat().st_uid == os.getuid()
            assert backup.exists() == (case in ("switched", "switched-active", "failed-recovery"))
        else:
            assert not old.exists()
        assert not work.exists()
        assert json.loads((control / "receipt.json").read_text())["Ready"]["database"] == identity(new / "infraternal.sqlite")
        if case == "nested-metadata":
            for relative, (mode, uid, gid, attributes) in metadata.items():
                info = (new / relative).stat()
                assert (info.st_mode, info.st_uid, info.st_gid) == (mode, uid, gid)
                copied = {n: os.getxattr(new / relative, n) for n in os.listxattr(new / relative)}
                assert attributes == copied, (relative, attributes, copied)
                print(f"METADATA: {relative} mode/uid/gid and {sorted(copied)} preserved", flush=True)
        pid = systemctl("show", "-p", "MainPID", "--value", server).stdout.strip()
        systemctl("start", server)
        assert systemctl("show", "-p", "MainPID", "--value", server).stdout.strip() == pid
        assert health(port)
        print(f"CASE {label} completed systemctl_exit={result.returncode} elapsed={time.monotonic()-timer:.2f}s", flush=True)
    except Exception:
        subprocess.run(["journalctl", "--user", "--quiet", "--no-pager", "-n", "12", "--user-unit", server], check=False)
        raise
    finally:
        systemctl("stop", target, server, check=False)
        systemctl("--runtime", "disable", server, check=False)
        systemctl("reset-failed", server, check=False)
        if joined is not None:
            # Stopping the fixture unit releases any systemctl caller awaiting the job.
            joined.communicate(timeout=10)
        for path in (drop, hook, unit, boot_target):
            path.unlink(missing_ok=True)
        if drop_dir.is_dir():
            drop_dir.rmdir()
        systemctl("daemon-reload")
        # chmod only the private fixture after assertions about the retained backup.
        if backup.is_dir():
            for path in (backup, *backup.rglob("*")):
                if path.is_dir() and not path.is_symlink():
                    path.chmod(path.stat().st_mode | stat.S_IWUSR)


def cli_admission(workspace):
    """Observe the real installer stopping the original before request publication."""
    root = workspace / "admit"
    home, state = root / "home", root / "state"
    home.mkdir(parents=True)
    state.mkdir()
    old = root / "old"
    new = state / "infraternal"
    request = state / ".infraternal.cutover/request.json"
    # Use the manager's private runtime units. The host's persistent config
    # may have group-writable parents and must stay untouched by the fixture.
    config = Path(os.environ["XDG_RUNTIME_DIR"])
    port = port_number()
    name = f"d395-{os.getpid()}-admit"
    server = f"{name}.service"
    unit = config / "systemd/user" / server
    drop_dir = unit.with_name(f"{unit.name}.d")
    stop = drop_dir / "10-stop.conf"
    hook = drop_dir / "zz-infraternal-d395.conf"
    armed, entered, release = (root / item for item in ("arm", "entered", "release"))
    stop_script = root / "stop"
    stop_script.write_text(
        '#!/bin/sh\n'
        f'[ -f "{armed}" ] || exit 0\n'
        f': > "{entered}"\n'
        f'while [ ! -f "{release}" ]; do sleep .05; done\n'
    )
    stop_script.chmod(0o700)
    env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / "data"),
               XDG_CONFIG_HOME=str(config), XDG_STATE_HOME=str(state))
    cmd = [str(BIN), "--json", "server", "init", "--user", "--name", name,
           "--listen", f"127.0.0.1:{port}", "--behind-proxy", "--trusted-proxy", "127.0.0.1", "--yes"]
    assert not unit.exists() and not drop_dir.exists()
    moving = None
    try:
        result = subprocess.run([*cmd, "--data", str(old)], env=env, timeout=45, capture_output=True)
        assert result.returncode == 0, result
        assert wait_for(lambda: health(port))
        assert sqlite_values(old, "source") == [("source",)]
        drop_dir.mkdir()
        stop.write_text(f'[Service]\nExecStop="{stop_script}"\n')
        armed.touch()
        systemctl("daemon-reload")
        moving = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert wait_for(lambda: entered.is_file() or moving.poll() is not None)
        assert moving.poll() is None, moving.communicate()
        assert entered.is_file()
        assert hook.is_file() and not request.exists()
        for phase in ("Pre", "Post"):
            loaded = systemctl("show", "-p", f"ExecStart{phase}", "--value", server).stdout
            assert f"__server-cutover-{phase.lower()}" in loaded, loaded
        release.touch()
        output, errors = moving.communicate(timeout=60)
        assert moving.returncode == 0, (output, errors)
        assert health(port) and sqlite_values(new) == [("source",)]
        assert not old.exists() and not hook.exists()
        print("CASE cli-admission hook loaded before stop and publication, moved server ready", flush=True)

        # An explicit reinstall at the old path can start a new move with the
        # same arguments. A receipt for the previous destination is obsolete.
        systemctl("stop", server)
        shutil.rmtree(new)
        new.mkdir(mode=0o700)
        result = subprocess.run(
            [*cmd, "--data", str(old), "--force"], env=env, timeout=45, capture_output=True
        )
        assert result.returncode == 0, result
        assert wait_for(lambda: health(port))
        assert sqlite_values(old, "second source") == [("second source",)]
        result = subprocess.run(cmd, env=env, timeout=60, capture_output=True)
        assert result.returncode == 0, result
        assert health(port) and sqlite_values(new) == [("second source",)]
        assert not old.exists()
        print("CASE repeated-move old receipt did not suppress a new cutover", flush=True)
    finally:
        release.touch()
        if moving is not None:
            moving.communicate(timeout=60)
        systemctl("stop", server, check=False)
        systemctl("--runtime", "disable", server, check=False)
        systemctl("disable", server, check=False)
        systemctl("reset-failed", server, check=False)
        for path in (stop, hook, unit):
            path.unlink(missing_ok=True)
        if drop_dir.is_dir():
            drop_dir.rmdir()
        systemctl("daemon-reload")


if __name__ == "__main__":
    failed = []
    with tempfile.TemporaryDirectory(prefix="d395-", dir=os.environ["XDG_RUNTIME_DIR"]) as workspace:
        for scenario in sys.argv[1:] or (*CASES, *(f"combined-{case}" for case in (*CASES, *COMBINED_RETIREMENT)),
                                         "cli-admission", "staging-refusal", "destination-drift"):
            try:
                if scenario == "cli-admission":
                    cli_admission(Path(workspace))
                elif scenario.startswith("combined-"):
                    run_case(Path(workspace), scenario.removeprefix("combined-"), combined=True)
                else:
                    run_case(Path(workspace), scenario)
            except Exception:
                failed.append(scenario)
                traceback.print_exc()
    print(f"REAL_SYSTEMD_MATRIX unexpected={failed!r}", flush=True)
    raise SystemExit(bool(failed))
