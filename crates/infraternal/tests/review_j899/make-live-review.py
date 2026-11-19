"""Add J899 manager interruption and metadata cases to the existing live fixture."""
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
script = source.read_text()
stop = '        wait_for(lambda: not active())\n'
script = script.replace(stop, stop + '''    if (root / "post-stop-kill").exists():
        (root / "post-stop-kill").unlink()
        os.kill(os.getppid(), signal.SIGKILL)
''', 1)
start = '    if not active():\n'
script = script.replace(start, '''    armed = root / ("after-" + args[0] + "-kill")
    if (root / "before-start-kill").exists() and args[0] == "start":
        (root / "before-start-kill").unlink()
        os.kill(os.getppid(), signal.SIGKILL)
        sys.exit(1)
''' + start, 1)
boundary = 'elif args == ["daemon-reload"] and'
script = script.replace(boundary, '''    if armed.exists():
        armed.unlink()
        os.kill(os.getppid(), signal.SIGKILL)
''' + boundary, 1)
script = script.replace('rename|resume|shared|force|partial|cutover|wrong-tree)', 'rename|resume|shared|force|partial|cutover|wrong-tree|post-stop|before-start|after-start|after-enable|metadata|standard)')
script = script.replace('target=/var/lib/infraternal\n', '''target=/var/lib/infraternal
if [[ "$method" == standard ]]; then old=$target; fi
''', 1)
marker = 'if [[ "$method" == partial ]]; then\n'
script = script.replace(marker, '''if [[ "$method" == standard ]]; then
    pid=$(cat "$P/server.pid")
    chown 0:65534 "$old"
    chmod 0711 "$old"
    metadata=$(stat -c '%a %u:%g %i' "$old")
    init --yes > "$P/standard.json" 2> "$P/standard.err"
    check STANDARD_NO_MOVE python3 -c 'import json,sys; assert "data_move" not in json.load(open(sys.argv[1]))["data"]' "$P/standard.json"
    check STANDARD_SAME_TREE test "$(stat -c '%a %u:%g %i' "$old")" = "$metadata"
    check STANDARD_SAME_UNIT test "$(fp "$UNIT")" = "$unit_before"
    check STANDARD_SAME_PROCESS test "$(cat "$P/server.pid")" = "$pid"
    check STANDARD_SERVER_ANSWERS token_ready "$old"
    /usr/bin/systemctl stop infraternal-server.service
    echo RESULT=0
    exit
fi
if [[ "$method" == metadata ]]; then
    chown 0:65534 "$old"
    chmod 2750 "$old"
    before=$(stat -c '%a %u:%g' "$old")
    init --yes > "$P/metadata.json" 2> "$P/metadata.err"
    check METADATA_SERVER_ANSWERS token_ready "$target"
    after=$(stat -c '%a %u:%g' "$target")
    echo "ROOT_DIRECTORY_METADATA old=$before new=$after"
    if [[ "$before" == "$after" ]]; then echo "CASE ROOT_DIRECTORY_METADATA ok"; else echo "CASE ROOT_DIRECTORY_METADATA BAD"; fi
    /usr/bin/systemctl stop infraternal-server.service
    [[ "$before" == "$after" ]]
    echo RESULT=0
    exit
fi
if [[ "$method" == post-stop || "$method" == before-start || "$method" == after-start || "$method" == after-enable ]]; then
    touch "$P/$method-kill"
    status=0
    init --yes > "$P/interrupted.json" 2> "$P/interrupted.err" || status=$?
    check INSTALLER_KILLED test "$status" = 137
    check INTERUPTED_SOURCE_RETAINED test -f "$old/probe"
    live_data=$target
    if [[ "$method" == post-stop ]]; then live_data=$old; fi
    active=$(/usr/bin/systemctl show -p ActiveState --value infraternal-server.service)
    echo "AFTER_INTERRUPTION method=$method manager=$active recorded=$live_data"
    if [[ "$method" == post-stop ]]; then
        check PRE_SWITCH_OLD_UNIT_UNCHANGED test "$(fp "$UNIT")" = "$unit_before"
    else
        check POST_SWITCH_TARGET_IN_UNIT grep -Fq '"--data" "/var/lib/infraternal"' "$UNIT"
    fi
    if [[ "$active" == active ]]; then
        check ACTIVE_SERVER_ANSWERS token_ready "$live_data"
    else
        echo 'CASE INTERRUPTED_SERVER_IS_INACTIVE'
        /usr/bin/systemctl start infraternal-server.service
        check BOOT_PATH_ANSWERS wait_token_ready "$live_data"
    fi
    printf 'write on the selected boot path\n' > "$live_data/j899-selected"
    init --yes > "$P/retry.json" 2> "$P/retry.err"
    check RETRY_PRESERVES_SELECTED_WRITES test -f "$target/j899-selected"
    check RETRY_SERVER_ANSWERS token_ready "$target"
    check RETRY_REMOVES_OLD_TREE test ! -e "$old"
    /usr/bin/systemctl stop infraternal-server.service
    echo RESULT=0
    exit
fi
''' + marker, 1)
output.write_text(script)
