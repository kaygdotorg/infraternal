#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Terminal multiplexer case (#260, part B).
#
#   term.sh <local|wan|loss|scale>
#
# Two namespaces joined by one veth pair: the host side h2h-ts (10.230.0.1)
# runs the infraternal server (with its embedded infraternal agent and session
# shims), the tmux server, the Zellij servers and a private sshd; the viewer
# side h2h-tc (10.230.0.2) runs the viewers for the network cases.
#
# Viewers, all measured to the same point (bytes delivered to the terminal):
#   ix          native infraternal leg-A client → server → shim → PTY (h2h ix)
#   tmux        `tmux attach` on a PTY, same namespace (local terminal)
#   zellij      `zellij attach` on a PTY, same namespace
#   tmux-ssh    `ssh -tt host tmux attach` from h2h-tc (the like-for-like network case)
#   zellij-ssh  `ssh -tt host zellij attach` from h2h-tc
#   ssh         a plain interactive SSH login, no multiplexer (reference)
#
# Profiles: local (no netem; viewers on the host side), wan (150 ms one-way
# netem on each side = 300 ms RTT), loss (150 ms one-way + 2 % loss on each
# side), scale (memory at 1/10/50 sessions and idle cost).
source "$H2H_KIT/lib/common.sh"
PROFILE=$1
H2H_CASE=term-$PROFILE
trap cleanup EXIT

USER_NAME=$(h2h_user)
USER_UID=$(id -u "$USER_NAME")
USER_GID=$(id -g "$USER_NAME")
SHELLS=bash,sh,dash,zsh,fish,ksh,mksh
B=$H2H_RUN/bin
U=$H2H_RUN/u
R=$H2H_RUN/root
# R holds root's files (host key, cookie); the account may traverse it to its
# own 0600 cookie and to authorized_keys, never list it.
mkdir -p "$B" "$R" && chmod 755 "$H2H_RUN" "$B" && chmod 711 "$R"
for f in h2h infraternal tmux zellij; do install -m 755 "$H2H_BIN/$f" "$B/$f"; done
install -d -m 700 -o "$USER_UID" -g "$USER_GID" "$U" "$U/rt" "$U/tmux" "$U/zsock" "$U/zcfg" "$U/zcache" "$U/zdata" "$U/ssh" "$U/tmp"
printf 'show_startup_tips false\nshow_release_notes false\n' > "$U/zcfg/config.kdl"
chown "$USER_UID:$USER_GID" "$U/zcfg/config.kdl"
note account "{\"user\":\"$USER_NAME\",\"shell\":\"$(getent passwd "$USER_NAME" | cut -d: -f7)\"}"

netns_add h2h-ts
netns_add h2h-tc
ip link add ts0 netns h2h-ts type veth peer name tc0 netns h2h-tc
ip -n h2h-ts addr add 10.230.0.1/24 dev ts0
ip -n h2h-tc addr add 10.230.0.2/24 dev tc0
ip -n h2h-ts link set ts0 up
ip -n h2h-tc link set tc0 up
ns_holder TS_PID h2h-ts

case $PROFILE in
    wan) netem_set h2h-ts ts0 delay 150ms; netem_set h2h-tc tc0 delay 150ms ;;
    loss) netem_set h2h-ts ts0 delay 150ms loss 2%; netem_set h2h-tc tc0 delay 150ms loss 2% ;;
esac

# --- the host side --------------------------------------------------------------
ZENV="TMPDIR=$U/tmp ZELLIJ_CONFIG_DIR=$U/zcfg XDG_CACHE_HOME=$U/zcache XDG_DATA_HOME=$U/zdata ZELLIJ_SOCKET_DIR=$U/zsock"
TENV="TMUX_TMPDIR=$U/tmux"
host() { ns_user h2h-ts "$@"; }

ns_user h2h-ts XDG_RUNTIME_DIR="$U/rt" "$B/infraternal" server --listen 0.0.0.0:47100 --data "$U/ixdata" \
    --public-origin https://localhost:47100 --behind-proxy --trusted-proxy 127.0.0.1 > "$H2H_RUN/ix-server.log" 2>&1 &
# `ip netns exec`, setpriv and env all exec, so $! is the server itself.
IX_PID=$!
register_pid "$IX_PID"
wait_for 30 in_ns h2h-ts bash -c 'exec 3<>/dev/tcp/127.0.0.1/47100' || die "infraternal server did not listen: $(tail -c 800 "$H2H_RUN/ix-server.log")"
umask 077
host "$B/infraternal" server setup-token --data "$U/ixdata" --json \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["data"]["token"])' > "$R/setup-token"
in_ns h2h-ts "$H" ix-register --server 127.0.0.1:47100 --origin https://localhost:47100 \
    --setup-token-file "$R/setup-token" --cookie-out "$R/cookie" > /dev/null
rm -f "$R/setup-token"
umask 022
# The account's own session cookie; its viewers run as that account.
chown "$USER_UID:$USER_GID" "$R/cookie"
IX_LOCAL="--backend ix --server 127.0.0.1:47100 --origin https://localhost:47100 --cookie-file $R/cookie"
IX_REMOTE="--backend ix --server 10.230.0.1:47100 --origin https://localhost:47100 --cookie-file $R/cookie"
ix_open() { in_ns h2h-ts "$H" ix-open $IX_LOCAL --count "$1" | python3 -I -c 'import json,sys; print(" ".join(json.load(sys.stdin)))'; }

tmux_new() { host env $TENV "$B/tmux" -f /dev/null new-session -d -s "$1" -x 120 -y 40; }
zellij_new() { host env $ZENV "$B/zellij" attach --create-background "$1" > /dev/null; }
register_cmd "ns_user h2h-ts env $TENV $B/tmux kill-server"
register_cmd "ns_user h2h-ts env $ZENV $B/zellij kill-all-sessions -y"

SSH_OK=0
if [[ $PROFILE == wan || $PROFILE == loss ]] && [[ -x /usr/sbin/sshd ]] && command -v ssh >/dev/null && command -v ssh-keygen >/dev/null; then
    ssh-keygen -q -t ed25519 -N '' -f "$R/hostkey"
    host ssh-keygen -q -t ed25519 -N '' -f "$U/ssh/id"
    cp "$U/ssh/id.pub" "$R/authorized_keys"
    chmod 644 "$R/authorized_keys"
    printf '[10.230.0.1]:2222 %s\n' "$(cut -d' ' -f1,2 "$R/hostkey.pub")" > "$U/ssh/known_hosts"
    chown "$USER_UID:$USER_GID" "$U/ssh/known_hosts"
    cat > "$R/sshd_config" <<EOF
Port 2222
ListenAddress 10.230.0.1
HostKey $R/hostkey
AuthorizedKeysFile $R/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog no
StrictModes no
PidFile none
AllowUsers $USER_NAME
PermitRootLogin prohibit-password
X11Forwarding no
AllowTcpForwarding no
EOF
    sandboxed "$TS_PID" /usr/sbin/sshd -D -e -f "$R/sshd_config" > "$H2H_RUN/sshd.log" 2>&1 &
    register_pid $!
    wait_for 10 in_ns h2h-tc bash -c 'exec 3<>/dev/tcp/10.230.0.1/2222' && SSH_OK=1
    note ssh-version "{\"ssh\":\"$(ssh -V 2>&1)\"}"
fi
[[ $SSH_OK == 1 || $PROFILE == scale || $PROFILE == local ]] || log "no usable sshd/ssh: SSH viewers skipped"
SSH="ssh -tt -F none -i $U/ssh/id -o UserKnownHostsFile=$U/ssh/known_hosts -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o LogLevel=ERROR -p 2222 $USER_NAME@10.230.0.1"
if [[ $SSH_OK == 1 ]]; then
    # A listening private server is insufficient: reject fixture auth failures
    # before timing clients, and retain its public diagnostic log on failure.
    if ! ns_user h2h-tc ssh -F none -i "$U/ssh/id" \
        -o UserKnownHostsFile="$U/ssh/known_hosts" -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes -o BatchMode=yes -p 2222 "$USER_NAME@10.230.0.1" true \
        > "$H2H_RESULTS/$H2H_CASE/ssh-preflight.txt" 2>&1; then
        cp "$H2H_RUN/sshd.log" "$H2H_RESULTS/$H2H_CASE/ssh-server.log"
        die 'private SSH preflight failed; see ssh-server.log'
    fi
fi

# viewer <system> <session>: arguments that make h2h attach the given viewer.
viewer() {
    case $1 in
        ix) [[ $PROFILE == local || $PROFILE == scale ]] && echo "$IX_LOCAL --session $2" || echo "$IX_REMOTE --session $2" ;;
        tmux) echo "--backend pty --client" "$(printf %q "env $TENV $B/tmux -f /dev/null attach -t $2")" ;;
        zellij) echo "--backend pty --client" "$(printf %q "env $ZENV $B/zellij attach $2")" ;;
        tmux-ssh) echo "--backend pty --client" "$(printf %q "$SSH $TENV $B/tmux -f /dev/null attach -t $2")" ;;
        zellij-ssh) echo "--backend pty --client" "$(printf %q "$SSH env $ZENV $B/zellij attach $2")" ;;
        ssh) echo "--backend pty --client" "$(printf %q "$SSH")" ;;
    esac
}
# run_viewer <ns> <system> <session> <h2h-subcommand> [args…]
run_viewer() {
    local ns=$1 system=$2 session=$3 sub=$4; shift 4
    eval "ns_user $ns $H $sub $(viewer "$system" "$session") \"\$@\""
}
new_session() { # new_session <system> <name> → prints the id to attach
    case $1 in
        ix) ix_open 1 ;;
        tmux | tmux-ssh) tmux_new "$2"; echo "$2" ;;
        zellij | zellij-ssh) zellij_new "$2"; echo "$2" ;;
        ssh) echo - ;;
    esac
}

head -c 75000000 /dev/urandom | base64 -w 120 > "$U/blob"
chown "$USER_UID:$USER_GID" "$U/blob"
CAT="cat $U/blob; printf 'H2H_%s\\n' DONE"
YES="timeout 10 yes; printf 'H2H_%s\\n' DONE"
MARK="clear; printf 'H2H_%s\\n' MARK"

suite() { # suite <ns> <systems…>: echo, output floods, reattach
    local ns=$1; shift
    local system id
    local samples; samples=$(dur 300 40)
    [[ $PROFILE != local ]] && samples=$(dur 100 15)
    for system in "$@"; do
        [[ $system == *ssh* && $SSH_OK != 1 ]] && continue
        id=$(new_session "$system" "s-$system")
        measure "echo-$system" run_viewer "$ns" "$system" "$id" term-echo --inner "$B/h2h echo-inner" --samples "$samples" || true
        measure "cat100mb-$system" run_viewer "$ns" "$system" "$id" term-flood --command "$CAT" --marker H2H_DONE --timeout-s 180 || true
        if [[ $PROFILE == local ]]; then
            measure "yes10s-$system" run_viewer "$ns" "$system" "$id" term-flood --command "$YES" --marker H2H_DONE --timeout-s 120 || true
        fi
        if [[ $system != ssh ]]; then
            run_viewer "$ns" "$system" "$id" term-type --text "$MARK" --marker H2H_MARK > /dev/null || true
            measure "attach-$system" run_viewer "$ns" "$system" "$id" term-attach --marker H2H_MARK --samples "$(dur 20 4)" || true
        fi
    done
}

mux_selection() { # the system's own processes, without the shells it runs
    case $1 in
        # Shims detach from the server's process tree. Their private executable
        # path selects them and their shells without including other sessions.
        ix) echo "--cmdline-contains $B/infraternal --exclude-comm $SHELLS" ;;
        tmux) echo "--pids $(host env $TENV "$B/tmux" display-message -p '#{pid}') --exclude-comm $SHELLS" ;;
        zellij) echo "--cmdline-contains $U/zsock --exclude-comm $SHELLS" ;;
    esac
}

scale() {
    local system=$1 have=0 n id first="" ids
    for n in 1 10 50; do
        while ((have < n)); do
            if (( $(awk '/MemAvailable/ {print $2}' /proc/meminfo) < 1500000 )); then
                log "$system: stopping at $have sessions, under 1.5 GB available"
                note "stopped-$system" "{\"sessions\":$have,\"reason\":\"MemAvailable under 1.5 GB\"}"
                break 2
            fi
            case $system in
                ix) ids=$(ix_open $((n - have))); have=$n; first=${first:-${ids%% *}} ;;
                tmux) ids=s$have; tmux_new "$ids"; have=$((have + 1)); first=${first:-s0} ;;
                zellij) ids=s$have; zellij_new "$ids"; have=$((have + 1)); first=${first:-s0} ;;
            esac
            # Default unattached sizes differ. Seed every session through the
            # same 120x40 viewer before comparing detached memory footprints.
            for id in $ids; do
                run_viewer h2h-ts "$system" "$id" term-hold --seconds 0 > /dev/null
            done
        done
        sleep "$(dur 3 1)"
        measure "mem-$system-$n" "$H" proc-mem $(mux_selection "$system")
        measure "shells-$system-$n" "$H" proc-mem $(mux_selection "$system" | sed 's/--exclude-comm.*//') --only-comm $SHELLS
    done
    measure "idle-detached-$system" "$H" proc-idle $(mux_selection "$system") --seconds "$(dur 20 3)"
    local hold_s; hold_s=$(dur 30 4)
    run_viewer h2h-ts "$system" "$first" term-hold --seconds $((hold_s + 4)) > "$H2H_RESULTS/$H2H_CASE/viewer-$system.json" &
    local hold=$!
    sleep 2
    measure "idle-attached-$system" "$H" proc-idle $(mux_selection "$system") --seconds "$hold_s"
    wait "$hold" || true
}

case $PROFILE in
    local) suite h2h-ts ix tmux zellij ;;
    wan | loss) suite h2h-tc ix tmux-ssh zellij-ssh ssh ;;
    scale)
        note geometry '{"cols":120,"rows":40,"seeded_by_viewer":true}'
        for s in ix tmux zellij; do scale "$s"; done ;;
    *) die "unknown profile $PROFILE" ;;
esac
log done
