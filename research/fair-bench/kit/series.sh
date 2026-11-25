#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1199 (#260, #580; from J1137/J1160) hold driver, runs on hd01 (ssh only; nothing heavy here).
#   series.sh <hold-tag> <row>...      e.g. series.sh e1 G.1 W K J G.2
# A row is an engine letter plus an optional ".n" tag, so a repeated engine in one hold gets its
# own result directory (repeating a name would overwrite the earlier windows, J1140 gotcha).
#   Engine rows (bare protocol, wg set, MTU 1390, the product's guard table on j99w):
#     G = gotatun-cli at the dev pin e87fef91 (J1159: side-socket receive rule on, sender off),
#     J = the same binary with the bench sender switch GOTATUN_SIDE_SOCKET=1 on both nodes,
#     W = wireguard-go, K = kernel WireGuard.
#   Product rows (each product's own defaults): I = infraternal mesh (production node + coordinator
#     fixture), T = Tailscale + headscale on C, N = NetBird (kernel WG mode) + combined server on C.
# Per row: up (setup time on the VMs' clocks), path record, warm-up, 20 s idle sample, the windows
# (DIRS r f x CFS), 15 s settle, 20 s post-load idle sample, path record, down.
set -uo pipefail
cd "$(dirname "$0")"
A=root@calternal-perf-01-backup01.vpn.kayg.org      # node A, 10.70.3.196 in j99 (4 vCPU)
B=root@infraternal-perf-01-backup01.vpn.kayg.org    # node B, 10.70.3.197 in j99 (6 vCPU)
C=root@calternal-perf-02-backup01.vpn.kayg.org      # control planes only, 10.70.3.198
A_IP=10.70.3.196 B_IP=10.70.3.197 C_IP=10.70.3.198
R=/root/j1199
on() { local h=$1; shift; ssh -o BatchMode=yes -o ServerAliveInterval=15 "$h" "$@"; }
side() { local h=$1; shift; on "$h" $R/side.sh "$@"; }
take_all() { on $B $R/lock.sh take "$1" && on $A $R/lock.sh take "$1" && on $C $R/lock.sh take "$1"; }
release_all() { for h in $A $B $C; do on "$h" $R/lock.sh release || true; done; }
ns_all_up() { side $B nsup $B_IP iperf && side $A nsup $A_IP && side $C nsup $C_IP; }
ns_all_down() { for h in $A $B $C; do side "$h" nsdown || true; done; }
log() { echo "[$(date -u +%T)] $*"; }

# engine_up <letter>: bring the row up; sets PEER. Control planes (T, N) start on C first; the
# setup clock starts when the first node process starts (control plane already running).
engine_up() {
    local e=$1 pa pb env=
    case $e in
        G) env="GTBIN=$R/bin/gotatun-j59" ;;
        J) env="GTBIN=$R/bin/gotatun-j59 XENV=GOTATUN_SIDE_SOCKET=1" ;;
    esac
    case $e in
        K|W|G|J)
            local kind=kernel; [[ $e == W ]] && kind=wggo; [[ $e == G || $e == J ]] && kind=gotatun
            pa=$(side $A wgkey); pb=$(side $B wgkey)
            PEER=10.66.0.2
            on $B "$env $R/side.sh up $kind 10.66.0.2 $pa $A_IP" > /dev/null || return 1
            side $A reachbg $PEER
            on $A "$env $R/side.sh up $kind 10.66.0.1 $pb $B_IP" > /dev/null || return 1 ;;
        I)
            side $B up ix-serve > /dev/null || return 1
            PEER=$(side $A up ix-drive $B_IP) || return 1
            side $B up ix-watch > /dev/null || return 1
            # The peer's mesh address is known only once the driver compiled both nodes.
            side $A reachbg $PEER ;;
        T|N)
            local ctl=hsctl node=ts; [[ $e == N ]] && ctl=nbsrv node=nb
            side $C up $ctl > /dev/null || return 1
            for h in $B $A; do
                on $C "cat $R/run/setup-key" | on $h "umask 077; mkdir -p $R/run; cat > $R/run/setup-key" || return 1
            done
            on $C "rm -f $R/run/setup-key"
            side $B up $node > /dev/null || return 1
            PEER=$(on $B cat $R/run/peer)
            side $A reachbg $PEER
            side $A up $node > /dev/null || return 1 ;;
        *) return 2 ;;
    esac
    REACH=$(side $A waitreach) || return 1
}
engine_down() { for h in $A $B $C; do side "$h" down > /dev/null 2>&1; done; }
# psnap_all <name>: the per-process netns snapshot on all three VMs at once.
psnap_all() { for h in $A $B $C; do on $h "python3 -I $R/psnap.py $1" & done; wait; }

hold=$1; shift
ev=$HOME/.cache/codex-scratch/j1199/evidence/raw/$hold
mkdir -p "$ev"
fail=0
cleanup() { ns_all_down > /dev/null 2>&1; release_all > /dev/null 2>&1; log "released"; }
trap cleanup EXIT
for h in $A $B $C; do on $h "mkdir -p $R && chmod 700 $R && cat > $R/lock.sh && chmod 700 $R/lock.sh" < ./lock.sh; done
# A hold tag is used once: a leftover result directory (an aborted run's windows and their done
# files) would make the driver read old windows as new ones.
for h in $A $B $C; do on $h "test ! -e $R/res/$hold" || { echo "result dir $hold exists on $h" >&2; trap - EXIT; exit 1; }; done
take_all "$hold" || { log "lock failed"; exit 1; }
log "locks held"
# The kit (scripts, a few KB) is refreshed inside our own hold; binaries were staged before it
# (stage.sh, only while no hold was active) and only their hashes are checked here.
for h in $A $B $C; do tar -C "$PWD" --exclude __pycache__ --exclude series.sh -cf - . | on $h "tar -C $R -xf - --no-same-owner && chmod 700 $R/*.sh"; done
for h in $A $B $C; do echo "== $h"; on $h "sha256sum $R/bin/* | cut -c1-16,65-; uptime; nproc"; done > "$ev/stage.log" 2>&1 || { log "hash check failed"; exit 1; }
ns_all_down > /dev/null 2>&1
ns_all_up > "$ev/nsup.log" 2>&1 || { log "nsup failed"; exit 1; }
for h in $A $B $C; do on $h "mkdir -p $R/res/$hold; uptime > $R/res/$hold/uptime.before"; done
# No engine at all: the machines' own idle context switches, the floor every idle number sits on.
r=$R/res/$hold/X
for h in $A $B $C; do on $h "mkdir -p $r"; done
psnap_all $r/idle0.json
# sleep: the 20 s idle sample.
sleep 20
psnap_all $r/idle1.json
for row in "$@"; do
    e=${row%%.*}
    r=$R/res/$hold/$row
    for h in $A $B $C; do on $h "mkdir -p $r"; done
    ok=0
    for attempt in 1 2; do
        if engine_up "$e" > "$ev/$row.up.log" 2>&1; then ok=1; break; fi
        log "$row up failed (attempt $attempt): $(tail -c 400 "$ev/$row.up.log")"
        engine_down
    done
    ((ok)) || { fail=1; continue; }
    # Setup time: first node process start (either VM) to the first packet through (A's clock).
    for h in $A $B $C; do on $h "cat $R/run/started.* $R/run/ready.* 2>/dev/null | tr '\n' ' '; echo"; done > "$ev/$row.stamps"
    echo "reach $REACH" >> "$ev/$row.stamps"
    s_a=$(on $A "cat $R/run/started.node") s_b=$(on $B "cat $R/run/started.node")
    setup=$(python3 -c 'import sys; print(round(float(sys.argv[3]) - min(float(sys.argv[1]), float(sys.argv[2])), 3))' "$s_a" "$s_b" "$REACH")
    echo "$setup" > "$ev/$row.setup"
    # Guard table: the product row captures it, every engine row runs behind the same table.
    for h in $A $B; do
        case $e in
            I) on $h "ip netns exec j99 nft list table inet infraternal_mesh > $R/guard.nft" || log "guard capture failed on $h" ;;
            G|J|W|K) [[ ${NOGUARD:-0} == 1 ]] || on $h "$R/side.sh guard" > /dev/null || { log "guard load failed on $h"; fail=1; } ;;
        esac
        on $h "ip netns exec j99 nft list ruleset > $r/nft.start; $R/side.sh paths > $r/paths.start 2>&1; echo $PEER > $r/peer"
    done
    on $C "$R/side.sh paths > $r/paths.start 2>&1"
    log "$row up, peer $PEER, setup ${setup}s"
    # A ".cap" row only brings the engine up (e.g. I.cap captures the guard table) and goes down.
    if [[ $row == *.cap ]]; then engine_down; log "$row down (capture only)"; continue; fi
    on $A "ip netns exec j99 $R/bin/iperf3 -c $PEER -t 3 > /dev/null 2>&1"
    # sleep: let the warm-up's buffers drain before the idle sample.
    sleep 15
    psnap_all $r/idle0.json
    # sleep: the 20 s idle sample before load.
    sleep 20
    psnap_all $r/idle1.json
    for dir in ${DIRS:-r f}; do
        rarg=; [[ $dir == r ]] && rarg=r
        for cf in ${CFS:-cubic:1 cubic:8 bbr:1 bbr:8}; do
            cc=${cf%%:*} f=${cf#*:}
            w=$r/$dir-$cc$f
            t0=$(( $(date +%s) + 6 ))
            on $B "setsid nohup $R/window.sh b $t0 $w $cc $f $PEER $rarg > /dev/null 2>&1 < /dev/null &"
            on $A "setsid nohup $R/window.sh a $t0 $w $cc $f $PEER $rarg > /dev/null 2>&1 < /dev/null &"
            done_a= done_b=
            for _ in $(seq 1 60); do
                # sleep: poll interval for the two ends' done files.
                sleep 3
                done_a=$(on $A "cat $w/done 2>/dev/null")
                done_b=$(on $B "cat $w/done 2>/dev/null")
                [[ -n $done_a && -n $done_b ]] && break
            done
            gbit=$(on $A "python3 -c 'import json; print(round(json.load(open(\"$w/iperf.json\"))[\"end\"][\"sum_received\"][\"bits_per_second\"]/1e9,3))' 2>/dev/null")
            p99=$(on $A "python3 -c 'import json; d=json.load(open(\"$w/rr-key.json\")); print(d[\"p50_ms\"], d[\"p99_ms\"], d[\"p999_ms\"], d[\"lost\"])' 2>/dev/null")
            log "$row $dir $cc$f done a=$done_a b=$done_b gbit=$gbit rr(p50 p99 p99.9 lost)=$p99"
            [[ $done_a == 0 && $done_b == 0 ]] || fail=1
        done
    done
    # sleep: settle after the last window before the post-load sample.
    sleep 15
    psnap_all $r/idle2.json
    # sleep: the 20 s idle sample after load.
    sleep 20
    psnap_all $r/idle3.json
    for h in $A $B $C; do on $h "ip netns exec j99 nft list ruleset > $r/nft.end 2>&1; $R/side.sh paths > $r/paths.end 2>&1"; done
    engine_down
    log "$row down"
done
for h in $A $B $C; do on $h "uptime > $R/res/$hold/uptime.after; ip netns exec j99 nft list table inet j99guard > $R/res/$hold/guard-counters.txt"; done
ns_all_down > /dev/null 2>&1
release_all > /dev/null 2>&1
trap - EXIT
log "released"
for x in a:$A b:$B c:$C; do
    mkdir -p "$ev/${x%%:*}"
    on ${x#*:} "tar czf - -C $R/res $hold" | tar xzf - -C "$ev/${x%%:*}"
done
log "HOLD_DONE fail=$fail"
