#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1239 (#260; J1230's driver, from J1137/J1160) hold driver, runs on hd01 (ssh only; nothing heavy here).
#   series.sh <hold-tag> <row>...      e.g. series.sh d1 G.a L2n L2s G.b K
# Rows other than G and K are named in rows.conf (row|binary|switches). CFS entries are
# <cc>:<flows>[@<total Mbit/s>] (a rate cap, J1160). PERF_ROWS lists rows that get one extra
# forward CUBIC 8 window profiled on B (never counted as a result).
# A row is an engine letter plus an optional ".n" tag, so a repeated engine in one hold gets its
# own result directory (repeating a name would overwrite the earlier windows, J1140 gotcha).
# Engine rows only (bare protocol, wg set, MTU 1390, the product's guard table on the tunnel);
# the letters are listed at engine_up. Only VMs A and B are used.
# Per row: up (setup time on the VMs' clocks), path record, warm-up, 20 s idle sample, the windows
# (DIRS r f x CFS), 15 s settle, 20 s post-load idle sample, path record, down.
set -uo pipefail
cd "$(dirname "$0")"
A=root@calternal-perf-01-backup01.vpn.kayg.org      # node A, 10.70.3.196 in j39 (4 vCPU)
B=root@infraternal-perf-01-backup01.vpn.kayg.org    # node B, 10.70.3.197 in j39 (6 vCPU)
A_IP=10.70.3.196 B_IP=10.70.3.197
R=/root/j1239
on() { local h=$1; shift; ssh -o BatchMode=yes -o ServerAliveInterval=15 "$h" "$@"; }
side() { local h=$1; shift; on "$h" $R/side.sh "$@"; }
take_all() { on $B $R/lock.sh take "$1" && on $A $R/lock.sh take "$1"; }
release_all() { for h in $A $B; do on "$h" $R/lock.sh release || true; done; }
ns_all_up() { side $B nsup $B_IP iperf && side $A nsup $A_IP; }
ns_all_down() { for h in $A $B; do side "$h" nsdown || true; done; }
log() { echo "[$(date -u +%T)] $*"; }

# engine_up <row>: bring the row up; sets PEER.
#   G  = gotatun-cli at the dev pin cd295c2e (J1199's static musl ring + mimalloc recipe),
#   G2 = two G devices (ports 51820/51821, tunnels 10.66/10.67): the per-pipeline ceiling,
#   K  = kernel WireGuard,
#   anything else = a candidate named in rows.conf (its binary in $R/bin and its switches).
# row_conf <row>: "binary|switches" from rows.conf, empty if the row is not listed.
row_conf() { awk -F'|' -v r="$1" '$1 == r { print $2 "|" $3 }' rows.conf; }
engine_up() {
    local e=$1 pa pb pa2 pb2 env= conf
    case $e in
        G|G2) env="GTBIN=$R/bin/gotatun-g" ;;
        K) ;;
        *) conf=$(row_conf "$e"); [[ -n $conf ]] || return 2
           env="GTBIN=$R/bin/${conf%%|*} XENV='${conf#*|}'" ;;
    esac
    pa=$(side $A wgkey); pb=$(side $B wgkey)
    PEER=10.66.0.2
    case $e in
        G2)
            pa2=$(side $A wgkey2); pb2=$(side $B wgkey2)
            on $B "$env $R/side.sh up gotatun2 10.66.0.2 $pa $A_IP 10.67.0.2 $pa2" > /dev/null || return 1
            side $A reachbg $PEER
            on $A "$env $R/side.sh up gotatun2 10.66.0.1 $pb $B_IP 10.67.0.1 $pb2" > /dev/null || return 1
            on $A "echo 10.67.0.2 > $R/run/peer2"
            on $A "ip netns exec j39 ping -c1 -W2 -q 10.67.0.2" > /dev/null || return 1 ;;
        *)
            local kind=kernel; [[ $e != K ]] && kind=gotatun
            on $B "$env $R/side.sh up $kind 10.66.0.2 $pa $A_IP" > /dev/null || return 1
            side $A reachbg $PEER
            on $A "$env $R/side.sh up $kind 10.66.0.1 $pb $B_IP" > /dev/null || return 1 ;;
    esac
    REACH=$(side $A waitreach) || return 1
}
engine_down() { for h in $A $B; do side "$h" down > /dev/null 2>&1; done; }
# psnap_all <name>: the per-process netns snapshot on all three VMs at once.
psnap_all() { for h in $A $B; do on $h "python3 -I $R/psnap.py $1" & done; wait; }

hold=$1; shift
ev=$HOME/.cache/codex-scratch/j1239/evidence/raw/$hold
mkdir -p "$ev"
fail=0
cleanup() { ns_all_down > /dev/null 2>&1; release_all > /dev/null 2>&1; log "released"; }
trap cleanup EXIT
for h in $A $B; do on $h "mkdir -p $R && chmod 700 $R && cat > $R/lock.sh && chmod 700 $R/lock.sh" < ./lock.sh; done
# A hold tag is used once: a leftover result directory (an aborted run's windows and their done
# files) would make the driver read old windows as new ones.
for h in $A $B; do on $h "test ! -e $R/res/$hold" || { echo "result dir $hold exists on $h" >&2; trap - EXIT; exit 1; }; done
take_all "$hold" || { log "lock failed"; exit 1; }
log "locks held"
# The kit (scripts, a few KB) is refreshed inside our own hold; binaries were staged before it
# (stage.sh, only while no hold was active) and only their hashes are checked here.
for h in $A $B; do tar -C "$PWD" --exclude __pycache__ --exclude series.sh -cf - . | on $h "tar -C $R -xf - --no-same-owner && chmod 700 $R/*.sh"; done
on $A "cp $R/guard-a.nft $R/guard.nft"; on $B "cp $R/guard-b.nft $R/guard.nft"
# J1239: binaries built after the last stage.sh are copied here, inside our own hold and before
# any measurement (copying is only ever refused during another job's hold).
for h in $A $B; do
    for f in "$HOME/.cache/codex-scratch/j1239/stage"/*; do
        want=$(sha256sum "$f" | cut -c1-64) name=$(basename "$f")
        have=$(on $h "sha256sum $R/bin/$name 2>/dev/null | cut -c1-64")
        [[ $have == "$want" ]] || on $h "umask 077; cat > $R/bin/$name && chmod 700 $R/bin/$name" < "$f"
    done
done
for h in $A $B; do echo "== $h"; on $h "sha256sum $R/bin/* | cut -c1-16,65-; uptime; nproc"; done > "$ev/stage.log" 2>&1 || { log "hash check failed"; exit 1; }
ns_all_down > /dev/null 2>&1
ns_all_up > "$ev/nsup.log" 2>&1 || { log "nsup failed"; exit 1; }
for h in $A $B; do on $h "mkdir -p $R/res/$hold; uptime > $R/res/$hold/uptime.before"; done
# No engine at all: the machines' own idle context switches, the floor every idle number sits on.
r=$R/res/$hold/X
for h in $A $B; do on $h "mkdir -p $r"; done
psnap_all $r/idle0.json
# sleep: the 20 s idle sample.
sleep 20
psnap_all $r/idle1.json
for row in "$@"; do
    e=${row%%.*}
    r=$R/res/$hold/$row
    for h in $A $B; do on $h "mkdir -p $r"; done
    ok=0
    for attempt in 1 2; do
        if engine_up "$e" > "$ev/$row.up.log" 2>&1; then ok=1; break; fi
        log "$row up failed (attempt $attempt): $(tail -c 400 "$ev/$row.up.log")"
        engine_down
    done
    ((ok)) || { fail=1; continue; }
    # Setup time: first node process start (either VM) to the first packet through (A's clock).
    for h in $A $B; do on $h "cat $R/run/started.* $R/run/ready.* 2>/dev/null | tr '\n' ' '; echo"; done > "$ev/$row.stamps"
    echo "reach $REACH" >> "$ev/$row.stamps"
    s_a=$(on $A "cat $R/run/started.node") s_b=$(on $B "cat $R/run/started.node")
    setup=$(python3 -c 'import sys; print(round(float(sys.argv[3]) - min(float(sys.argv[1]), float(sys.argv[2])), 3))' "$s_a" "$s_b" "$REACH")
    echo "$setup" > "$ev/$row.setup"
    # Guard table: the product row captures it, every engine row runs behind the same table.
    for h in $A $B; do
        case $e in
            *) [[ ${NOGUARD:-0} == 1 ]] || on $h "$R/side.sh guard" > /dev/null || { log "guard load failed on $h"; fail=1; } ;;
        esac
        on $h "ip netns exec j39 nft list ruleset > $r/nft.start; $R/side.sh paths > $r/paths.start 2>&1; echo $PEER > $r/peer"
    done
    log "$row up, peer $PEER, setup ${setup}s"
    # A ".cap" row only brings the engine up (e.g. I.cap captures the guard table) and goes down.
    if [[ $row == *.cap ]]; then engine_down; log "$row down (capture only)"; continue; fi
    on $A "ip netns exec j39 $R/bin/iperf3 -c $PEER -t 3 > /dev/null 2>&1"
    # sleep: let the warm-up's buffers drain before the idle sample.
    sleep 15
    psnap_all $r/idle0.json
    # sleep: the 20 s idle sample before load.
    sleep 20
    psnap_all $r/idle1.json
    # The window list: every DIRS x CFS window, then (PERF_ROWS) one profiled forward window.
    wins=()
    for dir in ${DIRS:-r f}; do for cf in ${CFS:-cubic:1 cubic:8 bbr:8}; do wins+=("$dir $cf -"); done; done
    [[ " ${PERF_ROWS:-} " == *" $row "* ]] && wins+=("f cubic:8 perf")
    for spec in "${wins[@]}"; do
        read -r dir cf prof <<< "$spec"
        rarg=f; [[ $dir == r ]] && rarg=r
        [[ $prof == - ]] && prof=
            cc=${cf%%:*} f=${cf#*:} rate=0
            [[ $f == *@* ]] && { rate=${f#*@}; f=${f%@*}; }
            w=$r/$dir-$cc$f; (( rate > 0 )) && w+="r$rate"; [[ -n $prof ]] && w+="-perf"
            t0=$(( $(date +%s) + 6 ))
            on $B "setsid nohup $R/window.sh b $t0 $w $cc $f $PEER $rarg $rate $prof > /dev/null 2>&1 < /dev/null &"
            on $A "setsid nohup $R/window.sh a $t0 $w $cc $f $PEER $rarg $rate $prof > /dev/null 2>&1 < /dev/null &"
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
            log "$row ${w##*/} done a=$done_a b=$done_b gbit=$gbit rr(p50 p99 p99.9 lost)=$p99"
            [[ $done_a == 0 && $done_b == 0 ]] || fail=1
            # The profile is reported on B right after its window (outside any measured window).
            if [[ -n $prof ]]; then
                on $B "cd $w && LD_LIBRARY_PATH=$R/perf/lib $R/perf/perf report -i perf.data --stdio --no-children --sort comm,dso,sym --percent-limit 0.3 > report-sym.txt 2> report.err; LD_LIBRARY_PATH=$R/perf/lib $R/perf/perf report -i perf.data --stdio --no-children --sort comm,dso --percent-limit 0.5 > report-dso.txt 2>> report.err; rm -f perf.data; wc -l report-sym.txt"
            fi
    done
    # sleep: settle after the last window before the post-load sample.
    sleep 15
    psnap_all $r/idle2.json
    # sleep: the 20 s idle sample after load.
    sleep 20
    psnap_all $r/idle3.json
    for h in $A $B; do on $h "ip netns exec j39 nft list ruleset > $r/nft.end 2>&1; $R/side.sh paths > $r/paths.end 2>&1"; done
    engine_down
    log "$row down"
done
for h in $A $B; do on $h "uptime > $R/res/$hold/uptime.after; ip netns exec j39 nft list table inet j39guard > $R/res/$hold/guard-counters.txt"; done
ns_all_down > /dev/null 2>&1
release_all > /dev/null 2>&1
trap - EXIT
log "released"
for x in a:$A b:$B; do
    mkdir -p "$ev/${x%%:*}"
    on ${x#*:} "tar czf - -C $R/res $hold" | tar xzf - -C "$ev/${x%%:*}"
done
log "HOLD_DONE fail=$fail"
