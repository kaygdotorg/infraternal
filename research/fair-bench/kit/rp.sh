#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1237 (#260, #580): the real production join path as a setup-time row ("R"), one VM's side.
#
# J1199's infraternal setup time came from the mesh test fixture (production node binary plus the
# coordinator compiler, no sign-in, no server). This is the path a customer takes: a real
# `infraternal server` with its own TLS certificate, a scripted owner (headless browser, virtual
# passkey; rp-approver.ts), and `infraternal up <origin>` on each node, with the printed code
# approved on the server's own page. The nodes then run the agent exactly as the installed unit would.
#
# Nothing on the VM's system is changed. The server and each node run in a private sandbox: a new mount, pid and
# uts namespace inside the fixture's network namespace, and a chroot whose /usr and /dev are the host's and whose
# /etc, /run, /tmp, /var/lib and /home are fresh tmpfs (the same idea as scripts/verify-up-approval-namespace). `up`
# writes `/.infraternal-up.journal` and its installation under /var/lib, /etc/systemd and /usr/local: all of that lands
# in the sandbox. In it /usr/bin/sudo and /usr/bin/systemctl are small stand-ins: the stand-in sudo runs the helper
# as the root we already are, the stand-in systemctl runs the unit's ExecStart (oneshot in the foreground, services in
# the background) instead of asking a service manager. Every process lives in the fixture's network namespace
# ($FB_NS, default j99), which only reaches the VM LAN; side.sh nsdown removes it all.
#
# The passkey (WebAuthn) needs a domain name, not an IP, as the page's origin: the server is reached as
# $RP_NAME (default mesh.j99.test), which each node maps to the server's LAN address in its private
# mount namespace (/etc/hosts) and the browser maps with --host-resolver-rules. No DNS, no public name.
#
#   rp.sh server <ip>                      real server on <ip>:443, writes $RUN/setup-token and $RUN/srv-cert.pem
#   rp.sh approver <origin> <ip> <port>    the scripted owner + approval listener (needs bun + playwright)
#   rp.sh join <label> <origin> <approver ip:port>   run `infraternal up` as a node; result in $RUN/join.<label>.json
#   rp.sh stop <label>                     stop that node's agent and namespace
set -euo pipefail
R=${FB_ROOT:-/root/j1237}
NS=${FB_NS:-j99}
RP_NAME=${RP_NAME:-mesh.j99.test}
RUN=${RP_RUN:-$R/run}
BIN=$R/bin
# The shipped binary trusts only the fixed public CA bundle at /etc/ssl/certs/ca-certificates.crt (it ignores
# SSL_CERT_FILE, #483). The server here has a throwaway certificate, so each node's private mount namespace binds a
# copy of that bundle plus the server's certificate over the path (scripts/verify-up-approval-namespace does the same).
# The binary is the unmodified production release build.
IX=$BIN/infraternal
nsx() { ip netns exec "$NS" "$@"; }
wait_for() { local t=$1; shift; local end=$((SECONDS + t)); until "$@" >/dev/null 2>&1; do ((SECONDS < end)) || return 1; sleep 0.1; done; }
bg() { local name=$1; shift; setsid nohup ip netns exec "$NS" "$@" > "$RUN/$name.out" 2> "$RUN/$name.err" < /dev/null & echo $! > "$RUN/$name.pid"; }

cmd_server() {
    local ip=$1 d=$RUN/srv
    export RP_SERVER_IP=$ip
    mkdir -p "$d/data" "$d/web" "$d/ca"; chmod 700 "$RUN" "$d" "$d/data" "$d/ca"
    tar xzf "$BIN/tracer-dist.tgz" -C "$d/web"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -keyout "$d/tls.key" -out "$d/tls.crt" -subj "/CN=$RP_NAME" -addext "subjectAltName=DNS:$RP_NAME,IP:$ip" 2> /dev/null
    chmod 600 "$d/tls.key"; cp "$d/tls.crt" "$RUN/srv-cert.pem"
    date +%s.%N > "$RUN/started.srv"
    # HTTPS comes from a reverse proxy, the documented `--behind-proxy` deployment: with `--tls-cert` the server
    # refused to start together with `--remote-listen` on the build host ("TLS configuration failed"), while
    # the proxy form, which is what the repo's own real-server specs run, starts. socat terminates TLS and
    # forwards the TCP stream (WebSocket upgrades included) to the server on the namespace's loopback.
    nsx ip link set lo up
    sandbox srv server "$IX" server --listen 127.0.0.1:8443 --public-origin "https://$RP_NAME" \
        --behind-proxy --trusted-proxy 127.0.0.1 --web-root "$d/web/dist" --data "$d/data" \
        --remote-listen "$ip:7443" --remote-ca-dir "$d/ca"
    wait_for 60 nsx sh -c "ss -ltn | grep -q '127.0.0.1:8443'" || { tail -c 1500 "$RUN/server.err" "$RUN/server.out" >&2; exit 1; }
    bg tlsfront socat "OPENSSL-LISTEN:443,bind=$ip,reuseaddr,fork,cert=$d/tls.crt,key=$d/tls.key,verify=0" TCP:127.0.0.1:8443
    wait_for 20 nsx sh -c "ss -ltn | grep -q '$ip:443'" || { tail -c 800 "$RUN/tlsfront.err" >&2; exit 1; }
    (umask 077; nsx "$IX" server setup-token --data "$d/data" --json 2> /dev/null \
        | python3 -I -c 'import json,sys
def find(o):
    if isinstance(o, dict):
        if isinstance(o.get("token"), str): return o["token"]
        for v in o.values():
            r = find(v)
            if r: return r
    return None
print(find(json.load(sys.stdin)))' > "$RUN/setup-token")
    [[ -s $RUN/setup-token && $(cat "$RUN/setup-token") != None ]] || { echo "no setup token" >&2; exit 1; }
    date +%s.%N > "$RUN/ready.srv"
    echo "server ready"
}

cmd_approver() {
    local origin=$1 ip=$2 port=$3
    : "${BUN:?set BUN to the bun binary}"
    rm -f "$RUN/approver.ready"
    # The kit is copied to $R; node resolves `playwright` from the script's own folder, so it runs from $R/app.
    [[ ! -f $R/rp-approver.ts ]] || cp "$R/rp-approver.ts" "$R/app/"
    # The page's certificate is the server's own self-signed one; the browser is told to accept it.
    # Optional browser environment (a perf VM keeps its browser build and font set in its own folders).
    mkdir -p "$RUN/browser-home"
    local envs=(HOME="$RUN/browser-home" CHROMIUM_MAP="$RP_NAME $RP_SERVER_IP")
    [[ -z ${PLAYWRIGHT_BROWSERS_PATH:-} ]] || envs+=(PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH")
    [[ -z ${RP_LIBS:-} ]] || envs+=(LD_LIBRARY_PATH="$RP_LIBS")
    [[ -z ${RP_FONTCONFIG:-} ]] || envs+=(FONTCONFIG_FILE="$RP_FONTCONFIG")
    bg approver env "${envs[@]}" \
        sh -c "cd $R/app && exec $BUN run $R/app/rp-approver.ts '$origin' '$RUN/setup-token' '$ip' '$port' '$RUN/approver.ready'"
    wait_for 180 test -s "$RUN/approver.ready" || { tail -c 2500 "$RUN/approver.err" "$RUN/approver.out" >&2; exit 1; }
    echo "approver ready"
}

# sandbox <label> <bg-name> <cmd...>: start <cmd> detached inside the sandbox `label` (see the header).
sandbox() {
    local label=$1 name=$2; shift 2
    mkdir -p "$RUN/root.$label/proc"
    setsid nohup ip netns exec "$NS" unshare -m -u -p -f --mount-proc="$RUN/root.$label/proc" \
        bash "$0" _sbxmain "$label" "$@" > "$RUN/$name.out" 2> "$RUN/$name.err" < /dev/null &
    echo $! > "$RUN/$name.pid"
}
# sandbox_run <label> <cmd...>: the same, but in the foreground (a one-shot command).
sandbox_run() {
    local label=$1; shift
    mkdir -p "$RUN/root.$label/proc"
    ip netns exec "$NS" unshare -m -u -p -f --mount-proc="$RUN/root.$label/proc" bash "$0" _sbxmain "$label" "$@"
}

# Inside the new namespaces: build the private root, then chroot into it and exec the command.
cmd__sbxmain() {
    local label=$1; shift
    local root=$RUN/root.$label f=$RUN/fake.$label
    hostname "j99-$label"
    mkdir -p "$f" "$root"/{usr,etc,dev,sys,run,tmp,var/lib,home,root,opt} "$root$R"; chmod 755 "$f" "$root"
    mount --make-rprivate /
    mount --rbind /usr "$root/usr"
    ln -sfn usr/bin "$root/bin"; ln -sfn usr/lib "$root/lib"; ln -sfn usr/lib64 "$root/lib64"; ln -sfn usr/sbin "$root/sbin"
    mount --rbind /dev "$root/dev"
    mount --rbind /sys "$root/sys"
    for d in run var/lib home; do mount -t tmpfs -o mode=755 tmpfs "$root/$d"; done
    mount -t tmpfs -o mode=1777 tmpfs "$root/tmp"
    mkdir -m 700 "$root/run/infraternal"; mkdir -p "$root/etc/systemd/system" "$root/etc/ssl/certs" "$root/usr/local"
    for e in passwd group nsswitch.conf resolv.conf localtime; do cp -L "/etc/$e" "$root/etc/$e" 2> /dev/null || true; done
    # The mesh refuses a machine ID on tmpfs, under /run or on another device than /etc, so the sandbox's /etc is a
    # plain directory on the VM's disk (inside our own run folder) and each sandbox gets its own random ID.
    openssl rand -hex 16 > "$root/etc/machine-id"
    # The server's name resolves to its LAN address in this sandbox only.
    { cat /etc/hosts; echo "${RP_SERVER_IP:?} $RP_NAME"; } > "$root/etc/hosts"
    # The shipped binary trusts only this fixed bundle: the host's plus the server's throwaway certificate.
    cat /etc/ssl/certs/ca-certificates.crt "$RUN/srv-cert.pem" > "$root/etc/ssl/certs/ca-certificates.crt" 2> /dev/null \
        || cp "$RUN/srv-cert.pem" "$root/etc/ssl/certs/ca-certificates.crt"
    chmod 644 "$root/etc/ssl/certs/ca-certificates.crt"
    cat > "$f/sudo" <<SUDO
#!/bin/sh
set -eu
printf 'sudo\\n' >> $RUN/sudo.$label.log
[ "\${1-}" = "--" ] || exit 2
shift
[ "\$#" -ge 2 ] || exit 2
shift
exec env TMPDIR=/tmp "$IX" "\$@"
SUDO
    cat > "$f/systemctl" <<SYSTEMCTL
#!/bin/bash
set -u
printf '%s\\n' "\$*" >> $RUN/systemctl.$label.log
start() { # run the unit's ExecStart: a oneshot to its end, a service in the background
    local u=/etc/systemd/system/\$1 cmd
    cmd=\$(sed -n 's/^ExecStart=//p' "\$u" | head -1)
    [ -n "\$cmd" ] || return 0
    if grep -q '^Type=oneshot' "\$u"; then timeout 30 \$cmd > /dev/null 2>&1
    else setsid nohup \$cmd >> $RUN/agent.$label.out 2>&1 < /dev/null & echo \$! >> $RUN/agent.$label.pids; fi
}
case "\${1-}" in
    is-active) echo active ;;
    enable) [ "\${2-}" = "--now" ] && start "\$3" ;;
    restart|start) start "\$2" ;;
esac
exit 0
SYSTEMCTL
    chmod 755 "$f/sudo" "$f/systemctl"
    mount --bind "$f/sudo" "$root/usr/bin/sudo"
    mount --bind "$f/systemctl" "$root/usr/bin/systemctl"
    mount --rbind "$R" "$root$R"
    exec chroot "$root" /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root TERM=xterm FB_ROOT="$R" RP_RUN="$RUN" FB_NS="$NS" RP_NAME="$RP_NAME" RP_SERVER_IP="$RP_SERVER_IP" "$@"
}

# The node's own script, inside its sandbox: runs `infraternal up` on a pty, passes the printed code to the approver.
cmd__nodemain() {
    local label=$1 origin=$2 approver=$3
    : > "$RUN/agent.$label.pids"
    date +%s.%N > "$RUN/up.start.$label"
    # `up` shows its code only on a terminal: run it on a pseudo-terminal, stdout (the JSON) to a file.
    setsid script --quiet --flush --return --command "exec $IX up $origin --json >$RUN/up.stdout.$label" "$RUN/up.tty.$label" < <(sleep 900) > /dev/null 2>&1 &
    local upgrp=$!
    local code=
    for _ in $(seq 1 600); do
        code=$(grep -aoP 'Code: \K[A-Za-z0-9_-]{16}' "$RUN/up.tty.$label" 2> /dev/null | head -1 || true)
        [[ -n $code ]] && break
        sleep 0.05
    done
    [[ -n $code ]] || { echo '{"ok":false,"error":"no code"}' > "$RUN/join.$label.json"; return 1; }
    date +%s.%N > "$RUN/up.code.$label"
    python3 -I -c 'import sys, urllib.request
r = urllib.request.urlopen(urllib.request.Request("http://" + sys.argv[1] + "/approve", data=sys.argv[2].encode()), timeout=90)
print(r.read().decode())' "$approver" "$code" > "$RUN/approve.$label.json" 2>&1 || true
    date +%s.%N > "$RUN/up.approved.$label"
    for _ in $(seq 1 1800); do
        grep -q '"state"' "$RUN/up.stdout.$label" 2> /dev/null && break
        sleep 0.1
    done
    date +%s.%N > "$RUN/up.end.$label"
    python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps({"ok": d.get("state")=="ready", "state": d.get("state")}))' \
        "$RUN/up.stdout.$label" > "$RUN/join.$label.json" 2>&1 || echo '{"ok":false}' > "$RUN/join.$label.json"
    # Stay alive (the agent lives in this sandbox) until told to stop.
    while [[ ! -e $RUN/stop.$label ]]; do sleep 0.5; done
    for p in $(cat "$RUN/agent.$label.pids"); do kill "$p" 2> /dev/null || true; done
    kill -- -"$upgrp" 2> /dev/null || true
}

cmd_join() {
    local label=$1; shift
    rm -f "$RUN/stop.$label" "$RUN/join.$label.json"
    sandbox "$label" "node.$label" /usr/bin/bash "$R/rp.sh" _nodemain "$label" "$@"
}
cmd_stop() { touch "$RUN/stop.$1"; }

c=$1; shift
"cmd_$c" "$@"
