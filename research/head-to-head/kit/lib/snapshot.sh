#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Print the machine state a benchmark case could leave behind, in a stable,
# sorted text form. run.sh takes one snapshot before and one after every case
# (inside the same perf-lock hold) and requires the diff to be empty.
#
# Covered: kernel modules, root-namespace network state (namespaces, links,
# addresses, routes, rules, nftables/iptables), network sysctls, mounts,
# processes of the kit's programs, systemd units, users and groups, and the
# file trees a daemon could write to. Excluded on purpose (documented in the
# README): logs and journals, kernel counters, and the kit's own directory.
#
#   snapshot.sh <kit-dir>
set -uo pipefail
kit=$1
section() { printf '\n## %s\n' "$1"; }

section modules
cut -d' ' -f1 /proc/modules | sort

section netns
ip netns list 2>/dev/null | cut -d' ' -f1 | sort

section links
ip -o link show | sed -E 's/^[0-9]+: //; s/ qlen [0-9]+//; s/link\/ether [0-9a-f:]+ brd [0-9a-f:]+//' | awk '{print $1, $2}' | sort
section addresses
ip -o addr show | awk '{print $2, $3, $4}' | sort
section routes
{ ip route show table all; ip -6 route show table all; } 2>/dev/null | grep -v '^local fe80\|^multicast\|^fe80' \
    | sed -E 's/ expires [0-9]+sec//' | sort
section rules
{ ip rule show; ip -6 rule show; } 2>/dev/null | sort
section qdiscs
tc qdisc show 2>/dev/null | sed -E 's/ refcnt [0-9]+//' | sort

section nftables
if command -v nft >/dev/null; then nft list ruleset 2>/dev/null | sed -E 's/(packets|bytes) [0-9]+/\1 N/g'; fi
section iptables
for t in iptables-save ip6tables-save; do
    command -v "$t" >/dev/null && "$t" 2>/dev/null | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]/[N]/g'
done

section sysctl
sysctl -a 2>/dev/null | grep -E '^net\.(core|ipv4|ipv6|netfilter)\.' \
    | grep -vE 'nf_conntrack_count|stable_secret|base_reachable_time|tcp_fastopen_key|\.neigh\.|nf_conntrack_buckets|hash_secret' | sort

section mounts
awk '{print $5, $9}' /proc/self/mountinfo | sort

section processes
# Programs the kit runs, by executable name; anything else on the machine is
# not ours to judge.
ps -eo user=,comm=,args= 2>/dev/null | awk '$3 !~ /^\[/' \
    | awk '$2 ~ /^(h2h|tailscale|tailscaled|tscontrol|netbird|netbird-server|wireguard-go|zellij|tmux|infraternal|coordinator_fi)/ || /\/dev\/shm\/h2h-/' \
    | awk '{print $1, $2}' | sort

section units
systemctl list-units --all --no-legend --plain 2>/dev/null \
    | awk '{print $1, $3}' | grep -E 'h2h|tailscale|netbird|zellij|tmux|infraternal|perf\.slice' \
    | grep -v '^run-netns-' | sort

section accounts
cut -d: -f1,3,4,6,7 /etc/passwd | sort
cut -d: -f1,3 /etc/group | sort

section files
# Path, type, size and mode; mtimes are omitted because unrelated system
# daemons touch them. New, removed or resized files still show.
for root in /etc /usr/local /opt /root /var/lib /var/spool /var/tmp /srv /var/cache; do
    [[ -d $root ]] || continue
    find "$root" -xdev \( -path "$kit" -o -path '/var/lib/systemd/timers' -o -path '/var/lib/systemd/timesync' \
        -o -path '/var/lib/private/systemd' -o -path '/var/lib/apt/lists' -o -path '/var/cache/apt' \
        -o -path '/var/lib/sudo' -o -path '/root/.cache/infraternal-perf' -o -path '/root/.cache/nix/sentry' \) -prune \
        -o -printf '%p %y %s %m\n' 2>/dev/null
# The machine's own NetBird client rewrites its SSH snippet as peers change;
# the kit's NetBird runs with /etc on a throwaway overlay and cannot write it.
done | grep -vE '^/etc/ssh/ssh_config.d/99-netbird.conf |/\.(bash|zsh|python)_history |/var/lib/systemd/random-seed |/var/lib/logrotate/status |/var/lib/systemd/coredump/|/var/lib/tailscale/tailscaled\.log[0-9]*\.txt ' | sort
section top-level
for root in /tmp /run /dev/shm /home /var/log; do
    [[ -d $root ]] && find "$root" -maxdepth 1 -mindepth 1 -printf '%p %y\n' 2>/dev/null
# The cpuset audit makes a short-lived /tmp/j88i-audit-* directory of its own and may
# remove it after the next row's snapshot; counting it made a clean row look dirty.
done | grep -vE "^$kit |^/run/user |^/tmp/systemd-private-|^/run/systemd |^/run/udev |^/tmp/cc[A-Za-z0-9]{6}\.|^/tmp/j88i-audit-[A-Za-z0-9_]+ " | sort
for wtmp in /var/log/wtmp /var/log/btmp /var/log/lastlog /run/utmp; do
    if [[ -e $wtmp ]]; then stat -c '%n %s' "$wtmp"; fi
done
