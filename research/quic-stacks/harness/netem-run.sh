#!/usr/bin/env bash
# Role: Applies isolated loopback UDP delay and loss before one benchmark invocation.
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
ip_bin=$1
tc_bin=$2
delay=$3
jitter=$4
loss=$5
shift 5
"$ip_bin" link set lo up
"$tc_bin" qdisc replace dev lo root netem delay "$delay" "$jitter" loss "$loss"
"$tc_bin" -s qdisc show dev lo >&2
status=0
"$@" || status=$?
"$tc_bin" -s qdisc show dev lo >&2
exit "$status"
