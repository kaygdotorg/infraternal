#!/usr/bin/env bash
# Use the existing public shell profile in a private mount namespace; never alter host login accounts [13][215].
set -uo pipefail
if [[ ${1:-} != inside ]]; then
  exec unshare --mount --fork bash "$0" inside
fi
cd /root/infraternal-bench/dev-merge-d215
mount --make-rprivate /
mkdir -p home results/session-portable
printf 'root:x:0:0:Session fixture:/root/infraternal-bench/dev-merge-d215/home:/usr/bin/zsh\n' > fixture-passwd
printf 'root:x:0:\n' > fixture-group
printf '# Isolated benchmark login profile.\n' > fixture-profile
mount --bind fixture-passwd /etc/passwd
mount --bind fixture-group /etc/group
mount --bind fixture-profile /etc/profile
for spec in verify-session-bounds verify-session-exit-credit verify-session-exit-events verify-session-retention; do
  cat /proc/loadavg > "results/session-portable/$spec.load-before"
  INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/dev-merge-d215/state \
    python3 "scripts/$spec.py" --binary binaries/merged > "results/session-portable/$spec.log" 2>&1
  echo $? > "results/session-portable/$spec.exit"
  cat /proc/loadavg > "results/session-portable/$spec.load-after"
done
INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/dev-merge-d215/state \
  python3 scripts/verify-session-exit-credit.py --binary binaries/merged --exit-after-detach > results/session-portable/exit-after-detach.log 2>&1
echo $? > results/session-portable/exit-after-detach.exit
INFRATERNAL_TEST_STATE_ROOT=/root/infraternal-bench/dev-merge-d215/state \
  python3 scripts/verify-agent.py --binary binaries/merged > results/session-portable/idle-canary.log 2>&1
echo $? > results/session-portable/idle-canary.exit
