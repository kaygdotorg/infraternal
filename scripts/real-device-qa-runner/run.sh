#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs on the Mac Studio ("std"). Builds the XCUITest runner once, then runs one ACTIONS script against the
# infraternal-01 iPhone Simulator under the infraternal simulator lock, and leaves numbered screenshots plus
# `qa-lines.txt` (every QA_RESULT / QA_FRAME line) in a fresh out/<run>/ directory.
#
#   run.sh build
#   run.sh trust-ca <pem>               # boot the simulator, trust the QA CA in its own keychain
#   run.sh run <name> '<ACTIONS>'        # env: SIM_UDID (default: look up "infraternal-01"), RUNNER_OUT
#
# The lock is /tmp/infraternal-std-sim.lock, never calternal's. Nothing here edits a dotfile or touches the host
# desktop; the simulator and this directory are the only things it changes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export PATH="$PATH:/nix/var/nix/profiles/default/bin"
if [[ ${INFRATERNAL_LOCK_HELD:-} != "$ROOT" ]]; then
  FLOCK="$(command -v flock || true)"
  # macOS has no flock: use the one built into tools-flock (first run builds it from nixpkgs).
  [[ -n "$FLOCK" ]] || { [[ -x "$ROOT/tools-flock/bin/flock" ]] || nix build nixpkgs#flock --out-link "$ROOT/tools-flock" >/dev/null; FLOCK="$ROOT/tools-flock/bin/flock"; }
  exec "$FLOCK" -w 1800 /tmp/infraternal-std-sim.lock /usr/bin/env INFRATERNAL_LOCK_HELD="$ROOT" "$0" "$@"
fi
cd "$ROOT"
mkdir -p tmp out
export TMPDIR="$ROOT/tmp/"
UDID=${SIM_UDID:-$(xcrun simctl list devices | /usr/bin/awk -F'[()]' '/ infraternal-01 \(/ {print $2; exit}')}
[[ -n "$UDID" ]] || { echo "simulator infraternal-01 not found" >&2; exit 2; }

case "${1:-}" in
build)
  [[ -x tools-xcodegen/bin/xcodegen ]] || nix build nixpkgs#xcodegen --out-link tools-xcodegen >/dev/null
  tools-xcodegen/bin/xcodegen generate >/dev/null
  xcodebuild build-for-testing -project DeviceQA.xcodeproj -scheme DeviceQA -destination "platform=iOS Simulator,id=$UDID" \
    -derivedDataPath "$ROOT/dd" CODE_SIGNING_ALLOWED=NO > out/build.log 2>&1 || { tail -30 out/build.log >&2; exit 1; }
  # XCTest saves its own snapshots and recordings by default. They could capture a setup token on screen, so keep only
  # the screenshots the script takes on purpose (named qa-*).
  /usr/bin/python3 - dd/Build/Products/*.xctestrun <<'PY'
import plistlib, sys
path = sys.argv[1]
data = plistlib.load(open(path, "rb"))
for config in data.get("TestConfigurations", []):
    for target in config.get("TestTargets", []):
        target["SystemAttachmentLifetime"] = "keepNever"
        target["UserAttachmentLifetime"] = "keepAlways"
plistlib.dump(data, open(path, "wb"))
PY
  echo "runner built"
  ;;
trust-ca)
  # Boots infraternal-01 and adds the QA server's CA to the SIMULATOR's own keychain (never the Mac's), under the lock.
  pem=${2:?pem file}
  [[ "$(xcrun simctl list devices | /usr/bin/grep "$UDID" || true)" == *'(Booted)'* ]] || xcrun simctl boot "$UDID"
  xcrun simctl bootstatus "$UDID" -b > /dev/null 2>&1
  xcrun simctl keychain "$UDID" add-root-cert "$pem" && echo ca-trusted-in-simulator
  ;;
run)
  name=${2:?name}; actions=${3:?ACTIONS}
  state=$(xcrun simctl list devices | /usr/bin/grep "$UDID" || true)
  [[ "$state" == *'(Booted)'* ]] || xcrun simctl boot "$UDID"
  xcrun simctl bootstatus "$UDID" -b > /dev/null 2>&1
  # Face ID enrolment is a notify state that does not survive a simulator restart, and without it Safari refuses to
  # create or use a passkey ("Simulator requires enrolled biometrics"). Enrolling again is harmless, so do it every run.
  # Reduce Motion on (default): Safari never goes idle while this page animates, and XCUITest then waits a 60 s idle timeout
  # on every tap, so a run takes minutes instead of seconds. The page honours the setting, so it stops animating. Set
  # QA_REDUCE_MOTION=0 to test with motion. Safari is restarted once when the setting changes.
  if [[ "${QA_REDUCE_MOTION:-1}" == 1 ]]; then
    if [[ "$(xcrun simctl spawn "$UDID" defaults read com.apple.Accessibility ReduceMotionEnabled 2>/dev/null || echo 0)" != 1 ]]; then
      xcrun simctl spawn "$UDID" defaults write com.apple.Accessibility ReduceMotionEnabled -bool true
      xcrun simctl terminate "$UDID" com.apple.mobilesafari > /dev/null 2>&1 || true
    fi
  fi
  # QA_APPEARANCE=light|dark switches the whole simulator, so a check can be run in both themes.
  [[ -n "${QA_APPEARANCE:-}" ]] && xcrun simctl ui "$UDID" appearance "$QA_APPEARANCE"
  xcrun simctl spawn "$UDID" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1 > /dev/null
  xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit.enrollmentChanged > /dev/null
  shopt -s nullglob
  runs=("$ROOT"/dd/Build/Products/*.xctestrun)
  [[ ${#runs[@]} == 1 ]] || { echo "run '$0 build' first" >&2; exit 2; }
  dir="${RUNNER_OUT:-$ROOT/out}/$(date -u +%Y%m%dT%H%M%SZ)-$name"
  mkdir -p "$dir"
  export TEST_RUNNER_ACTIONS="$actions"
  set +e
  xcodebuild test-without-building -xctestrun "${runs[0]}" -destination "platform=iOS Simulator,id=$UDID" \
    -only-testing:DeviceQAUITests/DeviceQA/testSafari -parallel-testing-enabled NO -resultBundlePath "$dir/result.xcresult" > "$dir/test.log" 2>&1
  status=$?
  set -e
  xcrun xcresulttool export attachments --path "$dir/result.xcresult" --output-path "$dir" > "$dir/export.log" 2>&1 || true
  /usr/bin/python3 - "$dir" <<'PY'
import json, os, re, sys
d = sys.argv[1]
try:
    manifest = json.load(open(os.path.join(d, "manifest.json")))
except Exception:
    manifest = []
# Failure snapshots ignore the lifetime setting and can show a typed secret: whatever is not a deliberate qa-* shot goes.
keep = {a["exportedFileName"] for t in manifest for a in t["attachments"] if a["suggestedHumanReadableName"].startswith("qa-")}
for name in os.listdir(d):
    if name not in keep and name not in ("test.log", "export.log", "manifest.json", "result.xcresult"):
        path = os.path.join(d, name)
        if os.path.isfile(path): os.remove(path)
items = sorted((a for t in manifest for a in t["attachments"]), key=lambda a: a.get("timestamp", 0))
items = [a for a in items]
n = 0
for a in items:
    if not a["suggestedHumanReadableName"].startswith("qa-"):
        continue
    label = re.sub(r"_\d+_[0-9A-F-]{36}\.png$", "", a["suggestedHumanReadableName"])[3:]
    n += 1
    source = os.path.join(d, a["exportedFileName"])
    if os.path.exists(source):
        os.rename(source, os.path.join(d, "%02d-%s.png" % (n, label)))
PY
  # The result bundle still holds XCTest's failure snapshots (which can show a typed secret); the deliberate shots are
  # already exported, so the bundle goes.
  rm -rf "$dir/result.xcresult"
  /usr/bin/grep -h -E '^(QA_RESULT|QA_FRAME|QA_SHOT|QA_NOTE|QA_LABEL)|QA_DUMP' "$dir/test.log" > "$dir/qa-lines.txt" || true
  printf 'status=%s\nOUT=%s\n' "$status" "$dir"
  /usr/bin/grep -E '^QA_(RESULT|FRAME|NOTE|LABEL)' "$dir/qa-lines.txt" || true
  exit "$status"
  ;;
session)
  # Holds the simulator lock for a whole command, so several runs cannot be interleaved with another job's:
  #   run.sh session ./checklist.sh dark
  shift; "$@"
  ;;
*) echo "usage: run.sh build | run <name> '<ACTIONS>' | session <command...>" >&2; exit 2;;
esac
