#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The real-device checklist, run on the Mac Studio ("std") in the infraternal-01 iPhone Simulator, in one theme.
# `scripts/real-device-qa check` starts it as `run.sh session ./checklist.sh <light|dark> <url> <out-dir>`, so the
# simulator lock is held from the first tap to the last screenshot and no other job can navigate Safari in between.
#
# Each phase is one `run.sh run` (one XCUITest session). Phases never depend on a previous phase's page state except
# through the server: they all start with a fresh `open`, because Safari's tab can be moved by anything else.
# Tap positions that are written as x/y fractions were read from screenshots of an iPhone 18 Pro (402 x 874 pt) at the
# layout the pre-fix build draws; the page canvas is scaled, so its accessibility frames are NOT screen coordinates.
set -euo pipefail
cd "$(dirname "$0")"
theme=${1:?light|dark}; url=${2:?origin of the device-QA server}; out=${3:?output directory}
export QA_APPEARANCE=$theme RUNNER_OUT=$out
mkdir -p "$out"

TOP_PILL='0.5~0.1075'          # the "Console · N" pill at the top: opens the views menu
PILL='0.228~0.177'            # the machine pill, top-left of a window
CONNECTION_TAB='0.385~0.311'  # the second tab inside the machine panel
NEW_SHELL='0.616~0.501'       # "New shell" on an ended session, centred in a full-height (fresh-load) window
# The app's own theme wins over the system scheme once one is saved, so a "dark" run must ask for a dark theme in the
# URL (?theme=mocha is the dark default, latte the light one) as well as switching the simulator's appearance.
case "$theme" in dark) app_theme=mocha;; *) app_theme=latte;; esac
fresh="open~$url/?r=$(date +%s)&theme=$app_theme|wait~12"

# A fresh load shows the stored windows. When none is open the page offers an "Open shell" pill (an ended session's pill says
# "New shell"), and an account with two hosts answers it with a palette of "Open shell on <host>" rows, so: tap whichever pill is
# there and then the QA host's row, and do nothing when a window is already open. Wordings come from canvas/views/world.ts,
# canvas/windows/session-ui.on-demand.ts and canvas/toolbar/palette-rows.on-demand. QA_HOST_NAME is the QA host's name as the
# palette shows it.
#
# KNOWN LIMIT (measured 2026-11-15, #510): while the server's host CA is locked, the page can stay on a single, never-connecting
# "SSH shell" pane of the server's own host. Its key bar hides the toolbar and the views pill, the QA host is not listed, and
# every phase after sign-in then reports missing controls. The `unlock` phase below is what clears it; if a run starts in that
# state, run `check --phases unlock` by hand first and look at its screenshot.
QA_HOST_NAME=${QA_HOST_NAME:-infraternal-dev-02}
OPEN="tapif~Open shell/New shell~6|wait~2|tapifx~Open shell on $QA_HOST_NAME~4|wait~6"

# QA_PHASES="shell pill" runs only those phases (a phase that needed a fix can be rerun without the whole checklist).
wanted() { [[ -z "${QA_PHASES:-}" || " $QA_PHASES " == *" $1 "* ]]; }
run() { wanted "$1" || return 0; ./run.sh run "$theme-$1" "$2" || true; }

# 1. Sign in. With a session already stored this only proves the app opens signed in; without one it does the passkey ceremony.
run signin "$fresh|tapif~Continue with passkey~5|tapsbif~Use Passkey/Use Selected Passkey~6|face|wait~6|shot~console|exists~Show hosts/Console~console-visible~contains"

# 1a. Pick the theme. An account that has chosen a theme ignores the device's light/dark setting and `?theme=` (D352, D390), so
# a dark run must pick a dark theme in the app: the palette's colour rows are named by theme ("Mocha" dark, "Latte" light).
# The report measures the picture, so a run that stayed in the wrong theme fails instead of passing as dark.
case "$theme" in dark) pick=Mocha;; *) pick=Latte;; esac
run theme "$fresh|xy~$TOP_PILL|wait~2|tapx~Search everything|wait~3|type~$pick|wait~2|return|wait~3|shot~theme-picked"

# 1b. Unlock host connections. After a server restart (or a new session) the host CA is locked until one passkey tap, and a
# locked host is offline: its shell opens but takes no input. The palette row exists only while the CA is locked.
run unlock "$fresh|xy~$TOP_PILL|wait~2|tapx~Search everything|wait~3|type~Unlock host connections|wait~3|return|wait~4|tapsbif~Use Passkey/Use Selected Passkey~8|face|wait~10|shot~unlocked"

# 2 and 3. Open a shell, type, `exit`: does the window close, and does every window fit the 402 pt viewport?
run shell "$fresh|$OPEN|xy~0.5~0.3|wait~2|shot~shell-opened|frames~region~regions-before|type~echo qa-ok|return|wait~2|shot~shell-typed|type~exit|return|wait~5|shot~after-exit|absent~shell ended~exit-closes-window|frames~shell, region~win-after-exit"

# 4. The machine pill: both tabs, the facts, and whether a scrolled panel stays where it was for 35 s.
run pill "$fresh|$OPEN|xy~$PILL|wait~3|shot~pill-machine|labels|frames~Kernel~kernel-y0|swipe~0.5~0.72~0.5~0.3~1.2|wait~1|shot~pill-scrolled-now|frames~Kernel~kernel-y1|wait~35|frames~Kernel~kernel-y2|shot~pill-scrolled-35s|xy~$CONNECTION_TAB|wait~2|shot~pill-connection"

# 6, 8. The views menu: mesh, settings and the palette ("Search everything").
run menus "$fresh|xy~$TOP_PILL|wait~3|shot~views-menu|tapx~Mesh|wait~3|shot~mesh|frames~card~mesh-cards|xy~$TOP_PILL|wait~2|tapx~Settings|wait~4|shot~settings|$PAL|shot~palette"

# 7. Text sizes: heights of text rows in the machine panel, to compare between builds (the pixels are in the shots).
run text "$fresh|$OPEN|xy~$PILL|wait~3|frames~SYSTEM~text-heading|frames~Architecture~text-label|frames~Name~text-row|shot~text-sample"

# 9. Motion: a screen recording of the views menu and the machine panel opening and closing. Judged by eye / frame
#    timing from the video; this script only records it.
if wanted motion; then
video="$out/$theme-motion.mov"
udid=$(xcrun simctl list devices | /usr/bin/awk -F'[()]' '/ infraternal-01 \(/ {print $2; exit}')
xcrun simctl io "$udid" recordVideo --force "$video" > /dev/null 2>&1 &
rec=$!
run motion "$fresh|xy~$TOP_PILL|wait~2|xy~0.5~0.82|wait~1|xy~$PILL|wait~2|xy~0.5~0.82|wait~1|shot~motion-end"
kill -INT "$rec" 2>/dev/null || true
wait "$rec" 2>/dev/null || true
fi
echo "checklist done: $theme -> $out"
