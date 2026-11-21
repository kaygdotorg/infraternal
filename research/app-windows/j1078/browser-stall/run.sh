#!/bin/bash
# Runs the stall experiment once per frame interval in headless Chromium; kills only its own PIDs.
cd "$(dirname "$0")"
SHELL_BIN=$(ls -d ~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-*/chrome-headless-shell 2>/dev/null | tail -1)
[ -x "$SHELL_BIN" ] || SHELL_BIN=$(ls -d ~/.cache/ms-playwright/chromium_headless_shell-*/*/headless_shell 2>/dev/null | tail -1)
echo "browser=$SHELL_BIN"; "$SHELL_BIN" --version; uptime
for interval in 8 16; do
  node server.js $interval > out.$interval 2>&1 & SRV=$!
  for i in $(seq 1 50); do grep -q PORT out.$interval && break; sleep 0.1; done
  PORT=$(awk '/PORT/{print $2}' out.$interval)
  D=$(mktemp -d); "$SHELL_BIN" --no-sandbox --user-data-dir=$D --remote-debugging-port=0 "http://127.0.0.1:$PORT/" > chrome.$interval.log 2>&1 & CH=$!
  wait $SRV; kill $CH 2>/dev/null; wait $CH 2>/dev/null; rm -rf "$D"
  cat out.$interval
done
