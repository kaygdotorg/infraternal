<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Real-device QA runbook

Owner, 2026-11-11: "all this makes me think that our testing process sucks. you need to use test.ssh.kayg.org more
in your mac vm through safari and on std via an iPhone simulator ... to confirm actual/real behaviour".

`scripts/real-device-qa` drives the real web app in real iOS Safari (iPhone Simulator, iOS 27) on the Mac Studio
"std", against a device-QA server on mesh-staging, and writes a pass/fail table with screenshots. Run it after every
deploy. It catches what Chromium and Playwright WebKit cannot: the iOS keyboard and viewport, Safari's password
prompts, the passkey sheet, and layout at the real 402 x 874 pt screen.

## Why a separate server (and not test.ssh.kayg.org)

A browser cannot be signed in to an existing account from a second device. The account key is wrapped by a passkey
and unwrapped in the browser that holds that passkey; the server never has it (`addSecondPasskey` needs the existing
passkey in the same browser, recovery deletes every passkey and session, invites are an enterprise feature). So the
simulator needs an account it created itself. mesh-staging is a throwaway, prod-shaped AlmaLinux VM, so the QA
server runs there as a second instance beside J479's: its own user (`infraternal-qa`), data dir
(`/var/lib/infraternal-qa`), ports (127.0.0.1:7021, hosts 10.69.69.53:7543, TLS 8443), nginx and CA. J479's server,
nginx, data and `/run/infraternal` are never touched. Do not run a second *root* server there: both would use root's
fixed `/run/infraternal` and the second one's agent fails with "address in use".

## One-time setup (a fresh QA server or Studio)

1. `scripts/real-device-qa prepare`: copies the XCUITest runner to `~/Developer/infraternal-sim/qa-runner` on std,
   creates the simulator `infraternal-01` (iPhone 18 Pro, iOS 27.0) if missing, builds the runner, trusts the QA CA
   in the simulator.
2. `scripts/real-device-qa stage [BUNDLE_DIR]`: installs or refreshes the QA server on mesh-staging. BUNDLE_DIR is a
   release bundle on mesh-staging (`infraternal`, `web/`, `SOURCE`); the default is J479's current one. To test a
   branch, build its bundle the way J479 did and pass it.
3. `scripts/real-device-qa host-account`: a throwaway `qa-device` login on dev-02 with its own `qa-sshd` unit on
   :2222 (NetBird answers :22 itself) and the QA CA trusted on dev-02, because the host agent verifies the server's
   HTTPS certificate. The password is random and only ever lives in a 0600 file on the Studio.
4. `scripts/real-device-qa owner-setup` (fresh server only): the first-run flow in the simulator, with a real
   platform passkey and PRF made with a simulated Face ID.
5. `scripts/real-device-qa add-host` (fresh server only): Add host through the phone UI, down to a live shell.

Steps 4 and 5 are recorded UI flows. They were driven by hand once on 2026-11-11 and then encoded; if a step stops
matching (a label changed), the run names it and you re-drive that one step with `run.sh run <name> '<actions>'`.

## Every deploy

```
scripts/real-device-qa stage /path/to/new/bundle    # only when the build under test changed
scripts/real-device-qa check                        # light and dark, about 25 minutes
```

`check` holds the simulator lock for the whole run, so another job cannot move Safari mid-check. It is slow
(about 35 minutes per theme); `--phases "shell pill"` reruns single phases (signin shell pill menus text motion). The table is
printed and saved as `results.md` in `~/.cache/codex-scratch/real-device-qa/<UTC>/`. Attach the table, the
screenshots and the videos to the issue; never commit them (ADR 0003).

Verdicts: PASS and FAIL are measured. REVIEW means numbers cannot decide it: open the named screenshots or the video.
N/A means the QA server cannot show it (no mesh node, so no mesh cards). NOT RUN is the destructive step.

| Step | What is measured |
|---|---|
| 1 sign in | the app shows its Console after load, going through the passkey sheet if there is no session |
| 2 shell + exit | after `exit` the "shell ended" window must be gone |
| 3 window fits | every window region's width <= 402 pt, from accessibility frames |
| 4a machine pill | the panel shows the host's own kernel and architecture (read from the host over ssh) |
| 4b scroll holds | the panel's Kernel row y after the swipe equals y 35 s later |
| 5 Remove host | not run; by hand (below) |
| 6 mesh cards | frames if the QA server has a mesh node; otherwise N/A |
| 7 text sizes | row heights, for comparing builds; judged on `text-sample` |
| 8 palette, settings, themes | screenshots in both themes |
| 9 motion | a recording of the views menu and the machine panel |

### Step 5 by hand

Remove the QA host from the pill, then the palette, then the sidebar swipe (screenshot each), confirm none says
"sign in again", then run `scripts/real-device-qa add-host` to put it back. A removed host is rebuilt in under a
minute; the account and its passkey are untouched.

## Gotchas that cost hours (all in the runner already)

- The page's accessibility tree is **stale while the keyboard is up**: a tap on a frame lands on the keyboard. Close
  the keyboard with its accessory checkmark first. Frames inside the scaled page canvas are not screen coordinates.
- Any **system sheet** (Strong Password, Save Password, passkey) stalls the next XCUITest tap forever. Type in one
  run and close the sheet in the next.
- Matching a label against the live tree takes minutes (the canvas keeps every window in it). The runner parses one
  hierarchy dump instead.
- Face ID enrolment is lost on a simulator restart, and then passkeys fail with "Simulator requires enrolled
  biometrics". `run.sh` enrols on every run (`notifyutil -s/-p com.apple.BiometricKit.enrollmentChanged`) and
  approves prompts with `notifyutil -p com.apple.BiometricKit_Sim.pearl.match` (`face`).
- XCUITest keeps failure snapshots that can show a typed secret. `run.sh` deletes everything that is not a
  deliberate `qa-*` screenshot, and the result bundle.
- Other jobs may use the same simulator and lock. They can only act between runs, which is why `check` runs as one
  `run.sh session`.
- Passkeys here are scoped to `kayg.org` (rp id), so the simulator's passkey is also offered on test and prod
  hostnames. Do not approve prompts there.

## Secrets

The setup token and the host password are files (0600) on the Studio, typed by the runner (`typefile`), never argv.
Never take a screenshot while a token is on screen, and never attach recovery-key screenshots. The runner takes
none on those steps. The QA owner and host are disposable.

## Cleanup

`scripts/real-device-qa teardown` stops `qa-sshd`, deletes `qa-device`, removes the QA CA from dev-02's trust store
and stops the QA units on mesh-staging (data is kept in `/var/lib/infraternal-qa`; delete it to start from a fresh
first-run). Shut the simulator down with `xcrun simctl shutdown` when you are done.

## Desktop Safari (Mac VM) and what 2026-11-11 taught

`scripts/real-device-qa mac-setup` (once) and `mac` (per deploy) drive real Safari at 1440 x 900 and at a phone-narrow
402 px window through safaridriver, as lume, under `/tmp/mac-bench.lock` with the driver stopped by PID. They give the page's
own DOM: overflow, window rectangles, computed text sizes, per-frame motion, `scrollTop`. The Mac needs its own owner (the
simulator's passkey cannot be shared), so `mac-setup` installs a second QA server (`stage/install-qa2-instance.sh`, TLS on
:9000, because SELinux allows nginx only on http_port_t ports; :8443 and :9000 are such ports, :8444 is not). The Maintainer
trusts the QA CA in the Mac's System keychain for mesh-staging.vpn.kayg.org.

- Safari's WebDriver virtual authenticator hangs on `credentials.create`. The test-only in-page software authenticator is
  injected as a `<script>` element (WebDriver scripts run in an isolated JS world) and installed on
  `CredentialsContainer.prototype` (WebKit can garbage-collect the wrapper that carries a patch on `navigator.credentials`).
  Its signature counter must never go backwards: the state file is saved at the end of every session.
- After a page load the host CA is locked until "Unlock host connections" (one passkey tap); hosts stay offline and unlisted
  until then. The simulator checklist has an `unlock` phase for that.
- A removed host that is offline stays listed with its cleanup pending, so removal is proven by the re-add needing the full
  host-key and password flow, not by the toast (it disappears).
- **A dark run needs a dark device at first load, or a picked dark theme.** Since D390 an account that never picked a theme
  follows each device's light or dark setting, so a fresh QA owner created in a dark simulator shows a dark app and a light
  device of the same account shows a light one. Once someone picks a theme (Settings > Themes, or the palette), the account's
  theme wins on every device (D352) and the system setting no longer moves it: a dark run on such an account needs a dark theme
  picked. Before D390 (2026-11-12) every "dark" screenshot of an account whose first load was light stayed light.
- **Upgrading QA1 (2026-11-12 lesson):** stage the WHOLE release (`share/infraternal` of the Nix result, not just `infraternal`,
  `web/` and `SOURCE`). The four static `infraternal-*-musl` host binaries must sit beside the server, or Add host ends in "The
  matching static infraternal binary is unavailable". Copy it with `stage/qa1-upgrade.sh`, which also runs `restorecon -RF`: a
  `cp -a` from `/tmp` keeps the `tmp_t` SELinux type and systemd then fails the unit with 203/EXEC "Permission denied". Not a
  product bug: the product labels only binaries it installs on managed hosts (#401); the server release directory is placed by
  whoever deploys (here this script), so the deploy step owns its labels.
- A restart while Add host is installing stops that install ("Setup stopped before this host was ready"); re-run it.
- Safari offers "Save Password?" (with an empty user name field) after the host password form is submitted. It stalls the next
  tap; dismiss it with a tap on "Not Now" by position (`xy~0.315~0.526`).
- **Read the host tree with the sidebar OPEN (2026-11-13).** With the sidebar closed, `#tree` holds only the current view's
  rows, so a host that is connected looks missing; the c392 phase reported "tree lacks connected host" for that reason and
  nothing else. `tree_text` in `real-device-qa-mac-flow.py` now opens the sidebar first ("Show hosts" toggle). The
  locked-state read ("Unlock to connect") still needs a fresh QA1 restart to be measured with the fixed phase.
- **Never `shot` a page that can show a setup token.** A failed Continue leaves the typed token on screen; the runner also
  takes a final picture. Use `labels` and grep instead, and delete every picture of a run that types a token.
- The Mac has no `timeout` binary; use `lockf -t 0 /tmp/mac-bench.lock` (non-blocking) and retry when it is busy.
- A restart while the Add host card is open at the host-key step leaves "Check the host key again before trusting it" stuck on
  every press; only Cancel recovers. The same flow started AFTER the restart shows "Host connections are locked" with Unlock.
- Never `kill` by pattern on std: its `kayg` user is shared with other lanes (calternal). Kill by exact PID.

## Known gaps

- **The dark run is not dark yet.** (See the theme note above: the signed-in app ignores `?theme=`.)
- (older note) **The dark run is not dark yet.** `run.sh` switches the simulator to dark appearance (verified: `simctl ui
  appearance` reads `dark`, and Safari's own bar goes grey), but on 2026-11-11 the app itself stayed in its light
  theme in every dark screenshot. Whether the app ignores the system scheme on iOS or a stored theme wins is not
  isolated. Until it is, a dark check has to pick a dark theme in Settings > Themes first (not yet automated);
  treat "dark" columns as light-theme runs.
- The shell phase can abort in one theme if the "New shell" tap misses (it did once, in dark); the table then says
  REVIEW, and `check --phases shell` reruns it.
- Production cannot be signed in to from a simulator without the owner's own passkey, so prod gets no real-device run
  yet.
- Mac Safari is not covered. On 2026-11-11 `claude@infraternal-macos-01-std` could not `sudo -n` (a password is
  required), so neither `launchctl asuser 501 ... -u lume` (a GUI session to click in) nor `safaridriver --enable`
  was possible, and the Mac VM has no Touch ID for a platform passkey anyway. The same approach (its own owner on
  its own QA instance) would work if the Mac VM can make a passkey; that is unproven.
- Every tap takes up to a minute while Safari has a heavy page open (XCUITest waits for the app to idle), so a full
  light+dark check takes about 70 minutes. Rerun a single phase with `check --phases "shell"`.
- The QA server runs without a mesh node, so mesh cards (step 6) are N/A until a mesh node joins it.
