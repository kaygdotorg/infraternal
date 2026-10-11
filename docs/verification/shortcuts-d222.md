# D222 shortcut verification

Decision D222 (shortcuts follow each platform's leading terminals), research #155. Keymap commits on `shortcuts-d222`: the matching core (5df17287), the default keymap (d0aacfa1), font size (a934edca), and Keyboard Lock (91ae5037).

## What the probe measures

`apps/tracer/test/shortcut-probe.mjs` loads a bare page in each engine, attaches a capture-phase `keydown` listener that calls `preventDefault()`, presses each chord with Playwright, and records whether the page received the key and whether the key was cancelled. Run: `PATH=/usr/sbin:/usr/bin:$PATH bun test/shortcut-probe.mjs` (WebKit and Firefox need their system libraries on the PATH on this host).

Versions: Chromium 149.0.7827.55, WebKit 26.5 (the stand-in for Safari), Firefox 151.0.

**What synthetic input cannot prove.** The listener cancels every key it sees, so "cancelled" shows the page can cancel a key, not that the browser stayed quiet. Browser accelerators (⌘W, Ctrl+W, ⌘T and similar) act before the page in a real window, and Playwright's synthetic input does not trigger them. Every row below marked "hand check" must be pressed by a person in a real tab and in the installed app before the owner signs off.

## Per binding (every chord the probe covers)

| Binding | Chord | Chromium | WebKit | Firefox | Hand check (browser may act) |
|---|---|---|---|---|---|
| mac: split right | `Meta+KeyD` | received, cancelled | received, cancelled | received, cancelled | yes: bookmark this page (Chrome, Edge, Firefox, Safari) |
| mac: split down | `Meta+Shift+KeyD` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: new window right | `Meta+Enter` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: new window below | `Meta+Shift+Enter` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: palette | `Meta+KeyK` | received, cancelled | received, cancelled | received, cancelled | yes: focus the search field in some browsers |
| mac: palette alternate | `Meta+Shift+KeyP` | received, cancelled | received, cancelled | received, cancelled | yes: private window (Firefox) |
| mac: next window | `Meta+BracketRight` | received, cancelled | received, cancelled | received, cancelled | yes: next tab in some browsers (Safari: Cmd+Shift+]) |
| mac: previous window | `Meta+BracketLeft` | received, cancelled | received, cancelled | received, cancelled | yes: previous tab / back in some browsers |
| mac: move left | `Meta+Alt+ArrowLeft` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: move right | `Meta+Alt+ArrowRight` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: move up | `Meta+Alt+ArrowUp` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: move down | `Meta+Alt+ArrowDown` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: close window | `Meta+Alt+KeyW` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: panel | `Meta+Slash` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: font larger | `Meta+Equal` | received, cancelled | received, cancelled | received, cancelled | yes: zoom in |
| mac: font larger alternate | `Meta+Shift+Equal` | received, cancelled | received, cancelled | received, cancelled | yes: zoom in in some browsers |
| mac: font smaller | `Meta+Minus` | received, cancelled | received, cancelled | received, cancelled | yes: zoom out |
| mac: font reset | `Meta+Digit0` | received, cancelled | received, cancelled | received, cancelled | yes: reset zoom |
| mac: view 1 | `Meta+Digit1` | received, cancelled | received, cancelled | received, cancelled | yes: select tab 1 |
| mac: canvas lock | `Meta+Shift+KeyG` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| mac: input lock | `Meta+Shift+KeyL` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: split right | `Control+Shift+KeyD` | received, cancelled | received, cancelled | received, cancelled | yes: bookmark all tabs (Chrome, Edge, Firefox) |
| pc: split down | `Control+Shift+KeyE` | received, cancelled | received, cancelled | received, cancelled | yes: sidebar search (Edge) |
| pc: new window right | `Control+Shift+Enter` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: new window below | `Control+Shift+Alt+Enter` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: palette | `Control+Shift+KeyK` | received, cancelled | received, cancelled | received, cancelled | yes: web console (Firefox) |
| pc: palette alternate | `Control+Shift+KeyP` | received, cancelled | received, cancelled | received, cancelled | yes: print (Edge), private window (Firefox) |
| pc: next window | `Control+Shift+BracketRight` | received, cancelled | received, cancelled | received, cancelled | yes: next tab in some browsers |
| pc: previous window | `Control+Shift+BracketLeft` | received, cancelled | received, cancelled | received, cancelled | yes: previous tab in some browsers |
| pc: move left | `Control+Shift+ArrowLeft` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: move right | `Control+Shift+ArrowRight` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: move up | `Control+Shift+ArrowUp` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: move down | `Control+Shift+ArrowDown` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: close window | `Control+Shift+KeyX` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: panel | `Control+Shift+Slash` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: font larger | `Control+Equal` | received, cancelled | received, cancelled | received, cancelled | yes: zoom in |
| pc: font larger alternate | `Control+Shift+Equal` | received, cancelled | received, cancelled | received, cancelled | yes: zoom in in some browsers |
| pc: font smaller | `Control+Minus` | received, cancelled | received, cancelled | received, cancelled | yes: zoom out |
| pc: font reset | `Control+Digit0` | received, cancelled | received, cancelled | received, cancelled | yes: reset zoom |
| pc: view 1 | `Control+Shift+Digit1` | received, cancelled | received, cancelled | received, cancelled | yes: tab/zoom in some browsers |
| pc: canvas lock | `Control+Shift+KeyG` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: input lock | `Control+Shift+KeyL` | received, cancelled | received, cancelled | received, cancelled | no known browser binding |
| pc: plain Ctrl+K (terminal) | `Control+KeyK` | received, cancelled | received, cancelled | received, cancelled | yes: focus the search field (Chrome, Edge, Firefox) |

## Keys to check by hand

Keys a browser owns in a normal tab, or that a fullscreen Keyboard Lock hands over. Press each in Chromium, Edge, Firefox and Safari, in a tab and in the installed app, and record whether the window or the page responded:

- `Meta+KeyD`: bookmark this page (Chrome, Edge, Firefox, Safari)
- `Meta+KeyK`: focus the search field in some browsers
- `Meta+Shift+KeyP`: private window (Firefox)
- `Meta+Equal`: zoom in
- `Meta+Minus`: zoom out
- `Meta+Digit0`: reset zoom
- `Meta+Digit1`: select tab 1
- `Meta+BracketRight`: next tab in some browsers (Safari: Cmd+Shift+])
- `Meta+BracketLeft`: previous tab / back in some browsers
- `Meta+Shift+Equal`: zoom in in some browsers
- `Control+Shift+KeyP`: print (Edge), private window (Firefox)
- `Control+Shift+KeyD`: bookmark all tabs (Chrome, Edge, Firefox)
- `Control+Shift+KeyE`: sidebar search (Edge)
- `Control+Shift+KeyK`: web console (Firefox)
- `Control+KeyK`: focus the search field (Chrome, Edge, Firefox)
- `Control+Equal`: zoom in
- `Control+Minus`: zoom out
- `Control+Digit0`: reset zoom
- `Control+Shift+Equal`: zoom in in some browsers
- `Control+Shift+BracketRight`: next tab in some browsers
- `Control+Shift+BracketLeft`: previous tab in some browsers
- `Control+Shift+Digit1`: tab/zoom in some browsers
- `Meta+KeyW`, `Control+KeyW`, `Control+KeyT`, `Control+KeyN`: close or open a tab. Not default chords; they matter only in fullscreen with Keyboard Lock (the owner check for the bonus).
- `Control+Shift+KeyW`: closes the window in Chromium and Firefox. The canvas binds it only while the keys are locked.
- Keyboard Lock itself: it is not wired to a fullscreen action (none exists on release-prod-2 or dev, D193), so the bonus cannot be exercised yet. Test `navigator.keyboard.lock` in Chromium with a fullscreen page once the action exists.

## Specs

`apps/tracer/test/shortcuts-d222.spec.ts` (product canvas and single-terminal screen, Mac and Windows platforms emulated): every default window action, palette and alternate, the panel, the move action, lock-only close does nothing unlocked, font size steps and reset (Windows and Mac), Ctrl+K in a focused terminal reaches the shell (`accepted_input_bytes`), AltGr triggers nothing, a German layout's `?` opens the panel, and the two captures. `test/keyboard-lock.test.ts`, `test/shortcuts-keymap.test.ts`, `test/shortcuts.test.ts`, `test/platform-labels.test.ts` are unit tests.

Captures: `apps/tracer/captures/shortcuts-d222/mac-panel-ink-1440x900.png` and `windows-panel-ink-1440x900.png`.
