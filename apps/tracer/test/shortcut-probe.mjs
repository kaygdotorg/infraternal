/**
 * Browser probe for D222 (docs/verification/shortcuts-d222.md). For each default chord it loads a bare page, attaches a
 * keydown listener that calls preventDefault, presses the chord with Playwright, and records two facts: did the page
 * receive the keydown, and was it cancelled. Chromium, WebKit (the stand-in for Safari) and Firefox are each run.
 *
 * What it cannot show: browser accelerators (⌘W, Ctrl+T and similar) are handled by the browser before the page in a real
 * window, and synthetic input does not trigger them. Those rows are reported as "not synthetic-testable"; the doc lists them
 * for a hand check. Usage: bun test/shortcut-probe.mjs > probe.json
 */
import { chromium, firefox, webkit } from "playwright";

const CHORDS = {
  mac: [
    ["split right", "Meta+KeyD"], ["split down", "Meta+Shift+KeyD"], ["new window right", "Meta+Enter"], ["new window below", "Meta+Shift+Enter"],
    ["palette", "Meta+KeyK"], ["palette alternate", "Meta+Shift+KeyP"], ["next window", "Meta+BracketRight"], ["previous window", "Meta+BracketLeft"],
    ["move left", "Meta+Alt+ArrowLeft"], ["move right", "Meta+Alt+ArrowRight"], ["move up", "Meta+Alt+ArrowUp"], ["move down", "Meta+Alt+ArrowDown"],
    ["close window", "Meta+Alt+KeyW"], ["panel", "Meta+Slash"], ["font larger", "Meta+Equal"], ["font larger alternate", "Meta+Shift+Equal"],
    ["font smaller", "Meta+Minus"], ["font reset", "Meta+Digit0"], ["view 1", "Meta+Digit1"], ["canvas lock", "Meta+Shift+KeyG"], ["input lock", "Meta+Shift+KeyL"],
  ],
  pc: [
    ["split right", "Control+Shift+KeyD"], ["split down", "Control+Shift+KeyE"], ["new window right", "Control+Shift+Enter"], ["new window below", "Control+Shift+Alt+Enter"],
    ["palette", "Control+Shift+KeyK"], ["palette alternate", "Control+Shift+KeyP"], ["next window", "Control+Shift+BracketRight"], ["previous window", "Control+Shift+BracketLeft"],
    ["move left", "Control+Shift+ArrowLeft"], ["move right", "Control+Shift+ArrowRight"], ["move up", "Control+Shift+ArrowUp"], ["move down", "Control+Shift+ArrowDown"],
    ["close window", "Control+Shift+KeyX"], ["panel", "Control+Shift+Slash"], ["font larger", "Control+Equal"], ["font larger alternate", "Control+Shift+Equal"],
    ["font smaller", "Control+Minus"], ["font reset", "Control+Digit0"], ["view 1", "Control+Shift+Digit1"], ["canvas lock", "Control+Shift+KeyG"], ["input lock", "Control+Shift+KeyL"],
    ["plain Ctrl+K (terminal)", "Control+KeyK"],
  ],
};
const engines = { chromium, webkit, firefox };
const results = {};
for (const [name, launcher] of Object.entries(engines)) {
  let browser;
  try {
    browser = await launcher.launch();
  } catch (error) {
    results[name] = { error: String(error.message ?? error).split("\n")[0] };
    continue;
  }
  const page = await browser.newPage();
  const rows = {};
  for (const [family, list] of Object.entries(CHORDS)) {
    for (const [label, chord] of list) {
      await page.setContent(`<!doctype html><body><script>
        window.__seen = null;
        window.addEventListener("keydown", (e) => { window.__seen = { key: e.key, prevented: false }; e.preventDefault(); window.__seen.prevented = e.defaultPrevented; }, true);
      </script></body>`);
      await page.keyboard.press(chord).catch(() => undefined);
      const seen = await page.evaluate(() => window.__seen);
      rows[`${family}: ${label} ${chord}`] = {
        received: !!seen,
        cancelled: !!seen?.prevented,
      };
    }
  }
  results[name] = { version: browser.version(), rows };
  await browser.close();
}
console.log(JSON.stringify(results, null, 1));
