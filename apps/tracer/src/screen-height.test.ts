/**
 * The app surface must size itself from `inset: 0`, never from a viewport unit (#510).
 *
 * J600 saw the page fill only the top half of an iPhone, with a black band below, after the actions palette had been
 * used: its field raised the keyboard, and the surface kept the keyboard-sized height afterwards. `body` and `#app` are
 * `position: fixed; inset: 0`, which iOS recomputes against the layout viewport each frame. `.terminal-screen` also set
 * `height: 100dvh`, and an explicit height beats `inset`, so a `dvh` that stayed at its keyboard value pinned the whole
 * surface to it. A unit-free height cannot go stale, so the rule must not come back.
 */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

/** The production stylesheet, read as text. */
const css = readFileSync(new URL("../style.css", import.meta.url), "utf8");

/** The declarations of the first rule whose selector is exactly `selector`. */
function rule(selector: string): string {
  const at = css.indexOf(`\n${selector} {`);
  expect(at).toBeGreaterThan(-1);
  return css.slice(css.indexOf("{", at) + 1, css.indexOf("}", at));
}

test(".terminal-screen fills the layout viewport through inset, not a viewport-unit height", () => {
  const body = rule(".terminal-screen");
  expect(body).toMatch(/position:\s*fixed/);
  expect(body).toMatch(/inset:\s*0/);
  expect(body).not.toMatch(/height:\s*[\d.]*\s*(dvh|vh|svh|lvh)/);
});
