/**
 * The D365 glass specs must never skip (#448).
 *
 * The pixel specs once opened a mockup scene and skipped themselves when it was missing, so on a branch without the mockup the
 * contrast rule was ungated and the run was still green. They now open only what the product ships. This test keeps it so: a
 * `glass-*.spec.ts` file that calls `test.skip`, `test.fixme`, `test.fail` or tests for a scene file before running fails the unit suite.
 */
import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** The browser specs directory. */
const DIR = join(import.meta.dir, "..", "test");

test("no glass spec can skip itself", () => {
  const specs = readdirSync(DIR).filter((f) => /^glass-.*\.spec\.ts$/.test(f));
  expect(specs.length).toBeGreaterThan(5);
  const offenders = specs.filter((f) => /\btest\.(skip|fixme|fail)\(|\bexistsSync\(|appwin-scenes|appmock=/.test(readFileSync(join(DIR, f), "utf8")));
  expect(offenders).toEqual([]);
});

/** The shared stylesheet and the sign-in sheet, where a glow behind glass text used to be drawn. */
const SHEETS = [join(import.meta.dir, "..", "..", "..", "packages", "ui", "styles.css"), join(import.meta.dir, "..", "auth.css")];

test("no glass surface draws a glow behind its text (#448, TASTE)", () => {
  for (const file of SHEETS) {
    const css = readFileSync(file, "utf8");
    expect(css, `${file} defines the glass halo token`).not.toContain("--ui-overlay-halo");
    // A text-shadow on glass is a glow; only `none` resets (and the avatar's one-pixel shade on its own solid gradient) remain.
    for (const line of css.split("\n").filter((l) => /text-shadow:/.test(l) && !/text-shadow:\s*none/.test(l) && !/\.glitch|ui-sidebar-avatar|font: 600 var\(--ui-size-eyebrow\)/.test(l))) expect(line, `${file}`).toBe("");
  }
});

test("the glass specs assert the solid fallback and the absence of text shadows", () => {
  const spec = readFileSync(join(DIR, "glass-surfaces.spec.ts"), "utf8");
  expect(spec).toContain("paintOf(");
  expect(spec).toContain("mustBeSolid(");
});
