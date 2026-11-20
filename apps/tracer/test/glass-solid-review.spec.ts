/**
 * Review of "glass turns solid instead of ghosting text" (#448, D365, job J1020): the card must not flicker between glass and
 * solid while the terminal under it changes, and the change itself must be a cross-fade of about 160 ms, never a flash.
 *
 * The palette is opened over the real terminal of the mock page. The screen under it is a flat grey fill written through the
 * terminal (`writeText`), so the backdrop the glass reads is known exactly. Paper (a light card) is solid over a dark screen and
 * glass over a light one; Ink is the mirror. Three checks per scheme:
 *
 * - ramp: the screen goes from one end of the grey ramp to the other and back in steps. The card changes answer once each way and
 *   the two switch points differ (the dead band of `SOLID_HYSTERESIS`), so a card that went solid does not come back at the same level.
 * - jitter: with the screen parked inside the dead band and flipping between two greys a few levels apart every 80 ms (text
 *   scrolling past the edge of the limit), the card does not change answer at all.
 * - scroll: rows of alternating bright and dark lines stream under the card for four seconds with a video recording; the per-frame
 *   log of fill and blur must show no more than one change of answer per second, and every change a smooth fade (no frame outside
 *   the two end values, which is what a flash would be).
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { glassReady } from "./glass-settled";

/** Where the series and the videos land. */
const OUT = tracerEvidencePath("glass-solid-review");
mkdirSync(OUT, { recursive: true });

/** One frame of the log kept by {@link logFrames}. */
interface Sample { t: number; answer: string; bg: string; blur: string; anims: number; under: string }

/** Opens the palette over a real terminal in `scheme` at card 4 and returns the page. */
async function openOver(page: Page, scheme: "ink" | "paper"): Promise<void> {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto(`/?mock=1&theme=${scheme}&card=4&fps=0`);
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await glassReady(page);
}

/** Paints every cell of the terminal with grey level `g`, in one write. */
async function fill(page: Page, g: number): Promise<void> {
  await page.evaluate((level) => {
    const m = window.__tracerTestDouble!.rendererMetrics()!;
    const row = " ".repeat(m.cols);
    let text = `\x1b[48;2;${level};${level};${level}m`;
    for (let r = 1; r <= m.rows; r++) text += `\x1b[${r};1H${row}`;
    window.__tracerTestDouble!.writeText(`${text}\x1b[0m`);
  }, g);
}

/** The answer the palette carries right now. */
const answerOf = (page: Page): Promise<string> => page.evaluate(() => document.querySelector<HTMLElement>("#palette")!.dataset.glassAnswer ?? "none");

/** Starts a per-frame log of the palette's answer, fill and blur in `globalThis.__series`. */
async function logFrames(page: Page): Promise<void> {
  await page.evaluate(() => {
    const series: Array<{ t: number; answer: string; bg: string; blur: string; anims: number; under: string }> = [];
    (globalThis as { __series?: typeof series }).__series = series;
    const tick = (now: number): void => {
      const p = document.querySelector<HTMLElement>("#palette");
      if (p) { const s = getComputedStyle(p); series.push({ t: now, answer: p.dataset.glassAnswer ?? "none", bg: s.backgroundColor, blur: s.backdropFilter, anims: p.getAnimations().length, under: p.dataset.glassUnder ?? "none" }); }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

/** The alpha of a computed colour string (`rgb(...)`, `rgba(...)` or `oklab(... / a)`). */
function alphaOf(css: string): number {
  const slash = /\/\s*([\d.]+%?)\s*\)/.exec(css);
  if (slash) return slash[1]!.endsWith("%") ? parseFloat(slash[1]!) / 100 : parseFloat(slash[1]!);
  const rgba = /^rgba\([^,]+,[^,]+,[^,]+,\s*([\d.]+)\)/.exec(css);
  return rgba ? parseFloat(rgba[1]!) : 1;
}

/** The blur radius of a computed backdrop filter in px (0 for none). */
const blurOf = (css: string): number => parseFloat(/blur\(([\d.]+)px\)/.exec(css)?.[1] ?? "0") || 0;

for (const scheme of ["paper", "ink"] as const) {
  test(`${scheme}: solid and glass change once each way with a dead band, and do not flicker at the edge`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: scheme === "ink" ? "dark" : "light" });
    const page = await context.newPage();
    await openOver(page, scheme);
    await page.evaluate(() => document.documentElement.setAttribute("data-glass-stats", ""));
    // Paper is solid over black, Ink over white: start at the end that makes the card solid.
    const solidEnd = scheme === "paper" ? 0 : 255;
    const step = scheme === "paper" ? 8 : -8;
    await fill(page, solidEnd);
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    // sleep: the open animation and the first read of the cells
    await page.waitForTimeout(700);
    expect(await answerOf(page), "solid over the hard end").toBe("solid");

    /** Puts the screen at `g` and waits long enough for the glass to have answered; returns the answer. */
    const at = async (g: number): Promise<string> => { await fill(page, g); await page.waitForTimeout(450); return answerOf(page); };

    // Ramp away from the hard end until the answer changes, then on to the far end, then all the way back.
    const up: Array<[number, string]> = [];
    let g = solidEnd;
    for (let i = 0; i < 32; i++) { g = Math.max(0, Math.min(255, g + step)); up.push([g, await at(g)]); }
    const goesGlassAt = up.find(([, a]) => a === "glass")?.[0];
    expect(goesGlassAt, `turned to glass somewhere on the ramp ${JSON.stringify(up)}`).toBeDefined();
    expect(up.filter(([, a], i) => i > 0 && a !== up[i - 1]![1]).length, `one change on the way up ${JSON.stringify(up)}`).toBe(1);
    const down: Array<[number, string]> = [];
    for (let i = 0; i < 32; i++) { g = Math.max(0, Math.min(255, g - step)); down.push([g, await at(g)]); }
    const goesSolidAt = down.find(([, a]) => a === "solid")?.[0];
    expect(goesSolidAt, `turned back to solid on the way down ${JSON.stringify(down)}`).toBeDefined();
    expect(down.filter(([, a], i) => i > 0 && a !== down[i - 1]![1]).length, `one change on the way down ${JSON.stringify(down)}`).toBe(1);
    // The dead band: the card went solid on the way down at a level this many greys closer to the solid end than it left it going up.
    const band = Math.abs(goesGlassAt! - goesSolidAt!);
    appendFileSync(`${OUT}/ramp.jsonl`, `${JSON.stringify({ scheme, goesGlassAt, goesSolidAt, band, up, down })}\n`);
    expect(Math.sign(goesGlassAt! - goesSolidAt!), "going up and coming back switch at different levels").toBe(scheme === "paper" ? 1 : -1);
    expect(band, "the dead band is at least one step wide").toBeGreaterThanOrEqual(8);

    // Jitter inside the dead band: park the screen at the middle of it, from the glass side, and flip it by a few levels.
    const mid = Math.round((goesGlassAt! + goesSolidAt!) / 2);
    for (const from of [solidEnd, 255 - solidEnd]) {
      await at(from);
      const before = await at(mid);
      await logFrames(page);
      for (let i = 0; i < 40; i++) { await fill(page, mid + (i % 2 === 0 ? 4 : -4)); await page.waitForTimeout(80); }
      const series = await page.evaluate(() => (globalThis as { __series?: Sample[] }).__series!);
      const answers = new Set(series.map((s) => s.answer));
      appendFileSync(`${OUT}/jitter.jsonl`, `${JSON.stringify({ scheme, from, mid, before, answers: [...answers], frames: series.length })}\n`);
      expect([...answers], `from ${from}, parked at ${mid} and flipping by 4: the answer never changes`).toEqual([before]);
    }
    await context.close();
  });

  test(`${scheme}: a terminal scrolling under the card changes its answer rarely and only by smooth fades`, async ({ browser }, info) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: scheme === "ink" ? "dark" : "light", recordVideo: { dir: `${OUT}/video-${scheme}`, size: { width: 1440, height: 900 } } });
    const page = await context.newPage();
    await openOver(page, scheme);
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    // sleep: the open animation
    await page.waitForTimeout(600);
    await logFrames(page);
    // About 30 lines a second for 4 s: every third line is a full-width inverse row (a bright band), the rest plain dense text.
    await page.evaluate(async () => {
      const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
      for (let i = 0; i < 120; i++) {
        const body = `drwxr-xr-x  12 kayg kayg  ${String(4096 + i * 37).padStart(6)} Nov  9 12:${String(i % 60).padStart(2, "0")} infraternal-${i.toString(16)}-build-output`;
        window.__tracerTestDouble!.writeText(i % 3 === 0 ? `\x1b[7m${body.padEnd(140)}\x1b[0m\r\n` : `${body}\r\n`);
        await wait(33);
      }
    });
    // sleep: let the last fade finish
    await page.waitForTimeout(400);
    const series = await page.evaluate(() => (globalThis as { __series?: Sample[] }).__series!);
    const changes: Array<{ at: number; to: string }> = [];
    series.forEach((s, i) => { if (i > 0 && s.answer !== series[i - 1]!.answer) changes.push({ at: Math.round(s.t - series[0]!.t), to: s.answer }); });
    const seconds = (series[series.length - 1]!.t - series[0]!.t) / 1000;
    // The frames around each change, to see whether it faded (several distinct fills, an animation running) or popped.
    const around = changes.map((c) => series.filter((s) => Math.abs(s.t - series[0]!.t - c.at) < 80).map((s) => ({ dt: Math.round(s.t - series[0]!.t), a: alphaOf(s.bg).toFixed(2), b: blurOf(s.blur).toFixed(1), anims: s.anims, ans: s.answer, under: s.under })));
    appendFileSync(`${OUT}/scroll.jsonl`, `${JSON.stringify({ scheme, around, frames: series.length, seconds: Number(seconds.toFixed(2)), changes, alphas: [...new Set(series.map((s) => alphaOf(s.bg).toFixed(2)))], blurs: [...new Set(series.map((s) => blurOf(s.blur)))] })}\n`);
    expect(changes.length / seconds, `answer changes per second while scrolling: ${JSON.stringify(changes)}`).toBeLessThanOrEqual(1);
    // No flash: every frame's fill and blur lie between the values the card HELD (steady for 250 ms or more) in this run; a flash
    // through transparent or through a blur spike would leave that range.
    const held = (pick: (s: Sample) => number): number[] => {
      const out: number[] = [];
      let from = 0;
      for (let i = 1; i <= series.length; i++) {
        if (i === series.length || pick(series[i]!) !== pick(series[from]!)) { if (series[i - 1]!.t - series[from]!.t >= 250) out.push(pick(series[from]!)); from = i; }
      }
      return out;
    };
    const heldAlpha = held((s) => alphaOf(s.bg)), heldBlur = held((s) => blurOf(s.blur));
    expect(heldAlpha.length, "the run has at least one steady state").toBeGreaterThan(0);
    // No pop: no single frame moves the fill by more than 0.2 or the blur by more than 12 px. A 160 ms ease-out fade moves the
    // fill by about 0.07 and the blur by about 5.3 px in its first 16 ms frame; a pop (a fade that did not run) moves it all at once.
    const steps = series.slice(1).map((s, i) => ({ dt: Math.round(s.t - series[0]!.t), alpha: Math.abs(alphaOf(s.bg) - alphaOf(series[i]!.bg)), blur: Math.abs(blurOf(s.blur) - blurOf(series[i]!.blur)) }));
    const worst = steps.reduce((a, b) => (b.alpha > a.alpha ? b : a), { dt: 0, alpha: 0, blur: 0 });
    const worstBlur = steps.reduce((a, b) => (b.blur > a.blur ? b : a), { dt: 0, alpha: 0, blur: 0 });
    appendFileSync(`${OUT}/scroll-steps.jsonl`, `${JSON.stringify({ scheme, worstAlphaStep: worst, worstBlurStep: worstBlur })}\n`);
    expect(worst.alpha, `largest single-frame step of the fill: ${JSON.stringify(worst)}`).toBeLessThanOrEqual(0.2);
    expect(worstBlur.blur, `largest single-frame step of the blur: ${JSON.stringify(worstBlur)}`).toBeLessThanOrEqual(12);
    for (const s of series) {
      expect(alphaOf(s.bg), "fill alpha stays inside the steady values").toBeGreaterThanOrEqual(Math.min(...heldAlpha) - 0.02);
      expect(alphaOf(s.bg)).toBeLessThanOrEqual(Math.max(...heldAlpha) + 0.02);
      expect(blurOf(s.blur), "blur stays inside the steady values").toBeGreaterThanOrEqual(Math.min(...heldBlur) - 0.5);
      expect(blurOf(s.blur)).toBeLessThanOrEqual(Math.max(...heldBlur) + 0.5);
    }
    await context.close();
    info.annotations.push({ type: "video", description: `${OUT}/video-${scheme}` });
  });
}

for (const scheme of ["paper", "ink"] as const) {
  for (const direction of ["to-glass", "to-solid"] as const) {
    test(`${scheme} ${direction}: the change is a 160 ms fade of the fill and the blur, monotonic, nothing outside the two end values`, async ({ browser }) => {
      const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: scheme === "ink" ? "dark" : "light" });
      const page = await context.newPage();
      await openOver(page, scheme);
      // The end that makes the card solid (black under Paper, white under Ink) and the end that keeps it glass.
      const hard = scheme === "paper" ? 0 : 255, easy = 255 - hard;
      await fill(page, direction === "to-glass" ? hard : easy);
      await page.keyboard.press("Control+Shift+K");
      await expect(page.locator("#palette")).toBeVisible();
      // sleep: the open animation and the first read
      await page.waitForTimeout(700);
      expect(await answerOf(page)).toBe(direction === "to-glass" ? "solid" : "glass");
      await logFrames(page);
      await fill(page, direction === "to-glass" ? easy : hard);
      // sleep: the glass answers within a sample and fades for 160 ms
      await page.waitForTimeout(900);
      const series = await page.evaluate(() => (globalThis as { __series?: Sample[] }).__series!);
      const alphas = series.map((s) => alphaOf(s.bg)), blurs = series.map((s) => blurOf(s.blur));
      const moving = series.filter((s, i) => i > 0 && (alphaOf(s.bg) !== alphaOf(series[i - 1]!.bg) || blurOf(s.blur) !== blurOf(series[i - 1]!.blur)));
      const duration = moving.length ? moving[moving.length - 1]!.t - moving[0]!.t : 0;
      const first = alphas[0]!, last = alphas[alphas.length - 1]!;
      const distinct = (xs: number[]): number[] => xs.filter((a, i) => i === 0 || a !== xs[i - 1]).map((a) => Number(a.toFixed(3)));
      appendFileSync(`${OUT}/fade.jsonl`, `${JSON.stringify({ scheme, direction, first, last, duration: Math.round(duration), alphas: distinct(alphas), blurs: distinct(blurs) })}\n`);
      const hi = Math.max(first, last), lo = Math.min(first, last);
      for (const a of alphas) { expect(a, "fill never outside the two end values").toBeGreaterThanOrEqual(lo - 0.02); expect(a).toBeLessThanOrEqual(hi + 0.02); }
      // monotone from the first end to the last
      const sign = last > first ? 1 : -1;
      for (let i = 1; i < alphas.length; i++) expect(sign * (alphas[i]! - alphas[i - 1]!), `fill moves the wrong way at frame ${i}`).toBeGreaterThanOrEqual(-0.02);
      expect(distinct(alphas).length, `a fade has intermediate frames, a pop has none: ${JSON.stringify(distinct(alphas))}`).toBeGreaterThan(3);
      expect(duration, "the fade lasts about 160 ms").toBeGreaterThan(80);
      expect(duration).toBeLessThan(320);
      await context.close();
    });
  }
}
